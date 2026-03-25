// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package arq provides a high-performance, QUIC-inspired reliable transport
// overlay specifically designed to operate over DNS/UDP architectures.
// ==============================================================================
package arq

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

// StreamState mirrors Python's Stream_State enum
type StreamState int

const (
	StateOpen StreamState = iota
	StateHalfClosedLocal
	StateHalfClosedRemote
	StateClosing
	StateReset
	StateClosed
	StateDraining
	StateTimeWait
)

// PacketEnqueuer abstracts the transmission layer (Client or Server stream)
type PacketEnqueuer interface {
	PushTXPacket(priority int, packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, compressionType uint8, ttl time.Duration, payload []byte) bool
}

type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Errorf(format string, args ...any)
}

type dummyLogger struct{}

func (d *dummyLogger) Debugf(f string, a ...any) {}
func (d *dummyLogger) Infof(f string, a ...any)  {}
func (d *dummyLogger) Errorf(f string, a ...any) {}

type arqDataItem struct {
	Data            []byte
	CreatedAt       time.Time
	LastSentAt      time.Time
	Retries         int
	CurrentRTO      time.Duration
	CompressionType uint8
	TTL             time.Duration
}

type arqControlItem struct {
	PacketType     uint8
	SequenceNum    uint16
	FragmentID     uint8
	TotalFragments uint8
	AckType        uint8
	Payload        []byte
	Priority       int
	CreatedAt      time.Time
	LastSentAt     time.Time
	Retries        int
	CurrentRTO     time.Duration
	TTL            time.Duration
}

var setupControlPacketTypes = map[uint8]bool{
	Enums.PACKET_STREAM_SYN: true,
	Enums.PACKET_SOCKS5_SYN: true,
}

type ARQ struct {
	mu sync.Mutex

	streamID             uint16
	sessionID            uint8
	ioReady              bool
	streamWorkersStarted bool
	enqueuer             PacketEnqueuer
	localConn            io.ReadWriteCloser
	logger               Logger

	mtu             int
	compressionType uint8

	// Sequence and buffers
	sndNxt        uint16
	rcvNxt        uint16
	sndBuf        map[uint16]*arqDataItem
	rcvBuf        map[uint16][]byte
	controlSndBuf map[uint32]*arqControlItem // key: ptype << 24 | sn << 8 | fragID

	// Stream lifecycle and flags
	state        StreamState
	closed       bool
	closeReason  string
	lastActivity time.Time

	finSent     bool
	finReceived bool
	finAcked    bool
	finSeqSent  *uint16

	rstReceived bool
	rstSent     bool
	rstAcked    bool
	rstSeqSent  *uint16

	localWriteClosed bool
	stopLocalRead    bool
	deferredClose    bool
	deferredReason   string
	deferredDeadline time.Time
	deferredPacket   uint8
	waitingAck       bool
	waitingAckFor    uint8
	ackWaitDeadline  time.Time

	// Backpressure
	windowSize    int
	limit         int
	windowNotFull chan struct{} // Acts as asyncio.Event
	writeLock     sync.Mutex    // equivalent to asyncio.Lock for writer

	// Tuning Configuration
	rto                  time.Duration
	maxRTO               time.Duration
	inactivityTimeout    time.Duration
	dataPacketTTL        time.Duration
	maxDataRetries       int
	terminalDrainTimeout time.Duration
	terminalAckWait      time.Duration

	// Control-plane tuning
	enableControlReliability bool
	controlRto               time.Duration
	controlMaxRto            time.Duration
	controlMaxRetries        int
	controlPacketTTL         time.Duration

	// Virtual streams do not emit local close side effects.
	isVirtual bool

	// Concurrency
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	flushSignal chan struct{}
}

type closeWriter interface {
	CloseWrite() error
}

// Config represents the extensive ARQ tuning configuration identically ported from Python
type Config struct {
	WindowSize               int
	RTO                      float64
	MaxRTO                   float64
	IsVirtual                bool
	StartPaused              bool
	EnableControlReliability bool
	ControlRTO               float64
	ControlMaxRTO            float64
	ControlMaxRetries        int
	InactivityTimeout        float64
	DataPacketTTL            float64
	MaxDataRetries           int
	ControlPacketTTL         float64
	TerminalDrainTimeout     float64
	TerminalAckWaitTimeout   float64
	CompressionType          uint8
}

type CloseOptions struct {
	Force      bool
	SendRST    bool
	SendFIN    bool
	AfterDrain bool
	TTL        time.Duration
}

func (a *ARQ) IsClosed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed
}

func (a *ARQ) State() StreamState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state
}

// NewARQ instantiates a pristine reliable streaming overlay suitable for client or server
func NewARQ(streamID uint16, sessionID uint8, enqueuer PacketEnqueuer, localConn io.ReadWriteCloser, mtu int, logger Logger, cfg Config) *ARQ {
	if logger == nil {
		logger = &dummyLogger{}
	}

	windowSize := max(cfg.WindowSize, 300)

	limit := max(int(float64(windowSize)*0.8), 50)

	a := &ARQ{
		streamID:  streamID,
		sessionID: sessionID,
		ioReady:   !cfg.StartPaused,
		enqueuer:  enqueuer,
		localConn: localConn,
		logger:    logger,
		mtu:       mtu,

		sndBuf:        make(map[uint16]*arqDataItem),
		rcvBuf:        make(map[uint16][]byte),
		controlSndBuf: make(map[uint32]*arqControlItem),

		state:        StateOpen,
		lastActivity: time.Now(),

		windowSize:    windowSize,
		limit:         limit,
		windowNotFull: make(chan struct{}, 1),
		writeLock:     sync.Mutex{},
		flushSignal:   make(chan struct{}, 1),

		inactivityTimeout:    time.Duration(maxF(120.0, cfg.InactivityTimeout) * float64(time.Second)),
		dataPacketTTL:        time.Duration(maxF(120.0, cfg.DataPacketTTL) * float64(time.Second)),
		maxDataRetries:       maxI(60, cfg.MaxDataRetries),
		terminalDrainTimeout: time.Duration(maxF(60.0, cfg.TerminalDrainTimeout) * float64(time.Second)),
		terminalAckWait:      time.Duration(maxF(30.0, cfg.TerminalAckWaitTimeout) * float64(time.Second)),

		enableControlReliability: cfg.EnableControlReliability,
		controlMaxRetries:        maxI(5, cfg.ControlMaxRetries),
		controlPacketTTL:         time.Duration(maxF(120.0, cfg.ControlPacketTTL) * float64(time.Second)),

		isVirtual:       cfg.IsVirtual,
		compressionType: cfg.CompressionType,
	}

	a.streamWorkersStarted = false

	// Apply Event unblock state
	a.signalWindowNotFull()

	userMaxRto := maxF(0.05, cfg.MaxRTO)
	a.maxRTO = time.Duration(userMaxRto * float64(time.Second))
	a.rto = time.Duration(minF(maxF(0.05, cfg.RTO), userMaxRto) * float64(time.Second))

	userControlMaxRto := maxF(0.05, cfg.ControlMaxRTO)
	a.controlMaxRto = time.Duration(userControlMaxRto * float64(time.Second))
	a.controlRto = time.Duration(minF(maxF(0.05, cfg.ControlRTO), userControlMaxRto) * float64(time.Second))

	a.ctx, a.cancel = context.WithCancel(context.Background())
	return a
}

// Start launches the core background loops for IO multiplexing and retransmission
func (a *ARQ) Start() {
	a.wg.Add(1)
	go a.retransmitLoop()

	if a.ioReady {
		a.startStreamWorkers()
	}
}

func (a *ARQ) startStreamWorkers() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.streamWorkersStarted {
		return
	}

	if a.localConn == nil {
		return
	}

	a.streamWorkersStarted = true

	a.wg.Add(1)
	go a.ioLoop()

	a.wg.Add(1)
	go a.writeLoop()

	a.signalFlushReady()
}

func (a *ARQ) SetLocalConn(conn io.ReadWriteCloser) {
	a.mu.Lock()
	if a.localConn != nil {
		a.mu.Unlock()
		return
	}
	a.localConn = conn
	shouldStart := a.ctx != nil && a.ctx.Err() == nil && a.ioReady
	a.mu.Unlock()

	if shouldStart {
		a.startStreamWorkers()
		a.signalFlushReady()
	}
}

func (a *ARQ) SetIOReady(ready bool) {
	a.mu.Lock()
	changed := a.ioReady != ready
	a.ioReady = ready
	a.mu.Unlock()

	if !changed {
		return
	}

	if ready {
		a.startStreamWorkers()
		a.signalFlushReady()
	}
}

// Done returns a channel that is closed when the ARQ context is cancelled or the stream is closed.
func (a *ARQ) Done() <-chan struct{} {
	return a.ctx.Done()
}

// ---------------------------------------------------------------------
// Small Utilities
// ---------------------------------------------------------------------

func minF(x, y float64) float64 {
	if x < y {
		return x
	}
	return y
}

func maxF(x, y float64) float64 {
	if x > y {
		return x
	}
	return y
}

func maxI(x, y int) int {
	if x > y {
		return x
	}
	return y
}

// ---------------------------------------------------------------------
// Flow Control & Shared State Helpers
// ---------------------------------------------------------------------

func (a *ARQ) signalWindowNotFull() {
	select {
	case a.windowNotFull <- struct{}{}:
	default:
	}
}

func (a *ARQ) waitWindowNotFull() {
	select {
	case <-a.windowNotFull:
		a.signalWindowNotFull()
	case <-a.ctx.Done():
	}
}

func (a *ARQ) clearWindowNotFull() {
	select {
	case <-a.windowNotFull:
	default:
	}
}

func (a *ARQ) signalFlushReady() {
	select {
	case a.flushSignal <- struct{}{}:
	default:
	}
}

// IsReset checks whether stream is explicitly in reset path
func (a *ARQ) IsReset() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state == StateReset || a.rstReceived || a.rstSent
}

// setState atomically transitions the stream
func (a *ARQ) setState(newState StreamState) {
	a.state = newState
}

func (a *ARQ) finReceivedLocked() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.finReceived
}

func (a *ARQ) isClosed() bool {
	return a.IsClosed()
}

// clearAllQueues is used to wipe state instantly (RST / Abort semantics)
func (a *ARQ) clearAllQueues(clearControl bool) {
	a.sndBuf = make(map[uint16]*arqDataItem)
	a.rcvBuf = make(map[uint16][]byte)
	if clearControl {
		a.controlSndBuf = make(map[uint32]*arqControlItem)
	}

	a.signalWindowNotFull()
}

// ---------------------------------------------------------------------
// Transitions & Hooks
// ---------------------------------------------------------------------
func (a *ARQ) MarkFinSent() {
	a.mu.Lock()
	a.finSent = true

	if a.finReceived {
		a.setState(StateClosing)
	} else {
		a.setState(StateHalfClosedLocal)
	}
	a.mu.Unlock()

	a.tryFinalizeRemoteEOF()
}

func (a *ARQ) MarkFinReceived() {
	a.mu.Lock()
	if a.isVirtual {
		a.mu.Unlock()
		return
	}

	a.finReceived = true

	if a.finSent {
		a.setState(StateClosing)
		a.mu.Unlock()
		a.halfCloseLocalWriter()
		a.tryFinalizeRemoteEOF()
		return
	}

	a.setState(StateHalfClosedRemote)
	a.mu.Unlock()
	a.halfCloseLocalWriter()
	a.tryFinalizeRemoteEOF()
}

func (a *ARQ) markFinAcked() {
	a.mu.Lock()
	a.finAcked = true

	if a.finReceived {
		a.setState(StateClosing)
	}

	a.mu.Unlock()
}

func (a *ARQ) halfCloseLocalWriter() {
	a.mu.Lock()
	if a.localWriteClosed || a.closed {
		a.mu.Unlock()
		return
	}

	a.localWriteClosed = true
	conn := a.localConn
	a.mu.Unlock()

	if conn == nil {
		return
	}

	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func (a *ARQ) clearWaitingAck(packetType uint8) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.waitingAck && a.waitingAckFor == packetType {
		a.waitingAck = false
		a.waitingAckFor = 0
		a.ackWaitDeadline = time.Time{}
	}
}

func (a *ARQ) clearTrackedControlPacket(packetType uint8, sequenceNum uint16, fragmentID uint8) {
	a.mu.Lock()
	delete(a.controlSndBuf, uint32(packetType)<<24|uint32(sequenceNum)<<8|uint32(fragmentID))
	a.mu.Unlock()
}

func (a *ARQ) tryFinalizeRemoteEOF() {
	a.mu.Lock()
	waitingForFinAck := a.waitingAck && a.waitingAckFor == Enums.PACKET_STREAM_FIN
	shouldClose := !a.closed && a.finReceived && (a.finAcked || (a.finSent && !waitingForFinAck))
	a.mu.Unlock()

	if shouldClose {
		a.finalizeClose("FIN handshake completed")
	}
}

func (a *ARQ) MarkRstSent() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rstSent = true
	a.clearAllQueues(true)
	a.setState(StateReset)
}

func (a *ARQ) MarkRstReceived() {
	a.mu.Lock()
	if a.isVirtual {
		a.mu.Unlock()
		return
	}

	a.rstReceived = true
	a.clearAllQueues(true)
	a.setState(StateReset)
	a.mu.Unlock()
}

func (a *ARQ) markRstAcked() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rstAcked = true
	a.clearAllQueues(true)
	a.setState(StateReset)
}

// ---------------------------------------------------------------------
// Core Loops
// ---------------------------------------------------------------------

// ioLoop reads from local socket data and enqueues reliable outbound packets
func (a *ARQ) ioLoop() {
	defer a.wg.Done()

	resetRequired := false
	gracefulEOF := false
	alreadyHandled := false
	var errorReason string

	buf := make([]byte, a.mtu)

	for !a.isClosed() {
		a.waitWindowNotFull()

		a.mu.Lock()
		if a.stopLocalRead || a.closed {
			a.mu.Unlock()
			alreadyHandled = true
			break
		}

		if !a.ioReady {
			a.mu.Unlock()
			select {
			case <-a.ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}

		if a.localConn == nil {
			a.mu.Unlock()
			errorReason = "Local connection missing"
			resetRequired = true
			break
		}
		a.mu.Unlock()

		if c, ok := a.localConn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		}

		n, err := a.localConn.Read(buf)
		if err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				continue
			}

			if errors.Is(err, io.EOF) {
				errorReason = "Local App Closed Connection (EOF)"
				gracefulEOF = true
			} else {
				errorReason = "Read Error: " + err.Error()
				resetRequired = true
			}
			break
		}

		if n <= 0 {
			continue
		}

		raw := append([]byte(nil), buf[:n]...)

		a.mu.Lock()
		a.lastActivity = time.Now()
		sn := a.sndNxt
		a.sndNxt++

		a.sndBuf[sn] = &arqDataItem{
			Data:            raw,
			CreatedAt:       time.Now(),
			LastSentAt:      time.Now(),
			Retries:         0,
			CurrentRTO:      a.rto,
			CompressionType: a.compressionType,
			TTL:             0,
		}

		if len(a.sndBuf) >= a.limit {
			a.clearWindowNotFull()
		}
		a.mu.Unlock()

		a.enqueuer.PushTXPacket(
			Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA),
			Enums.PACKET_STREAM_DATA,
			sn, 0, 0, a.compressionType, 0, raw,
		)
	}

	if a.isClosed() || alreadyHandled {
		return
	}

	if resetRequired {
		a.Close(errorReason, CloseOptions{SendRST: true})
		return
	}

	if gracefulEOF {
		a.Close(errorReason, CloseOptions{SendFIN: true, AfterDrain: true})
		return
	}
}

// ---------------------------------------------------------------------
// Terminal Emit / Drain Helpers
// ---------------------------------------------------------------------

// deferTerminalPacket arms a drain-before-terminal phase.
// It stops new local reads, waits for pending outbound data to drain,
// then `settleTerminalDrain` decides whether to emit FIN or fall back to RST.
func (a *ARQ) deferTerminalPacket(reason string, packetType uint8) {
	a.mu.Lock()
	if a.closed || a.isVirtual {
		a.mu.Unlock()
		return
	}

	if a.state != StateReset && a.state != StateClosed {
		a.setState(StateDraining)
	}

	a.stopLocalRead = true
	a.deferredClose = true
	a.deferredReason = reason
	a.deferredPacket = packetType

	deadline := time.Now().Add(a.terminalDrainTimeout)
	if a.deferredDeadline.IsZero() || deadline.After(a.deferredDeadline) {
		a.deferredDeadline = deadline
	}

	sndBufLen := len(a.sndBuf)
	a.mu.Unlock()

	if sndBufLen == 0 {
		a.settleTerminalDrain()
	}
}

// settleTerminalDrain completes a previously deferred terminal close.
func (a *ARQ) settleTerminalDrain() {
	var (
		packetType uint8
		shouldEmit bool
		reason     string
	)

	a.mu.Lock()
	if a.closed || !a.deferredClose {
		a.mu.Unlock()
		return
	}

	switch {
	case len(a.sndBuf) == 0:
		shouldEmit = true
		packetType = a.deferredPacket
		reason = a.deferredReason
	case !a.deferredDeadline.IsZero() && time.Now().After(a.deferredDeadline):
		shouldEmit = true
		packetType = Enums.PACKET_STREAM_RST
		reason = a.deferredReason + " but drain timeout expired"
	default:
		a.mu.Unlock()
		return
	}

	a.deferredClose = false
	a.deferredReason = ""
	a.deferredDeadline = time.Time{}
	a.deferredPacket = 0
	a.mu.Unlock()
	if shouldEmit {
		a.Close(reason, CloseOptions{
			SendFIN: packetType == Enums.PACKET_STREAM_FIN,
			SendRST: packetType != Enums.PACKET_STREAM_FIN,
		})
	}
}

func (a *ARQ) emitTerminalPacketWithTTL(packetType uint8, reason string, ttl time.Duration) {
	a.mu.Lock()
	if a.closed || a.isVirtual {
		a.mu.Unlock()
		return
	}

	a.closeReason = reason
	a.stopLocalRead = true
	a.deferredClose = false
	a.deferredReason = ""
	a.deferredDeadline = time.Time{}
	a.deferredPacket = 0

	if a.waitingAck && a.waitingAckFor == packetType {
		a.mu.Unlock()
		return
	}

	switch packetType {
	case Enums.PACKET_STREAM_FIN:
		if a.rstSent || a.rstReceived || a.finSent {
			a.mu.Unlock()
			return
		}
		if a.finSeqSent == nil {
			seq := uint16(0)
			a.finSeqSent = &seq
		}
		finSeq := *a.finSeqSent
		a.waitingAck = true
		a.waitingAckFor = packetType
		a.ackWaitDeadline = time.Now().Add(a.terminalAckWait)
		a.mu.Unlock()

		a.MarkFinSent()
		ackType := uint8(Enums.PACKET_STREAM_FIN_ACK)
		a.SendControlPacketWithTTL(Enums.PACKET_STREAM_FIN, finSeq, 0, 0, nil, Enums.DefaultPacketPriority(Enums.PACKET_STREAM_FIN), a.enableControlReliability, &ackType, ttl)
	case Enums.PACKET_STREAM_RST:
		if a.rstReceived || a.rstSent {
			a.mu.Unlock()
			return
		}
		if a.rstSeqSent == nil {
			seq := uint16(0)
			a.rstSeqSent = &seq
		}
		rstSeq := *a.rstSeqSent
		a.clearAllQueues(true)
		a.waitingAck = true
		a.waitingAckFor = packetType
		a.ackWaitDeadline = time.Now().Add(a.terminalAckWait)
		a.mu.Unlock()

		a.MarkRstSent()
		ackType := uint8(Enums.PACKET_STREAM_RST_ACK)
		a.SendControlPacketWithTTL(Enums.PACKET_STREAM_RST, rstSeq, 0, 0, nil, Enums.DefaultPacketPriority(Enums.PACKET_STREAM_RST), a.enableControlReliability, &ackType, ttl)
	default:
		a.mu.Unlock()
	}
}

// ---------------------------------------------------------------------
// Retransmit Scheduler
// ---------------------------------------------------------------------

func (a *ARQ) retransmitLoop() {
	defer a.wg.Done()

	for {
		a.mu.Lock()
		rtoFactor := a.rto
		if a.enableControlReliability && a.controlRto < rtoFactor {
			rtoFactor = a.controlRto
		}

		baseInterval := rtoFactor / 3
		if baseInterval < 50*time.Millisecond {
			baseInterval = 50 * time.Millisecond
		}

		hasPending := len(a.sndBuf) > 0 || (a.enableControlReliability && len(a.controlSndBuf) > 0)
		a.mu.Unlock()

		interval := baseInterval
		if !hasPending {
			interval = max(baseInterval*4, 200*time.Millisecond)
		}

		timer := time.NewTimer(interval)
		select {
		case <-a.ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-timer.C:
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					a.logger.Debugf("Retransmit check panic on stream %d: %v", a.streamID, r)
				}
			}()
			a.checkRetransmits()
		}()
	}
}

// ---------------------------------------------------------------------
// Data Plane
// ---------------------------------------------------------------------

// ReceiveData handles inbound STREAM_DATA and emit STREAM_DATA_ACK.
func (a *ARQ) ReceiveData(sn uint16, data []byte) {
	if a.isClosed() || a.IsReset() {
		return
	}

	now := time.Now()
	a.mu.Lock()
	a.lastActivity = now
	diff := sn - a.rcvNxt

	if diff >= 32768 { // Packet is older than rcvNxt
		a.mu.Unlock()
		a.enqueuer.PushTXPacket(
			Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA_ACK),
			Enums.PACKET_STREAM_DATA_ACK,
			sn, 0, 0, 0, 0, nil,
		)
		return
	}

	if int(diff) > a.windowSize {
		a.mu.Unlock()
		return
	}

	_, exists := a.rcvBuf[sn]

	if !exists && len(a.rcvBuf) >= a.windowSize && sn != a.rcvNxt {
		a.mu.Unlock()
		return
	}

	if !exists {
		a.rcvBuf[sn] = append([]byte(nil), data...)
	}
	a.mu.Unlock()

	a.enqueuer.PushTXPacket(
		Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA_ACK),
		Enums.PACKET_STREAM_DATA_ACK,
		sn, 0, 0, 0, 0, nil,
	)

	a.signalFlushReady()
}

func (a *ARQ) writeLoop() {
	defer a.wg.Done()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.flushSignal:
		}

		for {
			if a.isClosed() {
				return
			}

			a.mu.Lock()
			if !a.ioReady || a.closed {
				a.mu.Unlock()
				break
			}

			if a.localConn == nil {
				a.mu.Unlock()
				a.Close("Local connection missing for writer", CloseOptions{SendRST: true})
				return
			}

			var toWrite [][]byte
			for {
				data, exists := a.rcvBuf[a.rcvNxt]
				if !exists {
					break
				}
				toWrite = append(toWrite, data)
				delete(a.rcvBuf, a.rcvNxt)
				a.rcvNxt++
			}
			conn := a.localConn
			a.mu.Unlock()

			if len(toWrite) == 0 {
				break
			}

			for _, chunk := range toWrite {
				a.writeLock.Lock()
				_, err := conn.Write(chunk)
				a.writeLock.Unlock()

				if err != nil {
					// Maybe we can later do drain before sending RST if thats server not client
					a.Close("Local App Closed Connection (writer closed)", CloseOptions{SendRST: true})
					return
				}
			}
		}
	}
}

// ReceiveAck resolves inbound STREAM_DATA_ACK and frees SEND_WINDOW backpressure buffer slots.
// It returns true only when this ARQ instance was actually tracking the data packet.
func (a *ARQ) ReceiveAck(packetType uint8, sn uint16) bool {
	a.mu.Lock()
	a.lastActivity = time.Now()
	handled := false

	if _, exists := a.sndBuf[sn]; exists {
		delete(a.sndBuf, sn)
		if len(a.sndBuf) < a.limit {
			a.signalWindowNotFull()
		}
		handled = true
	}
	a.mu.Unlock()

	if handled {
		if a.finReceivedLocked() {
			a.tryFinalizeRemoteEOF()
		}
		a.settleTerminalDrain()
	}
	return handled
}

// ---------------------------------------------------------------------
// Control Plane Verification
// ---------------------------------------------------------------------

func (a *ARQ) SendControlPacket(packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, payload []byte, priority int, trackForAck bool, customAckType *uint8) bool {
	return a.SendControlPacketWithTTL(packetType, sequenceNum, fragmentID, totalFragments, payload, priority, trackForAck, customAckType, 0)
}

func (a *ARQ) SendControlPacketWithTTL(packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, payload []byte, priority int, trackForAck bool, customAckType *uint8, ttl time.Duration) bool {
	copyData := append([]byte(nil), payload...)
	priority = Enums.NormalizePacketPriority(packetType, priority)
	ok := a.enqueuer.PushTXPacket(priority, packetType, sequenceNum, fragmentID, totalFragments, 0, ttl, copyData)
	if !ok {
		return false
	}

	if !a.enableControlReliability || !trackForAck {
		return true
	}

	var expectedAck uint8
	if customAckType != nil {
		expectedAck = *customAckType
	} else {
		val, ok := Enums.ControlAckFor(packetType)
		if !ok {
			return true
		}
		expectedAck = val
	}

	// Key: [8bit PacketType][16bit SequenceNum][8bit FragmentID]
	key := uint32(packetType)<<24 | uint32(sequenceNum)<<8 | uint32(fragmentID)
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.controlSndBuf[key]; exists {
		return true
	}

	initialRTO := a.controlRto
	if setupControlPacketTypes[packetType] {
		altRto := 350 * time.Millisecond
		if altRto < initialRTO {
			initialRTO = altRto
		}
	}

	a.controlSndBuf[key] = &arqControlItem{
		PacketType:     packetType,
		SequenceNum:    sequenceNum,
		FragmentID:     fragmentID,
		TotalFragments: totalFragments,
		AckType:        expectedAck,
		Payload:        copyData,
		Priority:       priority,
		CreatedAt:      now,
		LastSentAt:     now,
		Retries:        0,
		CurrentRTO:     initialRTO,
		TTL:            ttl,
	}

	return true
}

func (a *ARQ) handleTrackedPacketTTLExpiry(packetType uint8, reason string) {
	if _, ok := Enums.GetPacketCloseStream(packetType); ok && packetType != Enums.PACKET_STREAM_FIN {
		a.finalizeClose(reason)
		return
	}

	a.Close(reason, CloseOptions{SendRST: true})
}

func (a *ARQ) handleTrackedTerminalAck(originPtype uint8) bool {
	if _, ok := Enums.GetPacketCloseStream(originPtype); ok &&
		originPtype != Enums.PACKET_STREAM_FIN &&
		originPtype != Enums.PACKET_STREAM_RST {
		a.finalizeClose(fmt.Sprintf("%s acknowledged", Enums.PacketTypeName(originPtype)))
		return true
	}

	return false
}

func (a *ARQ) handleWaitingTerminalAck(ackPacketType uint8, isWaitingFin bool, isWaitingRst bool) bool {
	if ackPacketType == Enums.PACKET_STREAM_FIN_ACK && isWaitingFin {
		a.markFinAcked()
		a.clearWaitingAck(Enums.PACKET_STREAM_FIN)
		a.tryFinalizeRemoteEOF()
		return true
	}

	if ackPacketType == Enums.PACKET_STREAM_RST_ACK && isWaitingRst {
		a.markRstAcked()
		a.finalizeClose("RST acknowledged")
		return true
	}

	return false
}

func (a *ARQ) ReceiveControlAck(ackPacketType uint8, sequenceNum uint16, fragmentID uint8) bool {
	a.mu.Lock()
	a.lastActivity = time.Now()
	originPtype, ok := Enums.ReverseControlAckFor(ackPacketType)
	if !ok {
		a.mu.Unlock()
		return false
	}

	key := uint32(originPtype)<<24 | uint32(sequenceNum)<<8 | uint32(fragmentID)
	_, tracked := a.controlSndBuf[key]
	_, isCloseStreamPacket := Enums.GetPacketCloseStream(originPtype)

	if !tracked && isCloseStreamPacket {
		for _, info := range a.controlSndBuf {
			if info.PacketType == originPtype {
				tracked = true
				break
			}
		}
	}

	waitingFor := a.waitingAckFor
	isWaitingFin := ackPacketType == Enums.PACKET_STREAM_FIN_ACK && waitingFor == Enums.PACKET_STREAM_FIN
	isWaitingRst := ackPacketType == Enums.PACKET_STREAM_RST_ACK && waitingFor == Enums.PACKET_STREAM_RST

	if !tracked && !isWaitingFin && !isWaitingRst {
		a.mu.Unlock()
		return false
	}

	if tracked {
		if isCloseStreamPacket {
			for trackedKey, info := range a.controlSndBuf {
				if info.PacketType == originPtype {
					delete(a.controlSndBuf, trackedKey)
				}
			}
		} else {
			delete(a.controlSndBuf, key)
		}
	}
	a.mu.Unlock()

	if tracked && a.handleTrackedTerminalAck(originPtype) {
		return true
	}

	if a.handleWaitingTerminalAck(ackPacketType, isWaitingFin, isWaitingRst) {
		return true
	}

	return tracked
}

func (a *ARQ) HandleAckPacket(packetType uint8, sequenceNum uint16, fragmentID uint8) bool {
	if packetType == Enums.PACKET_STREAM_DATA_ACK {
		return a.ReceiveAck(packetType, sequenceNum)
	}

	if _, ok := Enums.ReverseControlAckFor(packetType); !ok {
		return false
	}

	return a.ReceiveControlAck(packetType, sequenceNum, fragmentID)
}

// ---------------------------------------------------------------------
// Retransmit Checks
// ---------------------------------------------------------------------

type rtxJob struct {
	sn              uint16
	data            []byte
	compressionType uint8
}

func (a *ARQ) checkRetransmits() {
	if a.isClosed() {
		return
	}

	now := time.Now()

	if a.handleTerminalRetransmitState(now) {
		return
	}

	a.mu.Lock()
	var jobs []rtxJob

	for sn, info := range a.sndBuf {
		if info.TTL > 0 {
			if now.Sub(info.CreatedAt) >= info.TTL {
				a.mu.Unlock()
				a.handleTrackedPacketTTLExpiry(Enums.PACKET_STREAM_DATA, "Packet TTL expired")
				return
			}
		} else if now.Sub(info.CreatedAt) >= a.dataPacketTTL && info.Retries >= a.maxDataRetries {
			a.mu.Unlock()
			a.Close("Max retransmissions exceeded", CloseOptions{SendRST: true})
			return
		}

		if now.Sub(info.LastSentAt) < info.CurrentRTO {
			continue
		}

		jobs = append(jobs, rtxJob{
			sn:              sn,
			data:            info.Data,
			compressionType: info.CompressionType,
		})

		info.LastSentAt = now
		info.Retries++

		grownRTO := time.Duration(float64(info.CurrentRTO) * 1.2)
		info.CurrentRTO = time.Duration(minF(float64(a.maxRTO), maxF(float64(a.rto), float64(grownRTO))))
	}
	a.mu.Unlock()

	for _, j := range jobs {
		a.enqueuer.PushTXPacket(
			Enums.DefaultPacketPriority(Enums.PACKET_STREAM_RESEND),
			Enums.PACKET_STREAM_RESEND,
			j.sn, 0, 0, j.compressionType, 0, j.data,
		)
	}

	if a.enableControlReliability {
		a.checkControlRetransmits(now)
	}
}

func (a *ARQ) handleTerminalRetransmitState(now time.Time) bool {
	a.mu.Lock()
	if a.deferredClose {
		shouldClose := len(a.sndBuf) == 0
		shouldAbort := !a.deferredDeadline.IsZero() && now.After(a.deferredDeadline)
		a.mu.Unlock()

		if shouldClose || shouldAbort {
			a.settleTerminalDrain()
		}

		return a.isClosed()
	}

	if a.waitingAck && !a.ackWaitDeadline.IsZero() && now.After(a.ackWaitDeadline) {
		waitingFor := a.waitingAckFor
		a.mu.Unlock()

		if waitingFor == Enums.PACKET_STREAM_RST {
			a.finalizeClose("Terminal ACK wait timeout")
			return true
		}

		if waitingFor == Enums.PACKET_STREAM_FIN && a.finSeqSent != nil {
			a.clearWaitingAck(Enums.PACKET_STREAM_FIN)
			a.clearTrackedControlPacket(Enums.PACKET_STREAM_FIN, *a.finSeqSent, 0)
			a.tryFinalizeRemoteEOF()
		}

		return false
	}

	// Check for peer-signaled reset termination
	if (a.state == StateReset || a.rstReceived) && !a.closed {
		a.mu.Unlock()
		a.finalizeClose("Stream Reset (Retransmit Path Check)")
		return true
	}

	if now.Sub(a.lastActivity) > a.inactivityTimeout {
		hasPending := len(a.sndBuf) > 0 || (a.enableControlReliability && len(a.controlSndBuf) > 0)
		if hasPending {
			a.lastActivity = now
			a.mu.Unlock()
			return false
		}

		a.mu.Unlock()
		a.Close("Stream Inactivity Timeout (Dead)", CloseOptions{SendRST: true})
		return true
	}

	a.mu.Unlock()
	return false
}

func (a *ARQ) checkControlRetransmits(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for key, info := range a.controlSndBuf {
		if info.TTL > 0 {
			if now.Sub(info.CreatedAt) >= info.TTL {
				delete(a.controlSndBuf, key)
				a.mu.Unlock()
				a.handleTrackedPacketTTLExpiry(info.PacketType, "Packet TTL expired")
				a.mu.Lock()
				return
			}
		} else {
			maxRetries := a.controlMaxRetries
			packetTTL := a.controlPacketTTL

			if setupControlPacketTypes[info.PacketType] {
				if maxRetries < 120 {
					maxRetries = 120
				}
				if packetTTL < 300*time.Second {
					packetTTL = 300 * time.Second
				}
			}

			expiredByTTL := now.Sub(info.CreatedAt) >= packetTTL
			exceededRetries := info.Retries >= maxRetries
			if expiredByTTL || exceededRetries {
				delete(a.controlSndBuf, key)
				reason := "Control packet expired"
				if exceededRetries {
					reason = "Control packet max retransmissions exceeded"
				}
				a.mu.Unlock()
				a.handleTrackedPacketTTLExpiry(info.PacketType, reason)
				a.mu.Lock()
				return
			}
		}

		if info.TTL == 0 {
			// no-op: legacy retry ownership remains active for non-TTL packets
		}

		if now.Sub(info.LastSentAt) < info.CurrentRTO {
			continue
		}

		ok := a.enqueuer.PushTXPacket(info.Priority, info.PacketType, info.SequenceNum, info.FragmentID, info.TotalFragments, 0, info.TTL, info.Payload)
		if !ok {
			info.LastSentAt = now
			continue
		}

		info.LastSentAt = now
		info.Retries++
		growth := 1.2
		floorRto := a.controlRto

		if setupControlPacketTypes[info.PacketType] {
			growth = 1.1
			altFloor := 350 * time.Millisecond
			if altFloor < floorRto {
				floorRto = altFloor
			}
		}

		grownRTO := time.Duration(float64(info.CurrentRTO) * growth)
		info.CurrentRTO = time.Duration(minF(float64(a.controlMaxRto), maxF(float64(floorRto), float64(grownRTO))))
	}
}

// ---------------------------------------------------------------------
// Final Close Path
// ---------------------------------------------------------------------

func (a *ARQ) finalizeClose(reason string) {
	a.mu.Lock()
	if a.closed || a.isVirtual {
		a.mu.Unlock()
		return
	}

	sndBufLen := len(a.sndBuf)
	rcvBufLen := len(a.rcvBuf)
	prevState := a.state
	finSent := a.finSent
	finReceived := a.finReceived
	finAcked := a.finAcked
	rstSent := a.rstSent
	rstReceived := a.rstReceived
	rstAcked := a.rstAcked
	a.closeReason = reason
	a.closed = true
	a.deferredClose = false
	a.deferredReason = ""
	a.deferredDeadline = time.Time{}
	a.deferredPacket = 0
	a.waitingAck = false
	a.waitingAckFor = 0
	a.ackWaitDeadline = time.Time{}

	if a.state == StateReset || a.rstReceived || a.rstSent {
		a.setState(StateReset)
	} else if a.finSent || a.finReceived {
		a.setState(StateTimeWait)
	} else {
		a.setState(StateClosing)
	}

	a.cancel()

	if a.localConn != nil {
		_ = a.localConn.Close()
	}

	a.clearAllQueues(true)
	a.mu.Unlock()

	a.logger.Debugf(
		"🧹 <green>ARQ Stream Closed</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Reason</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>PrevState</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>SndBuf</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>RcvBuf</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>FIN</blue>: <cyan>%t/%t/%t</cyan> <magenta>|</magenta> <blue>RST</blue>: <cyan>%t/%t/%t</cyan>",
		a.sessionID,
		a.streamID,
		reason,
		prevState,
		sndBufLen,
		rcvBufLen,
		finSent,
		finReceived,
		finAcked,
		rstSent,
		rstReceived,
		rstAcked,
	)
}

// Close is the single close entrypoint for this ARQ stream.
// Modes are expressed through options:
// - Force: finalize immediately
// - SendFIN: graceful close, optionally after drain
// - SendRST: reset close, optionally after drain
func (a *ARQ) Close(reason string, opts CloseOptions) {
	if a.isVirtual && !opts.Force {
		return
	}

	if opts.Force || (!opts.SendRST && !opts.SendFIN) {
		a.mu.Lock()
		a.isVirtual = false
		a.mu.Unlock()
		a.finalizeClose(reason)
		return
	}

	if opts.SendFIN {
		if opts.AfterDrain {
			a.deferTerminalPacket(reason, Enums.PACKET_STREAM_FIN)
			return
		}

		a.emitTerminalPacketWithTTL(Enums.PACKET_STREAM_FIN, reason, opts.TTL)
		return
	}

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}

	alreadyResetting := a.rstSent || a.rstReceived ||
		(a.waitingAck && a.waitingAckFor == Enums.PACKET_STREAM_RST) ||
		(a.deferredClose && a.deferredPacket == Enums.PACKET_STREAM_RST)

	if alreadyResetting {
		a.mu.Unlock()
		return
	}

	hasPendingData := len(a.sndBuf) > 0
	a.closeReason = reason
	a.setState(StateReset)
	a.deferredClose = false
	a.deferredReason = ""
	a.deferredDeadline = time.Time{}
	a.deferredPacket = 0
	a.mu.Unlock()

	if opts.AfterDrain && hasPendingData {
		a.deferTerminalPacket(reason, Enums.PACKET_STREAM_RST)
		return
	}

	a.emitTerminalPacketWithTTL(Enums.PACKET_STREAM_RST, reason, opts.TTL)
}
