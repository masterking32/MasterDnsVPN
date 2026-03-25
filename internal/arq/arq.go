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
	"net"
	"sync"
	"syscall"
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

type terminalOwner interface {
	OnARQClosed(reason string)
}

type queuedDataRemover interface {
	RemoveQueuedData(sequenceNum uint16) bool
}

type queuedDataNackRemover interface {
	RemoveQueuedDataNack(sequenceNum uint16) bool
}

type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

type dummyLogger struct{}

func (d *dummyLogger) Debugf(f string, a ...any) {}
func (d *dummyLogger) Infof(f string, a ...any)  {}
func (d *dummyLogger) Warnf(f string, a ...any)  {}
func (d *dummyLogger) Errorf(f string, a ...any) {}

type arqDataItem struct {
	Data            []byte
	CreatedAt       time.Time
	LastSentAt      time.Time
	Dispatched      bool
	LastNackSentAt  time.Time
	Retries         int
	CurrentRTO      time.Duration
	SampleEligible  bool
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
	Dispatched     bool
	Retries        int
	CurrentRTO     time.Duration
	SampleEligible bool
	TTL            time.Duration
}

type adaptiveRTOState struct {
	srtt        time.Duration
	rttvar      time.Duration
	currentBase time.Duration
	initialized bool
}

type rtxJob struct {
	sn              uint16
	data            []byte
	compressionType uint8
}

var setupControlPacketTypes = map[uint8]bool{
	Enums.PACKET_STREAM_SYN: true,
	Enums.PACKET_SOCKS5_SYN: true,
}

type ARQ struct {
	mu sync.RWMutex

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

	closeReadSent     bool
	closeReadReceived bool
	closeReadAcked    bool
	closeReadSeqSent  *uint16

	closeWriteSent     bool
	closeWriteReceived bool
	closeWriteAcked    bool
	closeWriteSeqSent  *uint16

	rstReceived bool
	rstSent     bool
	rstAcked    bool
	rstSeqSent  *uint16

	localWriteClosed  bool
	localWriterBroken bool
	localWritePending bool
	stopLocalRead     bool
	deferredClose     bool
	deferredReason    string
	deferredDeadline  time.Time
	deferredPacket    uint8
	clientEOFAt       time.Time
	closeReadAckedAt  time.Time
	waitingAck        bool
	waitingAckFor     uint8
	ackWaitDeadline   time.Time

	IsClient bool

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
	dataAdaptiveRTO          adaptiveRTOState
	controlAdaptiveRTO       adaptiveRTOState
	dataNackMaxGap           int
	dataNackRepeatInterval   time.Duration

	// Virtual streams do not emit local close side effects.
	isVirtual bool

	dataNackMu       sync.Mutex
	lastDataNackSent map[uint16]time.Time

	// Concurrency
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	flushSignal chan struct{}
}

type closeWriter interface {
	CloseWrite() error
}

type writeDeadlineSetter interface {
	SetWriteDeadline(time.Time) error
}

type ioErrorClass int

const (
	ioErrorFatal ioErrorClass = iota
	ioErrorTimeout
	ioErrorEOF
	ioErrorClosed
	ioErrorTransient
)

const (
	ioRetryBackoff         = 100 * time.Millisecond
	ioTransientReadBudget  = 3 * time.Second
	ioTransientWriteBudget = 3
)

func classifyIOError(err error) ioErrorClass {
	if err == nil {
		return ioErrorFatal
	}
	if errors.Is(err, io.EOF) {
		return ioErrorEOF
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return ioErrorClosed
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return ioErrorTimeout
		}
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.EAGAIN) || errors.Is(opErr.Err, syscall.EWOULDBLOCK) || errors.Is(opErr.Err, syscall.EINTR) {
			return ioErrorTransient
		}
	}
	if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
		return ioErrorTransient
	}
	return ioErrorFatal
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
	DataNackMaxGap           int
	DataNackRepeatSeconds    float64
	TerminalDrainTimeout     float64
	TerminalAckWaitTimeout   float64
	CompressionType          uint8
	IsClient                 bool
}

type CloseOptions struct {
	Force          bool
	SendRST        bool
	SendCloseWrite bool
	SendCloseRead  bool
	AfterDrain     bool
	TTL            time.Duration
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

func (a *ARQ) HasPendingSequence(sn uint16) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.sndBuf[sn]
	return ok
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
		dataNackMaxGap:           maxI(0, cfg.DataNackMaxGap),
		dataNackRepeatInterval:   time.Duration(maxF(0.1, cfg.DataNackRepeatSeconds) * float64(time.Second)),

		isVirtual:        cfg.IsVirtual,
		compressionType:  cfg.CompressionType,
		lastDataNackSent: make(map[uint16]time.Time),
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
	a.dataAdaptiveRTO = adaptiveRTOState{currentBase: a.rto}
	a.controlAdaptiveRTO = adaptiveRTOState{currentBase: a.controlRto}
	a.IsClient = cfg.IsClient

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

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func clampDuration(v, minV, maxV time.Duration) time.Duration {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func updateAdaptiveRTO(state adaptiveRTOState, sample, minRTO, maxRTO time.Duration) adaptiveRTOState {
	sample = clampDuration(sample, minRTO, maxRTO)

	if !state.initialized {
		state.srtt = sample
		state.rttvar = sample / 2
		state.initialized = true
	} else {
		delta := absDuration(state.srtt - sample)
		state.rttvar = time.Duration((3*state.rttvar + delta) / 4)
		state.srtt = time.Duration((7*state.srtt + sample) / 8)
	}

	state.currentBase = clampDuration(state.srtt+4*state.rttvar, minRTO, maxRTO)
	return state
}

const (
	dataRetransmitRTOGrowthFactor    = 1.35
	controlRetransmitRTOGrowthFactor = 1.25
	setupControlRTOGrowthFactor      = 1.15
)

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
	timer := time.NewTimer(200 * time.Millisecond)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()

	for {
		a.mu.RLock()
		if len(a.sndBuf) < a.limit || a.closed {
			a.mu.RUnlock()
			return
		}
		a.mu.RUnlock()

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(200 * time.Millisecond)

		select {
		case <-a.windowNotFull:
		case <-timer.C:
		case <-a.ctx.Done():
			return
		}
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

func (a *ARQ) closeReadReceivedLocked() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closeReadReceived
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
	a.dataNackMu.Lock()
	clear(a.lastDataNackSent)
	a.dataNackMu.Unlock()

	a.signalWindowNotFull()
}

func (a *ARQ) currentDataBaseRTO() time.Duration {
	base := a.dataAdaptiveRTO.currentBase
	if base <= 0 {
		return a.rto
	}
	return clampDuration(base, a.rto, a.maxRTO)
}

func (a *ARQ) currentControlBaseRTO() time.Duration {
	base := a.controlAdaptiveRTO.currentBase
	if base <= 0 {
		return a.controlRto
	}
	return clampDuration(base, a.controlRto, a.controlMaxRto)
}

func (a *ARQ) noteSuccessfulDataSample(sample time.Duration) {
	a.mu.Lock()
	a.dataAdaptiveRTO = updateAdaptiveRTO(a.dataAdaptiveRTO, sample, a.rto, a.maxRTO)
	a.mu.Unlock()
}

func (a *ARQ) noteSuccessfulControlSample(sample time.Duration) {
	a.mu.Lock()
	a.controlAdaptiveRTO = updateAdaptiveRTO(a.controlAdaptiveRTO, sample, a.controlRto, a.controlMaxRto)
	a.mu.Unlock()
}

func (a *ARQ) NoteTXPacketDequeued(packetType uint8, sequenceNum uint16, fragmentID uint8) {
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	switch packetType {
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND:
		if info, exists := a.sndBuf[sequenceNum]; exists {
			info.LastSentAt = now
			info.Dispatched = true
		}
	default:
		if !a.enableControlReliability {
			return
		}
		key := uint32(packetType)<<24 | uint32(sequenceNum)<<8 | uint32(fragmentID)
		if info, exists := a.controlSndBuf[key]; exists {
			info.LastSentAt = now
			info.Dispatched = true
		}
	}
}

// ---------------------------------------------------------------------
// Transitions & Hooks
// ---------------------------------------------------------------------
func (a *ARQ) MarkCloseReadSent() {
	a.mu.Lock()
	a.closeReadSent = true

	if a.closeReadReceived {
		a.setState(StateClosing)
	} else {
		a.setState(StateHalfClosedLocal)
	}
	a.mu.Unlock()

	a.tryFinalizeRemoteEOF()
}

func (a *ARQ) MarkCloseReadReceived() {
	a.mu.Lock()
	if a.isVirtual {
		a.mu.Unlock()
		return
	}

	a.closeReadReceived = true

	if a.closeReadSent {
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

func (a *ARQ) markCloseReadAcked() {
	a.mu.Lock()
	a.closeReadAcked = true
	a.closeReadAckedAt = time.Now()

	if a.closeReadReceived {
		a.setState(StateClosing)
	}

	a.mu.Unlock()
}

func (a *ARQ) MarkCloseWriteSent() {
	a.mu.Lock()
	a.closeWriteSent = true
	a.localWriterBroken = true
	a.localWriteClosed = true
	a.rcvBuf = make(map[uint16][]byte)
	if a.closeReadReceived {
		a.setState(StateClosing)
	}
	a.mu.Unlock()
}

func (a *ARQ) MarkCloseWriteReceived() {
	a.mu.Lock()
	if a.isVirtual {
		a.mu.Unlock()
		return
	}
	a.closeWriteReceived = true
	a.stopLocalRead = true

	if remover, ok := a.enqueuer.(queuedDataRemover); ok {
		for sn := range a.sndBuf {
			remover.RemoveQueuedData(sn)
		}
	}
	a.sndBuf = make(map[uint16]*arqDataItem)
	a.signalWindowNotFull()
	a.mu.Unlock()

	// A peer close-write can empty outbound state without passing through ReceiveAck.
	// If we were draining toward a deferred terminal packet, re-evaluate it now.
	a.settleTerminalDrain()
	a.tryFinalizeRemoteEOF()
}

func (a *ARQ) markCloseWriteAcked() {
	a.mu.Lock()
	a.closeWriteAcked = true
	a.localWriterBroken = true
	a.localWriteClosed = true
	a.mu.Unlock()
}

func (a *ARQ) maybeInitiateClientCloseReadAfterWriterBreak() {
	a.mu.Lock()
	shouldInitiate := a.IsClient &&
		a.localWriterBroken &&
		!a.closed &&
		!a.rstSent &&
		!a.rstReceived &&
		!a.closeReadSent &&
		!a.closeReadReceived
	pendingOutbound := len(a.sndBuf) > 0 || a.localWritePending
	a.mu.Unlock()

	if !shouldInitiate {
		return
	}

	a.Close("Client local endpoint disconnected after write side closed", CloseOptions{
		SendCloseRead: true,
		AfterDrain:    pendingOutbound,
	})
}

func (a *ARQ) tryFinalizeClientLocalDisconnect() {
	a.mu.Lock()
	shouldClose := a.IsClient &&
		!a.closed &&
		a.localWriterBroken &&
		a.closeWriteAcked &&
		a.closeReadSent &&
		a.closeReadAcked &&
		len(a.sndBuf) == 0 &&
		len(a.rcvBuf) == 0 &&
		!a.localWritePending &&
		!a.waitingAck &&
		!a.deferredClose
	a.mu.Unlock()

	if shouldClose {
		a.finalizeClose("client local disconnect completed")
	}
}

func (a *ARQ) markLocalWriterBroken() {
	a.mu.Lock()
	a.localWriterBroken = true
	a.localWritePending = false
	a.rcvBuf = make(map[uint16][]byte)
	a.mu.Unlock()
}

func (a *ARQ) noteClientEOF(now time.Time) {
	a.mu.Lock()
	if a.IsClient && a.clientEOFAt.IsZero() {
		a.clientEOFAt = now
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
	waitingForCloseReadAck := a.waitingAck && a.waitingAckFor == Enums.PACKET_STREAM_CLOSE_READ
	receiveDrained := len(a.rcvBuf) == 0 || a.localWriterBroken
	writeSideSettled := (!a.localWriterBroken && (!a.closeWriteSent || a.closeWriteAcked)) ||
		(a.localWriterBroken && (a.closeWriteSent || a.closeWriteAcked || a.closeWriteReceived))
	shouldClose := !a.closed &&
		a.closeReadReceived &&
		receiveDrained &&
		(!a.localWritePending || a.localWriterBroken) &&
		(a.closeReadAcked || (a.closeReadSent && !waitingForCloseReadAck)) &&
		writeSideSettled
	a.mu.Unlock()

	if shouldClose {
		a.finalizeClose("close handshake completed")
		return
	}

	a.tryFinalizeClientLocalDisconnect()
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
	resetAfterDrain := false
	gracefulEOF := false
	alreadyHandled := false
	var errorReason string
	var transientReadSince time.Time

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
		if n > 0 {
			transientReadSince = time.Time{}
			raw := append([]byte(nil), buf[:n]...)

			a.mu.Lock()
			a.lastActivity = time.Now()
			sn := a.sndNxt
			a.sndNxt++
			currentRTO := a.currentDataBaseRTO()

			a.sndBuf[sn] = &arqDataItem{
				Data:            raw,
				CreatedAt:       time.Now(),
				LastSentAt:      time.Time{},
				Dispatched:      false,
				Retries:         0,
				CurrentRTO:      currentRTO,
				SampleEligible:  true,
				CompressionType: a.compressionType,
				TTL:             0,
			}
			a.mu.Unlock()

			ok := a.enqueuer.PushTXPacket(
				Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA),
				Enums.PACKET_STREAM_DATA,
				sn, 0, 0, a.compressionType, 0, raw,
			)
			if !ok {
				a.mu.Lock()
				if info, exists := a.sndBuf[sn]; exists {
					info.Dispatched = true
					info.LastSentAt = time.Now()
				}
				a.mu.Unlock()
			}
		}

		if err != nil {
			switch classifyIOError(err) {
			case ioErrorTimeout:
				transientReadSince = time.Time{}
				continue
			case ioErrorTransient:
				now := time.Now()
				if transientReadSince.IsZero() {
					transientReadSince = now
				} else if now.Sub(transientReadSince) > ioTransientReadBudget {
					errorReason = "Repeated transient read errors: " + err.Error()
					resetRequired = true
					resetAfterDrain = n > 0
					break
				}
				time.Sleep(ioRetryBackoff)
				continue
			case ioErrorEOF:
				transientReadSince = time.Time{}
				errorReason = "Local App Closed Connection (EOF)"
				a.noteClientEOF(time.Now())
				gracefulEOF = true
			case ioErrorClosed:
				transientReadSince = time.Time{}
				if a.isGracefulCloseInProgress() {
					alreadyHandled = true
					break
				}
				errorReason = "Local connection closed"
				resetRequired = true
				resetAfterDrain = n > 0
			default:
				transientReadSince = time.Time{}
				errorReason = "Read Error: " + err.Error()
				resetRequired = true
				resetAfterDrain = n > 0
			}
			break
		}

		if n <= 0 {
			continue
		}
	}

	if a.isClosed() || alreadyHandled {
		return
	}

	if resetRequired {
		a.Close(errorReason, CloseOptions{SendRST: true, AfterDrain: resetAfterDrain})
		return
	}

	if gracefulEOF {
		a.Close(errorReason, CloseOptions{SendCloseRead: true, AfterDrain: true})
		return
	}
}

// ---------------------------------------------------------------------
// Terminal Emit / Drain Helpers
// ---------------------------------------------------------------------

// deferTerminalPacket arms a drain-before-terminal phase.
// It stops new local reads, waits for pending outbound data to drain,
// then `settleTerminalDrain` decides whether to emit the requested close packet or fall back to RST.
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
			SendCloseRead:  packetType == Enums.PACKET_STREAM_CLOSE_READ,
			SendCloseWrite: packetType == Enums.PACKET_STREAM_CLOSE_WRITE,
			SendRST:        packetType == Enums.PACKET_STREAM_RST,
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
	case Enums.PACKET_STREAM_CLOSE_READ:
		if a.rstSent || a.rstReceived || a.closeReadSent {
			a.mu.Unlock()
			return
		}
		if a.closeReadSeqSent == nil {
			seq := uint16(0)
			a.closeReadSeqSent = &seq
		}
		seq := *a.closeReadSeqSent
		a.waitingAck = true
		a.waitingAckFor = packetType
		a.ackWaitDeadline = time.Now().Add(a.terminalAckWait)
		a.mu.Unlock()

		a.MarkCloseReadSent()
		ackType := uint8(Enums.PACKET_STREAM_CLOSE_READ_ACK)
		a.SendControlPacketWithTTL(Enums.PACKET_STREAM_CLOSE_READ, seq, 0, 0, nil, Enums.DefaultPacketPriority(Enums.PACKET_STREAM_CLOSE_READ), a.enableControlReliability, &ackType, ttl)
	case Enums.PACKET_STREAM_CLOSE_WRITE:
		if a.rstReceived || a.rstSent || a.closeWriteSent {
			a.mu.Unlock()
			return
		}
		if a.closeWriteSeqSent == nil {
			seq := uint16(0)
			a.closeWriteSeqSent = &seq
		}
		seq := *a.closeWriteSeqSent
		a.waitingAck = true
		a.waitingAckFor = packetType
		a.ackWaitDeadline = time.Now().Add(a.terminalAckWait)
		a.mu.Unlock()

		a.MarkCloseWriteSent()
		ackType := uint8(Enums.PACKET_STREAM_CLOSE_WRITE_ACK)
		a.SendControlPacketWithTTL(Enums.PACKET_STREAM_CLOSE_WRITE, seq, 0, 0, nil, Enums.DefaultPacketPriority(Enums.PACKET_STREAM_CLOSE_WRITE), a.enableControlReliability, &ackType, ttl)
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

	timer := time.NewTimer(100 * time.Millisecond)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()

	for {
		a.mu.Lock()
		rtoFactor := a.rto
		if a.enableControlReliability && a.controlRto < rtoFactor {
			rtoFactor = a.controlRto
		}

		baseInterval := max(rtoFactor/3, 20*time.Millisecond)

		hasPending := len(a.sndBuf) > 0 || (a.enableControlReliability && len(a.controlSndBuf) > 0)
		a.mu.Unlock()

		interval := baseInterval
		if !hasPending {
			interval = max(baseInterval*4, 100*time.Millisecond)
		}

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(interval)
		select {
		case <-a.ctx.Done():
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
func (a *ARQ) ReceiveData(sn uint16, data []byte) bool {
	if a.isClosed() || a.IsReset() {
		return false
	}

	now := time.Now()
	a.mu.Lock()
	if a.localWriterBroken || a.closeWriteSent || a.closeWriteAcked {
		needCloseWrite := a.localWriterBroken &&
			!a.closeWriteSent &&
			!(a.waitingAck && a.waitingAckFor == Enums.PACKET_STREAM_CLOSE_WRITE) &&
			!a.closed &&
			!a.rstReceived &&
			!a.rstSent
		a.mu.Unlock()
		if needCloseWrite {
			a.Close("Inbound data received after local writer closed", CloseOptions{SendCloseWrite: true})
		}
		return false
	}
	a.lastActivity = now
	diff := sn - a.rcvNxt

	if diff >= 32768 { // Packet is older than rcvNxt
		a.mu.Unlock()
		a.enqueuer.PushTXPacket(
			Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA_ACK),
			Enums.PACKET_STREAM_DATA_ACK,
			sn, 0, 0, 0, 0, nil,
		)
		return true
	}

	if int(diff) > a.windowSize {
		a.mu.Unlock()
		return true
	}

	_, exists := a.rcvBuf[sn]

	if !exists && len(a.rcvBuf) >= a.windowSize && sn != a.rcvNxt {
		a.mu.Unlock()
		return true
	}

	if !exists {
		a.rcvBuf[sn] = append([]byte(nil), data...)
	}
	a.mu.Unlock()

	a.clearSentDataNack(sn)
	a.enqueuer.PushTXPacket(
		Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA_ACK),
		Enums.PACKET_STREAM_DATA_ACK,
		sn, 0, 0, 0, 0, nil,
	)

	a.maybeSendDataNacks(sn)

	a.signalFlushReady()
	return true
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
				a.Close("Local connection missing for writer", CloseOptions{SendRST: true, AfterDrain: true})
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
			a.localWritePending = len(toWrite) > 0
			conn := a.localConn
			a.mu.Unlock()

			if len(toWrite) == 0 {
				a.tryFinalizeRemoteEOF()
				break
			}

			shouldExit := false
			recheckClose := false
			func() {
				defer func() {
					a.mu.Lock()
					a.localWritePending = false
					a.mu.Unlock()
					if recheckClose {
						a.tryFinalizeRemoteEOF()
					}
				}()

				for _, chunk := range toWrite {
					remaining := chunk
					transientRetries := 0
					for len(remaining) > 0 {
						if wd, ok := conn.(writeDeadlineSetter); ok {
							_ = wd.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
						}
						a.writeLock.Lock()
						n, err := conn.Write(remaining)
						a.writeLock.Unlock()
						if n > 0 {
							remaining = remaining[n:]
						}
						if err == nil {
							continue
						}

						class := classifyIOError(err)
						if class == ioErrorTimeout || class == ioErrorTransient {
							if transientRetries >= ioTransientWriteBudget {
								a.markLocalWriterBroken()
								if a.isGracefulCloseInProgress() {
									a.Close("Local App Write Error during graceful close: "+err.Error(), CloseOptions{SendCloseWrite: true})
									shouldExit = true
									return
								}
								a.Close("Local App Write Error: "+err.Error(), CloseOptions{SendCloseWrite: true})
								shouldExit = true
								return
							}
							transientRetries++
							time.Sleep(ioRetryBackoff)
							continue
						}

						if class == ioErrorEOF || class == ioErrorClosed {
							a.markLocalWriterBroken()
							if a.isGracefulCloseInProgress() {
								a.Close("Local App Closed Connection (writer closed during graceful close)", CloseOptions{SendCloseWrite: true})
								shouldExit = true
								return
							}
							a.Close("Local App Closed Connection (writer closed)", CloseOptions{SendCloseWrite: true})
							shouldExit = true
							return
						}

						if a.isGracefulCloseInProgress() {
							a.markLocalWriterBroken()
							a.Close("Local App Write Error during graceful close: "+err.Error(), CloseOptions{SendCloseWrite: true})
							shouldExit = true
							return
						}
						a.markLocalWriterBroken()
						a.Close("Local App Write Error: "+err.Error(), CloseOptions{SendCloseWrite: true})
						shouldExit = true
						return
					}
				}
			}()
			if shouldExit {
				return
			}
			a.tryFinalizeRemoteEOF()
		}
	}
}

func (a *ARQ) isGracefulCloseInProgress() bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return true
	}

	if a.waitingAck && (a.waitingAckFor == Enums.PACKET_STREAM_CLOSE_READ || a.waitingAckFor == Enums.PACKET_STREAM_CLOSE_WRITE) {
		return true
	}

	if a.deferredClose && (a.deferredPacket == Enums.PACKET_STREAM_CLOSE_READ || a.deferredPacket == Enums.PACKET_STREAM_CLOSE_WRITE) {
		return true
	}

	switch a.state {
	case StateHalfClosedLocal, StateHalfClosedRemote, StateClosing, StateDraining, StateTimeWait:
		return true
	}

	return a.closeReadSent || a.closeReadReceived || a.closeWriteSent || a.closeWriteReceived
}

// ReceiveAck resolves inbound STREAM_DATA_ACK and frees SEND_WINDOW backpressure buffer slots.
// It returns true only when this ARQ instance was actually tracking the data packet.
func (a *ARQ) ReceiveAck(packetType uint8, sn uint16) bool {
	a.mu.Lock()
	now := time.Now()
	a.lastActivity = now
	handled := false
	var sample time.Duration
	sampleEligible := false

	if info, exists := a.sndBuf[sn]; exists {
		if info.SampleEligible && info.Dispatched && !info.LastSentAt.IsZero() {
			sample = now.Sub(info.LastSentAt)
			sampleEligible = true
		}
		delete(a.sndBuf, sn)
		if len(a.sndBuf) < a.limit {
			a.signalWindowNotFull()
		}
		handled = true
	}
	a.mu.Unlock()

	if handled {
		if sampleEligible {
			a.noteSuccessfulDataSample(sample)
		}
		if remover, ok := a.enqueuer.(queuedDataRemover); ok {
			remover.RemoveQueuedData(sn)
		}

		if a.closeReadReceivedLocked() {
			a.tryFinalizeRemoteEOF()
		}
		a.settleTerminalDrain()
	}
	return handled
}

func (a *ARQ) HandleDataNack(sn uint16) bool {
	if a.isClosed() || a.IsReset() {
		return false
	}

	now := time.Now()
	a.mu.Lock()
	a.lastActivity = now
	info, exists := a.sndBuf[sn]
	if !exists {
		a.mu.Unlock()
		return false
	}
	prevNackSentAt := info.LastNackSentAt
	if !prevNackSentAt.IsZero() && now.Sub(prevNackSentAt) < a.dataNackRepeatInterval {
		a.mu.Unlock()
		return false
	}
	info.LastNackSentAt = now

	data := append([]byte(nil), info.Data...)
	compressionType := info.CompressionType
	ttl := info.TTL
	a.mu.Unlock()

	ok := a.enqueuer.PushTXPacket(
		Enums.DefaultPacketPriority(Enums.PACKET_STREAM_RESEND),
		Enums.PACKET_STREAM_RESEND,
		sn, 0, 0, compressionType, ttl, data,
	)
	if !ok {
		a.mu.Lock()
		if info, exists := a.sndBuf[sn]; exists && info.LastNackSentAt.Equal(now) {
			info.LastNackSentAt = prevNackSentAt
		}
		a.mu.Unlock()
		return false
	}
	a.mu.Lock()
	if info, exists := a.sndBuf[sn]; exists {
		info.SampleEligible = false
	}
	a.mu.Unlock()
	return true
}

func (a *ARQ) maybeSendDataNacks(sn uint16) {
	if a == nil || a.dataNackMaxGap <= 0 {
		return
	}

	a.mu.RLock()
	rcvNxt := a.rcvNxt
	closed := a.closed
	a.mu.RUnlock()
	if closed {
		return
	}

	diff := sn - rcvNxt
	if diff == 0 || diff >= 32768 {
		return
	}

	windowSpan := uint16(a.dataNackMaxGap)
	start := rcvNxt
	if diff > windowSpan {
		start = sn - windowSpan
	}

	a.mu.RLock()
	missingSeqs := make([]uint16, 0, a.dataNackMaxGap)
	for missing := start; missing != sn; missing++ {
		if _, buffered := a.rcvBuf[missing]; buffered {
			continue
		}
		missingSeqs = append(missingSeqs, missing)
	}
	a.mu.RUnlock()

	now := time.Now()
	minInterval := a.dataNackRepeatInterval
	for _, missing := range missingSeqs {
		if !a.shouldSendDataNack(missing, now, minInterval) {
			continue
		}
		if !a.enqueuer.PushTXPacket(
			Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA_NACK),
			Enums.PACKET_STREAM_DATA_NACK,
			missing, 0, 0, 0, 0, nil,
		) {
			continue
		}
		a.noteDataNackSent(missing, now)
	}
}

func (a *ARQ) shouldSendDataNack(sn uint16, now time.Time, minInterval time.Duration) bool {
	a.dataNackMu.Lock()
	defer a.dataNackMu.Unlock()

	lastSentAt, exists := a.lastDataNackSent[sn]
	if !exists {
		return true
	}
	return now.Sub(lastSentAt) >= minInterval
}

func (a *ARQ) noteDataNackSent(sn uint16, now time.Time) {
	a.dataNackMu.Lock()
	a.lastDataNackSent[sn] = now
	a.dataNackMu.Unlock()
}

func (a *ARQ) clearSentDataNack(sn uint16) {
	a.dataNackMu.Lock()
	delete(a.lastDataNackSent, sn)
	a.dataNackMu.Unlock()

	if remover, ok := a.enqueuer.(queuedDataNackRemover); ok {
		remover.RemoveQueuedDataNack(sn)
	}
}

// ---------------------------------------------------------------------
// Control Plane Verification
// ---------------------------------------------------------------------

func (a *ARQ) SendControlPacketWithTTL(packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, payload []byte, priority int, trackForAck bool, customAckType *uint8, ttl time.Duration) bool {
	copyData := append([]byte(nil), payload...)
	priority = Enums.NormalizePacketPriority(packetType, priority)

	if !a.enableControlReliability || !trackForAck {
		return a.enqueuer.PushTXPacket(priority, packetType, sequenceNum, fragmentID, totalFragments, 0, ttl, copyData)
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

	key := uint32(packetType)<<24 | uint32(sequenceNum)<<8 | uint32(fragmentID)
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.controlSndBuf[key]; exists {
		return true
	}

	initialRTO := a.currentControlBaseRTO()
	if setupControlPacketTypes[packetType] {
		altRto := 350 * time.Millisecond
		if altRto < initialRTO {
			initialRTO = altRto
		}
	}

	ok := a.enqueuer.PushTXPacket(priority, packetType, sequenceNum, fragmentID, totalFragments, 0, ttl, copyData)

	dispatchedFlag := false
	lastSentAt := time.Time{}
	if !ok {
		dispatchedFlag = true
		lastSentAt = now
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
		LastSentAt:     lastSentAt,
		Dispatched:     dispatchedFlag,
		Retries:        0,
		CurrentRTO:     initialRTO,
		SampleEligible: true,
		TTL:            ttl,
	}

	return ok
}

func (a *ARQ) handleTrackedPacketTTLExpiry(packetType uint8, reason string) {
	if _, ok := Enums.GetPacketCloseStream(packetType); ok &&
		packetType != Enums.PACKET_STREAM_CLOSE_READ &&
		packetType != Enums.PACKET_STREAM_CLOSE_WRITE {
		a.finalizeClose(reason)
		return
	}

	a.Close(reason, CloseOptions{SendRST: true})
}

func (a *ARQ) handleTrackedTerminalAck(originPtype uint8) bool {
	if _, ok := Enums.GetPacketCloseStream(originPtype); ok &&
		originPtype != Enums.PACKET_STREAM_CLOSE_READ &&
		originPtype != Enums.PACKET_STREAM_CLOSE_WRITE &&
		originPtype != Enums.PACKET_STREAM_RST {
		a.finalizeClose(fmt.Sprintf("%s acknowledged", Enums.PacketTypeName(originPtype)))
		return true
	}

	return false
}

func (a *ARQ) handleWaitingTerminalAck(ackPacketType uint8, isWaitingCloseRead bool, isWaitingCloseWrite bool, isWaitingRst bool) bool {
	if ackPacketType == Enums.PACKET_STREAM_CLOSE_READ_ACK && isWaitingCloseRead {
		a.markCloseReadAcked()
		a.clearWaitingAck(Enums.PACKET_STREAM_CLOSE_READ)
		a.tryFinalizeRemoteEOF()
		return true
	}

	if ackPacketType == Enums.PACKET_STREAM_CLOSE_WRITE_ACK && isWaitingCloseWrite {
		a.markCloseWriteAcked()
		a.clearWaitingAck(Enums.PACKET_STREAM_CLOSE_WRITE)
		a.maybeInitiateClientCloseReadAfterWriterBreak()
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

func (a *ARQ) handleTrackedCloseOrResetAck(originPtype uint8) bool {
	switch originPtype {
	case Enums.PACKET_STREAM_CLOSE_READ:
		a.markCloseReadAcked()
		a.clearWaitingAck(Enums.PACKET_STREAM_CLOSE_READ)
		a.tryFinalizeRemoteEOF()
		return true
	case Enums.PACKET_STREAM_CLOSE_WRITE:
		a.markCloseWriteAcked()
		a.clearWaitingAck(Enums.PACKET_STREAM_CLOSE_WRITE)
		a.maybeInitiateClientCloseReadAfterWriterBreak()
		a.tryFinalizeRemoteEOF()
		return true
	case Enums.PACKET_STREAM_RST:
		a.markRstAcked()
		a.finalizeClose("RST acknowledged")
		return true
	default:
		return false
	}
}

func (a *ARQ) ReceiveControlAck(ackPacketType uint8, sequenceNum uint16, fragmentID uint8) bool {
	a.mu.Lock()
	now := time.Now()
	a.lastActivity = now
	originPtype, ok := Enums.ReverseControlAckFor(ackPacketType)
	if !ok {
		a.mu.Unlock()
		return false
	}

	key := uint32(originPtype)<<24 | uint32(sequenceNum)<<8 | uint32(fragmentID)
	info, tracked := a.controlSndBuf[key]
	_, isCloseStreamPacket := Enums.GetPacketCloseStream(originPtype)
	var sample time.Duration
	sampleEligible := false

	if !tracked && isCloseStreamPacket {
		for _, info := range a.controlSndBuf {
			if info.PacketType == originPtype {
				tracked = true
				break
			}
		}
	}

	waitingFor := a.waitingAckFor
	isWaitingCloseRead := ackPacketType == Enums.PACKET_STREAM_CLOSE_READ_ACK && waitingFor == Enums.PACKET_STREAM_CLOSE_READ
	isWaitingCloseWrite := ackPacketType == Enums.PACKET_STREAM_CLOSE_WRITE_ACK && waitingFor == Enums.PACKET_STREAM_CLOSE_WRITE
	isWaitingRst := ackPacketType == Enums.PACKET_STREAM_RST_ACK && waitingFor == Enums.PACKET_STREAM_RST

	if !tracked && !isWaitingCloseRead && !isWaitingCloseWrite && !isWaitingRst {
		a.mu.Unlock()
		return false
	}

	if tracked {
		if info != nil && info.SampleEligible && info.Dispatched && !info.LastSentAt.IsZero() {
			sample = now.Sub(info.LastSentAt)
			sampleEligible = true
		}
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

	if tracked && sampleEligible {
		a.noteSuccessfulControlSample(sample)
	}

	if tracked && a.handleTrackedCloseOrResetAck(originPtype) {
		return true
	}

	if tracked && a.handleTrackedTerminalAck(originPtype) {
		return true
	}

	if a.handleWaitingTerminalAck(ackPacketType, isWaitingCloseRead, isWaitingCloseWrite, isWaitingRst) {
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

func (a *ARQ) checkRetransmits() {
	if a.isClosed() {
		return
	}

	now := time.Now()

	if a.handleTerminalRetransmitState(now) {
		return
	}

	a.mu.Lock()
	type pendingRetransmit struct {
		sn              uint16
		data            []byte
		compressionType uint8
	}
	var jobs []pendingRetransmit

	for sn, info := range a.sndBuf {
		if info.TTL > 0 {
			if now.Sub(info.CreatedAt) >= info.TTL {
				a.mu.Unlock()
				a.handleTrackedPacketTTLExpiry(Enums.PACKET_STREAM_DATA, "Packet TTL expired")
				return
			}
		} else if now.Sub(info.CreatedAt) >= a.dataPacketTTL && info.Retries >= a.maxDataRetries {
			a.mu.Unlock()
			a.logger.Debugf("⚠️ <yellow>ARQ max retransmissions <magenta>|</magenta> Stream: <cyan>%d</cyan> <magenta>|</magenta> Session: <cyan>%d</cyan> <magenta>|</magenta> SN: <cyan>%d</cyan></yellow>", a.streamID, a.sessionID, sn)
			a.Close("Max retransmissions exceeded", CloseOptions{SendRST: true})
			return
		}

		if !info.Dispatched || now.Sub(info.LastSentAt) < info.CurrentRTO {
			continue
		}

		jobs = append(jobs, pendingRetransmit{
			sn:              sn,
			data:            info.Data,
			compressionType: info.CompressionType,
		})
	}
	a.mu.Unlock()

	rtxJobs := make([]rtxJob, 0, len(jobs))
	for _, job := range jobs {
		rtxJobs = append(rtxJobs, rtxJob{
			sn:              job.sn,
			data:            job.data,
			compressionType: job.compressionType,
		})
	}

	priorityKinds := a.retransmitPriorityKinds(rtxJobs)
	for i, j := range jobs {
		priority := Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA)
		packetType := uint8(Enums.PACKET_STREAM_DATA)

		if priorityKinds[i] {
			priority = Enums.DefaultPacketPriority(Enums.PACKET_STREAM_RESEND)
			packetType = uint8(Enums.PACKET_STREAM_RESEND)
		}

		ok := a.enqueuer.PushTXPacket(
			priority,
			packetType,
			j.sn, 0, 0, j.compressionType, 0, j.data,
		)
		if !ok {
			continue
		}

		a.mu.Lock()
		info, exists := a.sndBuf[j.sn]
		if exists {
			dataFloor := a.currentDataBaseRTO()
			info.LastSentAt = now
			info.Dispatched = false
			info.Retries++
			info.SampleEligible = false
			grownRTO := time.Duration(float64(info.CurrentRTO) * dataRetransmitRTOGrowthFactor)
			info.CurrentRTO = clampDuration(grownRTO, dataFloor, a.maxRTO)
		}
		a.mu.Unlock()
	}

	if a.enableControlReliability {
		a.checkControlRetransmits(now)
	}
}

func (a *ARQ) retransmitPriorityKinds(jobs []rtxJob) []bool {
	if len(jobs) == 0 {
		return nil
	}

	kinds := make([]bool, len(jobs))
	if len(jobs) == 1 {
		kinds[0] = true
		return kinds
	}

	frontBudget := a.windowSize / 10
	if frontBudget < 1 {
		frontBudget = 1
	}
	if frontBudget > 64 {
		frontBudget = 64
	}
	if frontBudget > len(jobs) {
		frontBudget = len(jobs)
	}

	sndNxt := a.sndNxt
	bestIdx := make([]int, 0, frontBudget)
	bestDist := make([]uint16, 0, frontBudget)

	insertBest := func(idx int, dist uint16) {
		pos := len(bestIdx)
		for pos > 0 {
			prev := pos - 1
			prevDist := bestDist[prev]
			prevIdx := bestIdx[prev]
			if prevDist > dist || (prevDist == dist && jobs[prevIdx].sn <= jobs[idx].sn) {
				break
			}
			pos--
		}

		bestIdx = append(bestIdx, 0)
		bestDist = append(bestDist, 0)
		copy(bestIdx[pos+1:], bestIdx[pos:])
		copy(bestDist[pos+1:], bestDist[pos:])
		bestIdx[pos] = idx
		bestDist[pos] = dist

		if len(bestIdx) > frontBudget {
			bestIdx = bestIdx[:frontBudget]
			bestDist = bestDist[:frontBudget]
		}
	}

	for i := range jobs {
		dist := uint16(sndNxt - jobs[i].sn)
		if len(bestIdx) < frontBudget {
			insertBest(i, dist)
			continue
		}

		last := len(bestIdx) - 1
		if dist > bestDist[last] || (dist == bestDist[last] && jobs[i].sn < jobs[bestIdx[last]].sn) {
			insertBest(i, dist)
		}
	}

	for _, idx := range bestIdx {
		kinds[idx] = true
	}

	return kinds
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

		if waitingFor == Enums.PACKET_STREAM_CLOSE_READ || waitingFor == Enums.PACKET_STREAM_CLOSE_WRITE {
			a.Close("Close handshake ACK wait timeout", CloseOptions{SendRST: true})
			return false
		}

		return false
	}

	// Check for peer-signaled reset termination.
	// Only trigger on a.rstReceived (peer sent RST to us). Do NOT use
	// a.state==StateReset here because StateReset is also set by MarkRstSent()
	// (when WE send RST). That would cause every locally-initiated RST to be
	// mis-identified as a peer reset, killing the stream immediately before the
	// RST_ACK arrives.
	if a.rstReceived && !a.closed {
		a.mu.Unlock()
		a.MarkRstReceived()
		a.Close("Peer reset signaled", CloseOptions{Force: true})
		return true
	}

	shouldInitiateCloseWriteAfterEOF := a.IsClient &&
		((!a.clientEOFAt.IsZero() && now.Sub(a.clientEOFAt) >= 2*time.Second) ||
			(!a.closeReadAckedAt.IsZero() && now.Sub(a.closeReadAckedAt) >= 2*time.Second)) &&
		!a.closed &&
		!a.rstSent &&
		!a.rstReceived &&
		a.closeReadSent &&
		a.closeReadAcked &&
		!a.closeWriteSent &&
		!a.closeWriteAcked &&
		!a.closeWriteReceived &&
		!(a.waitingAck && a.waitingAckFor == Enums.PACKET_STREAM_CLOSE_WRITE)
	if shouldInitiateCloseWriteAfterEOF {
		a.mu.Unlock()
		a.Close("Client close-read grace elapsed", CloseOptions{SendCloseWrite: true})
		return false
	}

	if now.Sub(a.lastActivity) > a.inactivityTimeout {
		hasPending := len(a.sndBuf) > 0 || (a.enableControlReliability && len(a.controlSndBuf) > 0)
		if hasPending {
			a.lastActivity = now
			a.mu.Unlock()
			return false
		}

		idleDur := now.Sub(a.lastActivity)
		a.mu.Unlock()
		a.logger.Debugf("⏰ <yellow>ARQ inactivity timeout <magenta>|</magenta> Stream: <cyan>%d</cyan> <magenta>|</magenta> Session: <cyan>%d</cyan> <magenta>|</magenta> Idle: <cyan>%s</cyan></yellow>", a.streamID, a.sessionID, idleDur.Truncate(time.Second))
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
				a.logger.Debugf("⚠️ <yellow>ARQ control expired <magenta>|</magenta> Stream: <cyan>%d</cyan> <magenta>|</magenta> Type: <cyan>0x%02x</cyan> <magenta>|</magenta> Reason: <cyan>%s</cyan></yellow>", a.streamID, info.PacketType, reason)
				a.mu.Unlock()
				a.handleTrackedPacketTTLExpiry(info.PacketType, reason)
				a.mu.Lock()
				return
			}
		}

		if info.TTL == 0 {
			// no-op: legacy retry ownership remains active for non-TTL packets
		}

		if !info.Dispatched || now.Sub(info.LastSentAt) < info.CurrentRTO {
			continue
		}

		ok := a.enqueuer.PushTXPacket(info.Priority, info.PacketType, info.SequenceNum, info.FragmentID, info.TotalFragments, 0, info.TTL, info.Payload)
		if !ok {
			continue
		}

		a.logger.Debugf("🔄 <yellow>ARQ control retransmit <magenta>|</magenta> Stream: <cyan>%d</cyan> <magenta>|</magenta> Type: <cyan>0x%02x</cyan> <magenta>|</magenta> Retry: <cyan>%d</cyan></yellow>", a.streamID, info.PacketType, info.Retries+1)
		info.LastSentAt = now
		info.Dispatched = false
		info.Retries++
		info.SampleEligible = false
		growth := controlRetransmitRTOGrowthFactor
		floorRto := a.currentControlBaseRTO()

		if setupControlPacketTypes[info.PacketType] {
			growth = setupControlRTOGrowthFactor
			altFloor := 350 * time.Millisecond
			if altFloor < floorRto {
				floorRto = altFloor
			}
		}

		grownRTO := time.Duration(float64(info.CurrentRTO) * growth)
		info.CurrentRTO = clampDuration(grownRTO, floorRto, a.controlMaxRto)
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
	closeReadSent := a.closeReadSent
	closeReadReceived := a.closeReadReceived
	closeReadAcked := a.closeReadAcked
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
	} else if a.closeReadSent || a.closeReadReceived || a.closeWriteSent || a.closeWriteReceived {
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
		"ARQ Stream Closed | Session: %d | Stream: %d | Reason: %s | PrevState: %d | SndBuf: %d | RcvBuf: %d | CloseRead: %t/%t/%t | RST: %t/%t/%t",
		a.sessionID,
		a.streamID,
		reason,
		prevState,
		sndBufLen,
		rcvBufLen,
		closeReadSent,
		closeReadReceived,
		closeReadAcked,
		rstSent,
		rstReceived,
		rstAcked,
	)

	if owner, ok := a.enqueuer.(terminalOwner); ok {
		owner.OnARQClosed(reason)
	}
}

// Close is the single close entrypoint for this ARQ stream.
// Modes are expressed through options:
// - Force: finalize immediately
// - SendCloseRead: local read side ended; peer should finish draining inbound and close writer
// - SendCloseWrite: local write side ended; peer should stop sending to us
// - SendRST: reset close, optionally after drain
func (a *ARQ) Close(reason string, opts CloseOptions) {
	if a.isVirtual && !opts.Force {
		return
	}

	if opts.Force || (!opts.SendRST && !opts.SendCloseRead && !opts.SendCloseWrite) {
		a.mu.Lock()
		a.isVirtual = false
		a.mu.Unlock()
		a.finalizeClose(reason)
		return
	}

	if opts.SendCloseRead {
		if opts.AfterDrain {
			a.deferTerminalPacket(reason, Enums.PACKET_STREAM_CLOSE_READ)
			return
		}

		a.emitTerminalPacketWithTTL(Enums.PACKET_STREAM_CLOSE_READ, reason, opts.TTL)
		return
	}

	if opts.SendCloseWrite {
		a.emitTerminalPacketWithTTL(Enums.PACKET_STREAM_CLOSE_WRITE, reason, opts.TTL)
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
