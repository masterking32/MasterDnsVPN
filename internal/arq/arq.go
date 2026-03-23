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
	PushTXPacket(priority int, packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, compressionType uint8, payload []byte) bool
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
}

var setupControlPacketTypes = map[uint8]bool{
	Enums.PACKET_STREAM_SYN: true,
	Enums.PACKET_SOCKS5_SYN: true,
}

type ARQ struct {
	mu sync.Mutex

	streamID  uint16
	sessionID uint8
	enqueuer  PacketEnqueuer
	localConn io.ReadWriteCloser
	logger    Logger

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

	finSent        bool
	finReceived    bool
	finAcked       bool
	finSeqSent     *uint16
	finSeqReceived *uint16

	rstReceived    bool
	rstSent        bool
	rstAcked       bool
	rstSeqSent     *uint16
	rstSeqReceived *uint16

	localWriteClosed  bool
	remoteWriteClosed bool
	stopLocalRead     bool
	deferredClose     bool
	deferredReason    string
	deferredDeadline  time.Time
	deferredPacket    uint8
	waitingAck        bool
	waitingAckFor     uint8
	ackWaitDeadline   time.Time

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
	finDrainTimeout      time.Duration
	gracefulDrainTimeout time.Duration
	terminalDrainTimeout time.Duration
	terminalAckWait      time.Duration

	// Control-plane tuning
	enableControlReliability bool
	controlRto               time.Duration
	controlMaxRto            time.Duration
	controlMaxRetries        int
	controlPacketTTL         time.Duration

	// SOCKS pre-connection payload handling
	isSocks           bool
	isClient          bool
	isVirtual         bool
	initialData       []byte
	socksHandshake    chan struct{}
	socksHandshakeErr uint8

	// Concurrency
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Config represents the extensive ARQ tuning configuration identically ported from Python
type Config struct {
	WindowSize               int
	RTO                      float64
	MaxRTO                   float64
	IsSocks                  bool
	IsClient                 bool
	IsVirtual                bool
	InitialData              []byte
	EnableControlReliability bool
	ControlRTO               float64
	ControlMaxRTO            float64
	ControlMaxRetries        int
	InactivityTimeout        float64
	DataPacketTTL            float64
	MaxDataRetries           int
	ControlPacketTTL         float64
	FinDrainTimeout          float64
	GracefulDrainTimeout     float64
	TerminalDrainTimeout     float64
	TerminalAckWaitTimeout   float64
	CompressionType          uint8
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

		inactivityTimeout:    time.Duration(maxF(120.0, cfg.InactivityTimeout) * float64(time.Second)),
		dataPacketTTL:        time.Duration(maxF(120.0, cfg.DataPacketTTL) * float64(time.Second)),
		maxDataRetries:       maxI(20, cfg.MaxDataRetries),
		finDrainTimeout:      time.Duration(maxF(30.0, cfg.FinDrainTimeout) * float64(time.Second)),
		gracefulDrainTimeout: time.Duration(maxF(60.0, cfg.GracefulDrainTimeout) * float64(time.Second)),
		terminalDrainTimeout: time.Duration(maxF(60.0, cfg.TerminalDrainTimeout) * float64(time.Second)),
		terminalAckWait:      time.Duration(maxF(30.0, cfg.TerminalAckWaitTimeout) * float64(time.Second)),

		enableControlReliability: cfg.EnableControlReliability,
		controlMaxRetries:        maxI(5, cfg.ControlMaxRetries),
		controlPacketTTL:         time.Duration(maxF(120.0, cfg.ControlPacketTTL) * float64(time.Second)),

		isSocks:         cfg.IsSocks,
		isClient:        cfg.IsClient,
		isVirtual:       cfg.IsVirtual,
		initialData:     cfg.InitialData,
		socksHandshake:  make(chan struct{}),
		compressionType: cfg.CompressionType,
	}

	// Apply Event unblock state
	a.signalWindowNotFull()

	userMaxRto := maxF(0.05, cfg.MaxRTO)
	a.maxRTO = time.Duration(userMaxRto * float64(time.Second))
	a.rto = time.Duration(minF(maxF(0.05, cfg.RTO), userMaxRto) * float64(time.Second))

	userControlMaxRto := maxF(0.05, cfg.ControlMaxRTO)
	a.controlMaxRto = time.Duration(userControlMaxRto * float64(time.Second))
	a.controlRto = time.Duration(minF(maxF(0.05, cfg.ControlRTO), userControlMaxRto) * float64(time.Second))

	if !a.isSocks {
		close(a.socksHandshake)
	}

	a.ctx, a.cancel = context.WithCancel(context.Background())
	return a
}

// Start launches the core background loops for IO multiplexing and retransmission
func (a *ARQ) Start() {
	a.wg.Add(1)
	go a.retransmitLoop()

	a.mu.Lock()
	hasConn := a.localConn != nil
	a.mu.Unlock()

	if hasConn {
		a.wg.Add(1)
		go a.ioLoop()
	}
}

func (a *ARQ) SetLocalConn(conn io.ReadWriteCloser) {
	a.mu.Lock()
	if a.localConn != nil {
		a.mu.Unlock()
		return
	}
	a.localConn = conn
	a.mu.Unlock()

	// Start ioLoop if ARQ is already running (ctx is not nil)
	if a.ctx != nil && a.ctx.Err() == nil {
		a.wg.Add(1)
		go a.ioLoop()
	}
}

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

func maxDuration(x, y time.Duration) time.Duration {
	if x > y {
		return x
	}
	return y
}

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

// markSocksConnected unblocks the SOCKS pipeline identically to python's async event
func (a *ARQ) MarkSocksConnected() {
	a.mu.Lock()
	select {
	case <-a.socksHandshake:
		a.mu.Unlock()
		return
	default:
		a.socksHandshakeErr = 0 // Success
		close(a.socksHandshake)
	}
	a.mu.Unlock()

	a.flushReadyLocalData()
	a.tryFinalizeRemoteEOF()
}

func (a *ARQ) MarkSocksFailed(errCode uint8) {
	a.mu.Lock()
	select {
	case <-a.socksHandshake:
		a.mu.Unlock()
		return
	default:
		a.socksHandshakeErr = errCode
		close(a.socksHandshake)
	}
	a.mu.Unlock()
}

func (a *ARQ) InjectOutboundData(data []byte) {
	if len(data) == 0 || a.isClosed() {
		return
	}

	offset := 0
	for offset < len(data) && !a.isClosed() {
		end := offset + a.mtu
		if end > len(data) {
			end = len(data)
		}
		chunk := append([]byte(nil), data[offset:end]...)

		a.mu.Lock()
		sn := a.sndNxt
		a.sndNxt++
		now := time.Now()
		a.sndBuf[sn] = &arqDataItem{
			Data:            chunk,
			CreatedAt:       now,
			LastSentAt:      now,
			Retries:         0,
			CurrentRTO:      a.rto,
			CompressionType: a.compressionType,
		}
		if len(a.sndBuf) >= a.limit {
			a.clearWindowNotFull()
		}
		a.mu.Unlock()

		a.enqueuer.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA), Enums.PACKET_STREAM_DATA, sn, 0, 0, a.compressionType, chunk)
		offset = end
	}
}

func (a *ARQ) CancelPendingSOCKS(reason string) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closeReason = reason
	a.setState(StateReset)
	a.stopLocalRead = true
	a.sndBuf = make(map[uint16]*arqDataItem)
	a.rcvBuf = make(map[uint16][]byte)
	for key, item := range a.controlSndBuf {
		if item.PacketType == Enums.PACKET_SOCKS5_SYN {
			delete(a.controlSndBuf, key)
		}
	}
	a.signalWindowNotFull()
	a.mu.Unlock()

	a.MarkSocksFailed(Enums.PACKET_STREAM_RST)
	if a.localConn != nil {
		_ = a.localConn.Close()
	}

	if !a.rstSent && !a.rstReceived {
		a.mu.Lock()
		sn := a.sndNxt
		a.mu.Unlock()
		a.MarkRstSent(&sn)
		ackType := uint8(Enums.PACKET_STREAM_RST_ACK)
		a.SendControlPacket(Enums.PACKET_STREAM_RST, *a.rstSeqSent, 0, 0, nil, Enums.DefaultPacketPriority(Enums.PACKET_STREAM_RST), a.enableControlReliability, &ackType)
	}
}

func (a *ARQ) GetSocksHandshakeResult() (uint8, bool) {
	select {
	case <-a.socksHandshake:
		return a.socksHandshakeErr, true
	default:
		return 0, false
	}
}

func (a *ARQ) SocksHandshakeChan() <-chan struct{} {
	return a.socksHandshake
}

// clearAllQueues is used to wipe state instantly (RST / Abort semantics)
func (a *ARQ) clearAllQueues() {
	a.sndBuf = make(map[uint16]*arqDataItem)
	a.rcvBuf = make(map[uint16][]byte)
	a.controlSndBuf = make(map[uint32]*arqControlItem)
	a.signalWindowNotFull()
}

// ---------------------------------------------------------------------
// Transitions & Hooks
// ---------------------------------------------------------------------

func (a *ARQ) MarkFinSent(seqSN *uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.finSent = true
	if seqSN != nil {
		v := *seqSN
		a.finSeqSent = &v
	} else if a.finSeqSent == nil {
		v := a.sndNxt
		a.finSeqSent = &v
	}

	if a.finReceived {
		a.setState(StateClosing)
	} else {
		a.setState(StateHalfClosedLocal)
	}
}

func (a *ARQ) MarkFinReceived(sn uint16) {
	a.mu.Lock()
	if a.isVirtual {
		a.mu.Unlock()
		return
	}
	a.finReceived = true
	a.finSeqReceived = &sn
	a.stopLocalRead = true

	if a.finSent {
		a.setState(StateClosing)
	} else {
		a.setState(StateHalfClosedRemote)
	}
	a.mu.Unlock()

	a.tryFinalizeRemoteEOF()
}

func (a *ARQ) markFinAcked(sn uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.finSeqSent != nil && *a.finSeqSent == sn {
		a.finAcked = true
	}
	if a.finReceived {
		a.setState(StateClosing)
	}
}

func (a *ARQ) MarkRstSent(seqSN *uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rstSent = true
	if seqSN != nil {
		v := *seqSN
		a.rstSeqSent = &v
	} else if a.rstSeqSent == nil {
		v := a.sndNxt
		a.rstSeqSent = &v
	}
	a.setState(StateReset)
}

func (a *ARQ) MarkRstReceived(sn uint16) {
	a.mu.Lock()
	if a.isVirtual {
		a.mu.Unlock()
		return
	}
	a.rstReceived = true
	a.rstSeqReceived = &sn
	a.setState(StateReset)
	a.clearAllQueues()
	a.mu.Unlock()
}

func (a *ARQ) markRstAcked(sn uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.rstSeqSent != nil && *a.rstSeqSent == sn {
		a.rstAcked = true
	}
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
	var errorReason string

	// Handle initial injection if socks proxy and predefined bytes are buffered
	if a.isSocks && len(a.initialData) > 0 {
		offset := 0
		totalLen := len(a.initialData)
		for offset < totalLen && !a.isClosed() {
			end := offset + a.mtu
			if end > totalLen {
				end = totalLen
			}
			chunk := a.initialData[offset:end]

			a.mu.Lock()
			sn := a.sndNxt
			a.sndNxt++
			now := time.Now()
			a.sndBuf[sn] = &arqDataItem{
				Data:            append([]byte(nil), chunk...),
				CreatedAt:       now,
				LastSentAt:      now,
				Retries:         0,
				CurrentRTO:      a.rto,
				CompressionType: a.compressionType,
			}
			a.mu.Unlock()
			a.enqueuer.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA), Enums.PACKET_STREAM_DATA, sn, 0, 0, a.compressionType, chunk)
			offset += a.mtu
		}
	}

	select {
	case <-a.socksHandshake:
	case <-a.ctx.Done():
		return
	}

	if errCode, ok := a.GetSocksHandshakeResult(); ok && errCode != 0 {
		return
	}

	buf := make([]byte, a.mtu)

	for !a.isClosed() {
		a.waitWindowNotFull()

		a.mu.Lock()
		if a.finReceived && !a.stopLocalRead {
			a.stopLocalRead = true
			a.closeReason = "Remote FIN received; local reader stopped"
			if a.state == StateOpen {
				a.setState(StateHalfClosedRemote)
			}
		}

		if a.stopLocalRead {
			a.closeReason = "Remote FIN received; local reader stopped"
			a.mu.Unlock()
			break
		}
		a.mu.Unlock()

		if a.localConn == nil {
			break
		}

		n, err := a.localConn.Read(buf)
		if err != nil {
			if err == io.EOF {
				errorReason = "Local App Closed Connection (EOF)"
				if a.shouldAbortOnLocalEOF() {
					resetRequired = true
				} else {
					gracefulEOF = true
				}
			} else {
				errorReason = "Read Error: " + err.Error()
				resetRequired = true
			}
			break
		}

		if n == 0 {
			errorReason = "Local App Closed Connection (EOF)"
			if a.shouldAbortOnLocalEOF() {
				resetRequired = true
			} else {
				gracefulEOF = true
			}
			break
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
		}

		if len(a.sndBuf) >= a.limit {
			a.clearWindowNotFull()
		}
		a.mu.Unlock()

		a.enqueuer.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA), Enums.PACKET_STREAM_DATA, sn, 0, 0, a.compressionType, raw)
	}

	// Closure Handling Strategy
	if a.isClosed() {
		return
	}
	if resetRequired {
		a.Abort(errorReason, true)
	} else if a.finReceivedLocked() {
		deadline := time.Now().Add(a.finDrainTimeout)
		for time.Now().Before(deadline) && !a.isClosed() {
			a.mu.Lock()
			empty := len(a.sndBuf) == 0
			a.mu.Unlock()
			if empty {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}

		a.mu.Lock()
		leftovers := len(a.sndBuf) > 0
		a.mu.Unlock()

		if leftovers && !a.isClosed() {
			if a.isClient {
				a.Abort("Remote FIN received but local send buffer did not drain", true)
			} else {
				a.deferTerminalPacket("Remote FIN received; waiting for outstanding data to drain", Enums.PACKET_STREAM_FIN)
			}
		} else if !a.isClosed() {
			a.initiateGracefulClose("Remote FIN fully handled")
		}
	} else if gracefulEOF {
		a.initiateGracefulClose(errorReason)
	}
}

func (a *ARQ) shouldAbortOnLocalEOF() bool {
	if !a.isClient {
		return false
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	return len(a.sndBuf) > 0
}

func (a *ARQ) finReceivedLocked() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.finReceived
}

func (a *ARQ) isClosed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed
}

// initiateGracefulClose delays closure until SND buffers map drain, emitting Graceful Fin
func (a *ARQ) initiateGracefulClose(reason string) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closeReason = reason
	if a.state != StateReset && a.state != StateClosed {
		a.setState(StateDraining)
	}
	a.mu.Unlock()

	a.deferTerminalPacket(reason, Enums.PACKET_STREAM_FIN)
	return

	deadline := time.Now().Add(a.gracefulDrainTimeout)
	for time.Now().Before(deadline) && !a.isClosed() {
		a.mu.Lock()
		if len(a.sndBuf) == 0 {
			a.mu.Unlock()
			break
		}
		a.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}

	if a.isClosed() {
		return
	}

	a.mu.Lock()
	leftovers := len(a.sndBuf) > 0
	a.mu.Unlock()

	if leftovers {
		if a.isClient {
			a.Abort(reason+" but send buffer did not drain", true)
		} else {
			a.deferGracefulClose(reason)
		}
		return
	}

	a.Close(reason, true)
}

func (a *ARQ) deferGracefulClose(reason string) {
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

	deadline := time.Now().Add(maxDuration(a.dataPacketTTL, a.gracefulDrainTimeout))
	if a.deferredDeadline.IsZero() || deadline.After(a.deferredDeadline) {
		a.deferredDeadline = deadline
	}
	a.mu.Unlock()
}

func (a *ARQ) settleDeferredClose() {
	var (
		shouldClose bool
		shouldAbort bool
		reason      string
	)

	a.mu.Lock()
	if a.closed || !a.deferredClose {
		a.mu.Unlock()
		return
	}

	switch {
	case len(a.sndBuf) == 0:
		shouldClose = true
		reason = a.deferredReason
		a.deferredClose = false
		a.deferredReason = ""
		a.deferredDeadline = time.Time{}
	case !a.deferredDeadline.IsZero() && time.Now().After(a.deferredDeadline):
		shouldAbort = true
		reason = a.deferredReason + " but emergency drain timeout expired"
		a.deferredClose = false
		a.deferredReason = ""
		a.deferredDeadline = time.Time{}
	}
	a.mu.Unlock()

	if shouldClose {
		a.Close(reason, true)
		return
	}
	if shouldAbort {
		a.Abort(reason, true)
	}
}

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
		a.emitTerminalPacket(packetType, reason)
	}
}

func (a *ARQ) emitTerminalPacket(packetType uint8, reason string) {
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
		a.waitingAck = true
		a.waitingAckFor = packetType
		a.ackWaitDeadline = time.Now().Add(a.terminalAckWait)
		a.mu.Unlock()

		sn := a.sndNxt
		a.MarkFinSent(&sn)
		ackType := uint8(Enums.PACKET_STREAM_FIN_ACK)
		a.SendControlPacket(Enums.PACKET_STREAM_FIN, *a.finSeqSent, 0, 0, nil, Enums.DefaultPacketPriority(Enums.PACKET_STREAM_FIN), a.enableControlReliability, &ackType)
	case Enums.PACKET_STREAM_RST:
		if a.rstReceived || a.rstSent {
			a.mu.Unlock()
			return
		}
		a.clearAllQueues()
		a.waitingAck = true
		a.waitingAckFor = packetType
		a.ackWaitDeadline = time.Now().Add(a.terminalAckWait)
		a.mu.Unlock()

		sn := a.sndNxt
		a.MarkRstSent(&sn)
		ackType := uint8(Enums.PACKET_STREAM_RST_ACK)
		a.SendControlPacket(Enums.PACKET_STREAM_RST, *a.rstSeqSent, 0, 0, nil, Enums.DefaultPacketPriority(Enums.PACKET_STREAM_RST), a.enableControlReliability, &ackType)
	default:
		a.mu.Unlock()
	}
}

func (a *ARQ) finalizeClose(reason string) {
	a.mu.Lock()
	if a.closed || a.isVirtual {
		a.mu.Unlock()
		return
	}
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

	a.clearAllQueues()
	a.mu.Unlock()
}

func (a *ARQ) tryFinalizeRemoteEOF() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed || a.remoteWriteClosed || !a.finReceived || a.finSeqReceived == nil || a.rcvNxt != *a.finSeqReceived {
		return
	}

	if a.isSocks {
		select {
		case <-a.socksHandshake:
		default:
			return
		}
	}

	a.remoteWriteClosed = true

	// In Go, closing for write only is trickier, but if it supports CloseWrite, we can.
	// We'll skip TCP half-close syscalls since net.Conn lacks it inherently without strict types, but it's safe to just ack.

	if a.finSent && a.finAcked && len(a.sndBuf) == 0 {
		go a.Close("Both FIN sides fully acknowledged", false)
	}
}

// flushReadyLocalData extracts from the unordered window buffer, sequentially emitting slices locally
func (a *ARQ) flushReadyLocalData() {
	if a.isClosed() {
		return
	}

	if a.isSocks {
		select {
		case <-a.socksHandshake:
		default:
			return
		}
	}

	a.mu.Lock()
	var toWrite [][]byte
	hasWritten := false

	for {
		data, exists := a.rcvBuf[a.rcvNxt]
		if !exists {
			break
		}
		toWrite = append(toWrite, data)
		delete(a.rcvBuf, a.rcvNxt)
		a.rcvNxt++
		hasWritten = true
	}
	a.mu.Unlock()

	if !hasWritten {
		return
	}

	a.writeLock.Lock()
	defer a.writeLock.Unlock()

	if a.localConn == nil {
		return
	}

	for _, chunk := range toWrite {
		_, err := a.localConn.Write(chunk)
		if err != nil {
			a.Abort("Local App Closed Connection (writer closed)", true)
			return
		}
	}
}

func (a *ARQ) retransmitLoop() {
	defer a.wg.Done()
	for {
		a.mu.Lock()
		rtoFactor := a.rto
		if a.enableControlReliability && a.controlRto < a.rto {
			rtoFactor = a.controlRto
		}
		baseInterval := rtoFactor / 3

		hasPending := len(a.sndBuf) > 0 || (a.enableControlReliability && len(a.controlSndBuf) > 0)
		a.mu.Unlock()

		interval := baseInterval
		if !hasPending {
			interval = baseInterval * 4
			if interval < 200*time.Millisecond {
				interval = 200 * time.Millisecond
			}
		} else if interval < 50*time.Millisecond {
			interval = 50 * time.Millisecond
		}

		select {
		case <-a.ctx.Done():
			return
		case <-time.After(interval):
			a.checkRetransmits()
		}
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

	if diff >= 32768 { // Negative diff equivalent in uint16, packet is old
		a.mu.Unlock()
		a.enqueuer.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA_ACK), Enums.PACKET_STREAM_DATA_ACK, sn, 0, 0, 0, nil)
		return
	}

	if int(diff) > a.windowSize {
		a.mu.Unlock()
		return
	}

	_, exists := a.rcvBuf[sn]
	if !exists && len(a.rcvBuf) >= a.windowSize { // Hardcap
		a.mu.Unlock()
		return
	}

	if !exists {
		a.rcvBuf[sn] = append([]byte(nil), data...)
	}
	a.mu.Unlock()

	a.flushReadyLocalData()
	a.enqueuer.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA_ACK), Enums.PACKET_STREAM_DATA_ACK, sn, 0, 0, 0, nil)
	a.tryFinalizeRemoteEOF()
}

// ReceiveAck resolves inbound STREAM_DATA_ACK and frees SEND_WINDOW backpressure buffer slots
func (a *ARQ) ReceiveAck(sn uint16) {
	a.mu.Lock()
	a.lastActivity = time.Now()

	if _, exists := a.sndBuf[sn]; exists {
		delete(a.sndBuf, sn)
		if len(a.sndBuf) < a.limit {
			a.signalWindowNotFull()
		}
	}
	a.mu.Unlock()

	a.settleTerminalDrain()
}

// ---------------------------------------------------------------------
// Control Plane Verification
// ---------------------------------------------------------------------

func (a *ARQ) SendControlPacket(packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, payload []byte, priority int, trackForAck bool, customAckType *uint8) bool {
	copyData := append([]byte(nil), payload...)
	priority = Enums.NormalizePacketPriority(packetType, priority)
	ok := a.enqueuer.PushTXPacket(priority, packetType, sequenceNum, fragmentID, totalFragments, 0, copyData)
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
	}

	return true
}

func (a *ARQ) ReceiveControlAck(ackPacketType uint8, sequenceNum uint16, fragmentID uint8) bool {
	a.mu.Lock()
	a.lastActivity = time.Now()
	waitingFor := a.waitingAckFor

	if ackPacketType == Enums.PACKET_STREAM_FIN_ACK {
		a.mu.Unlock()
		a.markFinAcked(sequenceNum)
		if waitingFor == Enums.PACKET_STREAM_FIN {
			a.finalizeClose("FIN acknowledged")
			return true
		}
		a.mu.Lock()
	} else if ackPacketType == Enums.PACKET_STREAM_RST_ACK {
		a.mu.Unlock()
		a.markRstAcked(sequenceNum)
		a.finalizeClose("RST acknowledged")
		return true
	}

	originPtype, ok := Enums.ReverseControlAckFor(ackPacketType)
	var cleared bool
	// Note: Local DNS fragments from server are handled by fragmentstore,
	// but control-plane fragments (like split DNS REQs) need matching keys.

	if !ok {
		key := uint32(ackPacketType)<<24 | uint32(sequenceNum)<<8 | uint32(fragmentID)
		_, exists := a.controlSndBuf[key]
		if exists {
			delete(a.controlSndBuf, key)
			cleared = true
		}
	} else {
		key := uint32(originPtype)<<24 | uint32(sequenceNum)<<8 | uint32(fragmentID)
		_, exists := a.controlSndBuf[key]
		if exists {
			delete(a.controlSndBuf, key)
			cleared = true
		}
	}
	a.mu.Unlock()
	return cleared
}

func (a *ARQ) checkRetransmits() {
	if a.isClosed() {
		return
	}

	a.mu.Lock()
	now := time.Now()
	if a.deferredClose {
		shouldClose := len(a.sndBuf) == 0
		shouldAbort := !a.deferredDeadline.IsZero() && now.After(a.deferredDeadline)
		a.mu.Unlock()
		if shouldClose || shouldAbort {
			a.settleTerminalDrain()
		}
		if a.isClosed() {
			return
		}
		a.mu.Lock()
	}
	if a.waitingAck && !a.ackWaitDeadline.IsZero() && now.After(a.ackWaitDeadline) {
		a.mu.Unlock()
		a.finalizeClose("Terminal ACK wait timeout")
		return
	}
	if a.rstReceived && a.state != StateReset {
		sn := uint16(0)
		if a.rstSeqReceived != nil {
			sn = *a.rstSeqReceived
		}
		a.mu.Unlock()
		a.MarkRstReceived(sn)
		a.Abort("Peer reset signaled", false)
		return
	}
	if now.Sub(a.lastActivity) > a.inactivityTimeout {
		if len(a.sndBuf) > 0 || (a.enableControlReliability && len(a.controlSndBuf) > 0) {
			a.lastActivity = now
		} else {
			a.mu.Unlock()
			a.Abort("Stream Inactivity Timeout (Dead)", true)
			return
		}
	}

	type rtxJob struct {
		sn              uint16
		data            []byte
		compressionType uint8
	}
	var jobs []rtxJob

	for sn, info := range a.sndBuf {
		if now.Sub(info.CreatedAt) >= a.dataPacketTTL && info.Retries >= a.maxDataRetries {
			a.mu.Unlock()
			a.Abort("Max retransmissions exceeded", true)
			return
		}

		if now.Sub(info.LastSentAt) >= info.CurrentRTO {
			jobs = append(jobs, rtxJob{sn, info.Data, info.CompressionType})
			info.LastSentAt = now
			info.Retries++

			grownRTO := time.Duration(float64(info.CurrentRTO) * 1.2)
			info.CurrentRTO = time.Duration(minF(float64(a.maxRTO), maxF(float64(a.rto), float64(grownRTO))))
		}
	}
	a.mu.Unlock()

	for _, j := range jobs {
		a.enqueuer.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_STREAM_RESEND), Enums.PACKET_STREAM_RESEND, j.sn, 0, 0, j.compressionType, j.data)
	}

	if a.enableControlReliability {
		a.checkControlRetransmits(now)
	}
}

func (a *ARQ) checkControlRetransmits(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for key, info := range a.controlSndBuf {
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

		if now.Sub(info.CreatedAt) >= packetTTL || info.Retries >= maxRetries {
			delete(a.controlSndBuf, key)
			continue
		}

		if now.Sub(info.LastSentAt) < info.CurrentRTO {
			continue
		}

		ok := a.enqueuer.PushTXPacket(info.Priority, info.PacketType, info.SequenceNum, info.FragmentID, info.TotalFragments, 0, info.Payload)
		if !ok {
			delete(a.controlSndBuf, key)
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

// Abort performs aggressive RST TCP closure and instantly zeroes out local buffers
func (a *ARQ) Abort(reason string, sendRst bool) {
	if !sendRst {
		a.finalizeClose(reason)
		return
	}

	a.mu.Lock()
	if a.closed || a.isVirtual {
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

	if a.isClient {
		a.mu.Lock()
		a.clearAllQueues()
		a.mu.Unlock()
		a.emitTerminalPacket(Enums.PACKET_STREAM_RST, reason)
		return
	}

	if hasPendingData {
		a.deferTerminalPacket(reason, Enums.PACKET_STREAM_RST)
		return
	}

	a.emitTerminalPacket(Enums.PACKET_STREAM_RST, reason)
	return

	a.mu.Lock()
	if a.closed || a.isVirtual {
		a.mu.Unlock()
		return
	}
	a.closeReason = reason
	a.setState(StateReset)
	a.deferredClose = false
	a.deferredReason = ""
	a.deferredDeadline = time.Time{}
	a.mu.Unlock()

	if sendRst && !a.rstSent && !a.rstReceived {
		a.mu.Lock()
		sn := a.sndNxt
		a.mu.Unlock()
		a.MarkRstSent(&sn)
		ackType := uint8(Enums.PACKET_STREAM_RST_ACK)
		a.SendControlPacket(Enums.PACKET_STREAM_RST, *a.rstSeqSent, 0, 0, nil, Enums.DefaultPacketPriority(Enums.PACKET_STREAM_RST), a.enableControlReliability, &ackType)
	}

	a.mu.Lock()
	a.clearAllQueues()
	a.mu.Unlock()
	a.Close(reason, false)
}

func (a *ARQ) Close(reason string, sendFin bool) {
	if sendFin {
		a.deferTerminalPacket(reason, Enums.PACKET_STREAM_FIN)
		return
	}
	a.finalizeClose(reason)
	return

	a.mu.Lock()
	if a.closed || a.isVirtual {
		a.mu.Unlock()
		return
	}
	a.closeReason = reason
	a.closed = true
	a.deferredClose = false
	a.deferredReason = ""
	a.deferredDeadline = time.Time{}

	if sendFin && !a.finSent && !a.rstSent && !a.rstReceived {
		sn := a.sndNxt
		a.mu.Unlock()
		a.MarkFinSent(&sn)
		ackType := uint8(Enums.PACKET_STREAM_FIN_ACK)
		a.SendControlPacket(Enums.PACKET_STREAM_FIN, *a.finSeqSent, 0, 0, nil, Enums.DefaultPacketPriority(Enums.PACKET_STREAM_FIN), a.enableControlReliability, &ackType)
		a.mu.Lock()
	}

	if a.state == StateReset || a.rstReceived || a.rstSent {
		a.setState(StateReset)
	} else if a.finSent && a.finReceived {
		a.setState(StateTimeWait)
	} else {
		a.setState(StateClosing)
	}

	a.cancel()

	if a.localConn != nil {
		_ = a.localConn.Close()
	}

	a.clearAllQueues()
	a.mu.Unlock()
}

// ForceClose permanently closes the ARQ stream regardless of IsVirtual.
func (a *ARQ) ForceClose(reason string) {
	a.mu.Lock()
	wasVirtual := a.isVirtual
	a.isVirtual = false
	a.mu.Unlock()

	if wasVirtual {
		// Override and instantly kill
		a.Abort(reason, false)
	} else {
		a.Close(reason, false)
	}
}

// Done returns a channel that is closed when the ARQ context is cancelled or the stream is closed.
func (a *ARQ) Done() <-chan struct{} {
	return a.ctx.Done()
}
