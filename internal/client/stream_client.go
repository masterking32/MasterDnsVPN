// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"net"
	"sync" // Added for sync.Pool
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/mlq"
)

var txPacketPool = sync.Pool{
	New: func() any {
		return &clientStreamTXPacket{}
	},
}

const (
	streamStatusPending         = "PENDING"
	streamStatusConnecting      = "CONNECTING"
	streamStatusSocksConnecting = "SOCKS_CONNECTING"
	streamStatusActive          = "ACTIVE"
	streamStatusDraining        = "DRAINING"
	streamStatusClosing         = "CLOSING"
	streamStatusTimeWait        = "TIME_WAIT"
	streamStatusSocksFailed     = "SOCKS_FAILED"
	streamStatusCancelled       = "CANCELLED"
	streamStatusClosed          = "CLOSED"
)

// Stream_client represents a single stream's data structure, mirroring the Python version's
// 'active_streams' dictionary elements.
type Stream_client struct {
	client *Client

	StreamID           uint16
	LocalSocksVersion  byte
	NetConn            net.Conn
	CreateTime         time.Time
	LastActivityTime   time.Time
	Status             string // PENDING, ACTIVE, CLOSED
	Stream             any    // The ARQ object
	StreamCreating     bool
	PendingInboundData map[uint16][]byte

	// High-performance multi-level priority queue
	txQueue *mlq.MultiLevelQueue[*clientStreamTXPacket]

	InitialPayload []byte
	PriorityCounts map[int]int

	// Metadata & Failover
	PreferredServerKey     string
	ResolverResendStreak   int
	LastResolverFailoverAt time.Time
	HandshakeLastProgress  time.Time
	CachedResolverPlan     []Connection
	CachedResolverPlanFor  string
	CachedResolverPlanSize int
	CachedResolverVersion  uint64

	resolverMu    sync.Mutex
	txQueueMu     sync.Mutex
	statusMu      sync.RWMutex
	terminalSince time.Time
	socksResultMu sync.Mutex
	cleanupOnce   sync.Once
}

// get_new_stream_id finds the next available stream ID using a circular counter (1-65535).
func (c *Client) get_new_stream_id() (uint16, bool) {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()

	start := c.last_stream_id + 1
	if start == 0 {
		start = 1
	}

	id := start
	wrapped := false

	// Cycle through IDs to find an available one in active_streams
	for {
		if _, exists := c.active_streams[id]; !exists {
			c.last_stream_id = id
			return id, true
		}

		id++
		if id == 0 {
			if wrapped {
				return 0, false // Fully occupied (unlikely but safe)
			}
			id = 1
			wrapped = true
		}

		if wrapped && id == start {
			return 0, false // Entire cycle checked, no free ID
		}
	}
}

// new_stream initializes a new Stream_client with default values.
func (c *Client) new_stream(streamID uint16, conn net.Conn, targetPayload []byte) *Stream_client {
	now := time.Now()

	s := &Stream_client{
		client:             c,
		StreamID:           streamID,
		NetConn:            conn,
		CreateTime:         now,
		LastActivityTime:   now,
		Status:             streamStatusPending,
		StreamCreating:     false,
		PendingInboundData: make(map[uint16][]byte),
		InitialPayload:     targetPayload,
		PriorityCounts:     make(map[int]int),

		txQueue: mlq.New[*clientStreamTXPacket](c.cfg.StreamQueueInitialCapacity),

		HandshakeLastProgress: now,
	}

	// Initialize and start the highly-optimized ARQ engine (Ported from Python)
	mtu := c.syncedUploadMTU
	if mtu <= 0 {
		mtu = 1200 // Safe default
	}

	arqCfg := arq.Config{
		WindowSize:               c.cfg.ARQWindowSize,
		RTO:                      c.cfg.ARQInitialRTOSeconds,
		MaxRTO:                   c.cfg.ARQMaxRTOSeconds,
		StartPaused:              conn != nil && streamID != 0 && (c.cfg.ProtocolType == "SOCKS5" || c.cfg.ProtocolType == "TCP"),
		EnableControlReliability: true,
		ControlRTO:               c.cfg.ARQControlInitialRTOSeconds,
		ControlMaxRTO:            c.cfg.ARQControlMaxRTOSeconds,
		ControlMaxRetries:        c.cfg.ARQMaxControlRetries,
		InactivityTimeout:        c.cfg.ARQInactivityTimeoutSeconds,
		DataPacketTTL:            c.cfg.ARQDataPacketTTLSeconds,
		MaxDataRetries:           c.cfg.ARQMaxDataRetries,
		DataNackMaxGap:           c.cfg.ARQDataNackMaxGap,
		DataNackRepeatSeconds:    c.cfg.ARQDataNackRepeatSeconds,
		ControlPacketTTL:         c.cfg.ARQControlPacketTTLSeconds,
		TerminalDrainTimeout:     c.cfg.ARQTerminalDrainTimeoutSec,
		TerminalAckWaitTimeout:   c.cfg.ARQTerminalAckWaitTimeoutSec,
		CompressionType:          c.uploadCompression,
		IsClient:                 true,
	}

	a := arq.NewARQ(streamID, c.sessionID, s, conn, mtu, c.log, arqCfg)
	s.Stream = a
	a.Start()

	c.streamsMu.Lock()
	if c.active_streams == nil {
		c.active_streams = make(map[uint16]*Stream_client)
	}
	c.active_streams[streamID] = s
	c.streamsMu.Unlock()
	c.bumpStreamSetVersion()

	if conn != nil && streamID != 0 {
		switch c.cfg.ProtocolType {
		case "SOCKS5":
			s.SetStatus(streamStatusSocksConnecting)
		case "TCP":
			s.SetStatus(streamStatusConnecting)
		}
	}

	if streamID != 0 {
		c.ensureStreamPreferredConnection(s)
	}

	if c.log != nil && streamID != 0 {
		c.log.Debugf(
			"🧦 <green>Stream Created <magenta>|</magenta> Stream: <cyan>%d</cyan> <magenta>|</magenta> Session: <cyan>%d</cyan> <magenta>|</magenta> Status: <cyan>%s</cyan></green>",
			streamID, c.sessionID, s.StatusValue(),
		)
	}

	return s
}

// PushTXPacket adds a packet to the appropriate priority queue if it's not a duplicate.
func (s *Stream_client) PushTXPacket(priority int, packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, compressionType uint8, ttl time.Duration, payload []byte) bool {
	dataKey := Enums.PacketIdentityKey(s.StreamID, Enums.PACKET_STREAM_DATA, sequenceNum, fragmentID)
	resendKey := Enums.PacketIdentityKey(s.StreamID, Enums.PACKET_STREAM_RESEND, sequenceNum, fragmentID)
	key := Enums.PacketIdentityKey(s.StreamID, packetType, sequenceNum, fragmentID)

	// Delegate to MLQ (Mechanism)
	priority = Enums.NormalizePacketPriority(packetType, priority)

	// Skip Ping packets if the queue is already congested (prevent bloat)
	if packetType == Enums.PACKET_PING && s.txQueue != nil && s.txQueue.Size() > 200 {
		return false
	}

	// Get a packet from the pool
	p := txPacketPool.Get().(*clientStreamTXPacket)
	p.PacketType = packetType
	p.SequenceNum = sequenceNum
	p.FragmentID = fragmentID
	p.TotalFragments = totalFragments
	p.CompressionType = compressionType
	p.Payload = payload
	p.CreatedAt = time.Now()
	p.TTL = ttl
	p.RetryCount = 0
	p.Scheduled = false

	s.txQueueMu.Lock()
	defer s.txQueueMu.Unlock()

	switch packetType {
	case Enums.PACKET_STREAM_DATA:
		if _, exists := s.txQueue.Get(dataKey); exists {
			s.ReleaseTXPacket(p)
			return false
		}
		if _, exists := s.txQueue.Get(resendKey); exists {
			s.ReleaseTXPacket(p)
			return false
		}
	case Enums.PACKET_STREAM_RESEND:
		if _, exists := s.txQueue.Get(resendKey); exists {
			s.ReleaseTXPacket(p)
			return false
		}
	default:
	}

	if ok := s.txQueue.Push(priority, key, p); !ok {
		// Duplicate found in census
		s.ReleaseTXPacket(p)
		return false
	}

	if packetType == Enums.PACKET_STREAM_RESEND {
		if stale, removed := s.txQueue.RemoveByKey(dataKey, func(p *clientStreamTXPacket) uint64 {
			return Enums.PacketIdentityKey(s.StreamID, p.PacketType, p.SequenceNum, p.FragmentID)
		}); removed {
			s.ReleaseTXPacket(stale)
		}
	}

	select {
	case s.client.txSignal <- struct{}{}:
	default:
	}

	return true
}

// PopNextTXPacket retrieves the highest priority packet from the queues.
func (s *Stream_client) PopNextTXPacket() (*clientStreamTXPacket, int, bool) {
	// Delegate to MLQ
	packet, priority, ok := s.txQueue.Pop(func(p *clientStreamTXPacket) uint64 {
		return Enums.PacketIdentityKey(s.StreamID, p.PacketType, p.SequenceNum, p.FragmentID)
	})
	if ok && packet != nil {
		s.NoteTXPacketDequeued(packet)
	}

	return packet, priority, ok
}

func (s *Stream_client) NoteTXPacketDequeued(packet *clientStreamTXPacket) {
	if s == nil || packet == nil {
		return
	}
	if a, ok := s.Stream.(*arq.ARQ); ok && a != nil {
		a.NoteTXPacketDequeued(packet.PacketType, packet.SequenceNum, packet.FragmentID)
	}
}

// GetQueuedPacket checks if a packet exists in any priority queue in O(1).
func (s *Stream_client) GetQueuedPacket(packetType uint8, sequenceNum uint16, fragmentID uint8) (*clientStreamTXPacket, bool) {
	key := Enums.PacketIdentityKey(s.StreamID, packetType, sequenceNum, fragmentID)
	return s.txQueue.Get(key)
}

func (s *Stream_client) RemoveQueuedData(sequenceNum uint16) bool {
	if s == nil || s.txQueue == nil {
		return false
	}

	s.txQueueMu.Lock()
	defer s.txQueueMu.Unlock()

	removedAny := false
	for _, packetType := range []uint8{Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND} {
		key := Enums.PacketIdentityKey(s.StreamID, packetType, sequenceNum, 0)
		p, ok := s.txQueue.RemoveByKey(key, func(p *clientStreamTXPacket) uint64 {
			return Enums.PacketIdentityKey(s.StreamID, p.PacketType, p.SequenceNum, p.FragmentID)
		})
		if ok {
			s.ReleaseTXPacket(p)
			removedAny = true
		}
	}
	return removedAny
}

func (s *Stream_client) RemoveQueuedDataNack(sequenceNum uint16) bool {
	if s == nil || s.txQueue == nil {
		return false
	}

	s.txQueueMu.Lock()
	defer s.txQueueMu.Unlock()

	key := Enums.PacketIdentityKey(s.StreamID, Enums.PACKET_STREAM_DATA_NACK, sequenceNum, 0)
	p, ok := s.txQueue.RemoveByKey(key, func(p *clientStreamTXPacket) uint64 {
		return Enums.PacketIdentityKey(s.StreamID, p.PacketType, p.SequenceNum, p.FragmentID)
	})
	if !ok {
		return false
	}

	s.ReleaseTXPacket(p)
	return true
}

func (s *Stream_client) cleanupResources() {
	if s.client != nil && s.client.log != nil && s.StreamID != 0 {
		s.client.log.Debugf(
			"🧹 <yellow>Stream Cleanup <magenta>|</magenta> Stream: <cyan>%d</cyan> <magenta>|</magenta> Session: <cyan>%d</cyan></yellow>",
			s.StreamID, s.client.sessionID,
		)
	}

	if s.NetConn != nil {
		_ = s.NetConn.Close()
	}

	if s.txQueue != nil {
		s.txQueue.Clear(func(p *clientStreamTXPacket) {
			s.ReleaseTXPacket(p)
		})
	}

	s.PendingInboundData = nil
	s.SetStatus(streamStatusClosed)
}

func (s *Stream_client) finalizeAfterARQClose() {
	if s == nil {
		return
	}

	s.cleanupOnce.Do(func() {
		if s.client != nil {
			s.client.streamsMu.Lock()
			if current, ok := s.client.active_streams[s.StreamID]; ok && current == s {
				delete(s.client.active_streams, s.StreamID)
			}
			s.client.streamsMu.Unlock()
			s.client.bumpStreamSetVersion()
		}

		s.cleanupResources()
	})
}

func (s *Stream_client) OnARQClosed(reason string) {
	if s != nil && s.client != nil {
		s.client.rememberClosedStream(s.StreamID, reason, time.Now())
	}
	s.finalizeAfterARQClose()
}

// Close gracefully shuts down the stream and releases all resources.
func (s *Stream_client) Close() {
	if s.Stream != nil {
		if a, ok := s.Stream.(*arq.ARQ); ok {
			a.Close("Stream_client.Close cleanup", arq.CloseOptions{Force: true})
		}
	}
	s.finalizeAfterARQClose()
}

func (s *Stream_client) CloseStream(force bool, ttl time.Duration) {
	if s == nil {
		return
	}

	if a, ok := s.Stream.(*arq.ARQ); ok && a != nil {
		if force {
			s.MarkTerminal(time.Now())
			s.SetStatus(streamStatusCancelled)
			if s.NetConn != nil {
				_ = s.NetConn.Close()
			}
			a.Close("Close stream requested", arq.CloseOptions{
				SendRST: true,
				TTL:     ttl,
			})
			return
		}

		a.Close("Close stream requested", arq.CloseOptions{
			SendCloseRead: true,
			AfterDrain:    true,
			TTL:           ttl,
		})
		return
	}

	s.finalizeAfterARQClose()
}

// ReleaseTXPacket returns a packet to the pool.
func (s *Stream_client) ReleaseTXPacket(p *clientStreamTXPacket) {
	if p == nil {
		return
	}
	p.Payload = nil // Clear payload reference
	p.TTL = 0
	txPacketPool.Put(p)
}

func (s *Stream_client) SetStatus(status string) {
	if s == nil {
		return
	}
	s.statusMu.Lock()
	s.Status = status
	s.statusMu.Unlock()
}

func (s *Stream_client) StatusValue() string {
	if s == nil {
		return streamStatusClosed
	}
	s.statusMu.RLock()
	status := s.Status
	s.statusMu.RUnlock()
	return status
}

func (s *Stream_client) MarkTerminal(now time.Time) {
	if s == nil {
		return
	}
	s.statusMu.Lock()
	if s.terminalSince.IsZero() {
		s.terminalSince = now
	}
	s.statusMu.Unlock()
}

func (s *Stream_client) ClearTerminal() {
	if s == nil {
		return
	}
	s.statusMu.Lock()
	s.terminalSince = time.Time{}
	s.statusMu.Unlock()
}

func (s *Stream_client) TerminalSince() time.Time {
	if s == nil {
		return time.Time{}
	}
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	return s.terminalSince
}

// -----------------------------------------------------------------------------------------
// Virtual Stream 0 Support
// -----------------------------------------------------------------------------------------

type fakeConnTimeoutError struct{}

func (fakeConnTimeoutError) Error() string   { return "fakeConn read timeout" }
func (fakeConnTimeoutError) Timeout() bool   { return true }
func (fakeConnTimeoutError) Temporary() bool { return true }

type fakeConn struct {
	mu           sync.Mutex
	readDeadline time.Time
	closedCh     chan struct{}
	closeOnce    sync.Once
}

func (f *fakeConn) Read(b []byte) (n int, err error) {
	for {
		f.mu.Lock()
		deadline := f.readDeadline
		closedCh := f.closedCh
		f.mu.Unlock()

		if closedCh == nil {
			return 0, net.ErrClosed
		}

		if deadline.IsZero() {
			<-closedCh
			return 0, net.ErrClosed
		}

		wait := time.Until(deadline)
		if wait <= 0 {
			return 0, fakeConnTimeoutError{}
		}

		timer := time.NewTimer(wait)
		select {
		case <-closedCh:
			if !timer.Stop() {
				<-timer.C
			}
			return 0, net.ErrClosed
		case <-timer.C:
			return 0, fakeConnTimeoutError{}
		}
	}
}

func (f *fakeConn) Write(b []byte) (n int, err error) {
	// Swallow data silently for Stream 0 local-writes
	return len(b), nil
}

func (f *fakeConn) Close() error {
	f.closeOnce.Do(func() {
		if f.closedCh != nil {
			close(f.closedCh)
		}
	})
	return nil
}

func (f *fakeConn) SetReadDeadline(deadline time.Time) error {
	f.mu.Lock()
	f.readDeadline = deadline
	f.mu.Unlock()
	return nil
}

func (f *fakeConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (f *fakeConn) SetDeadline(deadline time.Time) error {
	return f.SetReadDeadline(deadline)
}

func newFakeConn() *fakeConn {
	return &fakeConn{
		closedCh: make(chan struct{}),
	}
}

// InitVirtualStream0 initializes Stream #0 instantly upon Session start.
// This serves as the control and Ping channel running perpetually without timeout.
func (c *Client) InitVirtualStream0() {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()

	streamID := uint16(0)
	s := &Stream_client{
		client:     c,
		StreamID:   streamID,
		txQueue:    mlq.New[*clientStreamTXPacket](c.cfg.StreamQueueInitialCapacity),
		CreateTime: time.Now(),
	}

	mtu := c.syncedUploadMTU
	if mtu <= 0 {
		mtu = 1200
	}

	arqCfg := arq.Config{
		WindowSize:               c.cfg.ARQWindowSize,
		RTO:                      c.cfg.ARQInitialRTOSeconds,
		MaxRTO:                   c.cfg.ARQMaxRTOSeconds,
		IsVirtual:                true, // Bypasses internal timeout closures
		EnableControlReliability: true,
		ControlRTO:               c.cfg.ARQControlInitialRTOSeconds,
		ControlMaxRTO:            c.cfg.ARQControlMaxRTOSeconds,
		ControlMaxRetries:        c.cfg.ARQMaxControlRetries,
		InactivityTimeout:        999999.0, // Infinite
		DataPacketTTL:            999999.0,
		MaxDataRetries:           99999,
		DataNackMaxGap:           0,
		DataNackRepeatSeconds:    c.cfg.ARQDataNackRepeatSeconds,
		ControlPacketTTL:         999999.0,
		TerminalDrainTimeout:     c.cfg.ARQTerminalDrainTimeoutSec,
		TerminalAckWaitTimeout:   c.cfg.ARQTerminalAckWaitTimeoutSec,
		CompressionType:          c.uploadCompression,
	}

	conn := newFakeConn()
	a := arq.NewARQ(streamID, c.sessionID, s, conn, mtu, c.log, arqCfg)
	s.Stream = a
	c.active_streams[streamID] = s
	a.Start()
	c.bumpStreamSetVersion()

	c.log.Debugf("🚀 <green>Virtual Stream 0 (Control Channel) Initialized.</green>")
}

// CloseAllStreams is the hard-stop path used during runtime shutdown/reset.
// It finalizes streams locally so retransmit loops stop immediately.
func (c *Client) CloseAllStreams() {
	c.streamsMu.Lock()
	streams := make([]*Stream_client, 0, len(c.active_streams))
	for _, s := range c.active_streams {
		streams = append(streams, s)
	}
	c.active_streams = make(map[uint16]*Stream_client)
	c.streamsMu.Unlock()
	c.bumpStreamSetVersion()

	if c.log != nil {
		c.log.Debugf("🧦 <yellow>Closing all streams <magenta>|</magenta> Count: <cyan>%d</cyan></yellow>", len(streams))
	}

	for _, s := range streams {
		if s != nil {
			s.Close()
		}
	}

	c.clearRecentlyClosedStreams()
	c.clearOrphanResets()
}
