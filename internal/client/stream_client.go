// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"errors"
	"io"
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

	statusMu           sync.RWMutex
	terminalSince      time.Time
	pendingWatchCancel chan struct{}
	pendingWatchDone   chan struct{}
	pendingWatchOnce   sync.Once
	pendingLocalDataMu sync.Mutex
	pendingLocalData   [][]byte
}

// getTrackingKey generates a unified key for duplicate prevention.
// It ensures that certain types (like DATA and RESEND) share the same tracking slot.
func getTrackingKey(packetType uint8, sequenceNum uint16, fragmentID uint8) uint32 {
	t := packetType
	// Map related types to a single ID to prevent duplicates across types
	if t == Enums.PACKET_STREAM_RESEND {
		t = Enums.PACKET_STREAM_DATA
	}
	// Key: [8bit PacketType][16bit SequenceNum][8bit FragmentID]
	return uint32(t)<<24 | uint32(sequenceNum)<<8 | uint32(fragmentID)
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

		txQueue: mlq.New[*clientStreamTXPacket](64),

		HandshakeLastProgress: now,
	}

	// Initialize and start the highly-optimized ARQ engine (Ported from Python)
	mtu := c.syncedUploadMTU
	if mtu <= 0 {
		mtu = 1200 // Safe default
	}

	arqCfg := arq.Config{
		WindowSize:               c.cfg.ARQWindowSize,
		RTO:                      0.2, // Fast retry out of the gate
		MaxRTO:                   1.5,
		IsSocks:                  c.cfg.ProtocolType == "SOCKS5",
		IsClient:                 true,
		InitialData:              targetPayload,
		EnableControlReliability: true,
		ControlRTO:               0.8,
		ControlMaxRTO:            2.5,
		ControlMaxRetries:        40,
		InactivityTimeout:        1200.0,
		DataPacketTTL:            600.0,
		MaxDataRetries:           400,
		ControlPacketTTL:         600.0,
		FinDrainTimeout:          300.0,
		GracefulDrainTimeout:     600.0,
		TerminalDrainTimeout:     60.0,
		TerminalAckWaitTimeout:   30.0,
		CompressionType:          c.uploadCompression,
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

	if conn != nil && streamID != 0 && c.cfg.ProtocolType == "SOCKS5" {
		s.SetStatus(streamStatusSocksConnecting)
		s.startPendingSOCKSWatch()
	}

	return s
}

// PushTXPacket adds a packet to the appropriate priority queue if it's not a duplicate.
func (s *Stream_client) PushTXPacket(priority int, packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, compressionType uint8, payload []byte) bool {
	// Generate the tracking key (Policy)
	key := getTrackingKey(packetType, sequenceNum, fragmentID)

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
	p.RetryCount = 0
	p.Scheduled = false

	if ok := s.txQueue.Push(priority, key, p); !ok {
		// Duplicate found in census
		s.ReleaseTXPacket(p)
		return false
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
	packet, priority, ok := s.txQueue.Pop(func(p *clientStreamTXPacket) uint32 {
		return getTrackingKey(p.PacketType, p.SequenceNum, p.FragmentID)
	})

	return packet, priority, ok
}

// GetQueuedPacket checks if a packet exists in any priority queue in O(1).
func (s *Stream_client) GetQueuedPacket(packetType uint8, sequenceNum uint16, fragmentID uint8) (*clientStreamTXPacket, bool) {
	key := getTrackingKey(packetType, sequenceNum, fragmentID)
	return s.txQueue.Get(key)
}

// Close gracefully shuts down the stream and releases all resources.
func (s *Stream_client) Close() {
	s.stopPendingSOCKSWatch(false)

	// 1. Close the ARQ object if it exists
	if s.Stream != nil {
		if a, ok := s.Stream.(*arq.ARQ); ok {
			a.Close("Stream_client.Close called", false)
		}
	}

	// 2. Close the network connection
	if s.NetConn != nil {
		_ = s.NetConn.Close()
	}

	// 3. Clear the TX queue and return all packets to the pool (Safety)
	if s.txQueue != nil {
		s.txQueue.Clear(func(p *clientStreamTXPacket) {
			s.ReleaseTXPacket(p)
		})
	}

	// 4. Clear inbound buffer
	s.PendingInboundData = nil
	s.SetStatus(streamStatusClosed)
}

// ReleaseTXPacket returns a packet to the pool.
func (s *Stream_client) ReleaseTXPacket(p *clientStreamTXPacket) {
	if p == nil {
		return
	}
	p.Payload = nil // Clear payload reference
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

func (s *Stream_client) appendPendingLocalData(chunk []byte) {
	if s == nil || len(chunk) == 0 {
		return
	}
	buf := append([]byte(nil), chunk...)
	s.pendingLocalDataMu.Lock()
	s.pendingLocalData = append(s.pendingLocalData, buf)
	s.pendingLocalDataMu.Unlock()
}

func (s *Stream_client) takePendingLocalData() [][]byte {
	if s == nil {
		return nil
	}
	s.pendingLocalDataMu.Lock()
	chunks := s.pendingLocalData
	s.pendingLocalData = nil
	s.pendingLocalDataMu.Unlock()
	return chunks
}

func (s *Stream_client) startPendingSOCKSWatch() {
	if s == nil || s.NetConn == nil {
		return
	}

	s.pendingWatchOnce.Do(func() {
		s.pendingWatchCancel = make(chan struct{})
		s.pendingWatchDone = make(chan struct{})

		go func() {
			defer close(s.pendingWatchDone)

			readBufSize := s.client.syncedUploadMTU
			if readBufSize <= 0 {
				readBufSize = 4096
			}
			buf := make([]byte, readBufSize)

			for {
				select {
				case <-s.pendingWatchCancel:
					return
				default:
				}

				if s.StatusValue() != streamStatusSocksConnecting {
					return
				}

				_ = s.NetConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				n, err := s.NetConn.Read(buf)
				if n > 0 {
					s.appendPendingLocalData(buf[:n])
				}

				if err == nil {
					continue
				}
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}

				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
					s.client.handlePendingSOCKSLocalClose(s.StreamID, "local SOCKS connection closed before connect")
					return
				}

				s.client.handlePendingSOCKSLocalClose(s.StreamID, "local SOCKS connection failed before connect: "+err.Error())
				return
			}
		}()
	})
}

func (s *Stream_client) stopPendingSOCKSWatch(wait bool) {
	if s == nil || s.pendingWatchCancel == nil {
		return
	}

	select {
	case <-s.pendingWatchCancel:
	default:
		close(s.pendingWatchCancel)
	}

	if wait && s.pendingWatchDone != nil {
		select {
		case <-s.pendingWatchDone:
		case <-time.After(500 * time.Millisecond):
		}
	}

	// The pending watcher uses short read deadlines to probe early close/data.
	// Clear any leftover deadline before ARQ takes over normal blocking reads,
	// otherwise the first local read after SOCKS connect can look like a fatal error.
	if s.NetConn != nil {
		_ = s.NetConn.SetReadDeadline(time.Time{})
	}
}

// -----------------------------------------------------------------------------------------
// Virtual Stream 0 Support
// -----------------------------------------------------------------------------------------

type fakeConn struct{}

func (f *fakeConn) Read(b []byte) (n int, err error) {
	// Block eternally so ARQ's ioLoop doesn't spin or immediately exit
	select {}
}

func (f *fakeConn) Write(b []byte) (n int, err error) {
	// Swallow data silently for Stream 0 local-writes
	return len(b), nil
}

func (f *fakeConn) Close() error {
	return nil
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
		txQueue:    mlq.New[*clientStreamTXPacket](64),
		CreateTime: time.Now(),
	}

	mtu := c.syncedUploadMTU
	if mtu <= 0 {
		mtu = 1200
	}

	arqCfg := arq.Config{
		WindowSize:               c.cfg.ARQWindowSize,
		RTO:                      0.2, // Fast retry out of the gate
		MaxRTO:                   1.5,
		IsSocks:                  false,
		IsClient:                 true,
		IsVirtual:                true, // Bypasses internal timeout closures
		EnableControlReliability: true,
		ControlRTO:               0.8,
		ControlMaxRTO:            2.5,
		ControlMaxRetries:        40,
		InactivityTimeout:        999999.0, // Infinite
		DataPacketTTL:            999999.0,
		MaxDataRetries:           99999,
		ControlPacketTTL:         999999.0,
		FinDrainTimeout:          300.0,
		GracefulDrainTimeout:     600.0,
		TerminalDrainTimeout:     60.0,
		TerminalAckWaitTimeout:   30.0,
		CompressionType:          c.uploadCompression,
	}

	conn := &fakeConn{}
	a := arq.NewARQ(streamID, c.sessionID, s, conn, mtu, c.log, arqCfg)
	s.Stream = a
	c.active_streams[streamID] = s
	a.Start()

	c.log.Infof("🚀 <green>Virtual Stream 0 (Control Channel) Initialized.</green>")
}

// CloseAllStreams completely flushes all ARQ bindings. For Stream 0, it calls ForceClose.
func (c *Client) CloseAllStreams() {
	c.streamsMu.Lock()
	streams := make([]*Stream_client, 0, len(c.active_streams))
	for _, s := range c.active_streams {
		streams = append(streams, s)
	}
	c.active_streams = make(map[uint16]*Stream_client)
	c.streamsMu.Unlock()

	for _, s := range streams {
		if a, ok := s.Stream.(*arq.ARQ); ok {
			if s.StreamID == 0 {
				a.ForceClose("Session Reset (Virtual Stream 0 Force Destroy)")
			} else {
				a.Close("Session Reset (All Streams Destroy)", false)
			}
		}
	}

	c.clearOrphanResets()
}
