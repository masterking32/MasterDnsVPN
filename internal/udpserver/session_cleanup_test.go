// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"io"
	"testing"
	"time"

	"masterdnsvpn-go/internal/arq"
	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
	fragmentStore "masterdnsvpn-go/internal/fragmentstore"
	"masterdnsvpn-go/internal/mlq"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

type testReadWriteCloser struct {
	closed bool
}

func (t *testReadWriteCloser) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (t *testReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (t *testReadWriteCloser) Close() error {
	t.closed = true
	return nil
}

func newTestSessionRecord(sessionID uint8) *sessionRecord {
	r := &sessionRecord{
		ID:               sessionID,
		DownloadMTU:      512,
		DownloadMTUBytes: 512,
		Streams:          make(map[uint16]*Stream_server),
		ActiveStreams:    make([]uint16, 0, 4),
		RecentlyClosed:   make(map[uint16]time.Time, 4),
		OrphanQueue:      mlq.New[VpnProto.Packet](8),
	}
	r.ensureStream0(nil)
	return r
}

func newTestServerForCleanup() *Server {
	return &Server{
		deferredSession: nil,
		dnsFragments:    fragmentStore.New[dnsFragmentKey](8),
		socks5Fragments: fragmentStore.New[socks5FragmentKey](8),
	}
}

func TestCleanupClosedSessionClosesStreamsAndClearsQueues(t *testing.T) {
	s := newTestServerForCleanup()
	record := newTestSessionRecord(7)

	upstream := &testReadWriteCloser{}
	stream := record.getOrCreateStream(1, arq.Config{}, nil, nil)
	stream.UpstreamConn = upstream
	if !stream.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_STREAM_RST), Enums.PACKET_STREAM_RST, 12, 0, 0, 0, 0, nil) {
		t.Fatalf("expected TX packet to be queued")
	}
	record.enqueueOrphanReset(Enums.PACKET_STREAM_RST, 1, 12)

	s.cleanupClosedSession(record.ID, record)

	if !upstream.closed {
		t.Fatalf("expected upstream connection to be closed")
	}
	if stream.TXQueue.Size() != 0 {
		t.Fatalf("expected stream TX queue to be cleared, got %d", stream.TXQueue.Size())
	}
	if stream.Status != "CLOSED" {
		t.Fatalf("expected stream status CLOSED, got %q", stream.Status)
	}

	record.StreamsMu.RLock()
	streamCount := len(record.Streams)
	activeCount := len(record.ActiveStreams)
	record.StreamsMu.RUnlock()

	if streamCount != 0 {
		t.Fatalf("expected all session streams to be removed, got %d", streamCount)
	}
	if activeCount != 0 {
		t.Fatalf("expected all active stream ids to be cleared, got %d", activeCount)
	}
	if record.OrphanQueue.Size() != 0 {
		t.Fatalf("expected orphan queue to be cleared, got %d", record.OrphanQueue.Size())
	}
}

func TestSessionStoreCleanupReturnsExpiredRecordForFollowupCleanup(t *testing.T) {
	store := newSessionStore(8, 32)
	record := newTestSessionRecord(9)
	record.Signature[0] = 1
	record.Cookie = 99
	record.ResponseMode = 1
	record.setLastActivity(time.Now().Add(-2 * time.Minute))

	store.byID[record.ID] = record
	store.bySig[record.Signature] = record.ID
	store.activeCount = 1

	now := time.Now()
	expired := store.Cleanup(now, time.Minute, 10*time.Minute)
	if len(expired) != 1 {
		t.Fatalf("expected one expired session, got %d", len(expired))
	}
	if expired[0].ID != record.ID {
		t.Fatalf("expected expired session id %d, got %d", record.ID, expired[0].ID)
	}
	if expired[0].record != record {
		t.Fatalf("expected cleanup payload to include original session record")
	}
	if store.byID[record.ID] != nil {
		t.Fatalf("expected expired session to be removed from active store")
	}
	if _, ok := store.recentClosed[record.ID]; !ok {
		t.Fatalf("expected expired session to be tracked in recentClosed")
	}
}

func TestCleanupTerminalStreamsAbortsAndRemovesExpiredStreams(t *testing.T) {
	record := newTestSessionRecord(11)

	upstream := &testReadWriteCloser{}
	stream := record.getOrCreateStream(2, arq.Config{}, nil, nil)
	stream.UpstreamConn = upstream
	if !stream.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_STREAM_FIN), Enums.PACKET_STREAM_FIN, 21, 0, 0, 0, 0, nil) {
		t.Fatalf("expected TX packet to be queued")
	}

	stream.Abort("test cleanup")
	record.cleanupTerminalStreams(time.Now().Add(46*time.Second), 45*time.Second)

	if !upstream.closed {
		t.Fatalf("expected upstream connection to be closed during terminal cleanup")
	}
	if _, ok := record.getStream(2); ok {
		t.Fatalf("expected stream to be removed from session")
	}
	if !record.isRecentlyClosed(2, time.Now()) {
		t.Fatalf("expected stream to be tracked as recently closed")
	}
}

func TestDequeueSessionResponseDuplicatesLastPackedControlBlock(t *testing.T) {
	s := &Server{
		cfg: config.ServerConfig{
			PacketBlockControlDuplication: 3,
		},
		sessions: newSessionStore(8, 32),
	}

	record := newTestSessionRecord(12)
	record.MaxPackedBlocks = 2
	stream := record.getOrCreateStream(1, arq.Config{}, nil, nil)
	if !stream.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_STREAM_SYN_ACK), Enums.PACKET_STREAM_SYN_ACK, 11, 0, 0, 0, 0, nil) {
		t.Fatalf("expected first control packet to queue")
	}
	if !stream.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_STREAM_FIN_ACK), Enums.PACKET_STREAM_FIN_ACK, 12, 0, 0, 0, 0, nil) {
		t.Fatalf("expected second control packet to queue")
	}

	s.sessions.byID[record.ID] = record

	first, ok := s.dequeueSessionResponse(record.ID, time.Now())
	if !ok || first == nil {
		t.Fatalf("expected first dequeue to return a packet")
	}
	if first.PacketType != Enums.PACKET_PACKED_CONTROL_BLOCKS {
		t.Fatalf("expected packed control blocks packet, got %d", first.PacketType)
	}
	if len(first.Payload) != 2*VpnProto.PackedControlBlockSize {
		t.Fatalf("unexpected packed payload size: got=%d want=%d", len(first.Payload), 2*VpnProto.PackedControlBlockSize)
	}

	second, ok := s.dequeueSessionResponse(record.ID, time.Now())
	if !ok || second == nil {
		t.Fatalf("expected duplicated dequeue to return cached packet")
	}
	if second.PacketType != Enums.PACKET_PACKED_CONTROL_BLOCKS || string(second.Payload) != string(first.Payload) {
		t.Fatalf("expected second dequeue to return duplicated packed block")
	}

	third, ok := s.dequeueSessionResponse(record.ID, time.Now())
	if !ok || third == nil {
		t.Fatalf("expected final duplicated dequeue to return cached packet")
	}
	if third.PacketType != Enums.PACKET_PACKED_CONTROL_BLOCKS || string(third.Payload) != string(first.Payload) {
		t.Fatalf("expected third dequeue to return duplicated packed block")
	}

	if record.LastPackedControlBlock != nil || record.LastPackedControlBlockRemaining != 0 {
		t.Fatalf("expected packed block duplication cache to be drained")
	}

	if _, ok := s.dequeueSessionResponse(record.ID, time.Now()); ok {
		t.Fatalf("expected no more queued packets after cached duplicates are exhausted")
	}
}
