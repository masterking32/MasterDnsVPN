// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"net"
	"sync"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/streamutil"
)

type streamStateRecord struct {
	SessionID      uint8
	StreamID       uint16
	State          uint8
	TargetHost     string
	TargetPort     uint16
	UpstreamConn   net.Conn
	Connected      bool
	CreatedAt      time.Time
	LastActivityAt time.Time
	LastSequence   uint16
	OutboundSeq    uint16
	InboundDataSeq uint16
	InboundDataSet bool
	RemoteFinSeq   uint16
	RemoteFinSet   bool
}

type streamStateStore struct {
	mu       sync.Mutex
	sessions map[uint8]map[uint16]*streamStateRecord
}

func newStreamStateStore() *streamStateStore {
	return &streamStateStore{
		sessions: make(map[uint8]map[uint16]*streamStateRecord, 32),
	}
}

func (s *streamStateStore) EnsureOpen(sessionID uint8, streamID uint16, now time.Time) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	streams := s.sessions[sessionID]
	if streams == nil {
		streams = make(map[uint16]*streamStateRecord, 8)
		s.sessions[sessionID] = streams
	}

	if record := streams[streamID]; record != nil {
		record.LastActivityAt = now
		return cloneStreamStateRecord(record), false
	}

	record := &streamStateRecord{
		SessionID:      sessionID,
		StreamID:       streamID,
		State:          Enums.STREAM_STATE_OPEN,
		CreatedAt:      now,
		LastActivityAt: now,
	}
	streams[streamID] = record
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) BindTarget(sessionID uint8, streamID uint16, host string, port uint16, now time.Time) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, false
	}
	if record.TargetHost != "" && (record.TargetHost != host || record.TargetPort != port) {
		return nil, false
	}
	record.TargetHost = host
	record.TargetPort = port
	record.LastActivityAt = now
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) AttachUpstream(sessionID uint8, streamID uint16, host string, port uint16, conn net.Conn, now time.Time) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		streamutil.SafeClose(conn)
		return nil, false
	}
	if record.UpstreamConn != nil && record.UpstreamConn != conn {
		streamutil.SafeClose(conn)
		return nil, false
	}
	record.TargetHost = host
	record.TargetPort = port
	record.UpstreamConn = conn
	record.Connected = conn != nil
	record.LastActivityAt = now
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) Touch(sessionID uint8, streamID uint16, sequenceNum uint16, now time.Time) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, false
	}
	record.LastActivityAt = now
	record.LastSequence = sequenceNum
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) MarkRemoteFin(sessionID uint8, streamID uint16, sequenceNum uint16, now time.Time) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, false
	}
	record.LastActivityAt = now
	record.LastSequence = sequenceNum
	record.RemoteFinSeq = sequenceNum
	record.RemoteFinSet = true
	streamutil.CloseWrite(record.UpstreamConn)
	switch record.State {
	case Enums.STREAM_STATE_HALF_CLOSED_LOCAL:
		record.State = Enums.STREAM_STATE_DRAINING
	case Enums.STREAM_STATE_OPEN:
		record.State = Enums.STREAM_STATE_HALF_CLOSED_REMOTE
	}
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) ClassifyInboundData(sessionID uint8, streamID uint16, sequenceNum uint16, now time.Time) (*streamStateRecord, bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, false, false
	}
	record.LastActivityAt = now
	record.LastSequence = sequenceNum
	if record.InboundDataSet && streamutil.SequenceSeenOrOlder(record.InboundDataSeq, sequenceNum) {
		return cloneStreamStateRecord(record), true, false
	}
	record.InboundDataSeq = sequenceNum
	record.InboundDataSet = true
	return cloneStreamStateRecord(record), true, true
}

func (s *streamStateStore) IsDuplicateRemoteFin(sessionID uint8, streamID uint16, sequenceNum uint16, now time.Time) (*streamStateRecord, bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, false, false
	}
	record.LastActivityAt = now
	record.LastSequence = sequenceNum
	if record.RemoteFinSet && record.RemoteFinSeq == sequenceNum {
		return cloneStreamStateRecord(record), true, true
	}
	return cloneStreamStateRecord(record), true, false
}

func (s *streamStateStore) MarkLocalFin(sessionID uint8, streamID uint16, sequenceNum uint16, now time.Time) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, false
	}
	record.LastActivityAt = now
	record.LastSequence = sequenceNum
	switch record.State {
	case Enums.STREAM_STATE_HALF_CLOSED_REMOTE:
		record.State = Enums.STREAM_STATE_DRAINING
	case Enums.STREAM_STATE_OPEN:
		record.State = Enums.STREAM_STATE_HALF_CLOSED_LOCAL
	}
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) NextOutboundSequence(sessionID uint8, streamID uint16, now time.Time) (uint16, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return 0, false
	}
	record.LastActivityAt = now
	nextSeq := record.OutboundSeq + 1
	if nextSeq == 0 {
		nextSeq = 1
	}
	record.OutboundSeq = nextSeq
	return nextSeq, true
}

func (s *streamStateStore) ResetWithNextOutboundSequence(sessionID uint8, streamID uint16, now time.Time) (uint16, bool) {
	s.mu.Lock()
	streams := s.sessions[sessionID]
	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		s.mu.Unlock()
		return 0, false
	}

	nextSeq := record.OutboundSeq + 1
	if nextSeq == 0 {
		nextSeq = 1
	}
	record.OutboundSeq = nextSeq

	conn := record.UpstreamConn
	record.UpstreamConn = nil
	record.Connected = false
	record.LastActivityAt = now
	record.LastSequence = nextSeq
	record.State = Enums.STREAM_STATE_RESET
	delete(streams, streamID)
	if len(streams) == 0 {
		delete(s.sessions, sessionID)
	}
	s.mu.Unlock()

	streamutil.SafeClose(conn)
	return nextSeq, true
}

func (s *streamStateStore) MarkReset(sessionID uint8, streamID uint16, sequenceNum uint16, now time.Time) bool {
	s.mu.Lock()
	streams := s.sessions[sessionID]
	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		s.mu.Unlock()
		return false
	}
	conn := record.UpstreamConn
	record.UpstreamConn = nil
	record.Connected = false
	record.LastActivityAt = now
	record.LastSequence = sequenceNum
	record.State = Enums.STREAM_STATE_RESET
	delete(streams, streamID)
	if len(streams) == 0 {
		delete(s.sessions, sessionID)
	}
	s.mu.Unlock()

	streamutil.SafeClose(conn)
	return true
}

func (s *streamStateStore) Lookup(sessionID uint8, streamID uint16) (*streamStateRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.lookupLocked(sessionID, streamID)
	if record == nil {
		return nil, false
	}
	return cloneStreamStateRecord(record), true
}

func (s *streamStateStore) Exists(sessionID uint8, streamID uint16) bool {
	if s == nil || streamID == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lookupLocked(sessionID, streamID) != nil
}

func (s *streamStateStore) RemoveSession(sessionID uint8) {
	s.mu.Lock()
	streams := s.sessions[sessionID]
	delete(s.sessions, sessionID)
	s.mu.Unlock()
	for _, record := range streams {
		if record != nil {
			streamutil.SafeClose(record.UpstreamConn)
		}
	}
}

func (s *streamStateStore) lookupLocked(sessionID uint8, streamID uint16) *streamStateRecord {
	if streams, ok := s.sessions[sessionID]; ok {
		return streams[streamID]
	}
	return nil
}

func cloneStreamStateRecord(record *streamStateRecord) *streamStateRecord {
	if record == nil {
		return nil
	}
	cloned := *record
	return &cloned
}
