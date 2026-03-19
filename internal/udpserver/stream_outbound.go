// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"sync"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const streamOutboundInitialRetryDelay = 350 * time.Millisecond
const streamOutboundMaxRetryDelay = 2 * time.Second
const streamOutboundMinRetryDelay = 120 * time.Millisecond

var streamOutboundAckTypeByPending = buildStreamOutboundAckTypeByPending()
var streamOutboundAckRequired = buildStreamOutboundAckRequired()

type streamOutboundStore struct {
	mu                   sync.Mutex
	sessions             map[uint8]*streamOutboundSession
	configuredPackedCaps [256]uint16
	window               int
	queueLimit           int
}

type outboundPendingPacket struct {
	Packet     VpnProto.Packet
	CreatedAt  time.Time
	LastSentAt time.Time
	RetryAt    time.Time
	RetryDelay time.Duration
	RetryCount int
}

type streamOutboundSession struct {
	scheduler       *arq.Scheduler
	pending         []outboundPendingPacket
	retryBase       time.Duration
	srtt            time.Duration
	rttVar          time.Duration
	maxPackedBlocks int
}

func newStreamOutboundStore(windowSize int, queueLimit int) *streamOutboundStore {
	if windowSize < 1 {
		windowSize = 1
	}
	if windowSize > 32 {
		windowSize = 32
	}
	if queueLimit < 1 {
		queueLimit = 256
	}
	if queueLimit > 8192 {
		queueLimit = 8192
	}
	return &streamOutboundStore{
		sessions:   make(map[uint8]*streamOutboundSession, 32),
		window:     windowSize,
		queueLimit: queueLimit,
	}
}

func (s *streamOutboundStore) ConfigureSession(sessionID uint8, maxPackedBlocks int) {
	if s == nil || sessionID == 0 {
		return
	}
	limit := uint16(max(1, maxPackedBlocks))
	s.mu.Lock()
	s.configuredPackedCaps[sessionID] = limit
	session := s.sessions[sessionID]
	if session != nil && session.maxPackedBlocks != int(limit) {
		session.maxPackedBlocks = int(limit)
		session.scheduler.SetMaxPackedBlocks(int(limit))
	}
	s.mu.Unlock()
}

func (s *streamOutboundStore) Enqueue(sessionID uint8, target arq.QueueTarget, packet VpnProto.Packet) bool {
	if s == nil || sessionID == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.ensureSessionLocked(sessionID)
	if packet.PacketType == Enums.PACKET_STREAM_DATA && session.scheduler.Pending()+len(session.pending) >= s.queueLimit {
		return false
	}

	queued := arq.QueuedPacket{
		PacketType:      packet.PacketType,
		StreamID:        packet.StreamID,
		SequenceNum:     packet.SequenceNum,
		FragmentID:      packet.FragmentID,
		TotalFragments:  packet.TotalFragments,
		CompressionType: packet.CompressionType,
		Payload:         packet.Payload,
		Priority:        arq.DefaultPriorityForPacket(packet.PacketType),
	}
	return session.scheduler.Enqueue(target, queued)
}

func (s *streamOutboundStore) Next(sessionID uint8, now time.Time) (VpnProto.Packet, bool) {
	if s == nil || sessionID == 0 {
		return VpnProto.Packet{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.sessions[sessionID]
	if session == nil {
		return VpnProto.Packet{}, false
	}
	if len(session.pending) < s.window && session.scheduler.Pending() != 0 {
		dequeued, ok := session.scheduler.Dequeue()
		if !ok {
			return VpnProto.Packet{}, false
		}
		packet := vpnPacketFromQueued(dequeued.Packet)
		if !streamOutboundAckRequired[packet.PacketType] {
			return packet, true
		}
		retryBase := sessionRetryBase(session)
		session.pending = append(session.pending, outboundPendingPacket{
			Packet:     packet,
			CreatedAt:  now,
			LastSentAt: now,
			RetryAt:    now.Add(retryBase),
			RetryDelay: retryBase,
		})
		return packet, true
	}

	selectedIdx := -1
	for idx := range session.pending {
		if !session.pending[idx].RetryAt.After(now) {
			selectedIdx = idx
			break
		}
	}
	if selectedIdx < 0 {
		return VpnProto.Packet{}, false
	}

	pending := &session.pending[selectedIdx]
	packet := pending.Packet
	delay := pending.RetryDelay
	if delay <= 0 {
		delay = sessionRetryBase(session)
	}
	pending.LastSentAt = now
	pending.RetryAt = now.Add(delay)
	pending.RetryCount++
	delay *= 2
	if delay > streamOutboundMaxRetryDelay {
		delay = streamOutboundMaxRetryDelay
	}
	pending.RetryDelay = delay
	return packet, true
}

func (s *streamOutboundStore) ExpireStalled(sessionID uint8, now time.Time, maxRetries int, ttl time.Duration) []uint16 {
	if s == nil || sessionID == 0 {
		return nil
	}
	if maxRetries < 1 {
		maxRetries = 24
	}
	if ttl <= 0 {
		ttl = 120 * time.Second
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.sessions[sessionID]
	if session == nil || len(session.pending) == 0 {
		return nil
	}

	ttlDeadline := now.Add(-ttl)
	expired := make([]uint16, 0, 2)
	var expiredSet map[uint16]struct{}
	for _, pending := range session.pending {
		if pending.RetryCount < maxRetries && pending.CreatedAt.After(ttlDeadline) {
			continue
		}
		expired, expiredSet = appendUniqueExpiredStream(expired, expiredSet, pending.Packet.StreamID)
	}
	if len(expired) == 0 {
		return nil
	}

	if len(expired) == 1 {
		streamID := expired[0]
		prunePendingStreamPackets(session, streamID)
		session.scheduler.HandleStreamReset(streamID)
	} else {
		prunePendingStreamPacketSet(session, expired)
		for _, streamID := range expired {
			session.scheduler.HandleStreamReset(streamID)
		}
	}
	if session.scheduler.Pending() == 0 && len(session.pending) == 0 {
		delete(s.sessions, sessionID)
	}
	return expired
}

func (s *streamOutboundStore) Ack(sessionID uint8, packetType uint8, streamID uint16, sequenceNum uint16) bool {
	if s == nil || sessionID == 0 {
		return false
	}
	ackedAt := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.sessions[sessionID]
	if session == nil || len(session.pending) == 0 {
		return false
	}
	for idx := range session.pending {
		pending := session.pending[idx]
		if streamOutboundAckTypeByPending[pending.Packet.PacketType] != packetType {
			continue
		}
		if pending.Packet.StreamID != streamID || pending.Packet.SequenceNum != sequenceNum {
			continue
		}
		updateStreamOutboundRTO(session, pending, ackedAt)
		copy(session.pending[idx:], session.pending[idx+1:])
		lastIdx := len(session.pending) - 1
		session.pending[lastIdx] = outboundPendingPacket{}
		session.pending = session.pending[:lastIdx]
		if session.scheduler.Pending() == 0 && len(session.pending) == 0 {
			delete(s.sessions, sessionID)
		}
		return true
	}
	return false
}

func (s *streamOutboundStore) ClearStream(sessionID uint8, streamID uint16) {
	if s == nil || sessionID == 0 || streamID == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.sessions[sessionID]
	if session == nil {
		return
	}
	prunePendingStreamPackets(session, streamID)
	session.scheduler.HandleStreamReset(streamID)
	if session.scheduler.Pending() == 0 && len(session.pending) == 0 {
		delete(s.sessions, sessionID)
	}
}

func (s *streamOutboundStore) RemoveSession(sessionID uint8) {
	if s == nil || sessionID == 0 {
		return
	}
	s.mu.Lock()
	delete(s.sessions, sessionID)
	s.configuredPackedCaps[sessionID] = 0
	s.mu.Unlock()
}

func (s *streamOutboundStore) ensureSessionLocked(sessionID uint8) *streamOutboundSession {
	session := s.sessions[sessionID]
	if session != nil {
		return session
	}
	maxPackedBlocks := int(s.configuredPackedCaps[sessionID])
	if maxPackedBlocks < 1 {
		maxPackedBlocks = 1
	}
	session = &streamOutboundSession{
		scheduler:       arq.NewScheduler(maxPackedBlocks),
		pending:         make([]outboundPendingPacket, 0, s.window),
		retryBase:       streamOutboundInitialRetryDelay,
		maxPackedBlocks: maxPackedBlocks,
	}
	s.sessions[sessionID] = session
	return session
}

func vpnPacketFromQueued(packet arq.QueuedPacket) VpnProto.Packet {
	return VpnProto.Packet{
		PacketType:         packet.PacketType,
		StreamID:           packet.StreamID,
		SequenceNum:        packet.SequenceNum,
		FragmentID:         packet.FragmentID,
		TotalFragments:     packet.TotalFragments,
		CompressionType:    packet.CompressionType,
		HasStreamID:        packet.StreamID != 0,
		HasSequenceNum:     packet.SequenceNum != 0,
		HasFragmentInfo:    packet.TotalFragments != 0 || packet.FragmentID != 0,
		HasCompressionType: packet.CompressionType != 0,
		Payload:            packet.Payload,
	}
}

func prunePendingStreamPackets(session *streamOutboundSession, streamID uint16) {
	if session == nil || len(session.pending) == 0 {
		return
	}
	writeIdx := 0
	for _, pending := range session.pending {
		if pending.Packet.StreamID == streamID {
			continue
		}
		session.pending[writeIdx] = pending
		writeIdx++
	}
	for idx := writeIdx; idx < len(session.pending); idx++ {
		session.pending[idx] = outboundPendingPacket{}
	}
	session.pending = session.pending[:writeIdx]
}

func prunePendingStreamPacketSet(session *streamOutboundSession, streamIDs []uint16) {
	if session == nil || len(session.pending) == 0 || len(streamIDs) == 0 {
		return
	}
	if len(streamIDs) == 1 {
		prunePendingStreamPackets(session, streamIDs[0])
		return
	}

	streamSet := make(map[uint16]struct{}, len(streamIDs))
	for _, streamID := range streamIDs {
		streamSet[streamID] = struct{}{}
	}

	writeIdx := 0
	for _, pending := range session.pending {
		if _, drop := streamSet[pending.Packet.StreamID]; drop {
			continue
		}
		session.pending[writeIdx] = pending
		writeIdx++
	}
	for idx := writeIdx; idx < len(session.pending); idx++ {
		session.pending[idx] = outboundPendingPacket{}
	}
	session.pending = session.pending[:writeIdx]
}

func appendUniqueExpiredStream(dst []uint16, set map[uint16]struct{}, streamID uint16) ([]uint16, map[uint16]struct{}) {
	if streamID == 0 {
		return dst, set
	}
	switch len(dst) {
	case 0:
		return append(dst, streamID), set
	case 1:
		if dst[0] == streamID {
			return dst, set
		}
		return append(dst, streamID), set
	case 2:
		if dst[0] == streamID || dst[1] == streamID {
			return dst, set
		}
		return append(dst, streamID), set
	default:
		if set == nil {
			set = make(map[uint16]struct{}, len(dst)+1)
			for _, existing := range dst {
				set[existing] = struct{}{}
			}
		}
		if _, exists := set[streamID]; exists {
			return dst, set
		}
		set[streamID] = struct{}{}
		return append(dst, streamID), set
	}
}

func sessionRetryBase(session *streamOutboundSession) time.Duration {
	if session == nil {
		return streamOutboundInitialRetryDelay
	}
	retryBase := session.retryBase
	if retryBase < streamOutboundMinRetryDelay {
		return streamOutboundInitialRetryDelay
	}
	if retryBase > streamOutboundMaxRetryDelay {
		return streamOutboundMaxRetryDelay
	}
	return retryBase
}

func buildStreamOutboundAckTypeByPending() [256]uint8 {
	var values [256]uint8
	values[Enums.PACKET_STREAM_DATA] = Enums.PACKET_STREAM_DATA_ACK
	values[Enums.PACKET_STREAM_FIN] = Enums.PACKET_STREAM_FIN_ACK
	values[Enums.PACKET_STREAM_RST] = Enums.PACKET_STREAM_RST_ACK
	return values
}

func buildStreamOutboundAckRequired() [256]bool {
	var values [256]bool
	values[Enums.PACKET_STREAM_DATA] = true
	values[Enums.PACKET_STREAM_FIN] = true
	values[Enums.PACKET_STREAM_RST] = true
	return values
}

func updateStreamOutboundRTO(session *streamOutboundSession, pending outboundPendingPacket, ackedAt time.Time) {
	if session == nil || pending.RetryCount != 0 || pending.LastSentAt.IsZero() {
		return
	}
	sample := ackedAt.Sub(pending.LastSentAt)
	if sample <= 0 {
		return
	}
	if sample < streamOutboundMinRetryDelay {
		sample = streamOutboundMinRetryDelay
	}
	if sample > streamOutboundMaxRetryDelay {
		sample = streamOutboundMaxRetryDelay
	}
	if session.srtt <= 0 {
		session.srtt = sample
		session.rttVar = sample / 2
	} else {
		diff := session.srtt - sample
		if diff < 0 {
			diff = -diff
		}
		session.rttVar = (3*session.rttVar + diff) / 4
		session.srtt = (7*session.srtt + sample) / 8
	}
	rto := session.srtt + 4*session.rttVar
	if rto < streamOutboundMinRetryDelay {
		rto = streamOutboundMinRetryDelay
	}
	if rto > streamOutboundMaxRetryDelay {
		rto = streamOutboundMaxRetryDelay
	}
	session.retryBase = rto
}
