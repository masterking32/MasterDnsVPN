// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var ErrSessionTableFull = errors.New("session table full")

const (
	maxServerSessionID          = 255
	maxServerSessionSlots       = 255
	sessionInitTTL              = 10 * time.Minute
	sessionInitDataSize         = 10
	minSessionMTU               = 30
	maxSessionMTU               = 4096
	serverClosedStreamRecordTTL = 45 * time.Second
	serverClosedStreamRecordCap = 1000
)

type QueueTarget uint8

const (
	QueueTargetMain QueueTarget = iota
	QueueTargetStream
)

type sessionRecord struct {
	mu sync.RWMutex

	ID                   uint8
	Cookie               uint8
	ResponseMode         uint8
	UploadCompression    uint8
	DownloadCompression  uint8
	UploadMTU            uint16
	DownloadMTU          uint16
	DownloadMTUBytes     int
	VerifyCode           [4]byte
	Signature            [sessionInitDataSize]byte
	MaxPackedBlocks      int
	StreamReadBufferSize int
	CreatedAt            time.Time
	ReuseUntil           time.Time
	reuseUntilUnixNano   int64
	lastActivityUnixNano int64

	// New fields for ARQ refactor
	Streams        map[uint16]*Stream_server
	ActiveStreams  []uint16 // Sorted list of active stream IDs for Round-Robin
	RRStreamID     uint16   // Last served stream ID for RR
	EnqueueSeq     uint64   // Global sequence for FIFO inside same priority
	StreamsMu      sync.RWMutex
	RecentlyClosed map[uint16]time.Time
	OrphanPackets  []VpnProto.Packet
	OrphanIndex    map[uint32]int
}

// serverStreamTXPacket represents a queued packet pending transmission or retransmission.
type serverStreamTXPacket struct {
	PacketType      uint8
	SequenceNum     uint16
	FragmentID      uint8
	TotalFragments  uint8
	CompressionType uint8
	Payload         []byte
	CreatedAt       time.Time
}

var txPacketPool = sync.Pool{
	New: func() any {
		return &serverStreamTXPacket{}
	},
}

func getTXPacketFromPool() *serverStreamTXPacket {
	return txPacketPool.Get().(*serverStreamTXPacket)
}

func putTXPacketToPool(p *serverStreamTXPacket) {
	if p == nil {
		return
	}
	p.Payload = nil
	txPacketPool.Put(p)
}

func getTrackingKey(packetType uint8, sequenceNum uint16, fragmentID uint8) uint32 {
	t := packetType
	if t == Enums.PACKET_STREAM_RESEND {
		t = Enums.PACKET_STREAM_DATA
	}
	return uint32(t)<<24 | uint32(sequenceNum)<<8 | uint32(fragmentID)
}

// getEffectivePriority maps packet types to priorities (0 is highest, 5 is lowest).
func getEffectivePriority(packetType uint8, basePriority int) int {
	return Enums.NormalizePacketPriority(packetType, basePriority)
}

type sessionRuntimeView struct {
	ID                  uint8
	Cookie              uint8
	ResponseMode        uint8
	ResponseBase64      bool
	DownloadCompression uint8
	DownloadMTU         uint16
	DownloadMTUBytes    int
	MaxPackedBlocks     int
}

type closedSessionRecord struct {
	Cookie       uint8
	ResponseMode uint8
	ExpiresAt    time.Time
}

type sessionLookupState uint8

const (
	sessionLookupUnknown sessionLookupState = iota
	sessionLookupActive
	sessionLookupClosed
)

type sessionLookupResult struct {
	Cookie       uint8
	ResponseMode uint8
	State        sessionLookupState
}

type sessionValidationResult struct {
	Lookup sessionLookupResult
	Known  bool
	Valid  bool
	Active *sessionRuntimeView
}

type sessionStore struct {
	mu                     sync.Mutex
	nextID                 uint16
	activeCount            uint16
	nextReuseSweepUnixNano int64
	cookieBytes            [32]byte
	cookieIndex            int
	byID                   [maxServerSessionID + 1]*sessionRecord
	bySig                  map[[sessionInitDataSize]byte]uint8
	recentClosed           map[uint8]closedSessionRecord
}

func newSessionStore() *sessionStore {
	return &sessionStore{
		bySig:        make(map[[sessionInitDataSize]byte]uint8, 64),
		recentClosed: make(map[uint8]closedSessionRecord, 32),
		cookieIndex:  32,
		nextID:       1,
	}
}

func (s *sessionStore) findOrCreate(payload []byte, uploadCompressionType uint8, downloadCompressionType uint8, maxPacketsPerBatch int) (*sessionRecord, bool, error) {
	if len(payload) != sessionInitDataSize || !isValidSessionResponseMode(payload[0]) {
		return nil, false, nil
	}

	var signature [sessionInitDataSize]byte
	copy(signature[:], payload[:sessionInitDataSize])

	now := time.Now()
	nowUnixNano := now.UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireReuseLocked(nowUnixNano)

	if sessionID, ok := s.bySig[signature]; ok {
		if existing := s.byID[sessionID]; existing != nil {
			if nowUnixNano <= existing.reuseUntilUnixNano {
				existing.setLastActivityUnixNano(nowUnixNano)
				return existing, true, nil
			}
		}
		delete(s.bySig, signature)
	}

	slot := s.allocateSlotLocked()
	if slot < 0 {
		return nil, false, ErrSessionTableFull
	}

	record := &sessionRecord{
		ID:             uint8(slot),
		ResponseMode:   payload[0],
		CreatedAt:      now,
		ReuseUntil:     now.Add(sessionInitTTL),
		Signature:      signature,
		Streams:        make(map[uint16]*Stream_server),
		ActiveStreams:  make([]uint16, 0, 8),
		RecentlyClosed: make(map[uint16]time.Time, 8),
		OrphanIndex:    make(map[uint32]int, 8),
	}
	// Initialize virtual Stream 0 for control packets
	record.ensureStream0(nil) // Caller should update logger if needed
	record.reuseUntilUnixNano = record.ReuseUntil.UnixNano()
	record.setLastActivityUnixNano(nowUnixNano)
	record.UploadCompression = uploadCompressionType
	record.DownloadCompression = downloadCompressionType
	record.applyMTUFromSessionInit(
		binary.BigEndian.Uint16(payload[2:4]),
		binary.BigEndian.Uint16(payload[4:6]),
		maxPacketsPerBatch,
	)
	copy(record.VerifyCode[:], payload[6:10])
	record.Cookie = s.randomCookieLocked()

	s.byID[slot] = record
	s.activeCount++
	s.bySig[signature] = uint8(slot)
	s.updateNextReuseSweepLocked(record.reuseUntilUnixNano)
	delete(s.recentClosed, uint8(slot))
	s.nextID = uint16(nextSessionID(uint8(slot)))
	return record, false, nil
}

func (s *sessionStore) expireReuseLocked(nowUnixNano int64) {
	if len(s.bySig) == 0 {
		s.nextReuseSweepUnixNano = 0
		return
	}
	if s.nextReuseSweepUnixNano != 0 && nowUnixNano < s.nextReuseSweepUnixNano {
		return
	}

	nextReuseSweepUnixNano := int64(0)
	for signature, sessionID := range s.bySig {
		record := s.byID[sessionID]
		if record == nil || nowUnixNano > record.reuseUntilUnixNano {
			delete(s.bySig, signature)
			continue
		}
		if nextReuseSweepUnixNano == 0 || record.reuseUntilUnixNano < nextReuseSweepUnixNano {
			nextReuseSweepUnixNano = record.reuseUntilUnixNano
		}
	}
	s.nextReuseSweepUnixNano = nextReuseSweepUnixNano
}

func (s *sessionStore) Get(sessionID uint8) (*sessionRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record := s.byID[sessionID]
	if record == nil {
		return nil, false
	}
	return record, true
}

func (s *sessionStore) HasActive(sessionID uint8) bool {
	if s == nil || sessionID == 0 {
		return false
	}

	s.mu.Lock()
	active := s.byID[sessionID] != nil
	s.mu.Unlock()
	return active
}

func (s *sessionStore) Lookup(sessionID uint8) (sessionLookupResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if record := s.byID[sessionID]; record != nil {
		return sessionLookupResult{
			Cookie:       record.Cookie,
			ResponseMode: record.ResponseMode,
			State:        sessionLookupActive,
		}, true
	}
	if record, ok := s.recentClosed[sessionID]; ok {
		return sessionLookupResult{
			Cookie:       record.Cookie,
			ResponseMode: record.ResponseMode,
			State:        sessionLookupClosed,
		}, true
	}
	return sessionLookupResult{}, false
}

func (s *sessionStore) ValidateAndTouch(sessionID uint8, cookie uint8, now time.Time) sessionValidationResult {
	s.mu.Lock()
	if record := s.byID[sessionID]; record != nil {
		result := sessionValidationResult{
			Lookup: sessionLookupResult{
				Cookie:       record.Cookie,
				ResponseMode: record.ResponseMode,
				State:        sessionLookupActive,
			},
			Known: true,
			Valid: record.Cookie == cookie,
		}
		if result.Valid {
			view := record.runtimeView()
			result.Active = &view
		}
		s.mu.Unlock()
		if result.Valid {
			record.setLastActivity(now)
		}
		return result
	}

	if record, ok := s.recentClosed[sessionID]; ok {
		s.mu.Unlock()
		return sessionValidationResult{
			Lookup: sessionLookupResult{
				Cookie:       record.Cookie,
				ResponseMode: record.ResponseMode,
				State:        sessionLookupClosed,
			},
			Known: true,
			Valid: false,
		}
	}

	s.mu.Unlock()
	return sessionValidationResult{}
}

func (s *sessionStore) Close(sessionID uint8, now time.Time, retention time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.byID[sessionID]
	if record == nil {
		return false
	}

	delete(s.bySig, record.Signature)
	s.byID[sessionID] = nil
	if s.activeCount > 0 {
		s.activeCount--
	}
	if retention > 0 {
		s.recentClosed[sessionID] = closedSessionRecord{
			Cookie:       record.Cookie,
			ResponseMode: record.ResponseMode,
			ExpiresAt:    now.Add(retention),
		}
	} else {
		delete(s.recentClosed, sessionID)
	}
	return true
}

func (s *sessionStore) Cleanup(now time.Time, idleTimeout time.Duration, closedRetention time.Duration) []uint8 {
	s.mu.Lock()
	defer s.mu.Unlock()

	nowUnixNano := now.UnixNano()
	s.expireReuseLocked(nowUnixNano)

	for sessionID, record := range s.recentClosed {
		if !now.Before(record.ExpiresAt) {
			delete(s.recentClosed, sessionID)
		}
	}

	if idleTimeout <= 0 {
		return nil
	}

	expired := make([]uint8, 0, 8)
	idleTimeoutNanos := idleTimeout.Nanoseconds()
	for sessionID := 1; sessionID <= maxServerSessionID; sessionID++ {
		record := s.byID[sessionID]
		if record == nil {
			continue
		}
		lastActivityUnixNano := record.lastActivity()
		if lastActivityUnixNano != 0 && nowUnixNano-lastActivityUnixNano < idleTimeoutNanos {
			continue
		}

		delete(s.bySig, record.Signature)
		s.byID[sessionID] = nil
		if s.activeCount > 0 {
			s.activeCount--
		}
		if closedRetention > 0 {
			s.recentClosed[uint8(sessionID)] = closedSessionRecord{
				Cookie:       record.Cookie,
				ResponseMode: record.ResponseMode,
				ExpiresAt:    now.Add(closedRetention),
			}
		}
		expired = append(expired, uint8(sessionID))
	}

	return expired
}

func (s *sessionStore) SweepTerminalStreams(now time.Time, retention time.Duration) {
	s.mu.Lock()
	records := make([]*sessionRecord, 0, len(s.byID))
	for _, record := range s.byID {
		if record != nil {
			records = append(records, record)
		}
	}
	s.mu.Unlock()

	for _, record := range records {
		record.cleanupTerminalStreams(now, retention)
	}
}

func (s *sessionStore) allocateSlotLocked() int {
	if s.activeCount >= maxServerSessionSlots {
		return -1
	}

	start := int(s.nextID)
	if start < 1 || start > maxServerSessionID {
		start = 1
	}
	for slot := start; slot <= maxServerSessionID; slot++ {
		if s.byID[slot] == nil {
			return slot
		}
	}
	for slot := 1; slot < start; slot++ {
		if s.byID[slot] == nil {
			return slot
		}
	}
	return -1
}

func (s *sessionStore) randomCookieLocked() uint8 {
	if s.cookieIndex >= len(s.cookieBytes) {
		if _, err := rand.Read(s.cookieBytes[:]); err != nil {
			s.cookieIndex = len(s.cookieBytes)
			return 0
		}
		s.cookieIndex = 0
	}
	value := s.cookieBytes[s.cookieIndex]
	s.cookieIndex++
	return value
}

func (s *sessionStore) updateNextReuseSweepLocked(reuseUntilUnixNano int64) {
	if s.nextReuseSweepUnixNano == 0 || reuseUntilUnixNano < s.nextReuseSweepUnixNano {
		s.nextReuseSweepUnixNano = reuseUntilUnixNano
	}
}

func clampMTU(value uint16) uint16 {
	if value < minSessionMTU {
		return minSessionMTU
	}
	if value > maxSessionMTU {
		return maxSessionMTU
	}
	return value
}

func isValidSessionResponseMode(value uint8) bool {
	return value <= mtuProbeModeBase64
}

func (r *sessionRecord) setLastActivity(now time.Time) {
	r.setLastActivityUnixNano(now.UnixNano())
}

func (r *sessionRecord) setLastActivityUnixNano(nowUnixNano int64) {
	atomic.StoreInt64(&r.lastActivityUnixNano, nowUnixNano)
}

func (r *sessionRecord) lastActivity() int64 {
	return atomic.LoadInt64(&r.lastActivityUnixNano)
}

func nextSessionID(current uint8) uint8 {
	if current >= maxServerSessionID {
		return 1
	}
	return current + 1
}

func (r *sessionRecord) applyMTUFromSessionInit(uploadMTU uint16, downloadMTU uint16, maxPacketsPerBatch int) {
	if r == nil {
		return
	}
	r.UploadMTU = clampMTU(uploadMTU)
	r.DownloadMTU = clampMTU(downloadMTU)
	r.DownloadMTUBytes = int(r.DownloadMTU)
	r.MaxPackedBlocks = VpnProto.CalculateMaxPackedBlocks(r.DownloadMTUBytes, 80, maxPacketsPerBatch)
}

func (r *sessionRecord) runtimeView() sessionRuntimeView {
	return sessionRuntimeView{
		ID:                  r.ID,
		Cookie:              r.Cookie,
		ResponseMode:        r.ResponseMode,
		ResponseBase64:      r.ResponseMode == mtuProbeModeBase64,
		DownloadCompression: r.DownloadCompression,
		DownloadMTU:         r.DownloadMTU,
		DownloadMTUBytes:    r.DownloadMTUBytes,
		MaxPackedBlocks:     r.MaxPackedBlocks,
	}
}

// ensureStream0 creates correctly virtual stream 0 if not exist
func (r *sessionRecord) ensureStream0(logger arq.Logger) {
	r.getOrCreateStream(0, arq.Config{IsVirtual: true}, nil, logger)
}

func (r *sessionRecord) getOrCreateStream(streamID uint16, arqConfig arq.Config, localConn io.ReadWriteCloser, logger arq.Logger) *Stream_server {
	r.StreamsMu.Lock()
	defer r.StreamsMu.Unlock()

	if s, ok := r.Streams[streamID]; ok {
		return s
	}

	s := NewStreamServer(streamID, r.ID, arqConfig, localConn, r.DownloadMTUBytes, logger)
	r.Streams[streamID] = s

	// Active streams tracking: keep sorted for Round-Robin predictability
	found := false
	for _, id := range r.ActiveStreams {
		if id == streamID {
			found = true
			break
		}
	}
	if !found {
		// Insert sorted
		insertAt := 0
		for i, id := range r.ActiveStreams {
			if id > streamID {
				insertAt = i
				break
			}
			insertAt = i + 1
		}
		if insertAt == len(r.ActiveStreams) {
			r.ActiveStreams = append(r.ActiveStreams, streamID)
		} else {
			r.ActiveStreams = append(r.ActiveStreams[:insertAt+1], r.ActiveStreams[insertAt:]...)
			r.ActiveStreams[insertAt] = streamID
		}
	}

	return s
}

func (r *sessionRecord) getStream(streamID uint16) (*Stream_server, bool) {
	r.StreamsMu.RLock()
	s, ok := r.Streams[streamID]
	r.StreamsMu.RUnlock()
	return s, ok
}
func (r *sessionRecord) noteStreamClosed(streamID uint16, now time.Time) {
	if streamID == 0 {
		return
	}
	r.StreamsMu.Lock()
	defer r.StreamsMu.Unlock()

	// Cleanup old records
	expiredBefore := now.Add(-serverClosedStreamRecordTTL)
	for id, closedAt := range r.RecentlyClosed {
		if closedAt.Before(expiredBefore) {
			delete(r.RecentlyClosed, id)
		}
	}

	r.RecentlyClosed[streamID] = now

	// Cap the map size
	if len(r.RecentlyClosed) > serverClosedStreamRecordCap {
		var oldestID uint16
		var oldestAt time.Time
		first := true
		for id, closedAt := range r.RecentlyClosed {
			if first || closedAt.Before(oldestAt) {
				oldestID = id
				oldestAt = closedAt
				first = false
			}
		}
		delete(r.RecentlyClosed, oldestID)
	}
}

func (r *sessionRecord) isRecentlyClosed(streamID uint16, now time.Time) bool {
	r.StreamsMu.RLock()
	defer r.StreamsMu.RUnlock()

	closedAt, ok := r.RecentlyClosed[streamID]
	if !ok {
		return false
	}

	return now.Sub(closedAt) <= serverClosedStreamRecordTTL
}

func (r *sessionRecord) removeStream(streamID uint16, now time.Time) {
	if streamID == 0 {
		return
	}
	r.StreamsMu.Lock()
	delete(r.Streams, streamID)

	// Remove from ActiveStreams
	for i, id := range r.ActiveStreams {
		if id == streamID {
			r.ActiveStreams = append(r.ActiveStreams[:i], r.ActiveStreams[i+1:]...)
			break
		}
	}
	r.StreamsMu.Unlock()

	r.noteStreamClosed(streamID, now)
}

func (r *sessionRecord) cleanupTerminalStreams(now time.Time, retention time.Duration) {
	if r == nil {
		return
	}

	r.StreamsMu.RLock()
	snapshot := make(map[uint16]*Stream_server, len(r.Streams))
	for id, stream := range r.Streams {
		snapshot[id] = stream
	}
	r.StreamsMu.RUnlock()

	var removeIDs []uint16
	for streamID, stream := range snapshot {
		if streamID == 0 || stream == nil || stream.ARQ == nil {
			continue
		}

		state := stream.ARQ.State()
		stream.mu.Lock()
		switch state {
		case arq.StateDraining:
			stream.Status = "DRAINING"
		case arq.StateHalfClosedLocal, arq.StateHalfClosedRemote, arq.StateClosing:
			stream.Status = "CLOSING"
		case arq.StateTimeWait:
			stream.Status = "TIME_WAIT"
		}

		if stream.ARQ.IsClosed() {
			if stream.CloseTime.IsZero() {
				stream.CloseTime = now
			}
			stream.Status = "TIME_WAIT"
			if now.Sub(stream.CloseTime) >= retention {
				removeIDs = append(removeIDs, streamID)
			}
		}
		stream.mu.Unlock()
	}

	for _, streamID := range removeIDs {
		r.removeStream(streamID, now)
	}
}

func orphanResetKey(packetType uint8, streamID uint16) uint32 {
	return uint32(packetType)<<16 | uint32(streamID)
}

func (r *sessionRecord) enqueueOrphanReset(packetType uint8, streamID uint16, sequenceNum uint16) {
	if r == nil || streamID == 0 {
		return
	}

	packet := VpnProto.Packet{
		PacketType:     packetType,
		StreamID:       streamID,
		HasStreamID:    true,
		SequenceNum:    sequenceNum,
		HasSequenceNum: sequenceNum != 0,
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	key := orphanResetKey(packetType, streamID)
	if idx, ok := r.OrphanIndex[key]; ok && idx >= 0 && idx < len(r.OrphanPackets) {
		r.OrphanPackets[idx] = packet
		return
	}

	r.OrphanIndex[key] = len(r.OrphanPackets)
	r.OrphanPackets = append(r.OrphanPackets, packet)
}

func (r *sessionRecord) dequeueOrphanReset() (*VpnProto.Packet, bool) {
	if r == nil {
		return nil, false
	}

	if len(r.OrphanPackets) == 0 {
		return nil, false
	}

	packet := r.OrphanPackets[0]
	r.OrphanPackets = r.OrphanPackets[1:]
	delete(r.OrphanIndex, orphanResetKey(packet.PacketType, packet.StreamID))
	for i := range r.OrphanPackets {
		r.OrphanIndex[orphanResetKey(r.OrphanPackets[i].PacketType, r.OrphanPackets[i].StreamID)] = i
	}

	return &packet, true
}
