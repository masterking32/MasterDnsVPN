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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/mlq"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var ErrSessionTableFull = errors.New("session table full")

const (
	maxServerSessionID    = 255
	maxServerSessionSlots = 255
	sessionInitDataSize   = 10
	minSessionMTU         = 10
	maxSessionMTU         = 4096
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
	Streams                         map[uint16]*Stream_server
	ActiveStreams                   []uint16 // Sorted list of active stream IDs for Round-Robin
	activeStreamSetVersion         uint64
	activeStreamSnapshotIDs        []int32
	activeStreamSnapshotStreams    []*Stream_server
	activeStreamSnapshotVersion    uint64
	RRStreamID                      int32    // Last served stream ID for RR
	EnqueueSeq                      uint64   // Global sequence for FIFO inside same priority
	StreamQueueCap                  int
	StreamsMu                       sync.RWMutex
	RecentlyClosed                  map[uint16]recentlyClosedStreamRecord
	RecentlyClosedTTL               time.Duration
	RecentlyClosedCap               int
	OrphanQueue                     *mlq.MultiLevelQueue[VpnProto.Packet]
	LastPackedControlBlock          *VpnProto.Packet
	LastPackedControlBlockRemaining int
	closedFlag                      uint32
	streamCleanup                   func(uint8, uint16)
}

type recentlyClosedStreamRecord struct {
	ClosedAt       time.Time
	SuppressOrphan bool
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
	TTL             time.Duration
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
	p.TTL = 0
	txPacketPool.Put(p)
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

type closedSessionCleanup struct {
	ID     uint8
	record *sessionRecord
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
	orphanQueueCap         int
	streamQueueCap         int
	sessionInitTTL         time.Duration
	recentlyClosedTTL      time.Duration
	recentlyClosedCap      int
}

func newSessionStore(orphanQueueCap int, streamQueueCap int, options ...any) *sessionStore {
	if orphanQueueCap < 1 {
		orphanQueueCap = 8
	}
	if streamQueueCap < 1 {
		streamQueueCap = 32
	}

	sessionInitTTL := 10 * time.Minute
	recentlyClosedTTL := 600 * time.Second
	recentlyClosedCap := 2000
	if len(options) > 0 {
		if v, ok := options[0].(time.Duration); ok && v > 0 {
			sessionInitTTL = v
		}
	}
	if len(options) > 1 {
		if v, ok := options[1].(time.Duration); ok && v > 0 {
			recentlyClosedTTL = v
		}
	}
	if len(options) > 2 {
		if v, ok := options[2].(int); ok && v > 0 {
			recentlyClosedCap = v
		}
	}
	return &sessionStore{
		bySig:             make(map[[sessionInitDataSize]byte]uint8, 64),
		recentClosed:      make(map[uint8]closedSessionRecord, 32),
		cookieIndex:       32,
		nextID:            1,
		orphanQueueCap:    orphanQueueCap,
		streamQueueCap:    streamQueueCap,
		sessionInitTTL:    sessionInitTTL,
		recentlyClosedTTL: recentlyClosedTTL,
		recentlyClosedCap: recentlyClosedCap,
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
		ID:                uint8(slot),
		ResponseMode:      payload[0],
		CreatedAt:         now,
		ReuseUntil:        now.Add(s.sessionInitTTL),
		Signature:         signature,
		Streams:           make(map[uint16]*Stream_server),
		ActiveStreams:     make([]uint16, 0, 8),
		StreamQueueCap:    s.streamQueueCap,
		RecentlyClosed:    make(map[uint16]recentlyClosedStreamRecord, 8),
		RecentlyClosedTTL: s.recentlyClosedTTL,
		RecentlyClosedCap: s.recentlyClosedCap,
		OrphanQueue:       mlq.New[VpnProto.Packet](s.orphanQueueCap),
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
	if record == nil || record.isClosed() {
		return nil, false
	}
	return record, true
}

func (s *sessionStore) HasActive(sessionID uint8) bool {
	if s == nil || sessionID == 0 {
		return false
	}

	s.mu.Lock()
	record := s.byID[sessionID]
	s.mu.Unlock()
	return record != nil && !record.isClosed()
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

func (s *sessionStore) Close(sessionID uint8, now time.Time, retention time.Duration) (*sessionRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.byID[sessionID]
	if record == nil {
		return nil, false
	}
	record.markClosed()

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
	return record, true
}

func (s *sessionStore) Cleanup(now time.Time, idleTimeout time.Duration, closedRetention time.Duration) []closedSessionCleanup {
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

	expired := make([]closedSessionCleanup, 0, 8)
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
		record.markClosed()
		expired = append(expired, closedSessionCleanup{
			ID:     uint8(sessionID),
			record: record,
		})
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

func (s *sessionStore) SweepRecentlyClosedStreams(now time.Time) {
	s.mu.Lock()
	records := make([]*sessionRecord, 0, len(s.byID))
	for _, record := range s.byID {
		if record != nil {
			records = append(records, record)
		}
	}
	s.mu.Unlock()

	for _, record := range records {
		record.pruneRecentlyClosed(now)
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

func (r *sessionRecord) markClosed() {
	if r == nil {
		return
	}
	atomic.StoreUint32(&r.closedFlag, 1)
}

func (r *sessionRecord) reopen() {
	if r == nil {
		return
	}
	atomic.StoreUint32(&r.closedFlag, 0)
}

func (r *sessionRecord) isClosed() bool {
	if r == nil {
		return true
	}
	return atomic.LoadUint32(&r.closedFlag) != 0
}

// ensureStream0 creates correctly virtual stream 0 if not exist
func (r *sessionRecord) ensureStream0(logger arq.Logger) {
	if r == nil || r.isClosed() {
		return
	}
	r.getOrCreateStream(0, arq.Config{IsVirtual: true}, nil, logger)
}

func (r *sessionRecord) getOrCreateStream(streamID uint16, arqConfig arq.Config, localConn io.ReadWriteCloser, logger arq.Logger) *Stream_server {
	if r == nil || r.isClosed() {
		return nil
	}
	r.StreamsMu.Lock()
	defer r.StreamsMu.Unlock()
	if r.isClosed() {
		return nil
	}

	if s, ok := r.Streams[streamID]; ok {
		return s
	}

	delete(r.RecentlyClosed, streamID)

	s := NewStreamServer(streamID, r.ID, arqConfig, localConn, r.DownloadMTUBytes, r.StreamQueueCap, logger)
	s.onClosed = r.onStreamClosed
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
		r.markActiveStreamsChangedLocked()
	}

	return s
}

func shouldSuppressServerOrphanForCloseReason(reason string) bool {
	return strings.Contains(reason, "close handshake completed") ||
		strings.HasSuffix(reason, "acknowledged")
}

func (r *sessionRecord) onStreamClosed(streamID uint16, now time.Time, reason string) {
	if r == nil || streamID == 0 {
		return
	}
	r.removeStream(streamID, now, shouldSuppressServerOrphanForCloseReason(reason))
	if r.streamCleanup != nil {
		r.streamCleanup(r.ID, streamID)
	}
}

func (r *sessionRecord) getStream(streamID uint16) (*Stream_server, bool) {
	if r == nil || r.isClosed() {
		return nil, false
	}
	r.StreamsMu.RLock()
	s, ok := r.Streams[streamID]
	r.StreamsMu.RUnlock()
	return s, ok
}
func (r *sessionRecord) noteStreamClosed(streamID uint16, now time.Time, suppressOrphan bool) {
	if r == nil || r.isClosed() || streamID == 0 {
		return
	}
	r.StreamsMu.Lock()
	defer r.StreamsMu.Unlock()

	r.pruneRecentlyClosedLocked(now)

	r.RecentlyClosed[streamID] = recentlyClosedStreamRecord{
		ClosedAt:       now,
		SuppressOrphan: suppressOrphan,
	}

	// Cap the map size
	if len(r.RecentlyClosed) > r.closedStreamRecordCap() {
		var oldestID uint16
		var oldestAt time.Time
		first := true
		for id, record := range r.RecentlyClosed {
			if first || record.ClosedAt.Before(oldestAt) {
				oldestID = id
				oldestAt = record.ClosedAt
				first = false
			}
		}
		delete(r.RecentlyClosed, oldestID)
	}
}

func (r *sessionRecord) pruneRecentlyClosed(now time.Time) {
	if r == nil || r.isClosed() {
		return
	}
	r.StreamsMu.Lock()
	r.pruneRecentlyClosedLocked(now)
	r.StreamsMu.Unlock()
}

func (r *sessionRecord) pruneRecentlyClosedLocked(now time.Time) {
	if r == nil {
		return
	}
	expiredBefore := now.Add(-r.closedStreamRecordTTL())
	for id, record := range r.RecentlyClosed {
		if record.ClosedAt.Before(expiredBefore) {
			delete(r.RecentlyClosed, id)
		}
	}
}

func (r *sessionRecord) isRecentlyClosed(streamID uint16, now time.Time) bool {
	if r == nil || r.isClosed() {
		return false
	}
	r.StreamsMu.RLock()
	defer r.StreamsMu.RUnlock()

	record, ok := r.RecentlyClosed[streamID]
	if !ok {
		return false
	}

	return now.Sub(record.ClosedAt) <= r.closedStreamRecordTTL()
}

func (r *sessionRecord) shouldSuppressOrphanForClosedStream(streamID uint16, now time.Time) bool {
	if r == nil || r.isClosed() {
		return false
	}
	r.StreamsMu.RLock()
	defer r.StreamsMu.RUnlock()

	record, ok := r.RecentlyClosed[streamID]
	if !ok {
		return false
	}

	return now.Sub(record.ClosedAt) <= r.closedStreamRecordTTL() && record.SuppressOrphan
}

func (r *sessionRecord) closedStreamRecordTTL() time.Duration {
	if r == nil || r.RecentlyClosedTTL <= 0 {
		return 600 * time.Second
	}
	return r.RecentlyClosedTTL
}

func (r *sessionRecord) closedStreamRecordCap() int {
	if r == nil || r.RecentlyClosedCap < 1 {
		return 2000
	}
	return r.RecentlyClosedCap
}

func (r *sessionRecord) removeStream(streamID uint16, now time.Time, suppressOrphan bool) {
	if r == nil || r.isClosed() || streamID == 0 {
		return
	}
	r.StreamsMu.Lock()
	delete(r.Streams, streamID)

	r.removeActiveStreamLocked(streamID)
	r.StreamsMu.Unlock()

	r.noteStreamClosed(streamID, now, suppressOrphan)
}

func (r *sessionRecord) deactivateStream(streamID uint16) {
	if r == nil || r.isClosed() || streamID == 0 {
		return
	}

	r.StreamsMu.Lock()
	r.removeActiveStreamLocked(streamID)
	r.StreamsMu.Unlock()
}

func (r *sessionRecord) removeActiveStreamLocked(streamID uint16) {
	for i, id := range r.ActiveStreams {
		if id == streamID {
			r.ActiveStreams = append(r.ActiveStreams[:i], r.ActiveStreams[i+1:]...)
			r.markActiveStreamsChangedLocked()
			break
		}
	}
}

func (r *sessionRecord) markActiveStreamsChangedLocked() {
	r.activeStreamSetVersion++
}

func (r *sessionRecord) activeStreamSnapshot() ([]int32, []*Stream_server) {
	if r == nil || r.isClosed() {
		return nil, nil
	}

	r.StreamsMu.RLock()
	version := r.activeStreamSetVersion
	if version == r.activeStreamSnapshotVersion {
		ids := r.activeStreamSnapshotIDs
		streams := r.activeStreamSnapshotStreams
		r.StreamsMu.RUnlock()
		return ids, streams
	}
	r.StreamsMu.RUnlock()

	r.StreamsMu.Lock()
	defer r.StreamsMu.Unlock()

	if r.activeStreamSetVersion != r.activeStreamSnapshotVersion {
		snapshotIDs := make([]int32, len(r.ActiveStreams))
		snapshotStreams := make([]*Stream_server, len(r.ActiveStreams))
		for i, id := range r.ActiveStreams {
			snapshotIDs[i] = int32(id)
			snapshotStreams[i] = r.Streams[id]
		}
		r.activeStreamSnapshotIDs = snapshotIDs
		r.activeStreamSnapshotStreams = snapshotStreams
		r.activeStreamSnapshotVersion = r.activeStreamSetVersion
	}

	return r.activeStreamSnapshotIDs, r.activeStreamSnapshotStreams
}

func (r *sessionRecord) closeAllStreams(reason string) {
	if r == nil {
		return
	}
	r.markClosed()

	r.StreamsMu.RLock()
	streams := make([]*Stream_server, 0, len(r.Streams))
	for _, stream := range r.Streams {
		if stream != nil {
			streams = append(streams, stream)
		}
	}
	r.StreamsMu.RUnlock()

	for _, stream := range streams {
		stream.Abort(reason)
		stream.finalizeAfterARQClose(reason)
	}

	r.StreamsMu.Lock()
	clear(r.Streams)
	r.ActiveStreams = r.ActiveStreams[:0]
	r.markActiveStreamsChangedLocked()
	r.StreamsMu.Unlock()

	if r.OrphanQueue != nil {
		r.OrphanQueue.Clear(nil)
	}
}

func (r *sessionRecord) cleanupTerminalStreams(now time.Time, retention time.Duration) {
	if r == nil || r.isClosed() {
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

		forceClosedExpired := !stream.CloseTime.IsZero() && now.Sub(stream.CloseTime) >= retention
		if stream.ARQ.IsClosed() || forceClosedExpired {
			if stream.CloseTime.IsZero() {
				stream.CloseTime = now
			}
			stream.Status = "TIME_WAIT"
			if forceClosedExpired || now.Sub(stream.CloseTime) >= retention {
				removeIDs = append(removeIDs, streamID)
			}
		}
		stream.mu.Unlock()
	}

	for _, streamID := range removeIDs {
		if stream, ok := snapshot[streamID]; ok && stream != nil {
			stream.Abort("terminal stream retention cleanup")
			stream.finalizeAfterARQClose("terminal stream retention cleanup")
		}
		r.removeStream(streamID, now, false)
	}
}

func orphanResetKey(packetType uint8, streamID uint16) uint64 {
	return Enums.PacketTypeStreamKey(streamID, packetType)
}

func (r *sessionRecord) enqueueOrphanReset(packetType uint8, streamID uint16, sequenceNum uint16) {
	if r == nil || r.isClosed() || r.OrphanQueue == nil || streamID == 0 {
		return
	}

	packet := VpnProto.Packet{
		PacketType:     packetType,
		StreamID:       streamID,
		HasStreamID:    true,
		SequenceNum:    sequenceNum,
		HasSequenceNum: sequenceNum != 0,
	}

	key := orphanResetKey(packetType, streamID)
	// Orphans have high priority (0).
	r.OrphanQueue.Push(0, key, packet)
}
