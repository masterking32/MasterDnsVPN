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
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/arq"
)

var ErrSessionTableFull = errors.New("session table full")

const (
	maxServerSessionID    = 255
	maxServerSessionSlots = 255
	sessionInitTTL        = 10 * time.Minute
	sessionInitDataSize   = 10
	minSessionMTU         = 30
	maxSessionMTU         = 4096
)

type sessionRecord struct {
	ID                   uint8
	Cookie               uint8
	ResponseMode         uint8
	UploadCompression    uint8
	DownloadCompression  uint8
	UploadMTU            uint16
	DownloadMTU          uint16
	VerifyCode           [4]byte
	Signature            [sessionInitDataSize]byte
	MaxPackedBlocks      int
	CreatedAt            time.Time
	ReuseUntil           time.Time
	reuseUntilUnixNano   int64
	lastActivityUnixNano int64
}

type sessionRuntimeView struct {
	ID                  uint8
	Cookie              uint8
	ResponseMode        uint8
	ResponseBase64      bool
	DownloadCompression uint8
	DownloadMTU         uint16
	MaxPackedBlocks     int
}

type sessionSnapshot struct {
	ID                  uint8
	Cookie              uint8
	ResponseMode        uint8
	UploadCompression   uint8
	DownloadCompression uint8
	UploadMTU           uint16
	DownloadMTU         uint16
	VerifyCode          [4]byte
	Signature           [sessionInitDataSize]byte
	MaxPackedBlocks     int
	CreatedAt           time.Time
	LastActivityAt      time.Time
	ReuseUntil          time.Time
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
		ID:           uint8(slot),
		ResponseMode: payload[0],
		CreatedAt:    now,
		ReuseUntil:   now.Add(sessionInitTTL),
		Signature:    signature,
	}
	record.reuseUntilUnixNano = record.ReuseUntil.UnixNano()
	record.setLastActivityUnixNano(nowUnixNano)
	record.UploadCompression = uploadCompressionType
	record.DownloadCompression = downloadCompressionType
	record.UploadMTU = clampMTU(binary.BigEndian.Uint16(payload[2:4]))
	record.DownloadMTU = clampMTU(binary.BigEndian.Uint16(payload[4:6]))
	record.MaxPackedBlocks = arq.ComputeServerPackedControlBlockLimit(int(record.DownloadMTU), maxPacketsPerBatch)
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

func (s *sessionStore) Touch(sessionID uint8, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.byID[sessionID]
	if record == nil {
		return false
	}
	record.setLastActivity(now)
	return true
}

func (s *sessionStore) Active(sessionID uint8) (*sessionSnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.byID[sessionID]
	if record == nil {
		return nil, false
	}
	snapshot := record.snapshot()
	return &snapshot, true
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

func (s *sessionStore) ExpectedCookie(sessionID uint8) (uint8, bool) {
	info, ok := s.Lookup(sessionID)
	if !ok {
		return 0, false
	}
	return info.Cookie, true
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

func (r *sessionRecord) runtimeView() sessionRuntimeView {
	return sessionRuntimeView{
		ID:                  r.ID,
		Cookie:              r.Cookie,
		ResponseMode:        r.ResponseMode,
		ResponseBase64:      r.ResponseMode == mtuProbeModeBase64,
		DownloadCompression: r.DownloadCompression,
		DownloadMTU:         r.DownloadMTU,
		MaxPackedBlocks:     r.MaxPackedBlocks,
	}
}

func (r *sessionRecord) snapshot() sessionSnapshot {
	lastActivityUnixNano := r.lastActivity()
	lastActivityAt := time.Time{}
	if lastActivityUnixNano != 0 {
		lastActivityAt = time.Unix(0, lastActivityUnixNano)
	}

	return sessionSnapshot{
		ID:                  r.ID,
		Cookie:              r.Cookie,
		ResponseMode:        r.ResponseMode,
		UploadCompression:   r.UploadCompression,
		DownloadCompression: r.DownloadCompression,
		UploadMTU:           r.UploadMTU,
		DownloadMTU:         r.DownloadMTU,
		VerifyCode:          r.VerifyCode,
		Signature:           r.Signature,
		MaxPackedBlocks:     r.MaxPackedBlocks,
		CreatedAt:           r.CreatedAt,
		LastActivityAt:      lastActivityAt,
		ReuseUntil:          r.ReuseUntil,
	}
}
