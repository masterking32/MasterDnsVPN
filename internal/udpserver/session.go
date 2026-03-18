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
	"time"

	"masterdnsvpn-go/internal/compression"
)

var ErrSessionTableFull = errors.New("session table full")

const (
	maxServerSessions   = 255
	sessionInitTTL      = 10 * time.Minute
	sessionInitDataSize = 10
	minSessionMTU       = 30
	maxSessionMTU       = 4096
)

type sessionRecord struct {
	ID                  uint8
	Cookie              uint8
	ResponseMode        uint8
	UploadCompression   uint8
	DownloadCompression uint8
	UploadMTU           uint16
	DownloadMTU         uint16
	VerifyCode          [4]byte
	Signature           [sessionInitDataSize]byte
	CreatedAt           time.Time
	LastActivityAt      time.Time
	ReuseUntil          time.Time
}

type closedSessionRecord struct {
	Cookie    uint8
	ExpiresAt time.Time
}

type sessionStore struct {
	mu           sync.Mutex
	nextID       uint16
	byID         [maxServerSessions]*sessionRecord
	bySig        map[[sessionInitDataSize]byte]uint8
	recentClosed map[uint8]closedSessionRecord
}

func newSessionStore() *sessionStore {
	return &sessionStore{
		bySig:        make(map[[sessionInitDataSize]byte]uint8, 64),
		recentClosed: make(map[uint8]closedSessionRecord, 32),
	}
}

func (s *sessionStore) findOrCreate(payload []byte, uploadCompressionType uint8, downloadCompressionType uint8) (*sessionRecord, bool, error) {
	if len(payload) != sessionInitDataSize || !isValidSessionResponseMode(payload[0]) {
		return nil, false, nil
	}

	var signature [sessionInitDataSize]byte
	copy(signature[:], payload[:sessionInitDataSize])

	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireReuseLocked(now)

	if sessionID, ok := s.bySig[signature]; ok {
		if existing := s.byID[sessionID]; existing != nil {
			if now.Before(existing.ReuseUntil) || now.Equal(existing.ReuseUntil) {
				existing.LastActivityAt = now
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
		LastActivityAt: now,
		ReuseUntil:     now.Add(sessionInitTTL),
		Signature:      signature,
	}
	record.UploadCompression = compression.NormalizeType(uploadCompressionType)
	record.DownloadCompression = compression.NormalizeType(downloadCompressionType)
	record.UploadMTU = clampMTU(binary.BigEndian.Uint16(payload[2:4]))
	record.DownloadMTU = clampMTU(binary.BigEndian.Uint16(payload[4:6]))
	copy(record.VerifyCode[:], payload[6:10])
	record.Cookie = randomCookie()

	s.byID[slot] = record
	s.bySig[signature] = uint8(slot)
	delete(s.recentClosed, uint8(slot))
	s.nextID = uint16((slot + 1) % maxServerSessions)
	return record, false, nil
}

func (s *sessionStore) expireReuseLocked(now time.Time) {
	for signature, sessionID := range s.bySig {
		record := s.byID[sessionID]
		if record == nil || now.After(record.ReuseUntil) {
			delete(s.bySig, signature)
		}
	}
}

func (s *sessionStore) Touch(sessionID uint8, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.byID[sessionID]
	if record == nil {
		return false
	}
	record.LastActivityAt = now
	return true
}

func (s *sessionStore) Active(sessionID uint8) (*sessionRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.byID[sessionID]
	if record == nil {
		return nil, false
	}
	copyRecord := *record
	return &copyRecord, true
}

func (s *sessionStore) ExpectedCookie(sessionID uint8) (uint8, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if record := s.byID[sessionID]; record != nil {
		return record.Cookie, true
	}
	if record, ok := s.recentClosed[sessionID]; ok {
		return record.Cookie, true
	}
	return 0, false
}

func (s *sessionStore) ValidateCookie(sessionID uint8, cookie uint8) bool {
	expected, ok := s.ExpectedCookie(sessionID)
	return ok && expected == cookie
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
	if retention > 0 {
		s.recentClosed[sessionID] = closedSessionRecord{
			Cookie:    record.Cookie,
			ExpiresAt: now.Add(retention),
		}
	} else {
		delete(s.recentClosed, sessionID)
	}
	return true
}

func (s *sessionStore) Cleanup(now time.Time, idleTimeout time.Duration, closedRetention time.Duration) []uint8 {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireReuseLocked(now)

	for sessionID, record := range s.recentClosed {
		if !now.Before(record.ExpiresAt) {
			delete(s.recentClosed, sessionID)
		}
	}

	if idleTimeout <= 0 {
		return nil
	}

	expired := make([]uint8, 0, 8)
	for sessionID, record := range s.byID {
		if record == nil {
			continue
		}
		if now.Sub(record.LastActivityAt) < idleTimeout {
			continue
		}

		delete(s.bySig, record.Signature)
		s.byID[sessionID] = nil
		if closedRetention > 0 {
			s.recentClosed[uint8(sessionID)] = closedSessionRecord{
				Cookie:    record.Cookie,
				ExpiresAt: now.Add(closedRetention),
			}
		}
		expired = append(expired, uint8(sessionID))
	}

	return expired
}

func (s *sessionStore) allocateSlotLocked() int {
	for i := range maxServerSessions {
		slot := int((s.nextID + uint16(i)) % maxServerSessions)
		if s.byID[slot] == nil {
			return slot
		}
	}
	return -1
}

func randomCookie() uint8 {
	var buf [1]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0
	}
	return buf[0]
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
	return value == mtuProbeModeRaw || value == mtuProbeModeBase64
}
