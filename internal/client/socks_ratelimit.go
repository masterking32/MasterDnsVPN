// ==============================================================================
// MasterDnsVPN — Fix: Sharded SOCKS5 Rate Limiter
// Replaces the single sync.Mutex with 64 shards (FNV-based bucketing).
// Each shard has its own mutex so concurrent IPs contend only within their
// shard, reducing lock contention by ~64x under high connection load.
// ==============================================================================
package client

import (
	"hash/fnv"
	"net"
	"sync"
	"time"
)

const (
	socksRateLimitWindow         = 2 * time.Minute
	socksRateLimitMaxFailures    = 10
	socksRateLimitBaseBan        = 1 * time.Minute
	socksRateLimitMaxBanDuration = 15 * time.Minute
	socksRateLimitBanDecayAfter  = 10 * time.Minute
	socksRateLimitPurgeInterval  = 60 * time.Second

	// numShards must be a power of two for fast modulo via bitwise AND.
	numShards = 64
)

type socksAuthFailureRecord struct {
	timestamps []time.Time
	banUntil   time.Time
	banCount   int
}

type socksRateShard struct {
	mu        sync.Mutex
	records   map[string]*socksAuthFailureRecord
	lastPurge time.Time
}

// socksRateLimiter uses sharded maps to reduce mutex contention under high load.
type socksRateLimiter struct {
	shards [numShards]socksRateShard
}

func newSocksRateLimiter() *socksRateLimiter {
	r := &socksRateLimiter{}
	now := time.Now()
	for i := range r.shards {
		r.shards[i].records = make(map[string]*socksAuthFailureRecord)
		r.shards[i].lastPurge = now
	}
	return r
}

func (r *socksRateLimiter) shard(ip string) *socksRateShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ip))
	return &r.shards[h.Sum32()&(numShards-1)]
}

func isLoopbackIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

func extractIP(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	addr := conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func (r *socksRateLimiter) IsBlocked(ip string) bool {
	if ip == "" || isLoopbackIP(ip) {
		return false
	}
	s := r.shard(ip)
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[ip]
	if !ok || rec.banUntil.IsZero() {
		return false
	}
	return time.Now().Before(rec.banUntil)
}

func (r *socksRateLimiter) RecordFailure(ip string) bool {
	if ip == "" || isLoopbackIP(ip) {
		return false
	}
	now := time.Now()
	s := r.shard(ip)
	s.mu.Lock()
	defer s.mu.Unlock()

	if now.Sub(s.lastPurge) >= socksRateLimitPurgeInterval {
		s.purgeLocked(now)
		s.lastPurge = now
	}

	rec, ok := s.records[ip]
	if !ok {
		rec = &socksAuthFailureRecord{}
		s.records[ip] = rec
	}

	if !rec.banUntil.IsZero() && now.Before(rec.banUntil) {
		return true
	}

	if rec.banCount > 0 && !rec.banUntil.IsZero() && now.After(rec.banUntil) {
		if now.Sub(rec.banUntil) >= socksRateLimitBanDecayAfter {
			rec.banCount = 0
		}
	}

	cutoff := now.Add(-socksRateLimitWindow)
	trimmed := rec.timestamps[:0]
	for _, ts := range rec.timestamps {
		if ts.After(cutoff) {
			trimmed = append(trimmed, ts)
		}
	}
	rec.timestamps = append(trimmed, now)

	if len(rec.timestamps) >= socksRateLimitMaxFailures {
		rec.banCount++
		banDuration := socksRateLimitBaseBan
		for i := 1; i < rec.banCount; i++ {
			banDuration *= 2
			if banDuration >= socksRateLimitMaxBanDuration {
				banDuration = socksRateLimitMaxBanDuration
				break
			}
		}
		rec.banUntil = now.Add(banDuration)
		rec.timestamps = rec.timestamps[:0]
		return true
	}
	return false
}

func (r *socksRateLimiter) RecordSuccess(ip string) {
	if ip == "" || isLoopbackIP(ip) {
		return
	}
	s := r.shard(ip)
	s.mu.Lock()
	delete(s.records, ip)
	s.mu.Unlock()
}

func (r *socksRateLimiter) Reset() {
	if r == nil {
		return
	}
	now := time.Now()
	for i := range r.shards {
		s := &r.shards[i]
		s.mu.Lock()
		s.records = make(map[string]*socksAuthFailureRecord)
		s.lastPurge = now
		s.mu.Unlock()
	}
}

func (s *socksRateShard) purgeLocked(now time.Time) {
	cutoff := now.Add(-socksRateLimitWindow)
	for ip, rec := range s.records {
		if !rec.banUntil.IsZero() && now.Before(rec.banUntil) {
			continue
		}
		hasRecent := false
		for _, ts := range rec.timestamps {
			if ts.After(cutoff) {
				hasRecent = true
				break
			}
		}
		if !hasRecent && (rec.banUntil.IsZero() || now.After(rec.banUntil)) {
			delete(s.records, ip)
		}
	}
}
