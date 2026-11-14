// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (background_limiter.go) bounds background DNS query starts using a
// monotonic, cancellation-aware token-bucket rate limiter.
// ==============================================================================
package client

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// BackgroundQueryLimiter bounds background DNS query starts using a monotonic,
// cancellation-aware token bucket rate limiter. It applies strictly to background
// discovery, health checks, and burst probes; foreground tunnel traffic and
// initial startup probing are not throttled through this budget.
type BackgroundQueryLimiter struct {
	mu         sync.Mutex
	rate       float64 // tokens per second
	capacity   float64 // maximum burst capacity
	tokens     float64
	lastRefill time.Time
	nowFn      func() time.Time
}

// NewBackgroundQueryLimiter creates a BackgroundQueryLimiter with the specified
// queries-per-second rate and burst capacity.
func NewBackgroundQueryLimiter(rate float64, burst int) *BackgroundQueryLimiter {
	if rate <= 0 {
		rate = 15.0 // Conservative default: 15 QPS
	}
	if burst <= 0 {
		burst = int(rate)
		if burst < 1 {
			burst = 1
		}
	}
	return &BackgroundQueryLimiter{
		rate:       rate,
		capacity:   float64(burst),
		tokens:     float64(burst),
		lastRefill: time.Now(),
	}
}

// Acquire waits until a query token is available or until ctx is cancelled.
// It wraps ctx.Err() if cancelled before a token can be acquired.
// A nil context is treated as context.Background().
func (l *BackgroundQueryLimiter) Acquire(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if ctx.Err() != nil {
			return fmt.Errorf("acquire background query token: %w", ctx.Err())
		}

		waitTime := l.takeTokenOrWait()
		if waitTime <= 0 {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("acquire background query token: %w", ctx.Err())
		case <-time.After(waitTime):
		}
	}
}

// AcquireN acquires n query tokens consecutively, waiting if necessary or aborting on cancellation.
func (l *BackgroundQueryLimiter) AcquireN(ctx context.Context, n int) error {
	if l == nil || n <= 0 {
		return nil
	}
	for i := 0; i < n; i++ {
		if err := l.Acquire(ctx); err != nil {
			return fmt.Errorf("acquire background query token %d of %d: %w", i+1, n, err)
		}
	}
	return nil
}

// TryAcquire attempts to acquire a token immediately without blocking.
// Returns true if acquired, false otherwise.
func (l *BackgroundQueryLimiter) TryAcquire() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refillLocked()
	if l.tokens >= 1.0 {
		l.tokens -= 1.0
		return true
	}
	return false
}

// SetRate updates the rate and burst capacity.
func (l *BackgroundQueryLimiter) SetRate(rate float64, burst int) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if rate <= 0 {
		rate = 15.0
	}
	if burst <= 0 {
		burst = int(rate)
		if burst < 1 {
			burst = 1
		}
	}
	l.rate = rate
	l.capacity = float64(burst)
	if l.tokens > l.capacity {
		l.tokens = l.capacity
	}
}

func (l *BackgroundQueryLimiter) takeTokenOrWait() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.refillLocked()
	if l.tokens >= 1.0 {
		l.tokens -= 1.0
		return 0
	}

	missing := 1.0 - l.tokens
	return time.Duration((missing / l.rate) * float64(time.Second))
}

func (l *BackgroundQueryLimiter) refillLocked() {
	now := time.Now()
	if l.nowFn != nil {
		now = l.nowFn()
	}
	elapsed := now.Sub(l.lastRefill)
	if elapsed <= 0 {
		return
	}
	l.lastRefill = now
	l.tokens += elapsed.Seconds() * l.rate
	if l.tokens > l.capacity {
		l.tokens = l.capacity
	}
}

// burstWaitAllowance bounds a probe's scheduling allowance separately from its
// response timeout. Include the health batch concurrency so competing probes
// can all send their configured samples through the shared token budget.
func (l *BackgroundQueryLimiter) burstWaitAllowance(queries, concurrency int) time.Duration {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return time.Duration(float64(queries*concurrency) / l.rate * float64(time.Second))
}
