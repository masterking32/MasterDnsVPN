// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

type PingManager struct {
	client                *Client
	lastPingSentAt        atomic.Int64
	lastPongReceivedAt    atomic.Int64
	lastNonPingSentAt     atomic.Int64
	lastNonPongReceivedAt atomic.Int64

	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	wakeCh     chan struct{}
	lastWokeAt atomic.Int64
}

func newPingManager(client *Client) *PingManager {
	now := time.Now().UnixNano()
	p := &PingManager{
		client: client,
		wakeCh: make(chan struct{}, 1),
	}
	p.lastPingSentAt.Store(now)
	p.lastPongReceivedAt.Store(now)
	p.lastNonPingSentAt.Store(now)
	p.lastNonPongReceivedAt.Store(now)
	p.lastWokeAt.Store(now)
	return p
}

// Start starts the autonomous ping loop.
func (p *PingManager) Start(parentCtx context.Context) {
	p.Stop() // Ensure old one is stopped

	p.ctx, p.cancel = context.WithCancel(parentCtx)
	p.wg.Add(1)
	go p.pingLoop()
}

// Stop stops the ping loop.
func (p *PingManager) Stop() {
	if p.cancel != nil {
		p.cancel()
		p.wg.Wait()
		p.cancel = nil
	}
}

func (p *PingManager) NotifyPacket(packetType uint8, isInbound bool) {
	if p == nil {
		return
	}

	isPing := packetType == Enums.PACKET_PING
	isPong := packetType == Enums.PACKET_PONG

	now := time.Now().UnixNano()

	if isInbound {
		if isPong {
			p.lastPongReceivedAt.Store(now)
		} else {
			p.lastNonPongReceivedAt.Store(now)
			p.wake(now)
		}
	} else {
		if isPing {
			p.lastPingSentAt.Store(now)
		} else {
			p.lastNonPingSentAt.Store(now)
			p.wake(now)
		}
	}
}

func (p *PingManager) wake(now int64) {
	// Throttle wakeups to at most once per 100ms to reduce CPU overhead in high traffic
	if now-p.lastWokeAt.Load() < int64(100*time.Millisecond) {
		return
	}
	p.lastWokeAt.Store(now)
	select {
	case p.wakeCh <- struct{}{}:
	default:
	}
}

func (p *PingManager) nextInterval(nowNano int64) time.Duration {
	lastNonPingSent := p.lastNonPingSentAt.Load()
	lastNonPongRecv := p.lastNonPongReceivedAt.Load()

	// Use fast int64 comparisons for intervals
	warmThresholdNano := int64(p.client.cfg.PingWarmThreshold())

	if nowNano-lastNonPingSent < warmThresholdNano || nowNano-lastNonPongRecv < warmThresholdNano {
		return p.client.cfg.PingAggressiveInterval()
	}

	idleSent := nowNano - lastNonPingSent
	idleRecv := nowNano - lastNonPongRecv
	minIdle := idleSent
	if idleRecv < minIdle {
		minIdle = idleRecv
	}

	coolThresholdNano := int64(p.client.cfg.PingCoolThreshold())
	coldThresholdNano := int64(p.client.cfg.PingColdThreshold())
	switch {
	case minIdle < coolThresholdNano:
		return p.client.cfg.PingLazyInterval()
	case minIdle < coldThresholdNano:
		return p.client.cfg.PingCooldownInterval()
	default:
		return p.client.cfg.PingColdInterval()
	}
}

func (p *PingManager) pingLoop() {
	defer p.wg.Done()

	p.client.log.Debugf("\U0001F3D3 <cyan>Ping Manager loop started</cyan>")
	timer := time.NewTimer(p.client.cfg.PingAggressiveInterval())
	defer timer.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.wakeCh:
		case <-timer.C:
		}

		now := time.Now()
		nowNano := now.UnixNano()
		interval := p.nextInterval(nowNano)
		lastPing := p.lastPingSentAt.Load()

		if nowNano-lastPing >= int64(interval) {
			if p.client.SessionReady() {
				payload, err := buildClientPingPayload()
				if err == nil {
					// Use Stream 0 for pings
					p.client.streamsMu.RLock()
					s0 := p.client.active_streams[0]
					p.client.streamsMu.RUnlock()

					if s0 != nil {
						s0.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_PING), Enums.PACKET_PING, 0, 0, 0, 0, 0, payload)
					}
				}
			}
		}

		checkInterval := interval / 2
		if checkInterval < 100*time.Millisecond {
			checkInterval = 100 * time.Millisecond
		}
		if checkInterval > 1*time.Second {
			checkInterval = 1 * time.Second
		}

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(checkInterval)
	}
}

func buildClientPingPayload() ([]byte, error) {
	// Pre-allocate the fixed size payload to avoid multiple allocations and appends
	payload := make([]byte, 7)
	payload[0] = 'P'
	payload[1] = 'O'
	payload[2] = ':'

	// Use rand.Read directly into the pre-allocated buffer starting at index 3
	if _, err := rand.Read(payload[3:]); err != nil {
		return nil, err
	}
	return payload, nil
}
