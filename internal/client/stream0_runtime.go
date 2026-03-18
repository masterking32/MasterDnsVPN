// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"errors"
	"sync"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var ErrStream0RuntimeStopped = errors.New("stream 0 runtime stopped")

const (
	stream0DNSPriority  = 2
	stream0PingPriority = 4
)

var (
	stream0DNSRetryBaseDelay         = 350 * time.Millisecond
	stream0DNSRetryMaxDelay          = 2 * time.Second
	stream0PingIdleNoStreamThreshold = 20 * time.Second
	stream0PingIdleHighThreshold     = 10 * time.Second
	stream0PingIdleMediumThreshold   = 5 * time.Second
	stream0PingNoStreamInterval      = 10 * time.Second
	stream0PingHighIdleInterval      = 3 * time.Second
	stream0PingMediumIdleInterval    = time.Second
	stream0PingBusyInterval          = 200 * time.Millisecond
	stream0PingNoStreamMaxSleep      = time.Second
	stream0PingHighIdleMaxSleep      = 500 * time.Millisecond
	stream0PingMediumIdleMaxSleep    = 200 * time.Millisecond
	stream0PingBusyMaxSleep          = 180 * time.Millisecond
)

type stream0Result struct {
	packet VpnProto.Packet
	err    error
}

type stream0Pending struct {
	packetType     uint8
	payload        []byte
	resultCh       chan stream0Result
	deadline       time.Time
	retryDelay     time.Duration
	retryScheduled bool
}

type stream0Runtime struct {
	client    *Client
	scheduler *arq.Scheduler

	mu               sync.Mutex
	running          bool
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	wakeCh           chan struct{}
	pendingBySeq     map[uint16]*stream0Pending
	dnsActivitySeen  bool
	lastDataActivity time.Time
	lastPingTime     time.Time
}

func newStream0Runtime(client *Client) *stream0Runtime {
	now := time.Now()
	return &stream0Runtime{
		client:           client,
		scheduler:        arq.NewScheduler(1),
		wakeCh:           make(chan struct{}, 1),
		pendingBySeq:     make(map[uint16]*stream0Pending, 16),
		lastDataActivity: now,
		lastPingTime:     now,
	}
}

func (r *stream0Runtime) Start(parent context.Context) error {
	if r == nil {
		return ErrStream0RuntimeStopped
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		return nil
	}

	if parent == nil {
		parent = context.Background()
	}
	r.ctx, r.cancel = context.WithCancel(parent)
	r.running = true
	r.lastDataActivity = time.Now()
	r.lastPingTime = r.lastDataActivity
	r.scheduler.SetMaxPackedBlocks(r.client.MaxPackedBlocks())
	r.wg.Add(2)
	go r.txLoop()
	go r.pingLoop()
	return nil
}

func (r *stream0Runtime) IsRunning() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

func (r *stream0Runtime) SetMaxPackedBlocks(limit int) {
	if r == nil {
		return
	}
	r.scheduler.SetMaxPackedBlocks(limit)
}

func (r *stream0Runtime) NotifyDNSActivity() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.dnsActivitySeen = true
	r.lastDataActivity = time.Now()
	r.mu.Unlock()
}

func (r *stream0Runtime) ExchangeDNSQuery(payload []byte, timeout time.Duration) (VpnProto.Packet, error) {
	if r == nil || !r.IsRunning() {
		return VpnProto.Packet{}, ErrStream0RuntimeStopped
	}

	sequenceNum := r.client.nextMainSequence()
	resultCh := make(chan stream0Result, 1)
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return VpnProto.Packet{}, ErrStream0RuntimeStopped
	}
	r.pendingBySeq[sequenceNum] = &stream0Pending{
		packetType: packetTypeForDNSQuery(),
		payload:    append([]byte(nil), payload...),
		resultCh:   resultCh,
		deadline:   time.Now().Add(timeout),
		retryDelay: stream0DNSRetryBaseDelay,
	}
	r.dnsActivitySeen = true
	r.lastDataActivity = time.Now()
	r.mu.Unlock()

	enqueued := r.scheduler.Enqueue(arq.QueueTargetMain, arq.QueuedPacket{
		PacketType:  Enums.PACKET_DNS_QUERY_REQ,
		StreamID:    0,
		SequenceNum: sequenceNum,
		Payload:     payload,
		Priority:    stream0DNSPriority,
	})
	if !enqueued {
		r.removePending(sequenceNum)
		return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
	}
	r.notifyWake()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case result := <-resultCh:
		return result.packet, result.err
	case <-timer.C:
		r.removePending(sequenceNum)
		return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
	case <-r.ctx.Done():
		r.removePending(sequenceNum)
		return VpnProto.Packet{}, ErrStream0RuntimeStopped
	}
}

func (r *stream0Runtime) QueuePing() bool {
	if r == nil || !r.IsRunning() {
		return false
	}
	if r.scheduler.PendingPings() > 0 {
		return false
	}

	payload := []byte{'P', 'O', ':'}
	randomPart, err := randomBytes(4)
	if err != nil {
		return false
	}
	payload = append(payload, randomPart...)

	if !r.scheduler.Enqueue(arq.QueueTargetMain, arq.QueuedPacket{
		PacketType: Enums.PACKET_PING,
		Payload:    payload,
		Priority:   stream0PingPriority,
	}) {
		return false
	}
	r.notifyWake()
	return true
}

func (r *stream0Runtime) txLoop() {
	defer r.wg.Done()
	for {
		select {
		case <-r.ctx.Done():
			r.failAllPending(ErrStream0RuntimeStopped)
			return
		case <-r.wakeCh:
		}

		for {
			result, ok := r.scheduler.Dequeue()
			if !ok {
				break
			}
			r.processDequeue(result.Packet)
		}
	}
}

func (r *stream0Runtime) pingLoop() {
	defer r.wg.Done()
	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		shouldPing, sleepFor := r.nextPingSchedule(time.Now())
		if shouldPing {
			if r.QueuePing() {
				r.mu.Lock()
				r.lastPingTime = time.Now()
				r.mu.Unlock()
			}
		}

		if sleepFor <= 0 {
			sleepFor = 100 * time.Millisecond
		}

		timer := time.NewTimer(sleepFor)
		select {
		case <-r.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (r *stream0Runtime) nextPingSchedule(now time.Time) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.dnsActivitySeen {
		return false, time.Second
	}

	idleTime := now.Sub(r.lastDataActivity)
	pingInterval := stream0PingBusyInterval
	maxSleep := stream0PingBusyMaxSleep

	if idleTime > stream0PingIdleNoStreamThreshold {
		pingInterval = stream0PingNoStreamInterval
		maxSleep = stream0PingNoStreamMaxSleep
	} else if idleTime >= stream0PingIdleHighThreshold {
		pingInterval = stream0PingHighIdleInterval
		maxSleep = stream0PingHighIdleMaxSleep
	} else if idleTime >= stream0PingIdleMediumThreshold {
		pingInterval = stream0PingMediumIdleInterval
		maxSleep = stream0PingMediumIdleMaxSleep
	}

	timeSinceLastPing := now.Sub(r.lastPingTime)
	if timeSinceLastPing >= pingInterval {
		return true, pingInterval
	}

	sleepFor := pingInterval - timeSinceLastPing
	if sleepFor > maxSleep {
		sleepFor = maxSleep
	}
	return false, sleepFor
}

func (r *stream0Runtime) processDequeue(packet arq.QueuedPacket) {
	response, err := r.client.sendStream0Packet(packet)
	if err != nil {
		if packet.PacketType == Enums.PACKET_DNS_QUERY_REQ {
			r.scheduleRetry(packet.SequenceNum, err)
		}
		return
	}

	switch response.PacketType {
	case Enums.PACKET_DNS_QUERY_RES:
		r.completePending(response.SequenceNum, response, nil)
		r.noteServerDataActivity()
	case Enums.PACKET_PONG:
		r.noteServerDataActivity()
	case 0:
		if packet.PacketType == Enums.PACKET_DNS_QUERY_REQ {
			r.scheduleRetry(packet.SequenceNum, ErrTunnelDNSDispatchFailed)
		}
	default:
		if packet.PacketType == Enums.PACKET_DNS_QUERY_REQ {
			r.scheduleRetry(packet.SequenceNum, ErrTunnelDNSDispatchFailed)
		}
	}
}

func (r *stream0Runtime) noteServerDataActivity() {
	r.mu.Lock()
	r.lastDataActivity = time.Now()
	r.mu.Unlock()
}

func (r *stream0Runtime) notifyWake() {
	select {
	case r.wakeCh <- struct{}{}:
	default:
	}
}

func (r *stream0Runtime) completePending(sequenceNum uint16, packet VpnProto.Packet, err error) {
	r.mu.Lock()
	pending, ok := r.pendingBySeq[sequenceNum]
	if ok {
		delete(r.pendingBySeq, sequenceNum)
	}
	r.mu.Unlock()
	if ok {
		pending.resultCh <- stream0Result{packet: packet, err: err}
	}
}

func (r *stream0Runtime) removePending(sequenceNum uint16) {
	r.mu.Lock()
	delete(r.pendingBySeq, sequenceNum)
	r.mu.Unlock()
}

func (r *stream0Runtime) failAllPending(err error) {
	r.mu.Lock()
	pending := r.pendingBySeq
	r.pendingBySeq = make(map[uint16]*stream0Pending, 4)
	r.running = false
	r.mu.Unlock()

	for _, entry := range pending {
		entry.resultCh <- stream0Result{err: err}
	}
}

func (r *stream0Runtime) scheduleRetry(sequenceNum uint16, err error) {
	r.mu.Lock()
	entry, ok := r.pendingBySeq[sequenceNum]
	if !ok {
		r.mu.Unlock()
		return
	}
	now := time.Now()
	if !entry.deadline.After(now) {
		delete(r.pendingBySeq, sequenceNum)
		resultCh := entry.resultCh
		r.mu.Unlock()
		resultCh <- stream0Result{err: err}
		return
	}
	if entry.retryScheduled {
		r.mu.Unlock()
		return
	}
	delay := entry.retryDelay
	if delay <= 0 {
		delay = stream0DNSRetryBaseDelay
	}
	entry.retryScheduled = true
	if entry.retryDelay < stream0DNSRetryMaxDelay {
		nextDelay := entry.retryDelay * 2
		if nextDelay > stream0DNSRetryMaxDelay {
			nextDelay = stream0DNSRetryMaxDelay
		}
		entry.retryDelay = nextDelay
	}
	packetType := entry.packetType
	payload := append([]byte(nil), entry.payload...)
	r.mu.Unlock()

	timer := time.NewTimer(delay)
	go func() {
		defer timer.Stop()
		select {
		case <-r.ctx.Done():
			return
		case <-timer.C:
		}

		r.mu.Lock()
		entry, ok := r.pendingBySeq[sequenceNum]
		if !ok {
			r.mu.Unlock()
			return
		}
		entry.retryScheduled = false
		if !entry.deadline.After(time.Now()) || !r.running {
			delete(r.pendingBySeq, sequenceNum)
			resultCh := entry.resultCh
			r.mu.Unlock()
			resultCh <- stream0Result{err: err}
			return
		}
		r.mu.Unlock()

		if !r.scheduler.Enqueue(arq.QueueTargetMain, arq.QueuedPacket{
			PacketType:  packetType,
			StreamID:    0,
			SequenceNum: sequenceNum,
			Payload:     payload,
			Priority:    stream0DNSPriority,
		}) {
			r.scheduleRetry(sequenceNum, err)
			return
		}
		r.notifyWake()
	}()
}

func packetTypeForDNSQuery() uint8 {
	return Enums.PACKET_DNS_QUERY_REQ
}
