// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (balancer.go) handles connection balancing strategies.
// ==============================================================================
package client

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
)

const (
	BalancingRoundRobinDefault      = 0
	BalancingRandom                 = 1
	BalancingRoundRobin             = 2
	BalancingLeastLoss              = 3
	BalancingLowestLatency          = 4
	BalancingHybridScore            = 5
	BalancingLossThenLatency        = 6
	BalancingLeastLossTopRandom     = 7
	BalancingLeastLossTopRoundRobin = 8
)

type Connection struct {
	Domain            string
	Resolver          string
	ResolverPort      int
	ResolverLabel     string
	Key               string
	IsValid           bool
	StandbyEligible   bool
	UploadMTUBytes    int
	UploadMTUChars    int
	DownloadMTUBytes  int
	MTUResolveTime    time.Duration
	LastHealthCheckAt time.Time
}

type balancerStreamRouteState struct {
	mu                   sync.Mutex
	PreferredResolverKey string
	ResendStreak         int
	LastFailoverAt       time.Time
}

type balancerResolverSampleKey struct {
	resolverAddr string
	localAddr    string
	dnsID        uint16
}

type balancerResolverSample struct {
	serverKey  string
	sentAt     time.Time
	timedOut   bool
	timedOutAt time.Time
	evictAfter time.Time
}

type balancerTimeoutObservation struct {
	serverKey string
	at        time.Time
}

type balancerPendingShard struct {
	mu      sync.Mutex
	pending map[balancerResolverSampleKey]balancerResolverSample
}

type Balancer struct {
	pool             *ResolverPool
	strategy         int
	rrCounter        atomic.Uint64
	totalPacketsSent atomic.Uint64
	rngState         atomic.Uint64
	nextPendingSweep atomic.Int64
	pendingOverflow  atomic.Bool
	pendingSize      atomic.Int32
	pendingEvictRR   atomic.Uint32

	mu           sync.RWMutex
	log          *logger.Logger
	streamRoutes map[uint16]*balancerStreamRouteState

	pendingShards [resolverPendingShardCount]balancerPendingShard

	streamFailoverThreshold int
	streamFailoverCooldown  time.Duration

	autoDisableEnabled       bool
	autoDisableTimeoutWindow time.Duration
	onResolverDisabled       func(*Connection, string)
	confirmResolverDown      func(*Connection, time.Duration) bool
}

type connectionStats struct {
	sent            atomic.Uint64
	acked           atomic.Uint64
	lost            atomic.Uint64
	rttMicrosSum    atomic.Uint64
	rttCount        atomic.Uint64
	windowStartedAt atomic.Int64 // UnixNano
	windowSent      atomic.Uint32
	windowLost      atomic.Uint32
	windowMu        sync.Mutex
	halfLifeRunning atomic.Bool
}

const connectionStatsHalfLifeThreshold = 1000

func NewBalancer(strategy int, log *logger.Logger, pool ...*ResolverPool) *Balancer {
	var p *ResolverPool
	if len(pool) > 0 && pool[0] != nil {
		p = pool[0]
	} else {
		p = NewResolverPool(0, log)
	}
	b := &Balancer{
		pool:                    p,
		strategy:                strategy,
		log:                     log,
		streamRoutes:            make(map[uint16]*balancerStreamRouteState),
		streamFailoverThreshold: 1,
		streamFailoverCooldown:  time.Second,
	}
	for i := range b.pendingShards {
		b.pendingShards[i].pending = make(map[balancerResolverSampleKey]balancerResolverSample)
	}
	b.rngState.Store(seedRNG())
	return b
}

func (b *Balancer) Pool() *ResolverPool {
	if b == nil {
		return nil
	}
	return b.pool
}

func (b *Balancer) SetMaxActiveResolvers(maxActive int) {
	if b == nil || b.pool == nil {
		return
	}
	b.pool.SetMaxActive(maxActive)
}

func (b *Balancer) MaxActiveResolvers() int {
	if b == nil || b.pool == nil {
		return 0
	}
	return b.pool.MaxActive()
}

func (b *Balancer) SetStreamFailoverConfig(threshold int, cooldown time.Duration) {
	if b == nil {
		return
	}
	if threshold < 1 {
		threshold = 1
	}
	if cooldown <= 0 {
		cooldown = time.Second
	}

	b.mu.Lock()
	b.streamFailoverThreshold = threshold
	b.streamFailoverCooldown = cooldown
	b.mu.Unlock()
}

func (b *Balancer) SetAutoDisableConfig(enabled bool, window time.Duration) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.autoDisableEnabled = enabled
	b.autoDisableTimeoutWindow = window
	b.mu.Unlock()
}

func (b *Balancer) SetResolverDisabledHandler(handler func(*Connection, string)) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.onResolverDisabled = handler
	b.mu.Unlock()
}

func (b *Balancer) SetResolverDownConfirmHandler(handler func(*Connection, time.Duration) bool) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.confirmResolverDown = handler
	b.mu.Unlock()
}

func (b *Balancer) SetConnections(connections []*Connection) {
	if b == nil {
		return
	}
	b.mu.Lock()
	for i := range b.pendingShards {
		shard := &b.pendingShards[i]
		shard.mu.Lock()
		if shard.pending == nil {
			shard.pending = make(map[balancerResolverSampleKey]balancerResolverSample)
		} else {
			clear(shard.pending)
		}
		shard.mu.Unlock()
	}
	b.pendingOverflow.Store(false)
	b.pendingSize.Store(0)

	if b.streamRoutes == nil {
		b.streamRoutes = make(map[uint16]*balancerStreamRouteState)
	} else {
		clear(b.streamRoutes)
	}
	b.mu.Unlock()

	if b.pool != nil {
		b.pool.SetConnections(connections)
	}
}

func (b *Balancer) ActiveCount() int {
	if b == nil || b.pool == nil {
		return 0
	}
	return b.pool.ActiveCount()
}

func (b *Balancer) TotalCount() int {
	if b == nil || b.pool == nil {
		return 0
	}
	return b.pool.TotalCount()
}

func (b *Balancer) GetConnectionByKey(key string) (Connection, bool) {
	if b == nil || b.pool == nil {
		return Connection{}, false
	}
	return b.pool.GetConnectionByKey(key)
}

func (b *Balancer) SetConnectionValidity(key string, valid bool) bool {
	return b.SetConnectionValidityWithLog(key, valid, false)
}

func (b *Balancer) SetConnectionValidityWithLog(key string, valid bool, logReactivated bool) bool {
	if b == nil || b.pool == nil {
		return false
	}
	if !valid {
		b.mu.Lock()
		b.clearPreferredResolverReferencesLocked(key)
		b.mu.Unlock()
	}
	return b.pool.SetConnectionValidity(key, valid)
}

func (b *Balancer) SetConnectionStandbyEligible(key string, eligible bool) bool {
	if b == nil || b.pool == nil {
		return false
	}
	return b.pool.SetConnectionStandbyEligible(key, eligible)
}

func (b *Balancer) IsConnectionStandbyEligible(key string) bool {
	if b == nil || b.pool == nil {
		return false
	}
	return b.pool.IsConnectionStandbyEligible(key)
}

func (b *Balancer) SetSessionSynchronizedMTU(uploadMTU, downloadMTU int) {
	if b == nil || b.pool == nil {
		return
	}
	b.pool.SetSessionMTU(uploadMTU, downloadMTU)
}

func (b *Balancer) SessionSynchronizedMTU() (int, int) {
	if b == nil || b.pool == nil {
		return 0, 0
	}
	return b.pool.SessionMTU()
}

func (b *Balancer) ActiveConnections() []Connection {
	if b == nil || b.pool == nil {
		return nil
	}
	return b.pool.ActiveResolvers()
}

func (b *Balancer) InactiveConnections() []Connection {
	if b == nil || b.pool == nil {
		return nil
	}
	return b.pool.InactiveConnections()
}

func (b *Balancer) AllConnections() []Connection {
	if b == nil || b.pool == nil {
		return nil
	}
	return b.pool.AllConnections()
}

func (b *Balancer) SetConnectionMTU(key string, uploadBytes int, uploadChars int, downloadBytes int) bool {
	if b == nil || b.pool == nil {
		return false
	}
	return b.pool.SetConnectionMTU(key, uploadBytes, uploadChars, downloadBytes)
}

func (b *Balancer) ApplyMTUProbeResult(key string, uploadBytes int, uploadChars int, downloadBytes int, resolveTime time.Duration, active bool) bool {
	if b == nil || b.pool == nil {
		return false
	}
	if !active {
		b.mu.Lock()
		b.clearPreferredResolverReferencesLocked(key)
		b.mu.Unlock()
	}
	return b.pool.ApplyMTUProbeResult(key, uploadBytes, uploadChars, downloadBytes, resolveTime, active)
}

func (b *Balancer) OptimizeActivePool() bool {
	if b == nil || b.pool == nil {
		return false
	}
	return b.pool.Optimize()
}

func (b *Balancer) GetRankedEndpoints(maxCount int) []config.ResolverAddress {
	if b == nil || b.pool == nil {
		return nil
	}
	return b.pool.RankedEndpoints(maxCount)
}

func (b *Balancer) NextInactiveConnectionForHealthCheck(now time.Time, minInterval time.Duration) (Connection, bool) {
	if b == nil || b.pool == nil {
		return Connection{}, false
	}
	return b.pool.AcquireNextInactiveForRecheck(now, minInterval)
}

func (b *Balancer) SeedBurstStats(key string, sent, acked int, rtt time.Duration) {
	if b == nil || b.pool == nil {
		return
	}
	b.pool.SeedBurstStats(key, sent, acked, rtt)
}

func (b *Balancer) SeedConservativeStats(key string) {
	if b == nil || b.pool == nil {
		return
	}
	b.pool.SeedConservativeStats(key)
}

func (b *Balancer) admitQualifiedBatch(results []QualifiedResolver, selected []Connection) {
	if b == nil || b.pool == nil {
		return
	}
	b.pool.AdmitStartupBatch(results, selected)
}

func (b *Balancer) finalizeFastStart(qualifiedKeys map[string]struct{}, target int) {
	if b == nil || b.pool == nil {
		return
	}
	b.pool.FinalizeFastStart(qualifiedKeys, target)
}

func (b *Balancer) beginConnectionRecheck(key string) bool {
	if b == nil || b.pool == nil {
		return false
	}
	return b.pool.beginConnectionRecheck(key)
}

func (b *Balancer) completeConnectionRecheck(result ResolverRecheckResult) (Connection, bool) {
	if b == nil || b.pool == nil {
		return Connection{}, false
	}
	return b.pool.CompleteRecheck(result)
}

// ResolverStatsSnapshot captures a point-in-time snapshot of resolver metrics.
type ResolverStatsSnapshot struct {
	Connection      Connection
	Sent            uint64
	Acked           uint64
	Lost            uint64
	LossRatio       float64
	AverageRTT      time.Duration
	ActiveStreams   int
	IsValid         bool
	StandbyEligible bool
}

// GetStatsSnapshot thread-safely exports current metrics for all loaded resolvers.
func (b *Balancer) GetStatsSnapshot() []ResolverStatsSnapshot {
	if b == nil || b.pool == nil {
		return nil
	}

	snapshots := b.pool.GetStatsSnapshot()

	b.mu.RLock()
	defer b.mu.RUnlock()

	// Count active streams assigned per resolver key
	streamCounts := make(map[string]int)
	for _, route := range b.streamRoutes {
		if route == nil {
			continue
		}
		route.mu.Lock()
		key := route.PreferredResolverKey
		route.mu.Unlock()
		if key != "" {
			streamCounts[key]++
		}
	}

	for i := range snapshots {
		snapshots[i].ActiveStreams = streamCounts[snapshots[i].Connection.Key]
	}

	return snapshots
}

// SnapshotResolverStats returns a point-in-time snapshot of metrics for all loaded resolvers.
func (b *Balancer) SnapshotResolverStats() []ResolverStatsSnapshot {
	return b.GetStatsSnapshot()
}

func (b *Balancer) ReportSend(serverKey string) {
	if b == nil {
		return
	}
	b.totalPacketsSent.Add(1)
	if stats := b.statsForKey(serverKey); stats != nil {
		stats.sent.Add(1)
		stats.applyHalfLife()
	}
}

// TotalPacketsSent returns the monotonic total number of tunnel packets sent through the balancer.
func (b *Balancer) TotalPacketsSent() uint64 {
	if b == nil {
		return 0
	}
	return b.totalPacketsSent.Load()
}

func (b *Balancer) ReportSuccess(serverKey string, rtt time.Duration) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return
	}

	stats.acked.Add(1)
	if rtt > 0 {
		stats.rttMicrosSum.Add(uint64(rtt / time.Microsecond))
		stats.rttCount.Add(1)
	}
	stats.applyHalfLife()
}

func (b *Balancer) ReportTimeout(serverKey string, now time.Time, window time.Duration, minActive int) bool {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return false
	}
	stats.lost.Add(1)
	stats.applyHalfLife()

	totalTimedOut, totalSent := stats.recordWindowTimeout(now, window)
	conn, ok := b.pool.GetConnectionByKey(serverKey)
	if !ok || !conn.IsValid {
		return false
	}

	activeCount := b.pool.ActiveCount()
	minObservations := autoDisableMinObservationsForActiveCount(activeCount, window)
	if int(totalSent) < minObservations || totalTimedOut != totalSent {
		return false
	}

	if minActive < 0 {
		minActive = 0
	}

	if minActive < 2 {
		minActive = 2
	}

	if activeCount <= minActive {
		return false
	}

	b.mu.RLock()
	confirmHandler := b.confirmResolverDown
	b.mu.RUnlock()

	confirmRequired := confirmHandler != nil && activeCount <= 20
	if confirmRequired {
		connCopy := conn
		down := confirmHandler(&connCopy, window)

		conn, ok = b.pool.GetConnectionByKey(serverKey)
		if !ok || !conn.IsValid {
			return false
		}

		if !down {
			stats.resetWindow()
			return false
		}
	}

	stats.resetWindow()
	b.mu.Lock()
	b.clearPreferredResolverReferencesLocked(serverKey)
	b.mu.Unlock()

	b.pool.SetConnectionValidity(serverKey, false)

	b.mu.RLock()
	handler := b.onResolverDisabled
	b.mu.RUnlock()
	if handler != nil {
		handler(&conn, "TIMEOUT")
	}

	if b.log != nil {
		b.log.Warnf("<red>DNS Resolver disabled (100%% Loss): <cyan>%s</cyan> <cyan>%s</cyan>) | <cyan>%s</cyan> | Remaining: <cyan>%d</cyan></red>",
			conn.ResolverLabel, conn.Domain, conn.Resolver, b.pool.ActiveCount())
	}

	return true
}

func autoDisableMinObservationsForActiveCount(active int, window time.Duration) int {
	switch {
	case active <= 3:
		return 1000000
	case active <= 5:
		return scaleAutoDisableMinObservations(48, window)
	case active <= 8:
		return scaleAutoDisableMinObservations(40, window)
	case active <= 10:
		return scaleAutoDisableMinObservations(34, window)
	case active <= 15:
		return scaleAutoDisableMinObservations(26, window)
	case active <= 20:
		return scaleAutoDisableMinObservations(22, window)
	case active <= 30:
		return scaleAutoDisableMinObservations(18, window)
	case active <= 40:
		return scaleAutoDisableMinObservations(15, window)
	case active <= 50:
		return scaleAutoDisableMinObservations(13, window)
	case active <= 75:
		return scaleAutoDisableMinObservations(10, window)
	case active <= 100:
		return scaleAutoDisableMinObservations(8, window)
	case active <= 150:
		return scaleAutoDisableMinObservations(7, window)
	default:
		return scaleAutoDisableMinObservations(6, window)
	}
}

func autoDisableCheckIntervalForActiveCount(active int, window time.Duration) time.Duration {
	interval := window / 30
	if interval <= 0 {
		interval = 3 * time.Second
	}
	if interval < time.Second {
		interval = time.Second
	}
	maxInterval := 5 * time.Second
	if window >= 60*time.Second {
		maxInterval = 12 * time.Second
	} else if window >= 30*time.Second {
		maxInterval = 8 * time.Second
	}

	if interval > maxInterval {
		interval = maxInterval
	}

	switch {
	case active <= 3:
		if interval < 5*time.Second {
			interval = 5 * time.Second
		}
	case active <= 5:
		if interval < 5*time.Second {
			interval = 5 * time.Second
		}
	case active <= 8:
		if interval < 4500*time.Millisecond {
			interval = 4500 * time.Millisecond
		}
	case active <= 10:
		if interval < 4*time.Second {
			interval = 4 * time.Second
		}
	case active <= 15:
		if interval < 3500*time.Millisecond {
			interval = 3500 * time.Millisecond
		}
	case active <= 20:
		if interval < 3*time.Second {
			interval = 3 * time.Second
		}
	case active <= 30:
		if interval < 2500*time.Millisecond {
			interval = 2500 * time.Millisecond
		}
	case active <= 50:
		if interval < 2*time.Second {
			interval = 2 * time.Second
		}
	case active <= 75:
		if interval < 1500*time.Millisecond {
			interval = 1500 * time.Millisecond
		}
	}

	return interval
}

func scaleAutoDisableMinObservations(base int, window time.Duration) int {
	if base <= 0 {
		return base
	}
	switch {
	case window >= 60*time.Second:
		return base * 3
	case window >= 30*time.Second:
		return base * 2
	default:
		return base
	}
}

func (b *Balancer) RetractTimeout(serverKey string, now time.Time, window time.Duration) bool {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return false
	}

	current := stats.lost.Load()
	if current > 0 {
		stats.lost.Add(^uint64(0)) // Atomic decrement
	}

	stats.applyHalfLife()
	return stats.retractWindowTimeout(now, window)
}

func (b *Balancer) TrackResolverSend(
	packet []byte,
	resolverAddr string,
	localAddr string,
	serverKey string,
	sentAt time.Time,
	tunnelPacketTimeout time.Duration,
) {
	if b == nil || len(packet) < 2 || resolverAddr == "" || serverKey == "" {
		return
	}

	b.mu.RLock()
	window := b.autoDisableTimeoutWindow
	b.mu.RUnlock()
	activeCount := 0
	if b.pool != nil {
		activeCount = b.pool.ActiveCount()
	}
	checkInterval := autoDisableCheckIntervalForActiveCount(activeCount, window)

	key := balancerResolverSampleKey{
		resolverAddr: resolverAddr,
		localAddr:    localAddr,
		dnsID:        binary.BigEndian.Uint16(packet[:2]),
	}

	requestTimeout := resolverRequestTimeout(tunnelPacketTimeout, checkInterval, window)

	if b.pendingSize.Load() >= resolverPendingHardCap {
		extra := int(b.pendingSize.Load()) - resolverPendingHardCap + 1
		if extra > 0 {
			b.evictSomePendingGlobal(extra)
		}
	}

	shard := b.pendingShardForKey(key)
	shard.mu.Lock()
	_, exists := shard.pending[key]
	if int(b.pendingSize.Load()) >= resolverPendingSoftCap {
		b.pendingOverflow.Store(true)
		b.setNextPendingSweepLocked(sentAt)
	}
	shard.pending[key] = balancerResolverSample{
		serverKey: serverKey,
		sentAt:    sentAt,
	}
	if !exists {
		b.pendingSize.Add(1)
	}
	b.schedulePendingSweepAt(sentAt.Add(requestTimeout))
	shard.mu.Unlock()

	b.ReportSend(serverKey)
	if stats := b.statsForKey(serverKey); stats != nil {
		stats.recordWindowSend(sentAt, window)
	}
}

func (b *Balancer) TrackResolverSuccess(
	packet []byte,
	addr *net.UDPAddr,
	localAddr string,
	receivedAt time.Time,
	rtt time.Duration,
) {
	if b == nil || len(packet) < 2 || addr == nil {
		return
	}

	b.mu.RLock()
	window := b.autoDisableTimeoutWindow
	b.mu.RUnlock()

	key := balancerResolverSampleKey{
		resolverAddr: addr.String(),
		localAddr:    localAddr,
		dnsID:        binary.BigEndian.Uint16(packet[:2]),
	}

	shard := b.pendingShardForKey(key)
	shard.mu.Lock()
	sample, ok := shard.pending[key]
	if ok {
		delete(shard.pending, key)
		b.pendingSize.Add(-1)
	}
	shard.mu.Unlock()

	if !ok || sample.serverKey == "" {
		return
	}
	if sample.timedOut && !sample.timedOutAt.IsZero() {
		b.RetractTimeout(sample.serverKey, receivedAt, window)
	}
	if !sample.sentAt.IsZero() && !receivedAt.Before(sample.sentAt) {
		rtt = receivedAt.Sub(sample.sentAt)
	}
	if rtt > 0 {
		b.ReportSuccess(sample.serverKey, rtt)
	}
}

func (b *Balancer) TrackResolverFailure(
	packet []byte,
	addr *net.UDPAddr,
	localAddr string,
	failedAt time.Time,
) {
	if b == nil || len(packet) < 2 || addr == nil {
		return
	}

	b.mu.RLock()
	autoDisable := b.autoDisableEnabled
	window := b.autoDisableTimeoutWindow
	b.mu.RUnlock()

	key := balancerResolverSampleKey{
		resolverAddr: addr.String(),
		localAddr:    localAddr,
		dnsID:        binary.BigEndian.Uint16(packet[:2]),
	}

	shard := b.pendingShardForKey(key)
	shard.mu.Lock()
	sample, ok := shard.pending[key]
	if ok {
		delete(shard.pending, key)
		b.pendingSize.Add(-1)
	}
	shard.mu.Unlock()

	if !ok || sample.serverKey == "" || sample.timedOut || !autoDisable {
		return
	}
	b.ReportTimeout(sample.serverKey, failedAt, window, 1)
}

func (b *Balancer) CollectExpiredResolverTimeouts(
	now time.Time,
	tunnelPacketTimeout time.Duration,
) {
	if b == nil {
		return
	}

	b.mu.RLock()
	autoDisable := b.autoDisableEnabled
	window := b.autoDisableTimeoutWindow
	b.mu.RUnlock()
	activeCount := 0
	if b.pool != nil {
		activeCount = b.pool.ActiveCount()
	}
	checkInterval := autoDisableCheckIntervalForActiveCount(activeCount, window)

	if !autoDisable {
		return
	}
	if !b.pendingOverflow.Load() && !b.pendingSweepDue(now) {
		return
	}

	requestTimeout := resolverRequestTimeout(tunnelPacketTimeout, checkInterval, window)
	ttl := resolverSampleTTL(tunnelPacketTimeout)
	var (
		timeoutObservations []balancerTimeoutObservation
		nextDue             time.Time
	)
	for i := range b.pendingShards {
		shard := &b.pendingShards[i]
		shard.mu.Lock()
		observations, shardNextDue, removedCount := b.prunePendingLocked(shard.pending, now, requestTimeout, ttl)
		if removedCount > 0 {
			b.pendingSize.Add(int32(-removedCount))
		}
		if len(observations) > 0 {
			timeoutObservations = append(timeoutObservations, observations...)
		}
		if nextDue.IsZero() || (!shardNextDue.IsZero() && shardNextDue.Before(nextDue)) {
			nextDue = shardNextDue
		}
		shard.mu.Unlock()
	}
	if overflow := int(b.pendingSize.Load()) - resolverPendingHardCap; overflow >= 0 {
		b.evictSomePendingGlobal(overflow + 1)
	}
	b.setNextPendingSweepLocked(nextDue)
	b.pendingOverflow.Store(false)

	for _, observation := range timeoutObservations {
		b.ReportTimeout(observation.serverKey, observation.at, window, 1)
	}
}

func (b *Balancer) ResetServerStats(serverKey string) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return
	}

	stats.sent.Store(0)
	stats.acked.Store(0)
	stats.lost.Store(0)
	stats.rttMicrosSum.Store(0)
	stats.rttCount.Store(0)
}

func (stats *connectionStats) seedConservative() {
	stats.sent.Store(10)
	stats.acked.Store(8)
	stats.lost.Store(0)
	stats.rttMicrosSum.Store(0)
	stats.rttCount.Store(0)
}

func (stats *connectionStats) seedBurst(sentCount int, ackedCount int, avgRTT time.Duration) {
	if sentCount < 1 {
		sentCount = 1
	}
	if ackedCount < 0 {
		ackedCount = 0
	}
	lost := sentCount - ackedCount
	if lost < 0 {
		lost = 0
	}

	stats.sent.Store(uint64(sentCount))
	stats.acked.Store(uint64(ackedCount))
	stats.lost.Store(uint64(lost))
	if avgRTT > 0 && ackedCount > 0 {
		stats.rttMicrosSum.Store(uint64(avgRTT/time.Microsecond) * uint64(ackedCount))
		stats.rttCount.Store(uint64(ackedCount))
	} else {
		stats.rttMicrosSum.Store(0)
		stats.rttCount.Store(0)
	}
}

func (b *Balancer) GetBestConnection() (Connection, bool) {
	if b == nil || b.pool == nil {
		return Connection{}, false
	}
	active := b.pool.ActiveResolvers()
	if len(active) == 0 {
		return Connection{}, false
	}

	switch b.strategy {
	case BalancingRandom:
		idx := b.nextRandom() % uint64(len(active))
		return active[idx], true
	default:
		if pool, pick, handled := b.strategyCandidatePoolLocked(active, ""); handled {
			if len(pool) == 0 {
				return b.roundRobinBestConnectionLocked(active)
			}
			return b.pickFromPoolLocked(pool, pick)
		}
		scorer, hasSignal := b.strategyScorerLocked(active)
		if scorer == nil {
			return b.roundRobinBestConnectionLocked(active)
		}

		if !hasSignal {
			return b.roundRobinBestConnectionLocked(active)
		}

		return b.bestScoredConnectionLocked(active, scorer)
	}
}

func (b *Balancer) GetBestConnectionExcluding(excludeKey string) (Connection, bool) {
	if b == nil || b.pool == nil {
		return Connection{}, false
	}
	active := b.pool.ActiveResolvers()
	if len(active) == 0 {
		return Connection{}, false
	}

	return b.getBestConnectionExcludingLocked(active, excludeKey)
}

func (b *Balancer) EnsureStream(streamID uint16) {
	if b == nil || streamID == 0 {
		return
	}

	b.mu.Lock()
	b.ensureStreamRouteLocked(streamID)
	b.mu.Unlock()
}

func (b *Balancer) CleanupStream(streamID uint16) {
	if b == nil || streamID == 0 {
		return
	}

	b.mu.Lock()
	delete(b.streamRoutes, streamID)
	b.mu.Unlock()
}

func (b *Balancer) NoteStreamProgress(streamID uint16) {
	if b == nil || streamID == 0 {
		return
	}

	b.mu.RLock()
	state := b.streamRoutes[streamID]
	b.mu.RUnlock()

	if state != nil {
		state.mu.Lock()
		state.ResendStreak = 0
		state.mu.Unlock()
	}
}

func (b *Balancer) SelectTargets(packetType uint8, streamID uint16, requiredCount int) ([]Connection, error) {
	if b == nil || b.pool == nil {
		return nil, ErrNoValidConnections
	}
	active := b.pool.ActiveResolvers()

	// 1. Normalize count: 1 <= requiredCount <= len(active)
	requiredCount = normalizeRequiredCount(len(active), requiredCount, 1)
	if requiredCount <= 0 {
		return nil, ErrNoValidConnections
	}

	// 2. Base case: Single target or non-stream packet is ALWAYS dynamic via balancer
	if requiredCount == 1 || streamID == 0 || !isBalancerStreamDataLike(packetType) {
		selected := b.getUniqueConnectionsLocked(active, requiredCount)
		if len(selected) == 0 {
			return nil, ErrNoValidConnections
		}
		return selected, nil
	}

	// 3. Duplication case: Multi-path stream routing (Preferred + Dynamic Others)
	b.mu.RLock()
	state := b.streamRoutes[streamID]
	b.mu.RUnlock()

	if state == nil {
		// No state? Fallback to dynamic balancer
		return b.getUniqueConnectionsLocked(active, requiredCount), nil
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	// Get the sticky preferred resolver for the main path
	preferred, ok := b.selectPreferredConnectionForStreamLocked(active, packetType, state)
	if !ok {
		return b.getUniqueConnectionsLocked(active, requiredCount), nil
	}

	// Combine Preferred + Dynamic Others
	selected := make([]Connection, 0, requiredCount)
	selected = append(selected, preferred)

	if remaining := requiredCount - 1; remaining > 0 {
		others := b.getUniqueConnectionsExcludingLocked(active, remaining, preferred.Key)
		selected = append(selected, others...)
	}

	return selected, nil
}

func (b *Balancer) AverageRTT(serverKey string) (time.Duration, bool) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return 0, false
	}

	_, _, _, sum, count := stats.snapshot()
	if count == 0 {
		return 0, false
	}

	return time.Duration(sum/count) * time.Microsecond, true
}

func (b *Balancer) ensureStreamRouteLocked(streamID uint16) *balancerStreamRouteState {
	if streamID == 0 {
		return nil
	}

	state := b.streamRoutes[streamID]

	if state == nil {
		state = &balancerStreamRouteState{}
		b.streamRoutes[streamID] = state
	}

	return state
}

func isBalancerStreamDataLike(packetType uint8) bool {
	return packetType == Enums.PACKET_STREAM_DATA || packetType == Enums.PACKET_STREAM_RESEND
}

func (b *Balancer) selectPreferredConnectionForStreamLocked(active []Connection, packetType uint8, state *balancerStreamRouteState) (Connection, bool) {
	if state == nil {
		return Connection{}, false
	}

	// 1. Check for Failover (Streak reached during resend)
	if packetType == Enums.PACKET_STREAM_RESEND {
		state.ResendStreak++
		if current, ok := b.validPreferredConnectionLocked(active, state); ok {
			// Stay on current until threshold or cooldown
			if state.ResendStreak < b.streamFailoverThreshold || (time.Since(state.LastFailoverAt) < b.streamFailoverCooldown) {
				return current, true
			}

			// Failover triggered: Choose absolute best alternate
			if replacement, ok := b.selectAlternateConnectionLocked(active, current.Key); ok {
				state.PreferredResolverKey = replacement.Key
				state.ResendStreak = 0
				state.LastFailoverAt = time.Now()
				return replacement, true
			}
			return current, true
		}
	}

	// 2. Return current preferred if it is still valid
	if current, ok := b.validPreferredConnectionLocked(active, state); ok {
		return current, true
	}

	// 3. Current is dead or missing: Select a new one
	var replacement Connection
	var ok bool

	if state.PreferredResolverKey == "" {
		// New stream: Use "Top 10 Random" to distribute load
		replacement, ok = b.selectInitialPreferredConnectionLocked(active)
	} else {
		// Recovery from dead resolver: Use absolute best alternate
		replacement, ok = b.selectAlternateConnectionLocked(active, state.PreferredResolverKey)
	}

	if ok {
		state.PreferredResolverKey = replacement.Key
		state.ResendStreak = 0
		return replacement, true
	}

	return Connection{}, false
}

func (b *Balancer) validPreferredConnectionLocked(active []Connection, state *balancerStreamRouteState) (Connection, bool) {
	if state == nil || state.PreferredResolverKey == "" {
		return Connection{}, false
	}
	for _, conn := range active {
		if conn.Key == state.PreferredResolverKey && conn.IsValid {
			return conn, true
		}
	}
	return Connection{}, false
}

func (b *Balancer) selectAlternateConnectionLocked(active []Connection, excludeKey string) (Connection, bool) {
	if excludeKey != "" {
		if replacement, ok := b.getBestConnectionExcludingLocked(active, excludeKey); ok {
			return replacement, true
		}
	}

	selected := b.getUniqueConnectionsLocked(active, 1)
	if len(selected) == 0 {
		return Connection{}, false
	}
	if excludeKey == "" || selected[0].Key != excludeKey {
		return selected[0], true
	}
	if replacement, ok := b.getBestConnectionExcludingLocked(active, excludeKey); ok {
		return replacement, true
	}
	return Connection{}, false
}

func (b *Balancer) selectInitialPreferredConnectionLocked(active []Connection) (Connection, bool) {
	if len(active) == 0 {
		return Connection{}, false
	}

	switch b.strategy {
	case BalancingRandom, BalancingRoundRobin, BalancingRoundRobinDefault:
		return b.selectTargetByStrategyLocked(active)
	default:
		if pool, pick, handled := b.strategyCandidatePoolLocked(active, ""); handled {
			if len(pool) == 0 {
				return b.selectTargetByStrategyLocked(active)
			}
			return b.pickFromPoolLocked(pool, pick)
		}
		scorer, hasSignal := b.strategyScorerLocked(active)
		if scorer == nil {
			return b.selectTargetByStrategyLocked(active)
		}

		if !hasSignal {
			return b.selectTargetByStrategyLocked(active)
		}

		topN := 10
		if len(active) < topN {
			topN = len(active)
		}

		pool := b.selectLowestScoreLocked(active, topN, scorer)
		if len(pool) == 0 {
			return b.selectTargetByStrategyLocked(active)
		}

		return b.pickFromPoolLocked(pool, poolPickRandom)
	}
}

func (b *Balancer) getUniqueConnectionsExcludingLocked(active []Connection, requiredCount int, excludeKey string) []Connection {
	if requiredCount <= 0 || len(active) == 0 {
		return nil
	}

	all := b.getUniqueConnectionsLocked(active, requiredCount+1)
	selected := make([]Connection, 0, requiredCount)
	for _, conn := range all {
		if conn.Key == excludeKey {
			continue
		}
		selected = append(selected, conn)
		if len(selected) >= requiredCount {
			break
		}
	}
	return selected
}

func (b *Balancer) clearPreferredResolverReferencesLocked(serverKey string) {
	if serverKey == "" {
		return
	}
	for _, state := range b.streamRoutes {
		if state == nil {
			continue
		}
		state.mu.Lock()
		if state.PreferredResolverKey == serverKey {
			state.PreferredResolverKey = ""
			state.ResendStreak = 0
		}
		state.mu.Unlock()
	}
}

func (b *Balancer) statsForKey(serverKey string) *connectionStats {
	if b == nil || b.pool == nil {
		return nil
	}
	return b.pool.statsForKey(serverKey)
}

func (b *Balancer) connectionByKeyLocked(serverKey string) (*Connection, bool) {
	if b == nil || b.pool == nil {
		return nil, false
	}
	conn, ok := b.pool.GetConnectionByKey(serverKey)
	if !ok {
		return nil, false
	}
	return &conn, true
}

func (s *connectionStats) ensureWindowLocked(now time.Time, window time.Duration) {
	if s == nil {
		return
	}

	if now.IsZero() {
		now = time.Now()
	}

	if window <= 0 {
		s.windowStartedAt.CompareAndSwap(0, now.UnixNano())
		return
	}

	nowUnix := now.UnixNano()
	startedAt := s.windowStartedAt.Load()

	if startedAt == 0 || (nowUnix-startedAt) >= window.Nanoseconds() {
		if s.windowStartedAt.CompareAndSwap(startedAt, nowUnix) {
			s.windowSent.Store(0)
			s.windowLost.Store(0)
		}
	}
}

func (s *connectionStats) recordWindowSend(now time.Time, window time.Duration) {
	if s == nil {
		return
	}
	s.windowMu.Lock()
	s.ensureWindowLocked(now, window)
	s.windowSent.Add(1)
	s.windowMu.Unlock()
}

func (s *connectionStats) recordWindowTimeout(now time.Time, window time.Duration) (uint32, uint32) {
	if s == nil {
		return 0, 0
	}
	s.windowMu.Lock()
	s.ensureWindowLocked(now, window)
	totalTimedOut := s.windowLost.Add(1)
	totalSent := s.windowSent.Load()
	s.windowMu.Unlock()
	return totalTimedOut, totalSent
}

func (s *connectionStats) retractWindowTimeout(now time.Time, window time.Duration) bool {
	if s == nil {
		return false
	}
	s.windowMu.Lock()
	defer s.windowMu.Unlock()
	s.ensureWindowLocked(now, window)
	for {
		currentLost := s.windowLost.Load()
		if currentLost == 0 {
			return false
		}
		if s.windowLost.CompareAndSwap(currentLost, currentLost-1) {
			return true
		}
	}
}

func (s *connectionStats) resetWindow() {
	if s == nil {
		return
	}
	s.windowMu.Lock()
	defer s.windowMu.Unlock()
	s.windowStartedAt.Store(0)
	s.windowSent.Store(0)
	s.windowLost.Store(0)
}

func normalizeRequiredCount(validCount, requiredCount, defaultIfInvalid int) int {
	if validCount <= 0 {
		return 0
	}

	if requiredCount <= 0 {
		requiredCount = defaultIfInvalid
	}

	if requiredCount > validCount {
		return validCount
	}

	return requiredCount
}

const (
	resolverPendingSoftCap    = 8192
	resolverPendingHardCap    = 12288
	resolverPendingShardCount = 16
)

func resolverSampleTTL(tunnelPacketTimeout time.Duration) time.Duration {
	ttl := tunnelPacketTimeout * 3
	if ttl < 10*time.Second {
		ttl = 10 * time.Second
	}
	if ttl > 45*time.Second {
		ttl = 45 * time.Second
	}
	return ttl
}

func resolverRequestTimeout(tunnelPacketTimeout time.Duration, checkInterval time.Duration, window time.Duration) time.Duration {
	timeout := tunnelPacketTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if checkInterval > 0 && checkInterval < timeout {
		timeout = checkInterval
	}
	if window > 0 && window < timeout {
		timeout = window
	}
	if timeout < 500*time.Millisecond {
		timeout = 500 * time.Millisecond
	}
	return timeout
}

func resolverLateResponseGrace(requestTimeout time.Duration, ttl time.Duration) time.Duration {
	if requestTimeout <= 0 {
		requestTimeout = 5 * time.Second
	}
	grace := requestTimeout * 3
	if grace < time.Second {
		grace = time.Second
	}
	if ttl > 0 && grace > ttl {
		grace = ttl
	}
	return grace
}

func (b *Balancer) pendingSweepDue(now time.Time) bool {
	if b == nil {
		return false
	}
	nextUnix := b.nextPendingSweep.Load()
	return nextUnix == 0 || now.UnixNano() >= nextUnix
}

func (b *Balancer) schedulePendingSweepAt(next time.Time) {
	if b == nil || next.IsZero() {
		return
	}
	nextUnix := next.UnixNano()
	for {
		current := b.nextPendingSweep.Load()
		if current != 0 && current <= nextUnix {
			return
		}
		if b.nextPendingSweep.CompareAndSwap(current, nextUnix) {
			return
		}
	}
}

func (b *Balancer) setNextPendingSweepLocked(next time.Time) {
	if b == nil {
		return
	}
	if next.IsZero() {
		b.nextPendingSweep.Store(0)
		return
	}
	b.nextPendingSweep.Store(next.UnixNano())
}

func (b *Balancer) prunePendingLocked(pending map[balancerResolverSampleKey]balancerResolverSample, now time.Time, requestTimeout time.Duration, ttl time.Duration) ([]balancerTimeoutObservation, time.Time, int) {
	if b == nil || len(pending) == 0 {
		return nil, time.Time{}, 0
	}

	timeoutBefore := now.Add(-requestTimeout)
	absoluteCutoff := now.Add(-ttl)
	lateGrace := resolverLateResponseGrace(requestTimeout, ttl)
	var timeoutObservations []balancerTimeoutObservation
	var nextDue time.Time
	removedCount := 0

	for key, sample := range pending {
		if !sample.timedOut {
			timeoutAt := sample.sentAt.Add(requestTimeout)
			if !sample.sentAt.After(timeoutBefore) {
				sample.timedOut = true
				sample.timedOutAt = timeoutAt
				if sample.timedOutAt.After(now) {
					sample.timedOutAt = now
				}
				sample.evictAfter = sample.timedOutAt.Add(lateGrace)
				pending[key] = sample
				if sample.serverKey != "" {
					timeoutObservations = append(timeoutObservations, balancerTimeoutObservation{
						serverKey: sample.serverKey,
						at:        sample.timedOutAt,
					})
				}
			} else if nextDue.IsZero() || timeoutAt.Before(nextDue) {
				nextDue = timeoutAt
			}
			if sample.sentAt.Before(absoluteCutoff) {
				delete(pending, key)
				removedCount++
			}
			continue
		}

		if !sample.evictAfter.IsZero() && !sample.evictAfter.After(now) {
			delete(pending, key)
			removedCount++
			continue
		}
		if sample.sentAt.Before(absoluteCutoff) {
			delete(pending, key)
			removedCount++
			continue
		}
		evictAt := sample.evictAfter
		if evictAt.IsZero() {
			evictAt = sample.sentAt.Add(ttl)
		}
		if nextDue.IsZero() || evictAt.Before(nextDue) {
			nextDue = evictAt
		}
	}

	return timeoutObservations, nextDue, removedCount
}

func (b *Balancer) evictSomePendingGlobal(evictCount int) {
	if b == nil || evictCount <= 0 {
		return
	}
	for evictCount > 0 {
		removedAny := false
		start := int(b.pendingEvictRR.Add(1)-1) % resolverPendingShardCount
		for i := 0; i < resolverPendingShardCount && evictCount > 0; i++ {
			shard := &b.pendingShards[(start+i)%resolverPendingShardCount]
			shard.mu.Lock()
			for key := range shard.pending {
				delete(shard.pending, key)
				b.pendingSize.Add(-1)
				evictCount--
				removedAny = true
				break
			}
			shard.mu.Unlock()
		}
		if !removedAny {
			return
		}
	}
}

func (b *Balancer) pendingShardForKey(key balancerResolverSampleKey) *balancerPendingShard {
	if b == nil {
		return nil
	}
	idx := pendingShardIndex(key)
	return &b.pendingShards[idx]
}

func pendingShardIndex(key balancerResolverSampleKey) int {
	hash := uint32(key.dnsID)
	for i := 0; i < len(key.resolverAddr); i++ {
		hash = hash*33 + uint32(key.resolverAddr[i])
	}
	for i := 0; i < len(key.localAddr); i++ {
		hash = hash*33 + uint32(key.localAddr[i])
	}
	return int(hash % resolverPendingShardCount)
}

func (b *Balancer) pendingCount() int {
	if b == nil {
		return 0
	}
	return int(b.pendingSize.Load())
}

func (b *Balancer) pendingStoreForTest(key balancerResolverSampleKey, sample balancerResolverSample) {
	if b == nil {
		return
	}
	shard := b.pendingShardForKey(key)
	shard.mu.Lock()
	if _, exists := shard.pending[key]; !exists {
		b.pendingSize.Add(1)
	}
	shard.pending[key] = sample
	shard.mu.Unlock()
}

func (b *Balancer) pendingLookupForTest(key balancerResolverSampleKey) (balancerResolverSample, bool) {
	if b == nil {
		return balancerResolverSample{}, false
	}
	shard := b.pendingShardForKey(key)
	shard.mu.Lock()
	sample, ok := shard.pending[key]
	shard.mu.Unlock()
	return sample, ok
}

func (b *Balancer) GetUniqueConnections(requiredCount int) []Connection {
	if b == nil || b.pool == nil {
		return nil
	}
	active := b.pool.ActiveResolvers()
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.getUniqueConnectionsLocked(active, requiredCount)
}

func (b *Balancer) getUniqueConnectionsLocked(active []Connection, requiredCount int) []Connection {
	count := normalizeRequiredCount(len(active), requiredCount, 1)
	if count <= 0 {
		return nil
	}

	switch b.strategy {
	case BalancingRandom:
		return b.selectRandomLocked(active, count)
	default:
		if pool, pick, handled := b.strategyCandidatePoolLocked(active, ""); handled {
			if len(pool) == 0 {
				return b.selectRoundRobinLocked(active, count)
			}
			return b.limitConnectionPoolLocked(pool, count, pick)
		}
		scorer, hasSignal := b.strategyScorerLocked(active)
		if scorer == nil {
			return b.selectRoundRobinLocked(active, count)
		}

		if !hasSignal {
			return b.selectRoundRobinLocked(active, count)
		}

		return b.selectLowestScoreLocked(active, count, scorer)
	}
}

func (b *Balancer) selectTargetByStrategyLocked(active []Connection) (Connection, bool) {
	selected := b.getUniqueConnectionsLocked(active, 1)
	if len(selected) == 0 {
		return Connection{}, false
	}
	return selected[0], true
}

func (b *Balancer) getBestConnectionExcludingLocked(active []Connection, excludeKey string) (Connection, bool) {
	switch b.strategy {
	case BalancingRandom:
		ordered := b.rotatedActiveConnections(active, 1)
		for _, conn := range ordered {
			if conn.Key == excludeKey {
				continue
			}
			return conn, true
		}
		return Connection{}, false
	default:
		if pool, pick, handled := b.strategyCandidatePoolLocked(active, excludeKey); handled {
			if len(pool) == 0 {
				return b.roundRobinBestConnectionExcludingLocked(active, excludeKey)
			}
			return b.pickFromPoolLocked(pool, pick)
		}
		scorer, hasSignal := b.strategyScorerLocked(active)
		if scorer == nil {
			return b.roundRobinBestConnectionExcludingLocked(active, excludeKey)
		}

		if !hasSignal {
			return b.roundRobinBestConnectionExcludingLocked(active, excludeKey)
		}

		return b.bestScoredConnectionExcludingLocked(active, scorer, excludeKey)
	}
}

func (b *Balancer) selectRoundRobinLocked(active []Connection, count int) []Connection {
	n := len(active)
	if n == 0 || count <= 0 {
		return nil
	}
	start := roundRobinStartIndex(b.rrCounter.Add(uint64(count))-uint64(count), n)
	selected := make([]Connection, count)
	for i := 0; i < count; i++ {
		selected[i] = active[(start+i)%n]
	}
	return selected
}

func (b *Balancer) selectRandomLocked(active []Connection, count int) []Connection {
	n := len(active)
	if count <= 0 || n == 0 {
		return nil
	}
	if count == 1 {
		idx := b.nextRandom() % uint64(n)
		return []Connection{active[idx]}
	}

	indices := make([]int, n)
	for i := 0; i < n; i++ {
		indices[i] = i
	}
	for i := 0; i < count; i++ {
		j := i + int(b.nextRandom()%uint64(n-i))
		indices[i], indices[j] = indices[j], indices[i]
	}
	selected := make([]Connection, count)
	for i := 0; i < count; i++ {
		selected[i] = active[indices[i]]
	}
	return selected
}

func (b *Balancer) selectLowestScoreLocked(active []Connection, count int, scorer func(conn Connection) uint64) []Connection {
	n := len(active)
	if count <= 0 || n == 0 {
		return nil
	}
	if count == 1 {
		conn, ok := b.bestScoredConnectionLocked(active, scorer)
		if ok {
			return []Connection{conn}
		}
		return nil
	}

	type scoredConn struct {
		conn  Connection
		score uint64
	}

	ordered := b.rotatedActiveConnections(active, count)
	scored := make([]scoredConn, n)
	for i, conn := range ordered {
		scored[i] = scoredConn{conn: conn, score: scorer(conn)}
	}

	for i := 0; i < count && i < n; i++ {
		minIdx := i
		for j := i + 1; j < n; j++ {
			if scored[j].score < scored[minIdx].score {
				minIdx = j
			}
		}
		scored[i], scored[minIdx] = scored[minIdx], scored[i]
	}

	selected := make([]Connection, count)
	for i := 0; i < count; i++ {
		selected[i] = scored[i].conn
	}
	return selected
}

func (b *Balancer) bestScoredConnectionLocked(active []Connection, scorer func(conn Connection) uint64) (Connection, bool) {
	if len(active) == 0 {
		return Connection{}, false
	}
	ordered := b.rotatedActiveConnections(active, 1)
	bestIndex := -1
	var bestScore uint64
	for i, conn := range ordered {
		score := scorer(conn)
		if bestIndex == -1 || score < bestScore {
			bestIndex = i
			bestScore = score
		}
	}
	if bestIndex < 0 {
		return Connection{}, false
	}
	return ordered[bestIndex], true
}

func (b *Balancer) bestScoredConnectionExcludingLocked(active []Connection, scorer func(conn Connection) uint64, excludeKey string) (Connection, bool) {
	if len(active) == 0 {
		return Connection{}, false
	}
	ordered := b.rotatedActiveConnections(active, 1)
	bestIndex := -1
	var bestScore uint64
	for i, conn := range ordered {
		if conn.Key == excludeKey {
			continue
		}
		score := scorer(conn)
		if bestIndex == -1 || score < bestScore {
			bestIndex = i
			bestScore = score
		}
	}
	if bestIndex < 0 {
		return Connection{}, false
	}
	return ordered[bestIndex], true
}

func (b *Balancer) roundRobinBestConnectionLocked(active []Connection) (Connection, bool) {
	if len(active) == 0 {
		return Connection{}, false
	}
	pos := roundRobinStartIndex(b.rrCounter.Add(1)-1, len(active))
	return active[pos], true
}

func (b *Balancer) roundRobinBestConnectionExcludingLocked(active []Connection, excludeKey string) (Connection, bool) {
	if len(active) == 0 {
		return Connection{}, false
	}
	for _, conn := range b.rotatedActiveConnections(active, 1) {
		if conn.Key == excludeKey {
			continue
		}
		return conn, true
	}
	return Connection{}, false
}

func (b *Balancer) rotatedActiveConnections(active []Connection, step int) []Connection {
	n := len(active)
	if n == 0 {
		return nil
	}
	if step < 1 {
		step = 1
	}

	start := roundRobinStartIndex(b.rrCounter.Add(uint64(step))-uint64(step), n)
	ordered := make([]Connection, n)
	for i := range active {
		ordered[i] = active[(start+i)%n]
	}
	return ordered
}

func roundRobinStartIndex(counter uint64, n int) int {
	if n <= 0 {
		return 0
	}
	return int(counter % uint64(n))
}

func (b *Balancer) hasLossSignalLocked(active []Connection) bool {
	for _, conn := range active {
		stats := b.statsForKey(conn.Key)
		if stats == nil {
			continue
		}
		sent, _, _, _, _ := stats.snapshot()
		if sent > 0 {
			return true
		}
	}
	return false
}

func (b *Balancer) hasLatencySignalLocked(active []Connection) bool {
	for _, conn := range active {
		stats := b.statsForKey(conn.Key)
		if stats == nil {
			continue
		}
		_, _, _, _, count := stats.snapshot()
		if count > 0 {
			return true
		}
	}
	return false
}

func (b *Balancer) hasHybridSignalLocked(active []Connection) bool {
	return b.hasLossSignalLocked(active) || b.hasLatencySignalLocked(active)
}

func (b *Balancer) strategyScorerLocked(active []Connection) (func(conn Connection) uint64, bool) {
	switch b.strategy {
	case BalancingLeastLoss:
		return b.lossScoreLocked, b.hasLossSignalLocked(active)
	case BalancingLowestLatency:
		return b.latencyScoreLocked, b.hasLatencySignalLocked(active)
	case BalancingHybridScore:
		return b.hybridScoreLocked, b.hasHybridSignalLocked(active)
	default:
		return nil, false
	}
}

type balancerPoolPick int

const (
	poolPickRandom balancerPoolPick = iota
	poolPickRoundRobin
)

func (b *Balancer) strategyCandidatePoolLocked(active []Connection, excludeKey string) ([]Connection, balancerPoolPick, bool) {
	switch b.strategy {
	case BalancingLossThenLatency:
		if !b.hasHybridSignalLocked(active) {
			return nil, poolPickRandom, true
		}
		return b.lossThenLatencyCandidatesLocked(active, excludeKey), poolPickRandom, true
	case BalancingLeastLossTopRandom:
		if !b.hasLossSignalLocked(active) {
			return nil, poolPickRandom, true
		}
		return b.leastLossTopTierCandidatesLocked(active, excludeKey), poolPickRandom, true
	case BalancingLeastLossTopRoundRobin:
		if !b.hasLossSignalLocked(active) {
			return nil, poolPickRoundRobin, true
		}
		return b.leastLossTopTierCandidatesLocked(active, excludeKey), poolPickRoundRobin, true
	default:
		return nil, poolPickRandom, false
	}
}

func (b *Balancer) pickFromPoolLocked(pool []Connection, pick balancerPoolPick) (Connection, bool) {
	if len(pool) == 0 {
		return Connection{}, false
	}
	switch pick {
	case poolPickRoundRobin:
		pos := roundRobinStartIndex(b.rrCounter.Add(1)-1, len(pool))
		return pool[pos], true
	default:
		return pool[b.nextRandom()%uint64(len(pool))], true
	}
}

func (b *Balancer) limitConnectionPoolLocked(pool []Connection, count int, pick balancerPoolPick) []Connection {
	if len(pool) == 0 || count <= 0 {
		return nil
	}
	if count >= len(pool) {
		return pool
	}
	switch pick {
	case poolPickRoundRobin:
		start := roundRobinStartIndex(b.rrCounter.Add(uint64(count))-uint64(count), len(pool))
		ordered := make([]Connection, len(pool))
		for i := range pool {
			ordered[i] = pool[(start+i)%len(pool)]
		}
		return ordered[:count]
	default:
		if count == 1 {
			idx := int(b.nextRandom() % uint64(len(pool)))
			pool[0] = pool[idx]
			return pool[:1:1]
		}
		for i := 0; i < count; i++ {
			j := i + int(b.nextRandom()%uint64(len(pool)-i))
			pool[i], pool[j] = pool[j], pool[i]
		}
		return pool[:count:count]
	}
}

func (b *Balancer) lossThenLatencyCandidatesLocked(active []Connection, excludeKey string) []Connection {
	type candidate struct {
		conn    Connection
		loss    uint64
		latency uint64
		hasRTT  bool
	}

	if !b.hasHybridSignalLocked(active) || len(active) == 0 {
		return nil
	}

	candidates := make([]candidate, 0, len(active))
	bestLoss := ^uint64(0)
	for _, conn := range active {
		if excludeKey != "" && conn.Key == excludeKey {
			continue
		}
		loss := b.lossScoreLocked(conn)
		latency := b.hybridLatencyPenaltyLocked(conn)
		hasRTT := false
		stats := b.statsForKey(conn.Key)
		if stats != nil {
			_, _, _, _, count := stats.snapshot()
			hasRTT = count > 0
		}
		if loss < bestLoss {
			bestLoss = loss
		}
		candidates = append(candidates, candidate{
			conn:    conn,
			loss:    loss,
			latency: latency,
			hasRTT:  hasRTT,
		})
	}
	if len(candidates) == 0 {
		return nil
	}

	lossTolerance := uint64(25)
	if bestLoss >= 200 {
		lossTolerance = 0
	}
	lossCutoff := bestLoss + lossTolerance

	lossShortlist := make([]candidate, 0, len(candidates))
	bestLatency := ^uint64(0)
	for _, cand := range candidates {
		if cand.loss > lossCutoff {
			continue
		}
		lossShortlist = append(lossShortlist, cand)
		if cand.hasRTT && cand.latency < bestLatency {
			bestLatency = cand.latency
		}
	}
	if len(lossShortlist) == 0 {
		return nil
	}

	if bestLatency == ^uint64(0) {
		selected := make([]Connection, 0, len(lossShortlist))
		for _, cand := range lossShortlist {
			selected = append(selected, cand.conn)
		}
		return selected
	}

	latencyTolerance := latencyToleranceForTier(bestLatency)
	latencyCutoff := bestLatency + latencyTolerance

	selected := make([]Connection, 0, len(lossShortlist))
	for _, cand := range lossShortlist {
		if !cand.hasRTT || cand.latency <= latencyCutoff {
			selected = append(selected, cand.conn)
		}
	}
	if len(selected) > 0 {
		return selected
	}

	return []Connection{lossShortlist[0].conn}
}

func latencyToleranceForTier(bestLatency uint64) uint64 {
	if bestLatency >= 200 {
		return 0
	}

	tolerance := bestLatency / 4
	if tolerance < 2 {
		tolerance = 2
	}
	if tolerance > 25 {
		tolerance = 25
	}
	return tolerance
}

func (b *Balancer) leastLossTopTierCandidatesLocked(active []Connection, excludeKey string) []Connection {
	type candidate struct {
		conn Connection
		loss uint64
	}

	if !b.hasLossSignalLocked(active) || len(active) == 0 {
		return nil
	}

	candidates := make([]candidate, 0, len(active))
	for _, conn := range active {
		if excludeKey != "" && conn.Key == excludeKey {
			continue
		}
		candidates = append(candidates, candidate{
			conn: conn,
			loss: b.lossScoreLocked(conn),
		})
	}
	if len(candidates) == 0 {
		return nil
	}

	topCount := max(2, (len(candidates)+9)/10)
	if topCount > len(candidates) {
		topCount = len(candidates)
	}

	for i := 0; i < topCount; i++ {
		minIdx := i
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].loss < candidates[minIdx].loss {
				minIdx = j
			}
		}
		candidates[i], candidates[minIdx] = candidates[minIdx], candidates[i]
	}

	selected := make([]Connection, 0, topCount)
	for i := 0; i < topCount; i++ {
		selected = append(selected, candidates[i].conn)
	}
	return selected
}

func (b *Balancer) lossScoreLocked(conn Connection) uint64 {
	stats := b.statsForKey(conn.Key)
	if stats == nil {
		return 0
	}
	sent, _, lost, _, _ := stats.snapshot()
	if sent == 0 || lost == 0 {
		return 0
	}
	return (lost * 1000) / sent
}

func (b *Balancer) latencyScoreLocked(conn Connection) uint64 {
	stats := b.statsForKey(conn.Key)
	if stats == nil {
		return 999000
	}
	_, _, _, sum, count := stats.snapshot()
	if count == 0 {
		return 999000
	}
	return sum / count
}

func (b *Balancer) hybridScoreLocked(conn Connection) uint64 {
	lossPenalty := b.lossScoreLocked(conn)
	latencyPenalty := b.hybridLatencyPenaltyLocked(conn)
	return lossPenalty*8 + latencyPenalty
}

func (b *Balancer) hybridLatencyPenaltyLocked(conn Connection) uint64 {
	latencyMicros := b.latencyScoreLocked(conn)
	if latencyMicros == 999000 {
		return 200
	}

	latencyMillis := latencyMicros / 1000
	if latencyMillis > 1000 {
		return 1000
	}

	return latencyMillis
}

func (s *connectionStats) snapshot() (sent uint64, acked uint64, lost uint64, rttMicrosSum uint64, rttCount uint64) {
	if s == nil {
		return 0, 0, 0, 0, 0
	}

	sent = s.sent.Load()
	acked = s.acked.Load()
	lost = s.lost.Load()
	rttMicrosSum = s.rttMicrosSum.Load()
	rttCount = s.rttCount.Load()
	return sent, acked, lost, rttMicrosSum, rttCount
}

func (s *connectionStats) applyHalfLife() {
	if s == nil {
		return
	}

	sent := s.sent.Load()
	acked := s.acked.Load()
	lost := s.lost.Load()
	rttCount := s.rttCount.Load()

	if sent <= connectionStatsHalfLifeThreshold &&
		acked <= connectionStatsHalfLifeThreshold &&
		lost <= connectionStatsHalfLifeThreshold &&
		rttCount <= connectionStatsHalfLifeThreshold {
		return
	}

	if !s.halfLifeRunning.CompareAndSwap(false, true) {
		return
	}
	defer s.halfLifeRunning.Store(false)

	halveUint64 := func(counter *atomic.Uint64) {
		for {
			current := counter.Load()
			if current == 0 {
				return
			}
			if counter.CompareAndSwap(current, current/2) {
				return
			}
		}
	}

	halveUint64(&s.sent)
	halveUint64(&s.acked)
	halveUint64(&s.lost)
	halveUint64(&s.rttMicrosSum)
	halveUint64(&s.rttCount)
}

func (b *Balancer) nextRandom() uint64 {
	for {
		current := b.rngState.Load()
		next := xorshift64(current)
		if b.rngState.CompareAndSwap(current, next) {
			return next
		}
	}
}

func seedRNG() uint64 {
	seed := uint64(time.Now().UnixNano())
	if seed == 0 {
		return 0x9e3779b97f4a7c15
	}
	return seed
}

func xorshift64(v uint64) uint64 {
	if v == 0 {
		v = 0x9e3779b97f4a7c15
	}
	v ^= v << 13
	v ^= v >> 7
	v ^= v << 17
	return v
}
