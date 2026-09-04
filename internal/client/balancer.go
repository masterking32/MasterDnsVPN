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
	"math"
	"net"
	"sort"
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
	strategy         int
	rrCounter        atomic.Uint64
	healthRRCounter  atomic.Uint64
	rngState         atomic.Uint64
	nextPendingSweep atomic.Int64
	pendingOverflow  atomic.Bool
	pendingSize      atomic.Int32
	pendingEvictRR   atomic.Uint32

	mu                  sync.RWMutex
	log                 *logger.Logger
	maxActiveResolvers  int
	connections         []Connection
	indexByKey          map[string]int
	activeIDs           []int
	inactiveIDs         []int
	stats               []*connectionStats
	streamRoutes        map[uint16]*balancerStreamRouteState

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

func NewBalancer(strategy int, log *logger.Logger) *Balancer {
	b := &Balancer{
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

func (b *Balancer) SetMaxActiveResolvers(maxActive int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.maxActiveResolvers = maxActive
}

func (b *Balancer) MaxActiveResolvers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.maxActiveResolvers
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
	b.mu.Lock()
	defer b.mu.Unlock()

	size := len(connections)
	b.connections = make([]Connection, 0, size)
	b.indexByKey = make(map[string]int, size)
	b.activeIDs = make([]int, 0, size)
	b.inactiveIDs = make([]int, 0, size)
	b.stats = make([]*connectionStats, 0, size)
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

	for _, conn := range connections {
		if conn == nil || conn.Key == "" {
			continue
		}
		copied := *conn
		copied.IsValid = false
		copied.UploadMTUBytes = 0
		copied.UploadMTUChars = 0
		copied.DownloadMTUBytes = 0
		copied.MTUResolveTime = 0
		copied.LastHealthCheckAt = time.Time{}
		idx := len(b.connections)
		b.connections = append(b.connections, copied)
		b.indexByKey[copied.Key] = idx
		b.inactiveIDs = append(b.inactiveIDs, idx)
		b.stats = append(b.stats, &connectionStats{})
	}

}

func (b *Balancer) ActiveCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.activeIDs)
}

func (b *Balancer) TotalCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.connections)
}

func (b *Balancer) GetConnectionByKey(key string) (Connection, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	idx, ok := b.indexByKey[key]
	if !ok || idx < 0 || idx >= len(b.connections) {
		return Connection{}, false
	}
	return b.connections[idx], true
}

func (b *Balancer) SetConnectionValidity(key string, valid bool) bool {
	return b.SetConnectionValidityWithLog(key, valid, false)
}

func (b *Balancer) SetConnectionValidityWithLog(key string, valid bool, logReactivated bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	idx, ok := b.indexByKey[key]
	if !ok || idx < 0 || idx >= len(b.connections) {
		return false
	}
	if b.connections[idx].IsValid == valid {
		return true
	}

	b.connections[idx].IsValid = valid
	if valid {
		if stats := b.stats[idx]; stats != nil {
			stats.resetWindow()
		}
	} else {
		b.clearPreferredResolverReferencesLocked(key)
	}
	b.moveConnectionStateLocked(idx, valid)

	return true
}

// ResolverStatsSnapshot captures a point-in-time snapshot of resolver metrics.
type ResolverStatsSnapshot struct {
	Connection    Connection
	Sent          uint64
	Acked         uint64
	Lost          uint64
	LossRatio     float64
	AverageRTT    time.Duration
	ActiveStreams int
	IsValid       bool
}

// GetStatsSnapshot thread-safely exports current metrics for all loaded resolvers.
func (b *Balancer) GetStatsSnapshot() []ResolverStatsSnapshot {
	if b == nil {
		return nil
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	// Count active streams assigned per resolver key
	streamCounts := make(map[string]int)
	for _, route := range b.streamRoutes {
		if route != nil && route.PreferredResolverKey != "" {
			streamCounts[route.PreferredResolverKey]++
		}
	}

	snapshots := make([]ResolverStatsSnapshot, len(b.connections))
	for i, conn := range b.connections {
		var sent, acked, lost, rttSum, rttCount uint64
		if i < len(b.stats) && b.stats[i] != nil {
			sent = b.stats[i].sent.Load()
			acked = b.stats[i].acked.Load()
			lost = b.stats[i].lost.Load()
			rttSum = b.stats[i].rttMicrosSum.Load()
			rttCount = b.stats[i].rttCount.Load()
		}

		var avgRTT time.Duration
		if rttCount > 0 {
			avgRTT = time.Duration(rttSum/rttCount) * time.Microsecond
		}

		var lossRatio float64
		if sent > 0 {
			lossRatio = float64(lost) / float64(sent)
		}

		snapshots[i] = ResolverStatsSnapshot{
			Connection:    conn,
			Sent:          sent,
			Acked:         acked,
			Lost:          lost,
			LossRatio:     lossRatio,
			AverageRTT:    avgRTT,
			ActiveStreams: streamCounts[conn.Key],
			IsValid:       conn.IsValid,
		}
	}

	return snapshots
}

// GetRankedEndpoints returns unique ResolverAddress endpoints sorted in descending
// performance order based on composite scores, active status, and MTU validity.
func (b *Balancer) GetRankedEndpoints(maxCount int) []config.ResolverAddress {
	if b == nil {
		return nil
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.connections) == 0 {
		return nil
	}

	type scoredEndpoint struct {
		addr  config.ResolverAddress
		score float64
	}

	seenEndpoints := make(map[string]int) // endpointKey -> index in scored
	scored := make([]scoredEndpoint, 0, len(b.connections))

	for i, conn := range b.connections {
		// Only consider connections that have passed MTU discovery or are active or have stats
		hasStats := false
		if i < len(b.stats) && b.stats[i] != nil {
			sent, _, _, _, rttCount := b.stats[i].snapshot()
			if sent > 0 || rttCount > 0 {
				hasStats = true
			}
		}
		if !conn.IsValid && conn.UploadMTUBytes <= 0 && conn.DownloadMTUBytes <= 0 && !hasStats {
			continue
		}

		score := b.calculateConnectionScoreLocked(i)
		if conn.IsValid {
			score += 1000.0 // Active pool members boosted above standbys
		}

		epKey := formatResolverEndpoint(conn.Resolver, conn.ResolverPort)
		if existingIdx, exists := seenEndpoints[epKey]; exists {
			if score > scored[existingIdx].score {
				scored[existingIdx].score = score
			}
			continue
		}

		seenEndpoints[epKey] = len(scored)
		scored = append(scored, scoredEndpoint{
			addr: config.ResolverAddress{
				IP:   conn.Resolver,
				Port: conn.ResolverPort,
			},
			score: score,
		})
	}

	if len(scored) == 0 {
		return nil
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	if maxCount > 0 && len(scored) > maxCount {
		scored = scored[:maxCount]
	}

	result := make([]config.ResolverAddress, len(scored))
	for i, s := range scored {
		result[i] = s.addr
	}
	return result
}

func (b *Balancer) SetConnectionMTU(key string, uploadBytes int, uploadChars int, downloadBytes int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	idx, ok := b.indexByKey[key]
	if !ok || idx < 0 || idx >= len(b.connections) {
		return false
	}

	b.connections[idx].UploadMTUBytes = uploadBytes
	b.connections[idx].UploadMTUChars = uploadChars
	b.connections[idx].DownloadMTUBytes = downloadBytes
	return true
}

func (b *Balancer) ApplyMTUProbeResult(key string, uploadBytes int, uploadChars int, downloadBytes int, resolveTime time.Duration, active bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	idx, ok := b.indexByKey[key]
	if !ok || idx < 0 || idx >= len(b.connections) {
		return false
	}

	conn := &b.connections[idx]
	conn.UploadMTUBytes = uploadBytes
	conn.UploadMTUChars = uploadChars
	conn.DownloadMTUBytes = downloadBytes
	conn.MTUResolveTime = resolveTime
	wasValid := conn.IsValid
	conn.IsValid = active
	if active {
		if stats := b.stats[idx]; stats != nil {
			stats.resetWindow()
		}
	} else {
		b.clearPreferredResolverReferencesLocked(key)
	}

	if wasValid != active {
		b.moveConnectionStateLocked(idx, active)
	}

	return true
}

func (b *Balancer) ReportSend(serverKey string) {
	if stats := b.statsForKey(serverKey); stats != nil {
		stats.sent.Add(1)
		stats.applyHalfLife()
	}
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
	b.mu.Lock()
	conn, ok := b.connectionByKeyLocked(serverKey)
	if !ok || !conn.IsValid {
		b.mu.Unlock()
		return false
	}

	activeCount := len(b.activeIDs)
	minObservations := autoDisableMinObservationsForActiveCount(activeCount, window)
	if int(totalSent) < minObservations || totalTimedOut != totalSent {
		b.mu.Unlock()
		return false
	}

	if minActive < 0 {
		minActive = 0
	}

	if minActive < 2 {
		minActive = 2
	}

	if activeCount <= minActive {
		b.mu.Unlock()
		return false
	}

	confirmHandler := b.confirmResolverDown
	confirmRequired := confirmHandler != nil && activeCount <= 20
	if confirmRequired {
		connCopy := *conn
		b.mu.Unlock()

		down := confirmHandler(&connCopy, window)

		b.mu.Lock()
		conn, ok = b.connectionByKeyLocked(serverKey)
		if !ok || !conn.IsValid {
			b.mu.Unlock()
			return false
		}

		if !down {
			stats.resetWindow()
			b.mu.Unlock()
			return false
		}
	}

	conn.IsValid = false
	stats.resetWindow()
	b.clearPreferredResolverReferencesLocked(serverKey)

	if idx, ok := b.indexByKey[serverKey]; ok {
		b.moveConnectionStateLocked(idx, false)
	}

	if b.onResolverDisabled != nil {
		handler := b.onResolverDisabled
		handler(conn, "TIMEOUT")
	}

	if b.log != nil {
		b.log.Warnf("<red>DNS Resolver disabled (100%% Loss): <cyan>%s</cyan> <cyan>%s</cyan>) | <cyan>%s</cyan> | Remaining: <cyan>%d</cyan></red>",
			conn.ResolverLabel, conn.Domain, conn.Resolver, len(b.activeIDs))
	}

	b.mu.Unlock()
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
	activeCount := len(b.activeIDs)
	b.mu.RUnlock()
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
	activeCount := len(b.activeIDs)
	b.mu.RUnlock()
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

func (b *Balancer) SeedConservativeStats(serverKey string) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return
	}

	stats.sent.Store(10)
	stats.acked.Store(8)
	stats.lost.Store(0)
	stats.rttMicrosSum.Store(0)
	stats.rttCount.Store(0)
}

func (b *Balancer) SeedBurstStats(serverKey string, sentCount int, ackedCount int, avgRTT time.Duration) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return
	}

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
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.activeIDs) == 0 {
		return Connection{}, false
	}

	switch b.strategy {
	case BalancingRandom:
		idx := b.activeIDs[b.nextRandom()%uint64(len(b.activeIDs))]
		return b.connections[idx], true
	default:
		if pool, pick, handled := b.strategyCandidatePoolLocked(""); handled {
			if len(pool) == 0 {
				return b.roundRobinBestConnectionLocked()
			}
			return b.pickFromPoolLocked(pool, pick)
		}
		scorer, hasSignal := b.strategyScorerLocked()
		if scorer == nil {
			return b.roundRobinBestConnectionLocked()
		}

		if !hasSignal {
			return b.roundRobinBestConnectionLocked()
		}

		return b.bestScoredConnectionLocked(scorer)
	}
}

func (b *Balancer) GetBestConnectionExcluding(excludeKey string) (Connection, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.activeIDs) == 0 {
		return Connection{}, false
	}

	switch b.strategy {
	case BalancingRandom:
		ordered := b.rotatedActiveIndicesLocked(1)
		for _, idx := range ordered {
			if b.connections[idx].Key == excludeKey {
				continue
			}
			return b.connections[idx], true
		}
		return Connection{}, false
	default:
		if pool, pick, handled := b.strategyCandidatePoolLocked(excludeKey); handled {
			if len(pool) == 0 {
				return b.roundRobinBestConnectionExcludingLocked(excludeKey)
			}
			return b.pickFromPoolLocked(pool, pick)
		}
		scorer, hasSignal := b.strategyScorerLocked()
		if scorer == nil {
			return b.roundRobinBestConnectionExcludingLocked(excludeKey)
		}

		if !hasSignal {
			return b.roundRobinBestConnectionExcludingLocked(excludeKey)
		}

		return b.bestScoredConnectionExcludingLocked(scorer, excludeKey)
	}
}

func (b *Balancer) ActiveConnections() []Connection {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.connectionsByIDsLocked(b.activeIDs)
}

func (b *Balancer) InactiveConnections() []Connection {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.connectionsByIDsLocked(b.inactiveIDs)
}

func (b *Balancer) AllConnections() []Connection {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]Connection, len(b.connections))
	copy(result, b.connections)
	return result
}

func (b *Balancer) NextInactiveConnectionForHealthCheck(now time.Time, minInterval time.Duration) (Connection, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	n := len(b.inactiveIDs)
	if n == 0 {
		return Connection{}, false
	}

	if minInterval < 0 {
		minInterval = 0
	}

	start := roundRobinStartIndex(b.healthRRCounter.Add(1)-1, n)
	for i := 0; i < n; i++ {
		idx := b.inactiveIDs[(start+i)%n]
		if idx < 0 || idx >= len(b.connections) {
			continue
		}

		conn := &b.connections[idx]
		if !conn.LastHealthCheckAt.IsZero() && now.Sub(conn.LastHealthCheckAt) < minInterval {
			continue
		}

		conn.LastHealthCheckAt = now
		return *conn, true
	}

	return Connection{}, false
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
	b.mu.RLock()
	defer b.mu.RUnlock()

	// 1. Normalize count: 1 <= requiredCount <= len(activeIDs)
	requiredCount = normalizeRequiredCount(len(b.activeIDs), requiredCount, 1)
	if requiredCount <= 0 {
		return nil, ErrNoValidConnections
	}

	// 2. Base case: Single target or non-stream packet is ALWAYS dynamic via balancer
	if requiredCount == 1 || streamID == 0 || !isBalancerStreamDataLike(packetType) {
		selected := b.getUniqueConnectionsLocked(requiredCount)
		if len(selected) == 0 {
			return nil, ErrNoValidConnections
		}
		return selected, nil
	}

	// 3. Duplication case: Multi-path stream routing (Preferred + Dynamic Others)
	state := b.streamRoutes[streamID]
	if state == nil {
		// No state? Fallback to dynamic balancer
		return b.getUniqueConnectionsLocked(requiredCount), nil
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	// Get the sticky preferred resolver for the main path
	preferred, ok := b.selectPreferredConnectionForStreamLocked(packetType, state)
	if !ok {
		return b.getUniqueConnectionsLocked(requiredCount), nil
	}

	// Combine Preferred + Dynamic Others
	selected := make([]Connection, 0, requiredCount)
	selected = append(selected, preferred)

	if remaining := requiredCount - 1; remaining > 0 {
		others := b.getUniqueConnectionsExcludingLocked(remaining, preferred.Key)
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

func (b *Balancer) connectionsByIDsLocked(ids []int) []Connection {
	if len(ids) == 0 {
		return nil
	}
	result := make([]Connection, len(ids))
	for i, idx := range ids {
		if idx < 0 || idx >= len(b.connections) {
			continue
		}
		result[i] = b.connections[idx]
	}
	return result
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

func (b *Balancer) selectPreferredConnectionForStreamLocked(packetType uint8, state *balancerStreamRouteState) (Connection, bool) {
	if state == nil {
		return Connection{}, false
	}

	// 1. Check for Failover (Streak reached during resend)
	if packetType == Enums.PACKET_STREAM_RESEND {
		state.ResendStreak++
		if current, ok := b.validPreferredConnectionLocked(state); ok {
			// Stay on current until threshold or cooldown
			if state.ResendStreak < b.streamFailoverThreshold || (time.Since(state.LastFailoverAt) < b.streamFailoverCooldown) {
				return current, true
			}

			// Failover triggered: Choose absolute best alternate
			if replacement, ok := b.selectAlternateConnectionLocked(current.Key); ok {
				state.PreferredResolverKey = replacement.Key
				state.ResendStreak = 0
				state.LastFailoverAt = time.Now()
				return replacement, true
			}
			return current, true
		}
	}

	// 2. Return current preferred if it is still valid
	if current, ok := b.validPreferredConnectionLocked(state); ok {
		return current, true
	}

	// 3. Current is dead or missing: Select a new one
	var replacement Connection
	var ok bool

	if state.PreferredResolverKey == "" {
		// New stream: Use "Top 10 Random" to distribute load
		replacement, ok = b.selectInitialPreferredConnectionLocked()
	} else {
		// Recovery from dead resolver: Use absolute best alternate
		replacement, ok = b.selectAlternateConnectionLocked(state.PreferredResolverKey)
	}

	if ok {
		state.PreferredResolverKey = replacement.Key
		state.ResendStreak = 0
		return replacement, true
	}

	return Connection{}, false
}

func (b *Balancer) validPreferredConnectionLocked(state *balancerStreamRouteState) (Connection, bool) {
	if state == nil || state.PreferredResolverKey == "" {
		return Connection{}, false
	}
	conn, ok := b.connectionByKeyLocked(state.PreferredResolverKey)
	if !ok || !conn.IsValid || conn.Key == "" {
		return Connection{}, false
	}
	return *conn, true
}

func (b *Balancer) selectAlternateConnectionLocked(excludeKey string) (Connection, bool) {
	if excludeKey != "" {
		if replacement, ok := b.getBestConnectionExcludingLocked(excludeKey); ok {
			return replacement, true
		}
	}

	selected := b.getUniqueConnectionsLocked(1)
	if len(selected) == 0 {
		return Connection{}, false
	}
	if excludeKey == "" || selected[0].Key != excludeKey {
		return selected[0], true
	}
	if replacement, ok := b.getBestConnectionExcludingLocked(excludeKey); ok {
		return replacement, true
	}
	return Connection{}, false
}

func (b *Balancer) clearPreferredResolverReferencesLocked(serverKey string) {
	if serverKey == "" {
		return
	}
	for _, state := range b.streamRoutes {
		if state == nil || state.PreferredResolverKey != serverKey {
			continue
		}
		state.PreferredResolverKey = ""
		state.ResendStreak = 0
	}
}

// calculateConnectionScoreLocked computes a composite performance score for any resolver.
// Higher score = better resolver (more throughput, lower loss, lower RTT).
func (b *Balancer) calculateConnectionScoreLocked(idx int) float64 {
	if idx < 0 || idx >= len(b.connections) {
		return 0.0
	}
	conn := &b.connections[idx]
	downloadMTU := conn.DownloadMTUBytes
	if downloadMTU <= 0 {
		downloadMTU = 500
	}

	var sent, lost, rttSum, rttCount uint64
	if idx < len(b.stats) && b.stats[idx] != nil {
		sent, _, lost, rttSum, rttCount = b.stats[idx].snapshot()
	}

	lossRatio := 0.0
	if sent > 0 {
		lossRatio = float64(lost) / float64(sent)
	}

	var avgRTT time.Duration
	if rttCount > 0 {
		avgRTT = time.Duration(rttSum/rttCount) * time.Microsecond
	} else if conn.MTUResolveTime > 0 {
		avgRTT = conn.MTUResolveTime
	}

	if avgRTT <= 0 {
		return 1.0 // Unprobed default neutral low score
	}

	_, score := CalculateResolverScore(downloadMTU, avgRTT, lossRatio)
	if score <= 0 {
		return 1.0
	}
	return score
}

func (b *Balancer) moveConnectionStateLocked(idx int, valid bool) {
	if !valid {
		b.connections[idx].IsValid = false
		b.removeActiveIndexLocked(idx)
		b.addInactiveIndexLocked(idx)
		b.clearPreferredResolverReferencesLocked(b.connections[idx].Key)
		return
	}

	// If already in activeIDs, make sure marked valid
	for _, activeIdx := range b.activeIDs {
		if activeIdx == idx {
			b.connections[idx].IsValid = true
			return
		}
	}

	// If maxActiveResolvers is configured (> 0) and the active pool is full:
	if b.maxActiveResolvers > 0 && len(b.activeIDs) >= b.maxActiveResolvers {
		candScore := b.calculateConnectionScoreLocked(idx)

		// Find lowest scoring resolver currently in activeIDs
		worstActiveIdx := -1
		worstActiveScore := math.MaxFloat64
		worstActivePos := -1

		for pos, activeIdx := range b.activeIDs {
			score := b.calculateConnectionScoreLocked(activeIdx)
			if score < worstActiveScore {
				worstActiveScore = score
				worstActiveIdx = activeIdx
				worstActivePos = pos
			}
		}

		// Only displace if the incoming candidate is strictly higher scoring
		if worstActiveIdx >= 0 && candScore > worstActiveScore {
			demotedConn := &b.connections[worstActiveIdx]
			demotedConn.IsValid = false
			b.activeIDs[worstActivePos] = idx // Replace in activeIDs slice
			b.addInactiveIndexLocked(worstActiveIdx)
			b.clearPreferredResolverReferencesLocked(demotedConn.Key)

			b.removeInactiveIndexLocked(idx)
			b.connections[idx].IsValid = true

			if b.log != nil {
				candConn := &b.connections[idx]
				b.log.Infof("<green>🔄 DNS Resolver Promoted to Active Pool: %s (%s, score: %.1f) [Demoted: %s, score: %.1f] | Active Pool: %d/%d</green>",
					candConn.ResolverLabel, candConn.Domain, candScore,
					demotedConn.ResolverLabel, worstActiveScore,
					len(b.activeIDs), len(b.connections))
			}
			return
		}

		// Candidate does not beat active resolvers -> Place in Standby pool
		b.connections[idx].IsValid = false
		b.addInactiveIndexLocked(idx)
		b.removeActiveIndexLocked(idx)
		if b.log != nil {
			candConn := &b.connections[idx]
			b.log.Debugf("<cyan>⏸ DNS Resolver Added to Standby Pool (Pool Full): %s (%s, score: %.1f) | Active: %d</cyan>",
				candConn.ResolverLabel, candConn.Domain, candScore, len(b.activeIDs))
		}
		return
	}

	// Active pool has available capacity -> Add to activeIDs
	b.connections[idx].IsValid = true
	b.removeInactiveIndexLocked(idx)
	b.addActiveIndexLocked(idx)
}

// OptimizeActivePool scans active resolvers and replaces degraded ones with better standby candidates.
func (b *Balancer) OptimizeActivePool() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.optimizeActivePoolLocked()
}

func (b *Balancer) optimizeActivePoolLocked() bool {
	if b.maxActiveResolvers <= 0 || len(b.activeIDs) == 0 || len(b.inactiveIDs) == 0 {
		return false
	}

	swapped := false

	for i := 0; i < len(b.activeIDs); i++ {
		activeIdx := b.activeIDs[i]
		activeScore := b.calculateConnectionScoreLocked(activeIdx)

		// Find best qualified candidate in inactiveIDs
		bestInactiveIdx := -1
		bestInactiveScore := -1.0
		for _, inactIdx := range b.inactiveIDs {
			conn := &b.connections[inactIdx]
			if conn.UploadMTUBytes <= 0 || conn.DownloadMTUBytes <= 0 {
				continue
			}
			score := b.calculateConnectionScoreLocked(inactIdx)
			if score > bestInactiveScore {
				bestInactiveScore = score
				bestInactiveIdx = inactIdx
			}
		}

		// Swap if the best standby candidate is meaningfully better (>1.25x active score)
		if bestInactiveIdx >= 0 && bestInactiveScore > (activeScore*1.25) {
			demotedConn := &b.connections[activeIdx]
			promotedConn := &b.connections[bestInactiveIdx]

			demotedConn.IsValid = false
			b.clearPreferredResolverReferencesLocked(demotedConn.Key)

			promotedConn.IsValid = true

			// Swap IDs
			b.activeIDs[i] = bestInactiveIdx
			b.removeInactiveIndexLocked(bestInactiveIdx)
			b.addInactiveIndexLocked(activeIdx)

			if b.log != nil {
				b.log.Infof("<yellow>⚡ Active Resolver Swapped (Performance Degradation): %s (Score: %.1f) ➔ Replaced by %s (Score: %.1f)</yellow>",
					demotedConn.ResolverLabel, activeScore,
					promotedConn.ResolverLabel, bestInactiveScore)
			}
			swapped = true
		}
	}

	return swapped
}

func (b *Balancer) selectInitialPreferredConnectionLocked() (Connection, bool) {
	if len(b.activeIDs) == 0 {
		return Connection{}, false
	}

	switch b.strategy {
	case BalancingRandom, BalancingRoundRobin, BalancingRoundRobinDefault:
		return b.selectTargetByStrategyLocked()
	default:
		if pool, pick, handled := b.strategyCandidatePoolLocked(""); handled {
			if len(pool) == 0 {
				return b.selectTargetByStrategyLocked()
			}
			return b.pickFromPoolLocked(pool, pick)
		}
		scorer, hasSignal := b.strategyScorerLocked()
		if scorer == nil {
			return b.selectTargetByStrategyLocked()
		}

		if !hasSignal {
			return b.selectTargetByStrategyLocked()
		}

		topN := 10
		if len(b.activeIDs) < topN {
			topN = len(b.activeIDs)
		}

		pool := b.selectLowestScoreLocked(topN, scorer)
		if len(pool) == 0 {
			return b.selectTargetByStrategyLocked()
		}

		return b.pickFromPoolLocked(pool, poolPickRandom)
	}
}

func (b *Balancer) getUniqueConnectionsExcludingLocked(requiredCount int, excludeKey string) []Connection {
	if requiredCount <= 0 || len(b.activeIDs) == 0 {
		return nil
	}

	all := b.getUniqueConnectionsLocked(requiredCount + 1)
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

func (b *Balancer) addActiveIndexLocked(idx int) {
	for _, activeIdx := range b.activeIDs {
		if activeIdx == idx {
			return
		}
	}
	b.activeIDs = append(b.activeIDs, idx)
}

func (b *Balancer) addInactiveIndexLocked(idx int) {
	for _, inactiveIdx := range b.inactiveIDs {
		if inactiveIdx == idx {
			return
		}
	}
	b.inactiveIDs = append(b.inactiveIDs, idx)
}

func (b *Balancer) removeActiveIndexLocked(idx int) {
	for i, activeIdx := range b.activeIDs {
		if activeIdx == idx {
			b.activeIDs[i] = b.activeIDs[len(b.activeIDs)-1]
			b.activeIDs = b.activeIDs[:len(b.activeIDs)-1]
			break
		}
	}
}

func (b *Balancer) removeInactiveIndexLocked(idx int) {
	for i, inactiveIdx := range b.inactiveIDs {
		if inactiveIdx == idx {
			b.inactiveIDs[i] = b.inactiveIDs[len(b.inactiveIDs)-1]
			b.inactiveIDs = b.inactiveIDs[:len(b.inactiveIDs)-1]
			break
		}
	}
}

func (b *Balancer) statsForKey(serverKey string) *connectionStats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	idx, ok := b.indexByKey[serverKey]
	if !ok || idx < 0 || idx >= len(b.stats) {
		return nil
	}

	return b.stats[idx]
}

func (b *Balancer) connectionByKeyLocked(serverKey string) (*Connection, bool) {
	idx, ok := b.indexByKey[serverKey]
	if !ok || idx < 0 || idx >= len(b.connections) {
		return nil, false
	}

	return &b.connections[idx], true
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
	if b == nil {
		return nil
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.getUniqueConnectionsLocked(requiredCount)
}

func (b *Balancer) getUniqueConnectionsLocked(requiredCount int) []Connection {
	count := normalizeRequiredCount(len(b.activeIDs), requiredCount, 1)
	if count <= 0 {
		return nil
	}

	switch b.strategy {
	case BalancingRandom:
		return b.selectRandomLocked(count)
	default:
		if pool, pick, handled := b.strategyCandidatePoolLocked(""); handled {
			if len(pool) == 0 {
				return b.selectRoundRobinLocked(count)
			}
			return b.limitConnectionPoolLocked(pool, count, pick)
		}
		scorer, hasSignal := b.strategyScorerLocked()
		if scorer == nil {
			return b.selectRoundRobinLocked(count)
		}

		if !hasSignal {
			return b.selectRoundRobinLocked(count)
		}

		return b.selectLowestScoreLocked(count, scorer)
	}
}

func (b *Balancer) selectTargetByStrategyLocked() (Connection, bool) {
	selected := b.getUniqueConnectionsLocked(1)
	if len(selected) == 0 {
		return Connection{}, false
	}
	return selected[0], true
}

func (b *Balancer) getBestConnectionExcludingLocked(excludeKey string) (Connection, bool) {
	switch b.strategy {
	case BalancingRandom:
		ordered := b.rotatedActiveIndicesLocked(1)
		for _, idx := range ordered {
			if b.connections[idx].Key == excludeKey {
				continue
			}
			return b.connections[idx], true
		}
		return Connection{}, false
	default:
		if pool, pick, handled := b.strategyCandidatePoolLocked(excludeKey); handled {
			if len(pool) == 0 {
				return b.roundRobinBestConnectionExcludingLocked(excludeKey)
			}
			return b.pickFromPoolLocked(pool, pick)
		}
		scorer, hasSignal := b.strategyScorerLocked()
		if scorer == nil {
			return b.roundRobinBestConnectionExcludingLocked(excludeKey)
		}

		if !hasSignal {
			return b.roundRobinBestConnectionExcludingLocked(excludeKey)
		}

		return b.bestScoredConnectionExcludingLocked(scorer, excludeKey)
	}
}

func (b *Balancer) selectRoundRobinLocked(count int) []Connection {
	n := len(b.activeIDs)
	start := roundRobinStartIndex(b.rrCounter.Add(uint64(count))-uint64(count), n)
	selected := make([]Connection, count)
	for i := 0; i < count; i++ {
		selected[i] = b.connections[b.activeIDs[(start+i)%n]]
	}
	return selected
}

func (b *Balancer) selectRandomLocked(count int) []Connection {
	n := len(b.activeIDs)
	if count <= 0 || n == 0 {
		return nil
	}
	if count == 1 {
		idx := b.activeIDs[b.nextRandom()%uint64(n)]
		return []Connection{b.connections[idx]}
	}

	indices := append([]int(nil), b.activeIDs...)
	for i := 0; i < count; i++ {
		j := i + int(b.nextRandom()%uint64(n-i))
		indices[i], indices[j] = indices[j], indices[i]
	}
	return b.connectionsByIndicesLocked(indices[:count])
}

func (b *Balancer) selectLowestScoreLocked(count int, scorer func(int) uint64) []Connection {
	n := len(b.activeIDs)
	if count <= 0 || n == 0 {
		return nil
	}
	if count == 1 {
		conn, ok := b.bestScoredConnectionLocked(scorer)
		if ok {
			return []Connection{conn}
		}
		return nil
	}

	type scoredIdx struct {
		idx   int
		score uint64
	}

	ordered := b.rotatedActiveIndicesLocked(count)
	scored := make([]scoredIdx, n)
	for i, idx := range ordered {
		scored[i] = scoredIdx{idx: idx, score: scorer(idx)}
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

	indices := make([]int, count)
	for i := 0; i < count; i++ {
		indices[i] = scored[i].idx
	}
	return b.connectionsByIndicesLocked(indices)
}

func (b *Balancer) connectionsByIndicesLocked(indices []int) []Connection {
	selected := make([]Connection, len(indices))
	for i, idx := range indices {
		if idx < 0 || idx >= len(b.connections) {
			continue
		}
		selected[i] = b.connections[idx]
	}
	return selected
}

func (b *Balancer) bestScoredConnectionLocked(scorer func(int) uint64) (Connection, bool) {
	ordered := b.rotatedActiveIndicesLocked(1)
	bestIndex := -1
	var bestScore uint64
	for _, idx := range ordered {
		score := scorer(idx)
		if bestIndex == -1 || score < bestScore {
			bestIndex = idx
			bestScore = score
		}
	}
	if bestIndex < 0 {
		return Connection{}, false
	}
	return b.connections[bestIndex], true
}

func (b *Balancer) bestScoredConnectionExcludingLocked(scorer func(int) uint64, excludeKey string) (Connection, bool) {
	ordered := b.rotatedActiveIndicesLocked(1)
	bestIndex := -1
	var bestScore uint64
	for _, idx := range ordered {
		if b.connections[idx].Key == excludeKey {
			continue
		}
		score := scorer(idx)
		if bestIndex == -1 || score < bestScore {
			bestIndex = idx
			bestScore = score
		}
	}
	if bestIndex < 0 {
		return Connection{}, false
	}
	return b.connections[bestIndex], true
}

func (b *Balancer) roundRobinBestConnectionLocked() (Connection, bool) {
	if len(b.activeIDs) == 0 {
		return Connection{}, false
	}
	pos := roundRobinStartIndex(b.rrCounter.Add(1)-1, len(b.activeIDs))
	return b.connections[b.activeIDs[pos]], true
}

func (b *Balancer) roundRobinBestConnectionExcludingLocked(excludeKey string) (Connection, bool) {
	if len(b.activeIDs) == 0 {
		return Connection{}, false
	}
	for _, idx := range b.rotatedActiveIndicesLocked(1) {
		if b.connections[idx].Key == excludeKey {
			continue
		}
		return b.connections[idx], true
	}
	return Connection{}, false
}

func (b *Balancer) rotatedActiveIndicesLocked(step int) []int {
	if len(b.activeIDs) == 0 {
		return nil
	}
	if step < 1 {
		step = 1
	}

	start := roundRobinStartIndex(b.rrCounter.Add(uint64(step))-uint64(step), len(b.activeIDs))
	ordered := make([]int, len(b.activeIDs))
	for i := range b.activeIDs {
		ordered[i] = b.activeIDs[(start+i)%len(b.activeIDs)]
	}
	return ordered
}

func roundRobinStartIndex(counter uint64, n int) int {
	if n <= 0 {
		return 0
	}
	return int(counter % uint64(n))
}

func (b *Balancer) hasLossSignalLocked() bool {
	for _, idx := range b.activeIDs {
		stats := b.stats[idx]
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

func (b *Balancer) hasLatencySignalLocked() bool {
	for _, idx := range b.activeIDs {
		stats := b.stats[idx]
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

func (b *Balancer) hasHybridSignalLocked() bool {
	return b.hasLossSignalLocked() || b.hasLatencySignalLocked()
}

func (b *Balancer) strategyScorerLocked() (func(int) uint64, bool) {
	switch b.strategy {
	case BalancingLeastLoss:
		return b.lossScoreLocked, b.hasLossSignalLocked()
	case BalancingLowestLatency:
		return b.latencyScoreLocked, b.hasLatencySignalLocked()
	case BalancingHybridScore:
		return b.hybridScoreLocked, b.hasHybridSignalLocked()
	default:
		return nil, false
	}
}

type balancerPoolPick int

const (
	poolPickRandom balancerPoolPick = iota
	poolPickRoundRobin
)

func (b *Balancer) strategyCandidatePoolLocked(excludeKey string) ([]Connection, balancerPoolPick, bool) {
	switch b.strategy {
	case BalancingLossThenLatency:
		if !b.hasHybridSignalLocked() {
			return nil, poolPickRandom, true
		}
		return b.lossThenLatencyCandidatesLocked(excludeKey), poolPickRandom, true
	case BalancingLeastLossTopRandom:
		if !b.hasLossSignalLocked() {
			return nil, poolPickRandom, true
		}
		return b.leastLossTopTierCandidatesLocked(excludeKey), poolPickRandom, true
	case BalancingLeastLossTopRoundRobin:
		if !b.hasLossSignalLocked() {
			return nil, poolPickRoundRobin, true
		}
		return b.leastLossTopTierCandidatesLocked(excludeKey), poolPickRoundRobin, true
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
	if len(pool) == 0 {
		return nil
	}
	if count >= len(pool) {
		return pool
	}
	if pick == poolPickRoundRobin {
		start := roundRobinStartIndex(b.rrCounter.Add(uint64(count))-uint64(count), len(pool))
		ordered := make([]Connection, len(pool))
		for i := range pool {
			ordered[i] = pool[(start+i)%len(pool)]
		}
		return ordered[:count]
	}
	return pool[:count]
}

func (b *Balancer) lossThenLatencyCandidatesLocked(excludeKey string) []Connection {
	type candidate struct {
		idx     int
		loss    uint64
		latency uint64
	}

	if !b.hasHybridSignalLocked() || len(b.activeIDs) == 0 {
		return nil
	}

	candidates := make([]candidate, 0, len(b.activeIDs))
	bestLoss := ^uint64(0)
	for _, idx := range b.activeIDs {
		if excludeKey != "" && b.connections[idx].Key == excludeKey {
			continue
		}
		loss := b.lossScoreLocked(idx)
		latency := b.hybridLatencyPenaltyLocked(idx)
		if loss < bestLoss {
			bestLoss = loss
		}
		candidates = append(candidates, candidate{idx: idx, loss: loss, latency: latency})
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
		if cand.latency < bestLatency {
			bestLatency = cand.latency
		}
	}
	if len(lossShortlist) == 0 {
		return nil
	}

	latencyTolerance := latencyToleranceForTier(bestLatency)
	latencyCutoff := bestLatency + latencyTolerance

	selected := make([]Connection, 0, len(lossShortlist))
	for _, cand := range lossShortlist {
		if cand.latency > latencyCutoff {
			continue
		}
		selected = append(selected, b.connections[cand.idx])
	}
	if len(selected) > 0 {
		return selected
	}

	return []Connection{b.connections[lossShortlist[0].idx]}
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

func (b *Balancer) leastLossTopTierCandidatesLocked(excludeKey string) []Connection {
	type candidate struct {
		idx  int
		loss uint64
	}

	if !b.hasLossSignalLocked() || len(b.activeIDs) == 0 {
		return nil
	}

	candidates := make([]candidate, 0, len(b.activeIDs))
	for _, idx := range b.activeIDs {
		if excludeKey != "" && b.connections[idx].Key == excludeKey {
			continue
		}
		candidates = append(candidates, candidate{
			idx:  idx,
			loss: b.lossScoreLocked(idx),
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
		selected = append(selected, b.connections[candidates[i].idx])
	}
	return selected
}

func (b *Balancer) lossScoreLocked(idx int) uint64 {
	if idx < 0 || idx >= len(b.stats) || b.stats[idx] == nil {
		return 0
	}
	sent, _, lost, _, _ := b.stats[idx].snapshot()
	if sent == 0 || lost == 0 {
		return 0
	}
	return (lost * 1000) / sent
}

func (b *Balancer) latencyScoreLocked(idx int) uint64 {
	if idx < 0 || idx >= len(b.stats) || b.stats[idx] == nil {
		return 999000
	}
	_, _, _, sum, count := b.stats[idx].snapshot()
	if count == 0 {
		return 999000
	}
	return sum / count
}

func (b *Balancer) hybridScoreLocked(idx int) uint64 {
	lossPenalty := b.lossScoreLocked(idx)
	latencyPenalty := b.hybridLatencyPenaltyLocked(idx)
	return lossPenalty*8 + latencyPenalty
}

func (b *Balancer) hybridLatencyPenaltyLocked(idx int) uint64 {
	latencyMicros := b.latencyScoreLocked(idx)
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
