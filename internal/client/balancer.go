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
	"sync"
	"sync/atomic"
	"time"
)

const (
	BalancingRoundRobinDefault = 0
	BalancingRandom            = 1
	BalancingRoundRobin        = 2
	BalancingLeastLoss         = 3
	BalancingLowestLatency     = 4
)

type Balancer struct {
	strategy  int
	rrCounter atomic.Uint64
	rngState  atomic.Uint64
	version   atomic.Uint64

	mu       sync.Mutex
	snapshot atomic.Pointer[balancerSnapshot]
}

type connectionStats struct {
	sent         atomic.Uint64
	acked        atomic.Uint64
	rttMicrosSum atomic.Uint64
	rttCount     atomic.Uint64
}

type balancerSnapshot struct {
	version     uint64
	connections []*Connection
	valid       []int
	indexByKey  map[string]int
	stats       []*connectionStats
}

func NewBalancer(strategy int) *Balancer {
	b := &Balancer{strategy: strategy}
	b.rngState.Store(seedRNG())
	return b
}

func (b *Balancer) SetConnections(connections []*Connection) {
	b.mu.Lock()
	defer b.mu.Unlock()

	size := len(connections)
	indexByKey := make(map[string]int, size)
	stats := make([]*connectionStats, size)
	valid := make([]int, 0, size)

	for idx, conn := range connections {
		if conn == nil {
			continue
		}
		indexByKey[conn.Key] = idx
		stats[idx] = &connectionStats{}
		if conn.IsValid {
			valid = append(valid, idx)
		}
	}

	b.snapshot.Store(&balancerSnapshot{
		version:     b.version.Add(1),
		connections: connections,
		valid:       valid,
		indexByKey:  indexByKey,
		stats:       stats,
	})
}

func (b *Balancer) ValidCount() int {
	snap := b.snapshot.Load()
	if snap == nil {
		return 0
	}
	return len(snap.valid)
}

func (b *Balancer) SetConnectionValidity(key string, valid bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	snap := b.snapshot.Load()
	if snap == nil {
		return false
	}

	idx, ok := snap.indexByKey[key]
	if !ok {
		return false
	}

	conn := snap.connections[idx]
	if conn == nil || conn.IsValid == valid {
		return ok
	}

	conn.IsValid = valid
	b.snapshot.Store(&balancerSnapshot{
		version:     b.version.Add(1),
		connections: snap.connections,
		valid:       rebuildValidIndices(snap.connections),
		indexByKey:  snap.indexByKey,
		stats:       snap.stats,
	})
	return true
}

func (b *Balancer) RefreshValidConnections() {
	b.mu.Lock()
	defer b.mu.Unlock()

	snap := b.snapshot.Load()
	if snap == nil {
		return
	}

	b.snapshot.Store(&balancerSnapshot{
		version:     b.version.Add(1),
		connections: snap.connections,
		valid:       rebuildValidIndices(snap.connections),
		indexByKey:  snap.indexByKey,
		stats:       snap.stats,
	})
}

func (b *Balancer) SnapshotVersion() uint64 {
	snap := b.snapshot.Load()
	if snap == nil {
		return 0
	}
	return snap.version
}

func (b *Balancer) ReportSend(serverKey string) {
	if stats := b.statsForKey(serverKey); stats != nil {
		stats.sent.Add(1)
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

	sent := stats.sent.Load()
	if sent <= 1000 {
		return
	}

	stats.sent.Store(sent / 2)
	stats.acked.Store(stats.acked.Load() / 2)
	stats.rttMicrosSum.Store(stats.rttMicrosSum.Load() / 2)
	stats.rttCount.Store(stats.rttCount.Load() / 2)
}

func (b *Balancer) ResetServerStats(serverKey string) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return
	}

	stats.sent.Store(0)
	stats.acked.Store(0)
	stats.rttMicrosSum.Store(0)
	stats.rttCount.Store(0)
}

func (b *Balancer) GetBestConnection() (Connection, bool) {
	snap := b.snapshot.Load()
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, false
	}

	switch b.strategy {
	case BalancingRandom:
		idx := snap.valid[b.nextRandom()%uint64(len(snap.valid))]
		return derefConnection(snap.connections, idx)
	case BalancingLeastLoss:
		if !b.hasLossSignal(snap) {
			return b.roundRobinBestConnection(snap)
		}
		return b.bestScoredConnection(snap, b.lossScore)
	case BalancingLowestLatency:
		if !b.hasLatencySignal(snap) {
			return b.roundRobinBestConnection(snap)
		}
		return b.bestScoredConnection(snap, b.latencyScore)
	default:
		return b.roundRobinBestConnection(snap)
	}
}

func (b *Balancer) GetBestConnectionExcluding(excludeKey string) (Connection, bool) {
	snap := b.snapshot.Load()
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, false
	}

	switch b.strategy {
	case BalancingRandom:
		ordered := b.rotatedValidIndices(snap, 1)
		for _, idx := range ordered {
			conn, ok := derefConnection(snap.connections, idx)
			if !ok || conn.Key == excludeKey {
				continue
			}
			return conn, true
		}
		return Connection{}, false
	case BalancingLeastLoss:
		if !b.hasLossSignal(snap) {
			return b.roundRobinBestConnectionExcluding(snap, excludeKey)
		}
		return b.bestScoredConnectionExcluding(snap, b.lossScore, excludeKey)
	case BalancingLowestLatency:
		if !b.hasLatencySignal(snap) {
			return b.roundRobinBestConnectionExcluding(snap, excludeKey)
		}
		return b.bestScoredConnectionExcluding(snap, b.latencyScore, excludeKey)
	default:
		return b.roundRobinBestConnectionExcluding(snap, excludeKey)
	}
}

func (b *Balancer) GetUniqueConnections(requiredCount int) []Connection {
	snap := b.snapshot.Load()
	if snap == nil {
		return nil
	}

	count := normalizeRequiredCount(len(snap.valid), requiredCount, 1)
	if count <= 0 {
		return nil
	}

	if count == 1 {
		best, ok := b.GetBestConnection()
		if !ok {
			return nil
		}
		return []Connection{best}
	}

	switch b.strategy {
	case BalancingRandom:
		return b.selectRandom(snap, count)
	case BalancingLeastLoss:
		if !b.hasLossSignal(snap) {
			return b.selectRoundRobin(snap, count)
		}
		return b.selectLowestScore(snap, count, b.lossScore)
	case BalancingLowestLatency:
		if !b.hasLatencySignal(snap) {
			return b.selectRoundRobin(snap, count)
		}
		return b.selectLowestScore(snap, count, b.latencyScore)
	default:
		return b.selectRoundRobin(snap, count)
	}
}

func (b *Balancer) GetAllValidConnections() []Connection {
	snap := b.snapshot.Load()
	if snap == nil || len(snap.valid) == 0 {
		return nil
	}
	return snapshotConnections(snap.connections, snap.valid)
}

func rebuildValidIndices(connections []*Connection) []int {
	valid := make([]int, 0, len(connections))
	for idx, conn := range connections {
		if conn != nil && conn.IsValid {
			valid = append(valid, idx)
		}
	}
	return valid
}

func (b *Balancer) statsForKey(serverKey string) *connectionStats {
	snap := b.snapshot.Load()
	if snap == nil {
		return nil
	}
	idx, ok := snap.indexByKey[serverKey]
	if !ok || idx < 0 || idx >= len(snap.stats) {
		return nil
	}
	return snap.stats[idx]
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

func (b *Balancer) selectRoundRobin(snap *balancerSnapshot, count int) []Connection {
	start := int(b.rrCounter.Add(uint64(count)) - uint64(count))
	selected := make([]Connection, count)
	for i := 0; i < count; i++ {
		conn, ok := derefConnection(snap.connections, snap.valid[(start+i)%len(snap.valid)])
		if ok {
			selected[i] = conn
		}
	}
	return selected
}

func (b *Balancer) selectRandom(snap *balancerSnapshot, count int) []Connection {
	n := len(snap.valid)
	if count <= 0 || n == 0 {
		return nil
	}

	// Optimization for small count selection to avoid large allocations
	if count == 1 {
		idx := snap.valid[b.nextRandom()%uint64(n)]
		conn, ok := derefConnection(snap.connections, idx)
		if ok {
			return []Connection{conn}
		}
		return nil
	}

	indices := make([]int, n)
	copy(indices, snap.valid)

	for i := 0; i < count; i++ {
		j := i + int(b.nextRandom()%uint64(n-i))
		indices[i], indices[j] = indices[j], indices[i]
	}

	return snapshotConnections(snap.connections, indices[:count])
}

func (b *Balancer) selectLowestScore(snap *balancerSnapshot, count int, scorer func(*balancerSnapshot, int) uint64) []Connection {
	n := len(snap.valid)
	if count <= 0 || n == 0 {
		return nil
	}

	if count == 1 {
		conn, ok := b.bestScoredConnection(snap, scorer)
		if ok {
			return []Connection{conn}
		}
		return nil
	}

	type scoredIdx struct {
		idx   int
		score uint64
	}

	ordered := b.rotatedValidIndices(snap, count)
	scored := make([]scoredIdx, n)
	for i, idx := range ordered {
		scored[i] = scoredIdx{idx: idx, score: scorer(snap, idx)}
	}

	// Simple selection sort for small 'count'
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

	return snapshotConnections(snap.connections, indices)
}

func snapshotConnections(connections []*Connection, indices []int) []Connection {
	selected := make([]Connection, len(indices))
	for i, idx := range indices {
		if idx < 0 || idx >= len(connections) || connections[idx] == nil {
			continue
		}
		selected[i] = *connections[idx]
	}
	return selected
}

func (b *Balancer) bestScoredConnection(snap *balancerSnapshot, scorer func(*balancerSnapshot, int) uint64) (Connection, bool) {
	ordered := b.rotatedValidIndices(snap, 1)
	bestIndex := -1
	var bestScore uint64
	for _, idx := range ordered {
		score := scorer(snap, idx)
		if bestIndex == -1 || score < bestScore {
			bestIndex = idx
			bestScore = score
		}
	}
	if bestIndex < 0 {
		return Connection{}, false
	}
	return derefConnection(snap.connections, bestIndex)
}

func (b *Balancer) bestScoredConnectionExcluding(snap *balancerSnapshot, scorer func(*balancerSnapshot, int) uint64, excludeKey string) (Connection, bool) {
	ordered := b.rotatedValidIndices(snap, 1)
	bestIndex := -1
	var bestScore uint64
	for _, idx := range ordered {
		conn, ok := derefConnection(snap.connections, idx)
		if !ok || conn.Key == excludeKey {
			continue
		}
		score := scorer(snap, idx)
		if bestIndex == -1 || score < bestScore {
			bestIndex = idx
			bestScore = score
		}
	}
	if bestIndex < 0 {
		return Connection{}, false
	}
	return derefConnection(snap.connections, bestIndex)
}

func derefConnection(connections []*Connection, idx int) (Connection, bool) {
	if idx < 0 || idx >= len(connections) || connections[idx] == nil {
		return Connection{}, false
	}
	return *connections[idx], true
}

func (b *Balancer) lossScore(snap *balancerSnapshot, idx int) uint64 {
	stats := statsByIndex(snap, idx)
	if stats == nil {
		return 500
	}
	sent := stats.sent.Load()
	if sent < 5 {
		return 500
	}

	acked := stats.acked.Load()
	if acked >= sent {
		return 0
	}
	// loss ratio in per 1000 for integer math (a/b -> a*1000/b)
	return (sent - acked) * 1000 / sent
}

func (b *Balancer) latencyScore(snap *balancerSnapshot, idx int) uint64 {
	stats := statsByIndex(snap, idx)
	if stats == nil {
		return 999000
	}
	count := stats.rttCount.Load()
	if count < 5 {
		return 999000
	}
	return stats.rttMicrosSum.Load() / count
}

func (b *Balancer) roundRobinBestConnection(snap *balancerSnapshot) (Connection, bool) {
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, false
	}
	pos := int(b.rrCounter.Add(1)-1) % len(snap.valid)
	return derefConnection(snap.connections, snap.valid[pos])
}

func (b *Balancer) roundRobinBestConnectionExcluding(snap *balancerSnapshot, excludeKey string) (Connection, bool) {
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, false
	}
	ordered := b.rotatedValidIndices(snap, 1)
	for _, idx := range ordered {
		conn, ok := derefConnection(snap.connections, idx)
		if !ok || conn.Key == excludeKey {
			continue
		}
		return conn, true
	}
	return Connection{}, false
}

func (b *Balancer) rotatedValidIndices(snap *balancerSnapshot, step int) []int {
	if snap == nil || len(snap.valid) == 0 {
		return nil
	}
	if step < 1 {
		step = 1
	}

	start := int(b.rrCounter.Add(uint64(step)) - uint64(step))
	ordered := make([]int, len(snap.valid))
	for i := range snap.valid {
		ordered[i] = snap.valid[(start+i)%len(snap.valid)]
	}
	return ordered
}

func (b *Balancer) hasLossSignal(snap *balancerSnapshot) bool {
	if snap == nil {
		return false
	}
	for _, idx := range snap.valid {
		stats := statsByIndex(snap, idx)
		if stats != nil && stats.sent.Load() >= 5 {
			return true
		}
	}
	return false
}

func (b *Balancer) hasLatencySignal(snap *balancerSnapshot) bool {
	if snap == nil {
		return false
	}
	for _, idx := range snap.valid {
		stats := statsByIndex(snap, idx)
		if stats != nil && stats.rttCount.Load() >= 5 {
			return true
		}
	}
	return false
}

func statsByIndex(snap *balancerSnapshot, idx int) *connectionStats {
	if snap == nil || idx < 0 || idx >= len(snap.stats) {
		return nil
	}
	return snap.stats[idx]
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

// ConnectionStatEntry holds per-resolver stats for periodic reporting.
type ConnectionStatEntry struct {
	Key         string
	Valid       bool
	Sent        uint64
	Acked       uint64
	AvgRTTMicro uint64
}

// BalancerStats holds aggregated snapshot stats.
type BalancerStats struct {
	Total   int
	Valid   int
	Entries []ConnectionStatEntry
}

// Stats returns a snapshot of per-connection statistics.
func (b *Balancer) Stats() BalancerStats {
	snap := b.snapshot.Load()
	if snap == nil {
		return BalancerStats{}
	}

	entries := make([]ConnectionStatEntry, 0, len(snap.connections))
	for idx, conn := range snap.connections {
		if conn == nil {
			continue
		}
		entry := ConnectionStatEntry{
			Key:   conn.Key,
			Valid: conn.IsValid,
		}
		if idx < len(snap.stats) && snap.stats[idx] != nil {
			s := snap.stats[idx]
			entry.Sent = s.sent.Load()
			entry.Acked = s.acked.Load()
			cnt := s.rttCount.Load()
			if cnt > 0 {
				entry.AvgRTTMicro = s.rttMicrosSum.Load() / cnt
			}
		}
		entries = append(entries, entry)
	}

	return BalancerStats{
		Total:   len(snap.connections),
		Valid:   len(snap.valid),
		Entries: entries,
	}
}
