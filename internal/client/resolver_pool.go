// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
)

// CandidateState represents the four distinct finite state machine states
// that any resolver-domain pairing candidate can occupy.
type CandidateState int

const (
	StateInactive CandidateState = iota
	StateActive
	StateStandby
	StateRechecking
)

func (s CandidateState) String() string {
	switch s {
	case StateInactive:
		return "Inactive"
	case StateActive:
		return "Active"
	case StateStandby:
		return "Standby"
	case StateRechecking:
		return "Rechecking"
	default:
		return "Unknown"
	}
}

// poolCandidate encapsulates a connection pairing, its lifecycle state, and performance stats.
type poolCandidate struct {
	conn  Connection
	state CandidateState
	stats *connectionStats
}

// ResolverRecheckResult carries probe verification results for recheck evaluation.
type ResolverRecheckResult struct {
	Connection  Connection
	MTUVerified bool
	Burst       *BurstProbeResult
}

// Backward-compatibility alias
type resolverRecheckResult = ResolverRecheckResult

// ResolverPool provides deep encapsulation of resolver candidate lifecycle,
// capacity bounding, FastStart admission, health recheck leases, and active optimization.
type ResolverPool struct {
	mu                sync.RWMutex
	log               *logger.Logger
	maxActive         int
	syncedUploadMTU   int
	syncedDownloadMTU int

	candidates  []poolCandidate
	indexByKey  map[string]int
	activeIDs   []int
	inactiveIDs []int

	healthRRCounter atomic.Uint64
	onPoolChanged   func()
}

// NewResolverPool initializes an empty ResolverPool with max active capacity.
func NewResolverPool(maxActive int, log *logger.Logger) *ResolverPool {
	return &ResolverPool{
		maxActive:   maxActive,
		log:         log,
		candidates:  make([]poolCandidate, 0),
		indexByKey:  make(map[string]int),
		activeIDs:   make([]int, 0),
		inactiveIDs: make([]int, 0),
	}
}

// SetConnections loads candidate connections into the pool in StateInactive.
func (p *ResolverPool) SetConnections(connections []*Connection) {
	p.mu.Lock()
	defer p.mu.Unlock()

	size := len(connections)
	p.candidates = make([]poolCandidate, 0, size)
	p.indexByKey = make(map[string]int, size)
	p.activeIDs = make([]int, 0, size)
	p.inactiveIDs = make([]int, 0, size)

	for _, conn := range connections {
		if conn == nil || conn.Key == "" {
			continue
		}
		copied := *conn
		copied.IsValid = false
		copied.StandbyEligible = false
		copied.UploadMTUBytes = 0
		copied.UploadMTUChars = 0
		copied.DownloadMTUBytes = 0
		copied.MTUResolveTime = 0
		copied.LastHealthCheckAt = time.Time{}

		idx := len(p.candidates)
		p.candidates = append(p.candidates, poolCandidate{
			conn:  copied,
			state: StateInactive,
			stats: &connectionStats{},
		})
		p.indexByKey[copied.Key] = idx
		p.inactiveIDs = append(p.inactiveIDs, idx)
	}
}

// SetSessionMTU records negotiated session upload and download MTU for qualification.
func (p *ResolverPool) SetSessionMTU(uploadMTU, downloadMTU int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.syncedUploadMTU = uploadMTU
	p.syncedDownloadMTU = downloadMTU
}

// SessionMTU returns the configured session upload and download MTU.
func (p *ResolverPool) SessionMTU() (int, int) {
	if p == nil {
		return 0, 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.syncedUploadMTU, p.syncedDownloadMTU
}

// SetMaxActive updates the maximum active resolver limit.
func (p *ResolverPool) SetMaxActive(maxActive int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxActive = maxActive
}

// MaxActive returns the maximum active resolver limit.
func (p *ResolverPool) MaxActive() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.maxActive
}

// ActiveResolvers returns a snapshot copy of all connections in StateActive.
func (p *ResolverPool) ActiveResolvers() []Connection {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.connectionsByIDsLocked(p.activeIDs)
}

// InactiveConnections returns a snapshot copy of all inactive connections.
func (p *ResolverPool) InactiveConnections() []Connection {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.connectionsByIDsLocked(p.inactiveIDs)
}

// AllConnections returns a snapshot copy of all connections across all states.
func (p *ResolverPool) AllConnections() []Connection {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]Connection, len(p.candidates))
	for i := range p.candidates {
		result[i] = p.candidates[i].conn
	}
	return result
}

// ActiveCount returns the number of active resolvers.
func (p *ResolverPool) ActiveCount() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.activeIDs)
}

// TotalCount returns the total number of candidate connections in the pool.
func (p *ResolverPool) TotalCount() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.candidates)
}

// GetConnectionByKey returns a copy of the connection for the given key.
func (p *ResolverPool) GetConnectionByKey(key string) (Connection, bool) {
	if p == nil {
		return Connection{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	idx, ok := p.indexByKey[key]
	if !ok || idx < 0 || idx >= len(p.candidates) {
		return Connection{}, false
	}
	return p.candidates[idx].conn, true
}

// SetConnectionValidity changes the validity of a connection, adjusting active/standby state.
func (p *ResolverPool) SetConnectionValidity(key string, valid bool) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	ok := p.setConnectionValidityLocked(key, valid)
	cb := p.onPoolChanged
	p.mu.Unlock()

	if ok && cb != nil {
		cb()
	}
	return ok
}

func (p *ResolverPool) setConnectionValidityLocked(key string, valid bool) bool {
	idx, ok := p.indexByKey[key]
	if !ok || idx < 0 || idx >= len(p.candidates) {
		return false
	}
	cand := &p.candidates[idx]
	if cand.conn.IsValid == valid {
		if !valid {
			cand.conn.StandbyEligible = false
			cand.state = StateInactive
		} else {
			cand.conn.StandbyEligible = false
			cand.state = StateActive
		}
		return true
	}

	cand.conn.IsValid = valid
	if valid {
		cand.conn.StandbyEligible = false
		cand.state = StateActive
		if cand.stats != nil {
			cand.stats.resetWindow()
		}
	} else {
		cand.conn.StandbyEligible = false
		cand.state = StateInactive
	}
	p.moveConnectionStateLocked(idx, valid)

	return true
}

// SetConnectionStandbyEligible sets standby eligibility for an inactive connection.
func (p *ResolverPool) SetConnectionStandbyEligible(key string, eligible bool) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	idx, ok := p.indexByKey[key]
	if !ok || idx < 0 || idx >= len(p.candidates) {
		return false
	}
	cand := &p.candidates[idx]
	if cand.conn.IsValid {
		return false // Invariant 1: Active connection cannot be standby eligible
	}
	cand.conn.StandbyEligible = eligible
	if eligible {
		cand.state = StateStandby
	} else if cand.state == StateStandby {
		cand.state = StateInactive
	}
	return true
}

// IsConnectionStandbyEligible reports whether a candidate is currently in StateStandby.
func (p *ResolverPool) IsConnectionStandbyEligible(key string) bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	idx, ok := p.indexByKey[key]
	if !ok || idx < 0 || idx >= len(p.candidates) {
		return false
	}
	return p.candidates[idx].conn.StandbyEligible
}

// SetConnectionMTU updates MTU parameters for a candidate connection.
func (p *ResolverPool) SetConnectionMTU(key string, uploadBytes int, uploadChars int, downloadBytes int) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	idx, ok := p.indexByKey[key]
	if !ok || idx < 0 || idx >= len(p.candidates) {
		return false
	}

	cand := &p.candidates[idx]
	cand.conn.UploadMTUBytes = uploadBytes
	cand.conn.UploadMTUChars = uploadChars
	cand.conn.DownloadMTUBytes = downloadBytes
	return true
}

// ApplyMTUProbeResult applies MTU probe results and optionally activates the candidate.
func (p *ResolverPool) ApplyMTUProbeResult(key string, uploadBytes int, uploadChars int, downloadBytes int, resolveTime time.Duration, active bool) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	idx, ok := p.indexByKey[key]
	if !ok || idx < 0 || idx >= len(p.candidates) {
		p.mu.Unlock()
		return false
	}

	cand := &p.candidates[idx]
	cand.conn.UploadMTUBytes = uploadBytes
	cand.conn.UploadMTUChars = uploadChars
	cand.conn.DownloadMTUBytes = downloadBytes
	cand.conn.MTUResolveTime = resolveTime
	wasValid := cand.conn.IsValid
	cand.conn.IsValid = active
	if active {
		cand.conn.StandbyEligible = false
		cand.state = StateActive
		if cand.stats != nil {
			cand.stats.resetWindow()
		}
	} else {
		cand.conn.StandbyEligible = false
		cand.state = StateInactive
	}

	if wasValid != active {
		p.moveConnectionStateLocked(idx, active)
	}

	cb := p.onPoolChanged
	p.mu.Unlock()

	if wasValid != active && cb != nil {
		cb()
	}

	return true
}

// AdmitStartupBatch admits a startup qualification batch under atomic lock.
func (p *ResolverPool) AdmitStartupBatch(results []QualifiedResolver, selected []Connection) {
	if p == nil {
		return
	}
	p.mu.Lock()

	active := make(map[string]bool, len(selected))
	for _, conn := range selected {
		active[conn.Key] = true
	}
	for _, result := range results {
		idx, ok := p.indexByKey[result.Connection.Key]
		if ok && result.BurstResult.Qualified {
			burst := result.BurstResult
			p.candidates[idx].stats.seedBurst(burst.SentCount, burst.ReceivedCount, burst.AverageRTT)
		}
	}
	// Release capacity before admitting winners, then retain qualified overflow.
	for _, result := range results {
		if !active[result.Connection.Key] {
			p.setConnectionValidityLocked(result.Connection.Key, false)
		}
	}
	for _, conn := range selected {
		p.setConnectionValidityLocked(conn.Key, true)
	}
	for _, result := range results {
		idx, ok := p.indexByKey[result.Connection.Key]
		if ok && !active[result.Connection.Key] && result.BurstResult.Qualified && !p.candidates[idx].conn.IsValid {
			p.candidates[idx].conn.StandbyEligible = true
			p.candidates[idx].state = StateStandby
		}
	}

	cb := p.onPoolChanged
	p.mu.Unlock()

	if cb != nil {
		cb()
	}
}

// FinalizeFastStart trims the active pool to meet the endpoint quota.
func (p *ResolverPool) FinalizeFastStart(qualifiedKeys map[string]struct{}, target int) {
	if p == nil {
		return
	}
	p.mu.Lock()

	if qualifiedKeys != nil {
		for _, conn := range p.connectionsByIDsLocked(p.activeIDs) {
			if _, qualified := qualifiedKeys[conn.Key]; !qualified {
				p.setConnectionValidityLocked(conn.Key, false)
			}
		}
	}
	active := p.connectionsByIDsLocked(p.activeIDs)
	endpoints := make(map[string]bool)
	for _, conn := range active {
		endpoints[conn.ResolverLabel] = true
	}
	if len(endpoints) <= target {
		cb := p.onPoolChanged
		p.mu.Unlock()
		if cb != nil {
			cb()
		}
		return
	}
	kept := make(map[string]bool, target)
	for _, conn := range active {
		if len(kept) < target || kept[conn.ResolverLabel] {
			kept[conn.ResolverLabel] = true
			continue
		}
		p.setConnectionValidityLocked(conn.Key, false)
		idx := p.indexByKey[conn.Key]
		p.candidates[idx].conn.StandbyEligible = true
		p.candidates[idx].state = StateStandby
	}

	cb := p.onPoolChanged
	p.mu.Unlock()

	if cb != nil {
		cb()
	}
}

// AcquireNextInactiveForRecheck round-robin selects the next eligible candidate for health probing.
// Transitions the candidate to StateRechecking and revokes standby eligibility synchronously.
func (p *ResolverPool) AcquireNextInactiveForRecheck(now time.Time, minInterval time.Duration) (Connection, bool) {
	if p == nil {
		return Connection{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	n := len(p.inactiveIDs)
	if n == 0 {
		return Connection{}, false
	}

	if minInterval < 0 {
		minInterval = 0
	}

	start := roundRobinStartIndex(p.healthRRCounter.Add(1)-1, n)
	for i := 0; i < n; i++ {
		idx := p.inactiveIDs[(start+i)%n]
		if idx < 0 || idx >= len(p.candidates) {
			continue
		}

		cand := &p.candidates[idx]
		if cand.state == StateRechecking {
			continue
		}
		if !cand.conn.LastHealthCheckAt.IsZero() && now.Sub(cand.conn.LastHealthCheckAt) < minInterval {
			continue
		}

		cand.conn.LastHealthCheckAt = now
		cand.conn.StandbyEligible = false
		cand.state = StateRechecking
		return cand.conn, true
	}

	return Connection{}, false
}

func (p *ResolverPool) beginConnectionRecheck(key string) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	idx, ok := p.indexByKey[key]
	if !ok || idx < 0 || idx >= len(p.candidates) {
		return false
	}
	p.candidates[idx].conn.StandbyEligible = false
	p.candidates[idx].state = StateRechecking
	return true
}

// ReleaseRecheck releases a rechecking candidate without committing new qualification.
func (p *ResolverPool) ReleaseRecheck(key string, wasStandby bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	idx, ok := p.indexByKey[key]
	if !ok || idx < 0 || idx >= len(p.candidates) {
		return
	}
	cand := &p.candidates[idx]
	if cand.state != StateRechecking {
		return
	}
	if wasStandby {
		cand.conn.StandbyEligible = true
		cand.state = StateStandby
	} else {
		cand.conn.StandbyEligible = false
		cand.state = StateInactive
	}
}

// CompleteRecheck commits MTU and burst measurements, evaluating pool admission.
func (p *ResolverPool) CompleteRecheck(result ResolverRecheckResult) (Connection, bool) {
	if p == nil {
		return Connection{}, false
	}
	p.mu.Lock()

	idx, ok := p.indexByKey[result.Connection.Key]
	if !ok || idx < 0 || idx >= len(p.candidates) {
		p.mu.Unlock()
		return Connection{}, false
	}
	cand := &p.candidates[idx]
	if result.MTUVerified {
		cand.conn.UploadMTUBytes = result.Connection.UploadMTUBytes
		cand.conn.UploadMTUChars = result.Connection.UploadMTUChars
		cand.conn.DownloadMTUBytes = result.Connection.DownloadMTUBytes
	}
	qualified := result.MTUVerified && p.supportsSessionMTULocked(cand.conn) && (result.Burst == nil || result.Burst.Qualified)
	if qualified {
		if result.Burst == nil {
			cand.stats.seedConservative()
		} else {
			burst := result.Burst
			cand.stats.seedBurst(burst.SentCount, burst.ReceivedCount, burst.AverageRTT)
		}
	}
	p.setConnectionValidityLocked(cand.conn.Key, qualified)
	retConn := cand.conn

	cb := p.onPoolChanged
	p.mu.Unlock()

	if cb != nil {
		cb()
	}
	return retConn, true
}

// Optimize fills vacant slots with qualified standby resolvers, then replaces
// degraded active resolvers with meaningfully better standby candidates (>1.25x).
func (p *ResolverPool) Optimize() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	swapped := p.optimizeLocked()
	cb := p.onPoolChanged
	p.mu.Unlock()

	if swapped && cb != nil {
		cb()
	}
	return swapped
}

// supportsSessionMTULocked keeps recovery admission and standby promotion on
// the same MTU requirements, including when the session changes during a probe.
func (p *ResolverPool) supportsSessionMTULocked(conn Connection) bool {
	return conn.UploadMTUBytes > 0 && conn.DownloadMTUBytes > 0 &&
		conn.UploadMTUBytes >= p.syncedUploadMTU && conn.DownloadMTUBytes >= p.syncedDownloadMTU
}

func (p *ResolverPool) bestStandbyLocked() (int, float64) {
	// Find the best standby that can carry the current session.
	bestInactiveIdx := -1
	bestInactiveScore := -1.0
	for _, inactIdx := range p.inactiveIDs {
		cand := &p.candidates[inactIdx]
		if !cand.conn.StandbyEligible {
			continue
		}
		if !p.supportsSessionMTULocked(cand.conn) {
			continue
		}
		score := p.calculateConnectionScoreLocked(inactIdx)
		if score > bestInactiveScore {
			bestInactiveScore = score
			bestInactiveIdx = inactIdx
		}
	}

	return bestInactiveIdx, bestInactiveScore
}

func (p *ResolverPool) optimizeLocked() bool {
	if len(p.inactiveIDs) == 0 {
		return false
	}

	swapped := false
	for p.maxActive <= 0 || len(p.activeIDs) < p.maxActive {
		idx, _ := p.bestStandbyLocked()
		if idx < 0 {
			break
		}
		p.moveConnectionStateLocked(idx, true)
		swapped = true
	}

	for i := 0; i < len(p.activeIDs); i++ {
		activeIdx := p.activeIDs[i]
		activeScore := p.calculateConnectionScoreLocked(activeIdx)

		bestInactiveIdx, bestInactiveScore := p.bestStandbyLocked()

		// Swap if the best standby candidate is meaningfully better (>1.25x active score)
		if bestInactiveIdx >= 0 && bestInactiveScore > (activeScore*1.25) {
			demotedCand := &p.candidates[activeIdx]
			promotedCand := &p.candidates[bestInactiveIdx]

			demotedCand.conn.IsValid = false
			demotedCand.conn.StandbyEligible = true
			demotedCand.state = StateStandby

			promotedCand.conn.IsValid = true
			promotedCand.conn.StandbyEligible = false
			promotedCand.state = StateActive

			// Swap IDs
			p.activeIDs[i] = bestInactiveIdx
			p.removeInactiveIndexLocked(bestInactiveIdx)
			p.addInactiveIndexLocked(activeIdx)

			if p.log != nil {
				p.log.Infof("<yellow>⚡ Active Resolver Swapped (Performance Degradation): %s (Score: %.1f) ➔ Replaced by %s (Score: %.1f)</yellow>",
					demotedCand.conn.ResolverLabel, activeScore,
					promotedCand.conn.ResolverLabel, bestInactiveScore)
			}
			swapped = true
		}
	}

	return swapped
}

// RankedEndpoints returns unique resolver endpoints sorted descending by composite score.
func (p *ResolverPool) RankedEndpoints(maxCount int) []config.ResolverAddress {
	if p == nil {
		return nil
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.candidates) == 0 {
		return nil
	}

	type scoredEndpoint struct {
		addr  config.ResolverAddress
		score float64
	}

	seenEndpoints := make(map[string]int)
	scored := make([]scoredEndpoint, 0, len(p.candidates))

	for i := range p.candidates {
		cand := &p.candidates[i]
		if !cand.conn.IsValid && !cand.conn.StandbyEligible {
			continue
		}

		score := p.calculateConnectionScoreLocked(i)
		if cand.conn.IsValid {
			score += 1000.0 // Active pool members boosted above standbys
		}

		epKey := formatResolverEndpoint(cand.conn.Resolver, cand.conn.ResolverPort)
		if existingIdx, exists := seenEndpoints[epKey]; exists {
			if score > scored[existingIdx].score {
				scored[existingIdx].score = score
			}
			continue
		}

		seenEndpoints[epKey] = len(scored)
		scored = append(scored, scoredEndpoint{
			addr: config.ResolverAddress{
				IP:   cand.conn.Resolver,
				Port: cand.conn.ResolverPort,
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

// SetOnPoolChanged registers a callback triggered whenever pool membership changes.
func (p *ResolverPool) SetOnPoolChanged(cb func()) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onPoolChanged = cb
}

// SeedBurstStats seeds qualification burst statistics on a candidate.
func (p *ResolverPool) SeedBurstStats(key string, sentCount, ackedCount int, avgRTT time.Duration) {
	if p == nil {
		return
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	idx, ok := p.indexByKey[key]
	if !ok || idx < 0 || idx >= len(p.candidates) || p.candidates[idx].stats == nil {
		return
	}
	p.candidates[idx].stats.seedBurst(sentCount, ackedCount, avgRTT)
}

// SeedConservativeStats seeds baseline conservative statistics on a candidate.
func (p *ResolverPool) SeedConservativeStats(key string) {
	if p == nil {
		return
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	idx, ok := p.indexByKey[key]
	if !ok || idx < 0 || idx >= len(p.candidates) || p.candidates[idx].stats == nil {
		return
	}
	p.candidates[idx].stats.seedConservative()
}

// GetStatsSnapshot thread-safely exports current metrics for all loaded resolvers.
func (p *ResolverPool) GetStatsSnapshot() []ResolverStatsSnapshot {
	if p == nil {
		return nil
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	snapshots := make([]ResolverStatsSnapshot, len(p.candidates))
	for i := range p.candidates {
		cand := &p.candidates[i]
		var sent, acked, lost, rttSum, rttCount uint64
		if cand.stats != nil {
			sent = cand.stats.sent.Load()
			acked = cand.stats.acked.Load()
			lost = cand.stats.lost.Load()
			rttSum = cand.stats.rttMicrosSum.Load()
			rttCount = cand.stats.rttCount.Load()
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
			Connection:      cand.conn,
			Sent:            sent,
			Acked:           acked,
			Lost:            lost,
			LossRatio:       lossRatio,
			AverageRTT:      avgRTT,
			ActiveStreams:   0,
			IsValid:         cand.conn.IsValid,
			StandbyEligible: cand.conn.StandbyEligible,
		}
	}
	return snapshots
}

func (p *ResolverPool) statsForKey(key string) *connectionStats {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	idx, ok := p.indexByKey[key]
	if !ok || idx < 0 || idx >= len(p.candidates) {
		return nil
	}
	return p.candidates[idx].stats
}

func (p *ResolverPool) calculateConnectionScoreLocked(idx int) float64 {
	if idx < 0 || idx >= len(p.candidates) {
		return 0.0
	}
	cand := &p.candidates[idx]
	downloadMTU := cand.conn.DownloadMTUBytes
	if downloadMTU <= 0 {
		downloadMTU = 500
	}

	var sent, lost, rttSum, rttCount uint64
	if cand.stats != nil {
		sent, _, lost, rttSum, rttCount = cand.stats.snapshot()
	}

	lossRatio := 0.0
	if sent > 0 {
		lossRatio = float64(lost) / float64(sent)
	}

	var avgRTT time.Duration
	if rttCount > 0 {
		avgRTT = time.Duration(rttSum/rttCount) * time.Microsecond
	} else if cand.conn.MTUResolveTime > 0 {
		avgRTT = cand.conn.MTUResolveTime
	}

	if sent > 0 && lost >= sent {
		return 0
	}
	if avgRTT <= 0 {
		return 1.0 // Unprobed default neutral low score
	}

	ev := EvaluateResolver(ResolverMetrics{
		DownloadMTUBytes: downloadMTU,
		RTT:              avgRTT,
		LossRatio:        lossRatio,
	})
	if math.IsNaN(ev.CompositeScore) || ev.CompositeScore < 0 {
		return 0
	}
	return ev.CompositeScore
}

func (p *ResolverPool) moveConnectionStateLocked(idx int, valid bool) {
	cand := &p.candidates[idx]
	if !valid {
		cand.conn.IsValid = false
		cand.conn.StandbyEligible = false
		cand.state = StateInactive
		p.removeActiveIndexLocked(idx)
		p.addInactiveIndexLocked(idx)
		return
	}

	// If already in activeIDs, make sure marked valid
	for _, activeIdx := range p.activeIDs {
		if activeIdx == idx {
			cand.conn.IsValid = true
			cand.conn.StandbyEligible = false
			cand.state = StateActive
			return
		}
	}

	// If maxActive is configured (> 0) and the active pool is full:
	if p.maxActive > 0 && len(p.activeIDs) >= p.maxActive {
		candScore := p.calculateConnectionScoreLocked(idx)

		// Find lowest scoring resolver currently in activeIDs
		worstActiveIdx := -1
		worstActiveScore := math.MaxFloat64
		worstActivePos := -1

		for pos, activeIdx := range p.activeIDs {
			score := p.calculateConnectionScoreLocked(activeIdx)
			if score < worstActiveScore {
				worstActiveScore = score
				worstActiveIdx = activeIdx
				worstActivePos = pos
			}
		}

		// Only displace if the incoming candidate is strictly higher scoring
		if worstActiveIdx >= 0 && candScore > worstActiveScore {
			demotedCand := &p.candidates[worstActiveIdx]
			demotedCand.conn.IsValid = false
			demotedCand.conn.StandbyEligible = true
			demotedCand.state = StateStandby
			p.activeIDs[worstActivePos] = idx // Replace in activeIDs slice
			p.addInactiveIndexLocked(worstActiveIdx)

			p.removeInactiveIndexLocked(idx)
			cand.conn.IsValid = true
			cand.conn.StandbyEligible = false
			cand.state = StateActive

			if p.log != nil {
				p.log.Infof("<green>🔄 DNS Resolver Promoted to Active Pool: %s (%s, score: %.1f) [Demoted: %s, score: %.1f] | Active Pool: %d/%d</green>",
					cand.conn.ResolverLabel, cand.conn.Domain, candScore,
					demotedCand.conn.ResolverLabel, worstActiveScore,
					len(p.activeIDs), len(p.candidates))
			}
			return
		}

		// Candidate does not beat active resolvers -> Place in Standby pool
		cand.conn.IsValid = false
		cand.conn.StandbyEligible = true
		cand.state = StateStandby
		p.addInactiveIndexLocked(idx)
		p.removeActiveIndexLocked(idx)
		if p.log != nil {
			p.log.Debugf("<cyan>⏸ DNS Resolver Added to Standby Pool (Pool Full): %s (%s, score: %.1f) | Active: %d</cyan>",
				cand.conn.ResolverLabel, cand.conn.Domain, candScore, len(p.activeIDs))
		}
		return
	}

	// Active pool has available capacity -> Add to activeIDs
	cand.conn.IsValid = true
	cand.conn.StandbyEligible = false
	cand.state = StateActive
	p.removeInactiveIndexLocked(idx)
	p.addActiveIndexLocked(idx)
}

func (p *ResolverPool) connectionsByIDsLocked(ids []int) []Connection {
	result := make([]Connection, len(ids))
	for i, id := range ids {
		if id >= 0 && id < len(p.candidates) {
			result[i] = p.candidates[id].conn
		}
	}
	return result
}

func (p *ResolverPool) addActiveIndexLocked(idx int) {
	for _, activeIdx := range p.activeIDs {
		if activeIdx == idx {
			return
		}
	}
	p.activeIDs = append(p.activeIDs, idx)
}

func (p *ResolverPool) addInactiveIndexLocked(idx int) {
	for _, inactiveIdx := range p.inactiveIDs {
		if inactiveIdx == idx {
			return
		}
	}
	p.inactiveIDs = append(p.inactiveIDs, idx)
}

func (p *ResolverPool) removeActiveIndexLocked(idx int) {
	for i, activeIdx := range p.activeIDs {
		if activeIdx == idx {
			p.activeIDs[i] = p.activeIDs[len(p.activeIDs)-1]
			p.activeIDs = p.activeIDs[:len(p.activeIDs)-1]
			break
		}
	}
}

func (p *ResolverPool) removeInactiveIndexLocked(idx int) {
	for i, inactiveIdx := range p.inactiveIDs {
		if inactiveIdx == idx {
			p.inactiveIDs[i] = p.inactiveIDs[len(p.inactiveIDs)-1]
			p.inactiveIDs = p.inactiveIDs[:len(p.inactiveIDs)-1]
			break
		}
	}
}
