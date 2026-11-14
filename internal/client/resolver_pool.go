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

// CandidateState represents the five authoritative finite state machine states
// that any resolver-domain path candidate can occupy.
type CandidateState int

const (
	StateUntested CandidateState = iota
	StateChecking
	StateActive
	StateStandby
	StateRejected

	// Backward-compatibility aliases
	StateInactive   = StateUntested
	StateRechecking = StateChecking
)

func (s CandidateState) String() string {
	switch s {
	case StateUntested:
		return "Untested"
	case StateChecking:
		return "Checking"
	case StateActive:
		return "Active"
	case StateStandby:
		return "Standby"
	case StateRejected:
		return "Rejected"
	default:
		return "Unknown"
	}
}

// poolCandidate encapsulates a connection path, its lifecycle state, and performance stats.
type poolCandidate struct {
	conn                Connection
	state               CandidateState
	wasStandby          bool
	stats               *connectionStats
	burstThroughputKBps float64
	mtuObservedAt       time.Time
	mtuRTTObservedAt    time.Time
	burstObservedAt     time.Time
	failureReason       string
	lastStateChange     time.Time
	initialAttemptDone  bool
	failStreak          int
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
	targetEndpoints   int
	syncedUploadMTU   int
	syncedDownloadMTU int

	candidates  []poolCandidate
	indexByKey  map[string]int
	activeIDs   []int
	inactiveIDs []int

	healthRRCounter         atomic.Uint64
	recoveryFairnessCounter atomic.Uint64
	onPoolChanged           func()
	checkGeneration         uint64
	optionalReplacements    uint64
}

// SetTargetEndpoints sets the continuing minimum distinct-endpoint coverage goal.
func (p *ResolverPool) SetTargetEndpoints(target int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targetEndpoints = target
}

// TargetEndpoints returns the continuing minimum distinct-endpoint coverage goal.
func (p *ResolverPool) TargetEndpoints() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.targetEndpoints
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

// SetConnections loads candidate connections into the pool in StateUntested.
func (p *ResolverPool) SetConnections(connections []*Connection) {
	p.mu.Lock()
	defer p.mu.Unlock()

	size := len(connections)
	p.candidates = make([]poolCandidate, 0, size)
	p.indexByKey = make(map[string]int, size)
	p.activeIDs = make([]int, 0, size)
	p.inactiveIDs = make([]int, 0, size)
	p.optionalReplacements = 0

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
			state: StateUntested,
			stats: &connectionStats{},
		})
		p.indexByKey[copied.Key] = idx
		p.inactiveIDs = append(p.inactiveIDs, idx)
	}
}

// AddConnection adds a single connection to the pool in StateUntested.
func (p *ResolverPool) AddConnection(conn *Connection) bool {
	if p == nil || conn == nil || conn.Key == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.indexByKey[conn.Key]; exists {
		return false
	}
	copied := *conn
	copied.IsValid = false
	copied.StandbyEligible = false

	idx := len(p.candidates)
	p.candidates = append(p.candidates, poolCandidate{
		conn:  copied,
		state: StateUntested,
		stats: &connectionStats{},
	})
	p.indexByKey[copied.Key] = idx
	p.inactiveIDs = append(p.inactiveIDs, idx)
	return true
}

func (p *ResolverPool) syncConnectionFlagsLocked(cand *poolCandidate) {
	if cand == nil {
		return
	}
	cand.conn.IsValid = (cand.state == StateActive)
	cand.conn.StandbyEligible = (cand.state == StateStandby && p.supportsSessionMTULocked(cand.conn))
}

// candidateSnapshotLocked derives compatibility fields on a copy. Readers must
// never write into candidate storage while holding a shared lock.
func (p *ResolverPool) candidateSnapshotLocked(cand *poolCandidate) Connection {
	conn := cand.conn
	conn.IsValid = cand.state == StateActive
	conn.StandbyEligible = cand.state == StateStandby && p.supportsSessionMTULocked(conn)
	return conn
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

// SetMaxActive updates the maximum active path limit.
func (p *ResolverPool) SetMaxActive(maxActive int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxActive = maxActive
}

// MaxActive returns the maximum active path limit.
func (p *ResolverPool) MaxActive() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.maxActive
}

// ActiveResolvers returns a snapshot copy of all connections representing Active Paths.
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

// StandbyPaths returns a snapshot copy of all paths in StateStandby that meet Session MTU.
func (p *ResolverPool) StandbyPaths() []Connection {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	var result []Connection
	for _, idx := range p.inactiveIDs {
		if idx >= 0 && idx < len(p.candidates) {
			cand := &p.candidates[idx]
			if cand.state == StateStandby && p.supportsSessionMTULocked(cand.conn) {
				result = append(result, p.candidateSnapshotLocked(cand))
			}
		}
	}
	return result
}

// StandbyPairings is a compatibility alias for StandbyPaths.
func (p *ResolverPool) StandbyPairings() []Connection { return p.StandbyPaths() }

// StandbyResolvers is an alias for StandbyPaths for backward compatibility.
func (p *ResolverPool) StandbyResolvers() []Connection {
	return p.StandbyPaths()
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
		result[i] = p.candidateSnapshotLocked(&p.candidates[i])
	}
	return result
}

// ActiveCount returns the number of Active Paths.
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
	return p.candidateSnapshotLocked(&p.candidates[idx]), true
}

func (p *ResolverPool) matchesCheckingLeaseLocked(cand *poolCandidate, lease Connection) bool {
	return cand.state == StateChecking && lease.checkGeneration != 0 && cand.conn.checkGeneration == lease.checkGeneration
}

// CandidateState returns the current authoritative lifecycle state of the candidate.
func (p *ResolverPool) CandidateState(key string) (CandidateState, bool) {
	if p == nil {
		return StateUntested, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	idx, ok := p.indexByKey[key]
	if !ok || idx < 0 || idx >= len(p.candidates) {
		return StateUntested, false
	}
	return p.candidates[idx].state, true
}

// AcquireCandidateForChecking reserves a specific candidate for initial qualification or recheck.
// Transitions the candidate to StateChecking and revokes StandbyEligible while leased.
func (p *ResolverPool) AcquireCandidateForChecking(key string) (Connection, bool) {
	if p == nil {
		return Connection{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	idx, ok := p.indexByKey[key]
	if !ok || idx < 0 || idx >= len(p.candidates) {
		return Connection{}, false
	}
	cand := &p.candidates[idx]
	if cand.state == StateChecking || cand.state == StateActive {
		return Connection{}, false
	}
	cand.wasStandby = (cand.state == StateStandby)
	cand.state = StateChecking
	p.checkGeneration++
	cand.conn.checkGeneration = p.checkGeneration
	cand.conn.LastHealthCheckAt = time.Now()
	p.syncConnectionFlagsLocked(cand)
	return cand.conn, true
}

// CancelChecking handles interrupted or cancelled qualification work.
// Interrupted initial work returns to StateUntested.
// An interrupted recheck restores StateStandby only if it remains valid for the current Session;
// otherwise it becomes StateRejected.
func (p *ResolverPool) CancelChecking(lease Connection) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	idx, ok := p.indexByKey[lease.Key]
	if !ok || idx < 0 || idx >= len(p.candidates) {
		return
	}
	cand := &p.candidates[idx]
	if !p.matchesCheckingLeaseLocked(cand, lease) {
		return
	}
	if cand.wasStandby && p.supportsSessionMTULocked(cand.conn) {
		cand.state = StateStandby
	} else if cand.wasStandby {
		cand.state = StateRejected
	} else {
		cand.state = StateUntested
	}
	cand.wasStandby = false
	p.syncConnectionFlagsLocked(cand)
}

// CandidateMTUParams encapsulates probed MTU bounds and resolution latency.
type CandidateMTUParams struct {
	UploadBytes   int
	UploadChars   int
	DownloadBytes int
	ResolveTime   time.Duration
}

// FromMTUProbeResult converts an MTUProbeResult into CandidateMTUParams.
func (p *CandidateMTUParams) FromMTUProbeResult(res MTUProbeResult) {
	p.UploadBytes = res.UploadBytes
	p.UploadChars = res.UploadChars
	p.DownloadBytes = res.DownloadBytes
	p.ResolveTime = res.ResolveTime
}

func (p *ResolverPool) applyCandidateMTULocked(cand *poolCandidate, params CandidateMTUParams) {
	cand.mtuObservedAt = time.Now()
	cand.conn.UploadMTUBytes = params.UploadBytes
	cand.conn.UploadMTUChars = params.UploadChars
	cand.conn.DownloadMTUBytes = params.DownloadBytes
	if params.ResolveTime > 0 {
		cand.mtuRTTObservedAt = cand.mtuObservedAt
		cand.conn.MTUResolveTime = params.ResolveTime
	}
}

// CommitCandidateOutcomeWithParams commits qualification results using bundled MTU parameters.
func (p *ResolverPool) CommitCandidateOutcomeWithParams(lease Connection, qualified bool, params CandidateMTUParams) bool {
	return p.commitCandidateOutcome(lease, qualified, params)
}

// CommitCandidateOutcome commits qualification results for a candidate in StateChecking.
// If qualified is true and Session MTU is met, updates MTU parameters and promotes to Active or Standby.
// If qualified is false or Session MTU is not met, transitions candidate to StateRejected.
func (p *ResolverPool) CommitCandidateOutcome(lease Connection, qualified bool, uploadBytes, uploadChars, downloadBytes int, resolveTime time.Duration) bool {
	return p.commitCandidateOutcome(lease, qualified, CandidateMTUParams{UploadBytes: uploadBytes, UploadChars: uploadChars, DownloadBytes: downloadBytes, ResolveTime: resolveTime})
}

func (p *ResolverPool) commitCandidateOutcome(lease Connection, qualified bool, params CandidateMTUParams) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	idx, ok := p.indexByKey[lease.Key]
	if !ok || idx < 0 || idx >= len(p.candidates) {
		p.mu.Unlock()
		return false
	}
	cand := &p.candidates[idx]
	if !p.matchesCheckingLeaseLocked(cand, lease) {
		p.mu.Unlock()
		return false
	}

	cand.wasStandby = false
	cand.initialAttemptDone = true
	if qualified {
		cand.failStreak = 0
		p.applyCandidateMTULocked(cand, params)
		if !p.supportsSessionMTULocked(cand.conn) {
			qualified = false
		}
	}

	if !qualified {
		cand.failStreak++
		cand.state = StateRejected
		p.syncConnectionFlagsLocked(cand)
		p.removeActiveIndexLocked(idx)
		p.addInactiveIndexLocked(idx)
		cb := p.onPoolChanged
		p.mu.Unlock()
		if cb != nil {
			cb()
		}
		return true
	}

	p.moveConnectionStateLocked(idx, true)
	p.syncConnectionFlagsLocked(cand)
	cb := p.onPoolChanged
	p.mu.Unlock()

	if cb != nil {
		cb()
	}
	return true
}

// SetConnectionValidity changes the validity of a connection, adjusting active/standby state.
func (p *ResolverPool) SetConnectionValidity(key string, valid bool) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	if idx, exists := p.indexByKey[key]; exists && idx >= 0 && idx < len(p.candidates) && p.candidates[idx].state == StateChecking {
		p.mu.Unlock()
		return false
	}
	ok := p.setConnectionValidityLocked(key, valid)
	cb := p.onPoolChanged
	p.mu.Unlock()

	if ok && cb != nil {
		cb()
	}
	return ok
}

// DisableConnectionIfAboveFloor atomically disables an active connection only if the
// number of currently active connections strictly exceeds minActive.
func (p *ResolverPool) DisableConnectionIfAboveFloor(key string, minActive int) bool {
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
	if cand.state != StateActive {
		p.mu.Unlock()
		return false
	}
	if len(p.activeIDs) <= minActive {
		p.mu.Unlock()
		return false
	}
	ok = p.setConnectionValidityLocked(key, false)
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
	if (cand.state == StateActive) == valid {
		if !valid {
			p.transitionCandidateStateLocked(idx, StateRejected)
		} else {
			cand.state = StateActive
			p.syncConnectionFlagsLocked(cand)
		}
		return true
	}

	if valid {
		if cand.stats != nil {
			cand.stats.resetWindow()
		}
		p.transitionCandidateStateLocked(idx, StateActive)
	} else {
		p.transitionCandidateStateLocked(idx, StateRejected)
	}

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
	if cand.state == StateActive || cand.state == StateChecking {
		return false // Active paths and leased candidates are owned elsewhere.
	}
	if eligible {
		cand.state = StateStandby
	} else if cand.state == StateStandby {
		cand.state = StateRejected
	}
	p.syncConnectionFlagsLocked(cand)
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
	cand := &p.candidates[idx]
	return cand.state == StateStandby && p.supportsSessionMTULocked(cand.conn)
}

// SetCheckingMTU records intermediate qualification evidence only for its lease.
func (p *ResolverPool) SetCheckingMTU(lease Connection, params CandidateMTUParams) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	idx, ok := p.indexByKey[lease.Key]
	if !ok || !p.matchesCheckingLeaseLocked(&p.candidates[idx], lease) {
		return false
	}
	p.applyCandidateMTULocked(&p.candidates[idx], params)
	return true
}

// SetConnectionMTUParams updates MTU parameters using bundled CandidateMTUParams.
func (p *ResolverPool) SetConnectionMTUParams(key string, params CandidateMTUParams) bool {
	return p.SetConnectionMTU(key, params.UploadBytes, params.UploadChars, params.DownloadBytes, params.ResolveTime)
}

// SetConnectionMTU updates MTU parameters for a candidate connection.
func (p *ResolverPool) SetConnectionMTU(key string, uploadBytes int, uploadChars int, downloadBytes int, resolveTime ...time.Duration) bool {
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
	var rtt time.Duration
	if len(resolveTime) > 0 {
		rtt = resolveTime[0]
	}
	p.applyCandidateMTULocked(cand, CandidateMTUParams{
		UploadBytes:   uploadBytes,
		UploadChars:   uploadChars,
		DownloadBytes: downloadBytes,
		ResolveTime:   rtt,
	})
	return true
}

// ApplyMTUProbeParams applies bundled MTU parameters and optionally activates the candidate.
func (p *ResolverPool) ApplyMTUProbeParams(key string, params CandidateMTUParams, active bool) bool {
	return p.ApplyMTUProbeResult(key, params.UploadBytes, params.UploadChars, params.DownloadBytes, params.ResolveTime, active)
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
	cand.initialAttemptDone = true
	cand.conn.LastHealthCheckAt = time.Now()
	p.applyCandidateMTULocked(cand, CandidateMTUParams{
		UploadBytes:   uploadBytes,
		UploadChars:   uploadChars,
		DownloadBytes: downloadBytes,
		ResolveTime:   resolveTime,
	})
	wasValid := cand.conn.IsValid
	cand.wasStandby = false
	if active {
		cand.failStreak = 0
		cand.state = StateActive
		if cand.stats != nil {
			cand.stats.resetWindow()
		}
	} else {
		cand.failStreak++
		cand.state = StateRejected
	}
	p.syncConnectionFlagsLocked(cand)

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

// AdmitStartupBatch atomically commits completed qualification leases, then
// reconciles membership. Discovery reports evidence; only the pool chooses members.
func (p *ResolverPool) AdmitStartupBatch(results []QualifiedResolver) {
	if p == nil {
		return
	}
	p.mu.Lock()
	changed := false
	for _, result := range results {
		idx, ok := p.indexByKey[result.Connection.Key]
		if !ok {
			continue
		}
		cand := &p.candidates[idx]
		if !p.matchesCheckingLeaseLocked(cand, result.Connection) {
			continue
		}
		cand.initialAttemptDone = true
		cand.wasStandby = false
		if !result.BurstResult.Qualified || !p.supportsSessionMTULocked(cand.conn) {
			cand.failStreak++
			cand.state = StateRejected
		} else {
			burst := result.BurstResult
			cand.stats.seedBurst(burst.SentCount, burst.ReceivedCount, burst.AverageRTT)
			cand.burstObservedAt = time.Now()
			cand.burstThroughputKBps = burst.BurstThroughputKBps
			if cand.burstThroughputKBps <= 0 {
				cand.burstThroughputKBps = burst.ThroughputKBps
			}
			cand.failStreak = 0
			cand.state = StateStandby
		}
		p.syncConnectionFlagsLocked(cand)
		p.removeActiveIndexLocked(idx)
		p.addInactiveIndexLocked(idx)
		changed = true
	}
	if changed {
		p.optimizeLocked(0)
	}
	cb := p.onPoolChanged
	p.mu.Unlock()
	if changed && cb != nil {
		cb()
	}
}

// FinalizeFastStart validates startup qualification and reconciles using the
// continuing coverage goal. Readiness does not cap the number of usable endpoints.
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
	p.optimizeLocked(target)
	cb := p.onPoolChanged
	p.mu.Unlock()
	if cb != nil {
		cb()
	}
}

func (p *ResolverPool) isCandidateEligibleForRecoveryLocked(cand *poolCandidate, now time.Time, minInterval time.Duration) bool {
	if cand.state != StateStandby && cand.state != StateRejected {
		return false
	}

	backoff := minInterval
	if cand.state == StateRejected {
		mult := 1
		if cand.failStreak > 1 {
			shift := min(cand.failStreak-1, 8)
			mult = 1 << shift
		}
		backoff = minInterval * time.Duration(mult)
		if backoff > 5*time.Minute {
			backoff = 5 * time.Minute
		}
	}

	if cand.conn.LastHealthCheckAt.IsZero() {
		return true
	}
	return now.Sub(cand.conn.LastHealthCheckAt) >= backoff
}

func (p *ResolverPool) leaseCandidateForRecheckLocked(cand *poolCandidate, now time.Time) (Connection, bool) {
	cand.wasStandby = (cand.state == StateStandby)
	cand.conn.LastHealthCheckAt = now
	cand.state = StateChecking
	p.checkGeneration++
	cand.conn.checkGeneration = p.checkGeneration
	p.syncConnectionFlagsLocked(cand)
	return cand.conn, true
}

// AcquireNextInactiveForRecheck selects the next eligible candidate for health probing.
// When the active working set is sufficient, prioritizes untested first-pass work over
// repeated rejected/standby refreshes. When insufficient, fairly schedules between
// untested and recovery candidates without starvation.
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

	target := p.targetEndpoints
	if target <= 0 {
		target = p.maxActive
	}
	activeEndpoints := make(map[EndpointKey]struct{})
	for _, idx := range p.activeIDs {
		cand := &p.candidates[idx]
		if cand.state == StateActive && p.supportsSessionMTULocked(cand.conn) {
			activeEndpoints[p.endpointKey(cand.conn)] = struct{}{}
		}
	}
	workingSetSufficient := target > 0 && len(activeEndpoints) >= target

	start := roundRobinStartIndex(p.healthRRCounter.Add(1)-1, n)

	if workingSetSufficient {
		// Priority 1: Untested candidates for first-pass coverage
		for i := 0; i < n; i++ {
			idx := p.inactiveIDs[(start+i)%n]
			cand := &p.candidates[idx]
			if cand.state == StateUntested {
				return p.leaseCandidateForRecheckLocked(cand, now)
			}
		}
		// Priority 2: Standby and Rejected candidates meeting backoff
		for i := 0; i < n; i++ {
			idx := p.inactiveIDs[(start+i)%n]
			cand := &p.candidates[idx]
			if p.isCandidateEligibleForRecoveryLocked(cand, now, minInterval) {
				return p.leaseCandidateForRecheckLocked(cand, now)
			}
		}
		return Connection{}, false
	}

	// Working set is insufficient -> fair scheduling between recovery and untested
	fairRecoveryFirst := (p.recoveryFairnessCounter.Add(1) % 2) == 1
	if fairRecoveryFirst {
		for i := 0; i < n; i++ {
			idx := p.inactiveIDs[(start+i)%n]
			cand := &p.candidates[idx]
			if p.isCandidateEligibleForRecoveryLocked(cand, now, minInterval) {
				return p.leaseCandidateForRecheckLocked(cand, now)
			}
		}
		for i := 0; i < n; i++ {
			idx := p.inactiveIDs[(start+i)%n]
			cand := &p.candidates[idx]
			if cand.state == StateUntested {
				return p.leaseCandidateForRecheckLocked(cand, now)
			}
		}
	} else {
		for i := 0; i < n; i++ {
			idx := p.inactiveIDs[(start+i)%n]
			cand := &p.candidates[idx]
			if cand.state == StateUntested {
				return p.leaseCandidateForRecheckLocked(cand, now)
			}
		}
		for i := 0; i < n; i++ {
			idx := p.inactiveIDs[(start+i)%n]
			cand := &p.candidates[idx]
			if p.isCandidateEligibleForRecoveryLocked(cand, now, minInterval) {
				return p.leaseCandidateForRecheckLocked(cand, now)
			}
		}
	}

	return Connection{}, false
}

func (p *ResolverPool) beginConnectionRecheck(key string) bool {
	_, ok := p.AcquireCandidateForChecking(key)
	return ok
}

// prepareRecheck accepts a scheduled lease or acquires a new one for a direct caller.
func (p *ResolverPool) prepareRecheck(conn Connection) (Connection, bool) {
	if conn.checkGeneration == 0 {
		return p.AcquireCandidateForChecking(conn.Key)
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	idx, ok := p.indexByKey[conn.Key]
	if !ok || !p.matchesCheckingLeaseLocked(&p.candidates[idx], conn) {
		return Connection{}, false
	}
	return conn, true
}

// ReleaseRecheck releases a rechecking candidate without committing new qualification.
func (p *ResolverPool) ReleaseRecheck(lease Connection) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	idx, ok := p.indexByKey[lease.Key]
	if !ok || idx < 0 || idx >= len(p.candidates) {
		return
	}
	cand := &p.candidates[idx]
	if !p.matchesCheckingLeaseLocked(cand, lease) {
		return
	}
	effectiveStandby := cand.wasStandby
	if effectiveStandby && p.supportsSessionMTULocked(cand.conn) {
		cand.state = StateStandby
	} else if effectiveStandby {
		cand.state = StateRejected
	} else if cand.initialAttemptDone {
		cand.state = StateRejected
	} else {
		cand.state = StateUntested
	}
	cand.wasStandby = false
	p.syncConnectionFlagsLocked(cand)
}

func (p *ResolverPool) endpointKey(conn Connection) EndpointKey {
	return connectionEndpointKey(conn)
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
	if !p.matchesCheckingLeaseLocked(cand, result.Connection) {
		p.mu.Unlock()
		return Connection{}, false
	}
	cand.wasStandby = false
	cand.initialAttemptDone = true
	if result.MTUVerified {
		cand.conn.UploadMTUBytes = result.Connection.UploadMTUBytes
		cand.conn.UploadMTUChars = result.Connection.UploadMTUChars
		cand.conn.DownloadMTUBytes = result.Connection.DownloadMTUBytes
		cand.conn.MTUResolveTime = result.Connection.MTUResolveTime
		cand.mtuObservedAt = time.Now()
		cand.mtuRTTObservedAt = cand.mtuObservedAt
	}
	qualified := result.MTUVerified && p.supportsSessionMTULocked(cand.conn) && (result.Burst == nil || result.Burst.Qualified)
	if qualified {
		cand.failStreak = 0
		if result.Burst == nil {
			cand.stats.seedConservative()
		} else {
			burst := result.Burst
			cand.stats.seedBurst(burst.SentCount, burst.ReceivedCount, burst.AverageRTT)
			throughput := burst.BurstThroughputKBps
			if throughput <= 0 {
				throughput = burst.ThroughputKBps
			}
			if !burst.RateLimited {
				cand.burstThroughputKBps = throughput
				cand.burstObservedAt = time.Now()
			}
		}
	} else {
		cand.failStreak++
	}
	p.setConnectionValidityLocked(cand.conn.Key, qualified)
	p.syncConnectionFlagsLocked(cand)
	retConn := cand.conn

	cb := p.onPoolChanged
	p.mu.Unlock()

	if cb != nil {
		cb()
	}
	return retConn, true
}

// ResolverPoolCoverageStats tracks cumulative initial coverage and current qualification.
type ResolverPoolCoverageStats struct {
	ConfiguredPaths          int
	ConfiguredPairings       int // Deprecated: use ConfiguredPaths.
	CompletedInitialAttempts int
	RemainingUntested        int
	DistinctQualified        int
	IsFirstPassComplete      bool
	OptionalReplacements     uint64 // Performance swaps, excluding coverage repairs and vacancy filling.
}

// CoverageStats reports configured paths, completed initial attempts, remaining
// untested paths, and distinct qualified endpoints.
func (p *ResolverPool) CoverageStats() ResolverPoolCoverageStats {
	if p == nil {
		return ResolverPoolCoverageStats{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	configured := len(p.candidates)
	completed := 0
	distinctEndpoints := make(map[EndpointKey]struct{})

	for i := range p.candidates {
		cand := &p.candidates[i]
		if cand.initialAttemptDone {
			completed++
		}
		if cand.state == StateActive || cand.state == StateStandby {
			distinctEndpoints[p.endpointKey(cand.conn)] = struct{}{}
		}
	}

	untested := configured - completed
	if untested < 0 {
		untested = 0
	}

	return ResolverPoolCoverageStats{
		ConfiguredPaths:          configured,
		ConfiguredPairings:       configured,
		CompletedInitialAttempts: completed,
		RemainingUntested:        untested,
		DistinctQualified:        len(distinctEndpoints),
		IsFirstPassComplete:      completed >= configured,
		OptionalReplacements:     p.optionalReplacements,
	}
}

// IsFirstPassComplete returns true if every configured path has completed an initial attempt.
func (p *ResolverPool) IsFirstPassComplete() bool {
	if p == nil {
		return true
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for i := range p.candidates {
		if !p.candidates[i].initialAttemptDone {
			return false
		}
	}
	return true
}

// Optimize fills vacant slots with qualified Standby Paths, then replaces
// degraded Active Paths with meaningfully better standby candidates (>1.25x).
// When targetEndpoints is specified (> 0), it also swaps duplicate active paths
// for unrepresented standby endpoints to satisfy the unique-endpoint quota.
func (p *ResolverPool) Optimize(targetEndpoints ...int) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	target := 0
	if len(targetEndpoints) > 0 {
		target = targetEndpoints[0]
	}
	swapped := p.optimizeLocked(target)
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
	if p.syncedUploadMTU == 0 && p.syncedDownloadMTU == 0 {
		return true
	}
	return conn.UploadMTUBytes > 0 && conn.DownloadMTUBytes > 0 &&
		conn.UploadMTUBytes >= p.syncedUploadMTU && conn.DownloadMTUBytes >= p.syncedDownloadMTU
}

func (p *ResolverPool) bestStandbyLocked() (int, float64) {
	// Find the best standby that can carry the current session.
	bestInactiveIdx := -1
	bestInactiveScore := -1.0
	for _, inactIdx := range p.inactiveIDs {
		cand := &p.candidates[inactIdx]
		if cand.state != StateStandby {
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

func (p *ResolverPool) optimizeLocked(target int) bool {
	if target > 0 {
		p.targetEndpoints = target
	}
	changed := false
	// Reconciliation and direct admission use exactly the same membership policy.
	for _, idx := range append([]int(nil), p.activeIDs...) {
		if !p.supportsSessionMTULocked(p.candidates[idx].conn) {
			p.moveConnectionStateLocked(idx, false)
			changed = true
		}
	}
	for {
		standby := make([]int, 0, len(p.inactiveIDs))
		for _, idx := range p.inactiveIDs {
			c := &p.candidates[idx]
			if c.state == StateStandby && p.supportsSessionMTULocked(c.conn) {
				standby = append(standby, idx)
			}
		}
		sort.SliceStable(standby, func(i, j int) bool {
			a, b := standby[i], standby[j]
			sa, sb := p.calculateConnectionScoreLocked(a), p.calculateConnectionScoreLocked(b)
			if sa != sb {
				return sa > sb
			}
			return p.candidates[a].conn.Key < p.candidates[b].conn.Key
		})
		// Coverage repair precedes optional performance swaps once vacancies are filled.
		if p.maxActive > 0 && len(p.activeIDs) >= p.maxActive {
			endpoints := make(map[EndpointKey]bool)
			for _, idx := range p.activeIDs {
				endpoints[p.endpointKey(p.candidates[idx].conn)] = true
			}
			if len(endpoints) < p.targetEndpoints {
				sort.SliceStable(standby, func(i, j int) bool {
					return !endpoints[p.endpointKey(p.candidates[standby[i]].conn)] && endpoints[p.endpointKey(p.candidates[standby[j]].conn)]
				})
			}
		}
		promoted := false
		for _, idx := range standby {
			p.moveConnectionStateLocked(idx, true)
			if p.candidates[idx].state == StateActive {
				promoted, changed = true, true
				break // Rebuild the ordering after each membership change.
			}
		}
		if !promoted {
			return changed
		}
	}
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
		addr     config.ResolverAddress
		score    float64
		isActive bool
	}

	seenEndpoints := make(map[string]int)
	scored := make([]scoredEndpoint, 0, len(p.candidates))

	for i := range p.candidates {
		cand := &p.candidates[i]
		if cand.state != StateActive && cand.state != StateStandby {
			continue
		}
		if cand.state == StateStandby && !p.supportsSessionMTULocked(cand.conn) {
			continue
		}

		score := p.calculateConnectionScoreLocked(i)
		isActive := (cand.state == StateActive)

		epKey := formatResolverEndpoint(cand.conn.Resolver, cand.conn.ResolverPort)
		if existingIdx, exists := seenEndpoints[epKey]; exists {
			prev := scored[existingIdx]
			replace := false
			if isActive && !prev.isActive {
				replace = true
			} else if isActive == prev.isActive && score > prev.score {
				replace = true
			}
			if replace {
				scored[existingIdx].score = score
				scored[existingIdx].isActive = isActive
			}
			continue
		}

		seenEndpoints[epKey] = len(scored)
		scored = append(scored, scoredEndpoint{
			addr: config.ResolverAddress{
				IP:   cand.conn.Resolver,
				Port: cand.conn.ResolverPort,
			},
			score:    score,
			isActive: isActive,
		})
	}

	if len(scored) == 0 {
		return nil
	}

	sort.Slice(scored, func(i, j int) bool {
		// 1. Saved ordering prioritizes Active over Standby
		if scored[i].isActive != scored[j].isActive {
			return scored[i].isActive
		}
		// 2. Composite score descending
		if scored[i].score != scored[j].score {
			return scored[i].score > scored[j].score
		}
		// 3. Deterministic tie-breaker on endpoint address
		if scored[i].addr.IP != scored[j].addr.IP {
			return scored[i].addr.IP < scored[j].addr.IP
		}
		return scored[i].addr.Port < scored[j].addr.Port
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

// SetOnPoolChanged registers a nonblocking callback for membership and ranking-observation changes.
// The callback always runs without the pool lock held.
func (p *ResolverPool) SetOnPoolChanged(cb func()) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onPoolChanged = cb
}

// notifyRankingsChanged schedules a fresh ranking snapshot after live observations.
// Exported-order comparison and write coalescing belong to the persistence writer.
func (p *ResolverPool) notifyRankingsChanged() {
	if p == nil {
		return
	}
	p.mu.RLock()
	cb := p.onPoolChanged
	p.mu.RUnlock()
	if cb != nil {
		cb()
	}
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

		conn := p.candidateSnapshotLocked(cand)
		evaluation := p.evaluateCandidateLocked(i)
		snapshots[i] = ResolverStatsSnapshot{
			Connection:          conn,
			Sent:                sent,
			Acked:               acked,
			Lost:                lost,
			LossRatio:           lossRatio,
			AverageRTT:          avgRTT,
			ActiveStreams:       0,
			IsValid:             conn.IsValid,
			StandbyEligible:     conn.StandbyEligible,
			BurstThroughputKBps: cand.burstThroughputKBps,
			Evaluation:          &evaluation,
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

// CalculateConnectionScore returns the composite score for a candidate connection.
func (p *ResolverPool) CalculateConnectionScore(key string) float64 {
	if p == nil {
		return 0.0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	idx, ok := p.indexByKey[key]
	if !ok || idx < 0 || idx >= len(p.candidates) {
		return 0.0
	}
	return p.calculateConnectionScoreLocked(idx)
}

// CandidateEvaluation returns the same quality snapshot used for pool ranking.
func (p *ResolverPool) CandidateEvaluation(key string) (ResolverEvaluationSnapshot, bool) {
	if p == nil {
		return ResolverEvaluationSnapshot{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	idx, ok := p.indexByKey[key]
	if !ok {
		return ResolverEvaluationSnapshot{}, false
	}
	return p.evaluateCandidateLocked(idx), true
}

func (p *ResolverPool) evaluateCandidateLocked(idx int) ResolverEvaluationSnapshot {
	if idx < 0 || idx >= len(p.candidates) {
		return ResolverEvaluationSnapshot{Tier: "Poor"}
	}
	cand := &p.candidates[idx]
	var obs CandidateObservationInput
	if cand.stats != nil {
		obs = cand.stats.evaluationObservations()
	}
	obs.UploadMTUBytes = cand.conn.UploadMTUBytes
	obs.DownloadMTUBytes = cand.conn.DownloadMTUBytes
	obs.MTUResolveTime = cand.conn.MTUResolveTime
	obs.MTUObservedAt = cand.mtuObservedAt
	obs.MTURTTObservedAt = cand.mtuRTTObservedAt
	obs.BurstThroughputKBps = cand.burstThroughputKBps
	obs.BurstObservedAt = cand.burstObservedAt
	return EvaluateCandidateObservation(obs)
}

func (p *ResolverPool) calculateConnectionScoreLocked(idx int) float64 {
	ev := p.evaluateCandidateLocked(idx)
	return ev.CompositeScore
}

func (p *ResolverPool) transitionCandidateStateLocked(idx int, targetState CandidateState) {
	cand := &p.candidates[idx]
	if targetState == StateRejected {
		cand.state = StateRejected
		cand.wasStandby = false
		p.syncConnectionFlagsLocked(cand)
		p.removeActiveIndexLocked(idx)
		p.addInactiveIndexLocked(idx)
		if p.log != nil {
			p.log.Infof("<yellow>⚠️ Candidate Excluded (Eligibility Failure): %s (%s)</yellow>",
				p.endpointKey(cand.conn), cand.conn.Domain)
		}
		return
	}

	// targetState == StateActive: reconcile admission into active pool
	// If already in activeIDs, make sure marked active
	for _, activeIdx := range p.activeIDs {
		if activeIdx == idx {
			cand.state = StateActive
			cand.wasStandby = false
			p.syncConnectionFlagsLocked(cand)
			return
		}
	}

	// If maxActive is configured (> 0) and the active pool is full:
	if p.maxActive > 0 && len(p.activeIDs) >= p.maxActive {
		candScore := p.calculateConnectionScoreLocked(idx)
		candEndpoint := p.endpointKey(cand.conn)

		endpointCounts := make(map[EndpointKey]int)
		for _, activeIdx := range p.activeIDs {
			endpointCounts[p.endpointKey(p.candidates[activeIdx].conn)]++
		}
		uniqueEndpoints := len(endpointCounts)
		target := p.targetEndpoints

		// Priority 1: Endpoint Coverage Repair
		if (target > 0 && uniqueEndpoints < target) && endpointCounts[candEndpoint] == 0 {
			worstDupIdx := -1
			worstDupScore := math.MaxFloat64
			worstDupPos := -1

			for pos, activeIdx := range p.activeIDs {
				lbl := p.endpointKey(p.candidates[activeIdx].conn)
				if endpointCounts[lbl] > 1 {
					score := p.calculateConnectionScoreLocked(activeIdx)
					if score < worstDupScore {
						worstDupScore = score
						worstDupIdx = activeIdx
						worstDupPos = pos
					}
				}
			}

			if worstDupIdx >= 0 {
				demotedCand := &p.candidates[worstDupIdx]
				p.replaceActiveLocked(idx, worstDupIdx, worstDupPos)

				if p.log != nil {
					p.log.Infof("<green>🔄 Candidate Promoted to Active Path (Endpoint Coverage Repair): %s (%s, score: %.1f) [Demoted duplicate: %s, score: %.1f] | Active Paths: %d/%d</green>",
						p.endpointKey(cand.conn), cand.conn.Domain, candScore,
						p.endpointKey(demotedCand.conn), worstDupScore,
						len(p.activeIDs), len(p.candidates))
				}
				return
			}
		}

		// Priority 2: Performance Improvement (>1.25x strictly required, preserving achievable coverage)
		findMinActive := func(predicate func(activeIdx int, lbl EndpointKey) bool) (int, int, float64) {
			minIdx := -1
			minPos := -1
			minScore := math.MaxFloat64
			for pos, activeIdx := range p.activeIDs {
				lbl := p.endpointKey(p.candidates[activeIdx].conn)
				if predicate != nil && !predicate(activeIdx, lbl) {
					continue
				}
				score := p.calculateConnectionScoreLocked(activeIdx)
				if score < minScore {
					minScore = score
					minIdx = activeIdx
					minPos = pos
				}
			}
			return minIdx, minPos, minScore
		}

		displaceIdx, displacePos, displaceScore := findMinActive(func(activeIdx int, lbl EndpointKey) bool {
			return !(target > 0 && uniqueEndpoints <= target && endpointCounts[lbl] <= 1 && endpointCounts[candEndpoint] > 0 && lbl != candEndpoint)
		})
		if displaceIdx < 0 {
			displaceIdx, displacePos, displaceScore = findMinActive(func(activeIdx int, lbl EndpointKey) bool {
				return endpointCounts[lbl] > 1
			})
		}

		marginNeeded := displaceScore * 1.25
		if displaceIdx >= 0 && (candScore > marginNeeded || (displaceScore == 0 && candScore > 0)) {
			demotedCand := &p.candidates[displaceIdx]
			p.replaceActiveLocked(idx, displaceIdx, displacePos)
			p.optionalReplacements++

			if p.log != nil {
				p.log.Infof("<green>🔄 Candidate Promoted to Active Path (Performance Improvement): %s (%s, score: %.1f) [Demoted: %s, score: %.1f] | Active Paths: %d/%d</green>",
					cand.conn.ResolverLabel, cand.conn.Domain, candScore,
					demotedCand.conn.ResolverLabel, displaceScore,
					len(p.activeIDs), len(p.candidates))
			}
			return
		}

		// Candidate does not beat Active Paths -> Place in Standby status
		cand.state = StateStandby
		cand.wasStandby = false
		p.syncConnectionFlagsLocked(cand)
		p.addInactiveIndexLocked(idx)
		p.removeActiveIndexLocked(idx)
		if p.log != nil {
			p.log.Debugf("<cyan>⏸ Candidate Added to Standby Paths (Pool Full): %s (%s, score: %.1f) | Active Paths: %d</cyan>",
				cand.conn.ResolverLabel, cand.conn.Domain, candScore, len(p.activeIDs))
		}
		return
	}

	// Active pool has available capacity -> Add to activeIDs (Vacancy Filling)
	cand.state = StateActive
	cand.wasStandby = false
	p.syncConnectionFlagsLocked(cand)
	p.removeInactiveIndexLocked(idx)
	p.addActiveIndexLocked(idx)
	if p.log != nil {
		candScore := p.calculateConnectionScoreLocked(idx)
		p.log.Infof("<green>🔄 Candidate Promoted to Active Path (Vacancy Filling): %s (%s, score: %.1f) | Active Paths: %d/%d</green>",
			p.endpointKey(cand.conn), cand.conn.Domain, candScore,
			len(p.activeIDs), len(p.candidates))
	}
}

func (p *ResolverPool) moveConnectionStateLocked(idx int, valid bool) {
	if valid {
		p.transitionCandidateStateLocked(idx, StateActive)
	} else {
		p.transitionCandidateStateLocked(idx, StateRejected)
	}
}

func (p *ResolverPool) connectionsByIDsLocked(ids []int) []Connection {
	result := make([]Connection, len(ids))
	for i, id := range ids {
		if id >= 0 && id < len(p.candidates) {
			result[i] = p.candidateSnapshotLocked(&p.candidates[id])
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

// replaceActiveLocked keeps membership indexes and lifecycle flags in one operation.
func (p *ResolverPool) replaceActiveLocked(incoming, outgoing, activePos int) {
	demoted := &p.candidates[outgoing]
	demoted.state = StateStandby
	demoted.wasStandby = false
	p.syncConnectionFlagsLocked(demoted)
	p.activeIDs[activePos] = incoming
	p.addInactiveIndexLocked(outgoing)
	p.removeInactiveIndexLocked(incoming)
	promoted := &p.candidates[incoming]
	promoted.state = StateActive
	promoted.wasStandby = false
	p.syncConnectionFlagsLocked(promoted)
}
