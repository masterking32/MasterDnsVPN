# Technical Survey & Architecture Specification: R2 (Deep Resolver Pool Module & Balancer Refactor)

## 1. Executive Summary & Architecture Overview

MasterDnsVPN's client resolver subsystem currently mixes two fundamentally distinct concerns inside `internal/client/balancer.go` and its auxiliary file `internal/client/balancer_admission.go`:
1. **Resolver Pool Lifecycle Management**: Candidate collection, capacity bounding, MTU/burst qualification, 4-state candidate finite state machine (`StateInactive`, `StateActive`, `StateStandby`, `StateRechecking`), active pool admission, FastStart quota finalization, periodic recheck acquisition/release, and standby-vs-active pool optimization.
2. **Packet Dispatching & In-Flight Sample Tracking**: Multi-path packet routing across active resolvers (`SelectTargets`), sticky stream session routing with failover cooldowns, sliding-window timeout tracking, dynamic latency/loss score adjustments, atomic sent/acked/lost counters, and UDP query tracking across sharded pending maps.

In accordance with PR #205 and requirement **R2**, this survey maps the extraction of all pool management into a pure, cohesive, thread-safe module at `internal/client/resolver_pool.go` with its corresponding test suite `internal/client/resolver_pool_test.go`. The existing `balancer_admission.go` and `balancer_admission_test.go` are completely absorbed and deleted. `balancer.go` is refactored into a lean packet dispatcher that consumes active resolvers directly from `ResolverPool` while retaining backward-compatible delegation methods so existing tests (such as `empirical_challenge_test.go` and `balancer_test.go`) pass without regressions.

---

## 2. Existing Codebase Mapping

### 2.1. `internal/client/balancer_admission.go` (123 lines)
Currently provides private methods attached directly to `Balancer`:
- **`admitQualifiedBatch(results []QualifiedResolver, selected []Connection)`** (lines 7–37):
  Commits startup burst qualification results. For results marked `BurstResult.Qualified`, seeds burst statistics (`seedBurst`). Releases pool capacity by marking unselected results invalid, marks selected connections valid, and sets `StandbyEligible = true` on qualified candidates that were not selected for the active pool.
- **`finalizeFastStart(qualifiedKeys map[string]struct{}, target int)`** (lines 41–69):
  Trims active pool to meet `target` unique endpoints (`ResolverLabel`). Demotes active candidates whose key is not in `qualifiedKeys` (or when exceeding target) to inactive and flags them as `StandbyEligible = true`.
- **`beginConnectionRecheck(key string) bool`** & **`beginConnectionRecheckLocked(idx int)`** (lines 73–86):
  Excludes an inactive candidate from standby promotion by clearing `StandbyEligible = false`. This guarantees `OptimizeActivePool` cannot promote a candidate while a network probe is in-flight.
- **`resolverRecheckResult` struct** (lines 90–94):
  Holds `Connection`, `MTUVerified bool`, and `Burst *BurstProbeResult`.
- **`completeConnectionRecheck(result resolverRecheckResult) (Connection, bool)`** (lines 98–122):
  Updates MTU parameters (`UploadMTUBytes`, `UploadMTUChars`, `DownloadMTUBytes`). If verified and qualified, seeds conservative or burst statistics, and calls `setConnectionValidityLocked(conn.Key, true)`.

### 2.2. `internal/client/balancer_admission_test.go` (190 lines)
Contains 6 unit tests:
1. `TestAdmissionBatchReplacesSaturatedPool` (lines 28–49): Tests capacity displacement when new batch winners replace lower-ranked incumbents, and verifies standby placement.
2. `TestAdmissionBatchPreservesOtherBatches` (lines 51–59): Tests that successive startup batches do not displace prior qualified resolvers if capacity exists.
3. `TestAdmissionBatchSnapshotsNeverExposeIntermediatePlacement` (lines 61–89): Concurrency test ensuring atomic placement so candidates are never observed as both active and standby or missing during batch admission.
4. `TestAdmissionRecheckLifecycle` (lines 91–127): Tests both scheduled and direct recheck initiation, verifying that candidates undergoing recheck are not promoted by concurrent `OptimizeActivePool()`.
5. `TestAdmissionRecheckRejectionAndConservativeStats` (lines 129–160): Tests MTU failure, burst failure, and recheck without burst (seeding conservative 10/8 stats).
6. `TestAdmissionRecheckPreservesReplacementThreshold` (lines 162–189): Verifies that immediate recheck admission accepts strictly better scores, unlike periodic optimization which requires a 25% improvement threshold.

### 2.3. `internal/client/balancer.go` (2654 lines)
The file currently bundles pool management and packet dispatching:
- **Pool Management Fields in `Balancer` struct (to be moved to `ResolverPool`)**:
  - `maxActiveResolvers int` (line 97)
  - `syncedUploadMTU int`, `syncedDownloadMTU int` (lines 98–99)
  - `connections []Connection` (line 100)
  - `indexByKey map[string]int` (line 101)
  - `activeIDs []int`, `inactiveIDs []int` (lines 102–103)
- **Pool Management Methods in `Balancer` (to be moved to `ResolverPool`)**:
  - `SetConnections(connections []*Connection)` (lines 205–253)
  - `ActiveCount() int`, `TotalCount() int` (lines 255–265)
  - `GetConnectionByKey(key string) (Connection, bool)` (lines 267–276)
  - `SetConnectionValidity(...)` & `setConnectionValidityLocked(...)` (lines 278–317)
  - `SetConnectionStandbyEligible(...)`, `IsConnectionStandbyEligible(...)` (lines 321–346)
  - `SetSessionSynchronizedMTU(...)`, `SessionSynchronizedMTU()` (lines 351–369)
  - `GetRankedEndpoints(maxCount int) []config.ResolverAddress` (lines 451–524)
  - `SetConnectionMTU(...)`, `ApplyMTUProbeResult(...)` (lines 526–571)
  - `ActiveConnections()`, `InactiveConnections()`, `AllConnections()` (lines 1130–1148)
  - `NextInactiveConnectionForHealthCheck(...)` (lines 1151–1182)
  - `moveConnectionStateLocked(...)` (lines 1453–1531)
  - `OptimizeActivePool()` & `optimizeActivePoolLocked()` (lines 1533–1602)
- **Packet Dispatching & Sample Tracking Fields (retained in `Balancer`)**:
  - `strategy int` (line 85)
  - `rrCounter atomic.Uint64`, `totalPacketsSent atomic.Uint64`, `healthRRCounter atomic.Uint64`, `rngState atomic.Uint64` (lines 86–89)
  - `streamRoutes map[uint16]*balancerStreamRouteState` (line 105)
  - `streamFailoverThreshold int`, `streamFailoverCooldown time.Duration` (lines 109–110)
  - `pendingShards [16]balancerPendingShard`, `pendingSize atomic.Int32`, `pendingOverflow atomic.Bool`, `pendingEvictRR atomic.Uint32`, `nextPendingSweep atomic.Int64` (lines 90–93, 107)
  - `autoDisableEnabled bool`, `autoDisableTimeoutWindow time.Duration`, `onResolverDisabled`, `confirmResolverDown` (lines 112–115)
- **Packet Dispatching Methods (retained in `Balancer`)**:
  - `SelectTargets(packetType uint8, streamID uint16, requiredCount int) ([]Connection, error)` (lines 1220–1265)
  - `EnsureStream(streamID uint16)`, `CleanupStream(streamID uint16)`, `NoteStreamProgress(streamID uint16)` (lines 1184–1218)
  - `ReportSend(serverKey string)`, `TotalPacketsSent() uint64` (lines 573–590)
  - `ReportSuccess(serverKey string, rtt time.Duration)` (lines 592–604)
  - `ReportTimeout(...)`, `RetractTimeout(...)` (lines 606–684, 792–805)
  - `TrackResolverSend(...)`, `TrackResolverSuccess(...)`, `TrackResolverFailure(...)`, `CollectExpiredResolverTimeouts(...)` (lines 807–995)

### 2.4. `internal/client/client.go` & `client_utils.go`
- `Client` struct has `balancer *Balancer` (line 39) and `resolverMaintenanceStarted atomic.Bool` (line 90).
- `BuildConnectionMap()` (in `client_utils.go:605–652`) builds pairings and calls `c.balancer.SetConnections(pointers)`.
- `SaveRankedResolversToFile()` (in `client_utils.go:656–687`) calls `c.balancer.GetRankedEndpoints(maxRanked)`.
- `client.go:439` invokes `c.ensureResolverMaintenance(ctx)`. Under R4, this periodic loop is deleted and replaced with `c.pool.SetOnPoolChanged(func() { c.SaveRankedResolversToFile() })`.

---

## 3. Finite State Machine (FSM) & Candidate State Invariants

### 3.1. The Candidate States
Every resolver-domain pairing candidate in the pool exists in exactly one of four distinct states:

```
                  ┌────────────────────────────────────────────────────────┐
                  │                                                        │
                  ▼                                                        │ Demotion (100% loss /
       ┌─────────────────────┐       Capacity Admission (Batch / FastStart)│ probe failure)
       │    StateInactive    │ ───────────────────────────────────────────►│
       │ (IsValid=F, Stby=F) │ ◄─────────────────────────────────────────┐ │
       └─────────────────────┘       Recheck Failure / Cancellation      │ │
            ▲           │                                                │ │
            │           │ AcquireNextInactiveForRecheck                  │ │
            │           ▼                                                │ │
            │  ┌─────────────────────┐                                   │ │
            │  │   StateRechecking   │                                   │ │
            │  │ (IsValid=F, Stby=F) │                                   │ │
            │  └─────────────────────┘                                   │ │
            │    │            │                                          │ │
            │    │ Qualified  │ Qualified +                               │ │
            │    │ lower      │ beats active /                           │ │
ReleaseRecheck   │ score      │ capacity                                 │ │
(not standby)    │            ▼                                          │ │
            │    │     ┌─────────────────────┐                           │ │
            │    │     │     StateActive     │ ◄─────────────────────────┘ │
            │    │     │ (IsValid=T, Stby=F) │                             │
            │    │     └─────────────────────┘                             │
            │    │            ▲            │                               │
            │    │            │            │ Degradation Swap              │
            │    │            │            │ (Optimize: >1.25x)            │
            │    │            │ Promotion  │ or Displaced by New Batch     │
            │    │            │ (Optimize) │                               │
            │    │            │            ▼                               │
            │    │     ┌─────────────────────┐                             │
            │    └────►│    StateStandby     │ ◄───────────────────────────┘
            └───────── │ (IsValid=F, Stby=T) │   Qualified Overflow
          ReleaseRecheck └─────────────────────┘   (AdmitStartupBatch /
          (wasStandby)        │                    FinalizeFastStart)
                              │ AcquireNextInactiveForRecheck
                              ▼ (Revokes StandbyEligible!)
                       StateRechecking
```

| State | `IsValid` | `StandbyEligible` | In `activeIDs`? | In `inactiveIDs`? | Description |
|---|---|---|---|---|---|
| `StateInactive` | `false` | `false` | No | Yes | Untested, unprobed, failed MTU/burst, or demoted without qualification. |
| `StateActive` | `true` | `false` | Yes | No | Admitted active pool member actively carrying tunnel traffic. |
| `StateStandby` | `false` | `true` | No | Yes | Qualified resolver eligible for promotion during active pool optimization. |
| `StateRechecking` | `false` | `false` | No | Yes | Undergoing health check or probe. Leased out; promotion strictly prohibited. |

### 3.2. Detailed State Transition Matrix

| From | To | Trigger / Method | Precondition | Postcondition & Actions |
|---|---|---|---|---|
| `StateInactive` | `StateActive` | `AdmitStartupBatch` / FastStart | Qualified result; pool capacity available (`activeCount < maxActive`) | `IsValid=true`, `StandbyEligible=false`, added to `activeIDs`, removed from `inactiveIDs`. Window reset. |
| `StateInactive` | `StateStandby` | `AdmitStartupBatch` / `FinalizeFastStart` | Qualified burst result; candidate not in selected active set | `IsValid=false`, `StandbyEligible=true`. Preserves verified MTU and seeded stats. |
| `StateInactive` | `StateRechecking` | `AcquireNextInactiveForRecheck` | `now - LastHealthCheckAt >= minInterval` | `LastHealthCheckAt=now`, `state=StateRechecking`, `StandbyEligible=false`. |
| `StateStandby` | `StateRechecking` | `AcquireNextInactiveForRecheck` | `now - LastHealthCheckAt >= minInterval` | `LastHealthCheckAt=now`, `state=StateRechecking`, `StandbyEligible=false`. Revokes eligibility so `Optimize` cannot promote candidate during in-flight probe. |
| `StateRechecking` | `StateActive` | `CompleteRecheck` | `MTUVerified=true` && `Burst.Qualified=true` && (capacity available OR score > worst active) | If displaced worst active, demote worst active to `StateStandby`. Promoted becomes `StateActive` (`IsValid=true, StandbyEligible=false`). |
| `StateRechecking` | `StateStandby` | `CompleteRecheck` | `MTUVerified=true` && `Burst.Qualified=true`, but pool full and score <= worst active | `IsValid=false, StandbyEligible=true`. Seeded with burst or conservative stats. |
| `StateRechecking` | `StateStandby` | `ReleaseRecheck(key, wasStandby=true)` | Recheck probe aborted / cancelled, candidate was previously standby | Restores `StandbyEligible=true`, `state=StateStandby`. |
| `StateRechecking` | `StateInactive` | `CompleteRecheck` | `MTUVerified=false` OR `Burst.Qualified=false` | `IsValid=false, StandbyEligible=false`. Candidate demoted to inactive. |
| `StateRechecking` | `StateInactive` | `ReleaseRecheck(key, wasStandby=false)` | Recheck probe aborted / cancelled, candidate was inactive | `IsValid=false, StandbyEligible=false`. |
| `StateActive` | `StateStandby` | `Optimize` | Incumbent score degraded; best standby score > incumbent * 1.25 | Incumbent demoted (`IsValid=false, StandbyEligible=true`), standby promoted (`IsValid=true, StandbyEligible=false`). Stream routes cleared. |
| `StateActive` | `StateStandby` | `AdmitStartupBatch` / `CompleteRecheck` | Pool full; incoming qualified candidate has strictly higher score | Incumbent demoted (`IsValid=false, StandbyEligible=true`), incoming promoted. |
| `StateActive` | `StateStandby` | `FinalizeFastStart` | Candidate active, but exceeds endpoint target quota | Demoted (`IsValid=false, StandbyEligible=true`). |
| `StateActive` | `StateInactive` | `ReportTimeout` (100% loss auto-disable) | Consecutive timeouts exceed threshold; confirmed down | `IsValid=false, StandbyEligible=false`. Stream routes cleared. Moved to `inactiveIDs`. |

### 3.3. Mutual Exclusivity & Anti-Race Invariants
As rigorously proven by `TestEmpirical_ActiveStandbyMutualExclusivity` and `TestEmpirical_RecheckRevokesStandby_NoRaceWithOptimize`:
1. **Invariant 1: Mutual Exclusivity (`IsValid != StandbyEligible`)**:
   Under NO circumstances may `IsValid` and `StandbyEligible` both be `true`. An active resolver carrying traffic cannot simultaneously be a standby candidate.
2. **Invariant 2: Recheck Revocation**:
   When `AcquireNextInactiveForRecheck` leases a candidate, `StandbyEligible` MUST be set to `false` synchronously before the lock is released. High-frequency concurrent calls to `Optimize()` (up to 440,000+ calls observed during recheck) will skip this candidate, eliminating race conditions while network probes are in flight.
3. **Invariant 3: Atomic Batch Snapshots**:
   Batch transitions under `AdmitStartupBatch` and `FinalizeFastStart` execute under a single write lock (`mu.Lock()`), ensuring concurrent observers calling `ActiveResolvers()` or `GetStatsSnapshot()` never see intermediate or torn placements.

---

## 4. Capacity Bounding, Admission, and Optimization Mechanics

### 4.1. Capacity Bounding (`maxActive`)
- The active pool is bounded by `maxActive` (configured via `cfg.MaxActiveResolvers`).
- If `maxActive <= 0`, no limit is imposed.
- When `len(activeIDs) >= maxActive`:
  - An incoming candidate can only be admitted if its composite score strictly exceeds the lowest score among all currently active resolvers:
    `candScore > worstActiveScore`
  - When displaced, the worst active resolver is demoted to `StateStandby` (`StandbyEligible = true`), preserving its capacity for future re-promotion.

### 4.2. Startup Admission (`AdmitStartupBatch`)
- Input: `results []QualifiedResolver`, `selected []Connection`.
- Seeds burst stats (`SentCount`, `ReceivedCount`, `AverageRTT`) for all qualified results.
- Unselected candidates in the batch are demoted if active, while selected candidates are admitted.
- Qualified results not in `selected` are placed into `StateStandby`.
- If active pool membership changes, triggers `p.onPoolChanged()`.

### 4.3. FastStart Finalization (`FinalizeFastStart`)
- Input: `qualifiedKeys map[string]struct{}`, `target int`.
- If `qualifiedKeys != nil`, active connections not in `qualifiedKeys` are marked invalid.
- Ensures the active pool contains at most `target` unique endpoints (`ResolverLabel`).
- Any surplus active connections beyond `target` are demoted to `StateStandby`.
- If active pool membership changes, triggers `p.onPoolChanged()`.

### 4.4. Active Pool Optimization (`Optimize`)
- Scans all active resolvers in `activeIDs`.
- For each active resolver, computes its composite score:
  `activeScore = p.calculateScoreLocked(activeIdx)`
- Searches `inactiveIDs` for qualified standby candidates satisfying:
  1. `conn.StandbyEligible == true`
  2. Verified MTU: `conn.UploadMTUBytes > 0 && conn.DownloadMTUBytes > 0`
  3. Session MTU compliance:
     `syncedUploadMTU == 0 || conn.UploadMTUBytes >= syncedUploadMTU`
     `syncedDownloadMTU == 0 || conn.DownloadMTUBytes >= syncedDownloadMTU`
- Finds the highest-scoring candidate (`bestInactiveScore`).
- **Hysteresis Threshold**: Candidate is swapped only if:
  `bestInactiveScore > (activeScore * 1.25)`
  (Prevents flapping when candidate is only marginally better).
- Upon swap:
  - Active resolver -> demoted to `StateStandby`
  - Standby candidate -> promoted to `StateActive`
  - Indices swapped in `activeIDs` / `inactiveIDs`
  - Clears stream route affinities in `Balancer`
  - Invokes `p.onPoolChanged()` callback.
- Returns `true` if any swap took place.

### 4.5. Endpoint Ranking (`RankedEndpoints`)
- Input: `maxCount int`.
- Thread-safe read-lock (`p.mu.RLock()`).
- Filters for candidates that have passed MTU discovery, are active, or have recorded statistics.
- Computes composite score for each candidate.
- Applies an active pool boost: `score += 1000.0` so current active resolvers take precedence.
- Deduplicates across tunnel domains: groups by endpoint `formatResolverEndpoint(conn.Resolver, conn.ResolverPort)` and keeps the max score for each unique IP:Port.
- Sorts endpoints descending by score.
- Returns top `maxCount` `config.ResolverAddress`.

### 4.6. Event-Driven Persistence (`SetOnPoolChanged`)
- Replaces the 60-second periodic maintenance ticker from `resolver_maintenance.go`.
- Whenever pool membership changes (`AdmitStartupBatch`, `FinalizeFastStart`, `CompleteRecheck`, `Optimize`, or auto-disable), `p.onPoolChanged()` is called if non-nil.
- In `client.go`, registered during client initialization:
  ```go
  c.pool.SetOnPoolChanged(func() {
      c.SaveRankedResolversToFile()
  })
  ```
- Directly connects pool events to persistence without polling overhead.

---

## 5. Detailed Specifications for `internal/client/resolver_pool.go`

### 5.1. Data Structures & Types
```go
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

type CandidateState int

const (
	StateInactive CandidateState = iota
	StateActive
	StateStandby
	StateRechecking
)

type poolCandidate struct {
	conn            Connection
	state           CandidateState
	stats           connectionStats
}

type ResolverRecheckResult struct {
	Connection  Connection
	MTUVerified bool
	Burst       *BurstProbeResult
}

type ResolverPool struct {
	mu                sync.RWMutex
	log               *logger.Logger
	maxActive         int
	syncedUploadMTU   int
	syncedDownloadMTU int

	candidates        []poolCandidate
	indexByKey        map[string]int
	activeIDs         []int
	inactiveIDs       []int

	healthRRCounter   atomic.Uint64
	onPoolChanged     func()
}
```

### 5.2. Method Signatures & Behavioral Contracts

```go
// NewResolverPool initializes an empty ResolverPool with max active capacity.
func NewResolverPool(maxActive int, log *logger.Logger) *ResolverPool

// SetConnections loads candidate connections into the pool in StateInactive.
func (p *ResolverPool) SetConnections(connections []*Connection)

// SetSessionMTU records negotiated session upload and download MTU for qualification.
func (p *ResolverPool) SetSessionMTU(uploadMTU, downloadMTU int)

// SessionMTU returns the configured session upload and download MTU.
func (p *ResolverPool) SessionMTU() (int, int)

// SetMaxActive updates the maximum active resolver limit.
func (p *ResolverPool) SetMaxActive(maxActive int)

// MaxActive returns the maximum active resolver limit.
func (p *ResolverPool) MaxActive() int

// ActiveResolvers returns a snapshot copy of all connections in StateActive.
func (p *ResolverPool) ActiveResolvers() []Connection

// AllConnections returns a snapshot copy of all connections across all states.
func (p *ResolverPool) AllConnections() []Connection

// ActiveCount returns the number of active resolvers.
func (p *ResolverPool) ActiveCount() int

// TotalCount returns the total number of candidate connections in the pool.
func (p *ResolverPool) TotalCount() int

// GetConnectionByKey returns a copy of the connection for the given key.
func (p *ResolverPool) GetConnectionByKey(key string) (Connection, bool)

// SetConnectionValidity changes the validity of a connection, adjusting active/standby state.
func (p *ResolverPool) SetConnectionValidity(key string, valid bool) bool

// SetConnectionStandbyEligible sets standby eligibility for an inactive connection.
func (p *ResolverPool) SetConnectionStandbyEligible(key string, eligible bool) bool

// IsConnectionStandbyEligible reports whether a candidate is currently in StateStandby.
func (p *ResolverPool) IsConnectionStandbyEligible(key string) bool

// SetConnectionMTU updates MTU parameters for a candidate connection.
func (p *ResolverPool) SetConnectionMTU(key string, uploadBytes, uploadChars, downloadBytes int) bool

// ApplyMTUProbeResult applies MTU probe results and optionally activates the candidate.
func (p *ResolverPool) ApplyMTUProbeResult(key string, uploadBytes, uploadChars, downloadBytes int, resolveTime time.Duration, active bool) bool

// AdmitStartupBatch admits a startup qualification batch under atomic lock.
func (p *ResolverPool) AdmitStartupBatch(results []QualifiedResolver, selected []Connection)

// FinalizeFastStart trims the active pool to meet the endpoint quota.
func (p *ResolverPool) FinalizeFastStart(qualifiedKeys map[string]struct{}, target int)

// AcquireNextInactiveForRecheck round-robin selects the next eligible candidate for health probing.
// Transitions the candidate to StateRechecking and revokes standby eligibility.
func (p *ResolverPool) AcquireNextInactiveForRecheck(now time.Time, minInterval time.Duration) (Connection, bool)

// ReleaseRecheck releases a rechecking candidate without committing new qualification.
func (p *ResolverPool) ReleaseRecheck(key string, wasStandby bool)

// CompleteRecheck commits MTU and burst measurements, evaluating pool admission.
func (p *ResolverPool) CompleteRecheck(result ResolverRecheckResult) (Connection, bool)

// Optimize replaces degraded active resolvers with better standby candidates (>1.25x).
func (p *ResolverPool) Optimize() bool

// RankedEndpoints returns unique resolver endpoints sorted descending by composite score.
func (p *ResolverPool) RankedEndpoints(maxCount int) []config.ResolverAddress

// SetOnPoolChanged registers a callback triggered whenever pool membership changes.
func (p *ResolverPool) SetOnPoolChanged(cb func())

// SeedBurstStats seeds qualification burst statistics on a candidate.
func (p *ResolverPool) SeedBurstStats(key string, sentCount, ackedCount int, avgRTT time.Duration)

// SeedConservativeStats seeds baseline conservative statistics on a candidate.
func (p *ResolverPool) SeedConservativeStats(key string)

// GetStatsSnapshot thread-safely exports current metrics for all loaded resolvers.
func (p *ResolverPool) GetStatsSnapshot() []ResolverStatsSnapshot
```

---

## 6. Detailed Refactoring Plan for `internal/client/balancer.go`

### 6.1. Fields Removed from `Balancer`
- `maxActiveResolvers` -> Delegated to `b.pool.MaxActive()` / `SetMaxActive()`
- `syncedUploadMTU`, `syncedDownloadMTU` -> Delegated to `b.pool.SessionMTU()` / `SetSessionMTU()`
- `connections`, `indexByKey`, `activeIDs`, `inactiveIDs` -> Maintained in `b.pool`
- `b.pool *ResolverPool` added to `Balancer` struct

### 6.2. Retained Packet Dispatching & Sample Tracking
- `SelectTargets(packetType uint8, streamID uint16, requiredCount int) ([]Connection, error)`:
  Queries active resolvers directly via `b.pool.ActiveResolvers()`. Normalizes count, applies sticky stream routing with failover threshold/cooldown, and falls back to dynamic balancing strategy.
- `ReportSend(serverKey string)`:
  Increments `totalPacketsSent.Add(1)` and notifies stats.
- `ReportSuccess(serverKey string, rtt time.Duration)`:
  Updates acked count and RTT microsecond sum on the candidate.
- `ReportTimeout(serverKey string, now time.Time, window time.Duration, minActive int) bool`:
  Increments lost count. Evaluates sliding window for 100% loss. If auto-disable threshold is met and confirmed by `confirmResolverDown`:
  - Calls `b.pool.SetConnectionValidity(serverKey, false)`
  - Clears sticky stream routes referencing `serverKey`
  - Fires `onResolverDisabled` callback and warning log.
- `RetractTimeout(...)`:
  Decrements lost count in sliding window and candidate stats.
- `TrackResolverSend`, `TrackResolverSuccess`, `TrackResolverFailure`, `CollectExpiredResolverTimeouts`:
  In-flight DNS query sample tracking across 16 pending shards remains completely intact in `Balancer`.
- `TotalPacketsSent() uint64`:
  Returns `b.totalPacketsSent.Load()`.

### 6.3. Backward-Compatible Delegation Methods on `Balancer`
To guarantee 100% test compatibility for `balancer_test.go` and `empirical_challenge_test.go`:
```go
func (b *Balancer) Pool() *ResolverPool { return b.pool }
func (b *Balancer) SetConnections(c []*Connection) { b.pool.SetConnections(c) }
func (b *Balancer) ActiveCount() int { return b.pool.ActiveCount() }
func (b *Balancer) TotalCount() int { return b.pool.TotalCount() }
func (b *Balancer) ActiveConnections() []Connection { return b.pool.ActiveResolvers() }
func (b *Balancer) AllConnections() []Connection { return b.pool.AllConnections() }
func (b *Balancer) GetConnectionByKey(k string) (Connection, bool) { return b.pool.GetConnectionByKey(k) }
func (b *Balancer) SetConnectionValidity(k string, v bool) bool { return b.pool.SetConnectionValidity(k, v) }
func (b *Balancer) SetConnectionStandbyEligible(k string, e bool) bool { return b.pool.SetConnectionStandbyEligible(k, e) }
func (b *Balancer) IsConnectionStandbyEligible(k string) bool { return b.pool.IsConnectionStandbyEligible(k) }
func (b *Balancer) SetConnectionMTU(k string, u, uc, d int) bool { return b.pool.SetConnectionMTU(k, u, uc, d) }
func (b *Balancer) ApplyMTUProbeResult(k string, u, uc, d int, r time.Duration, a bool) bool { return b.pool.ApplyMTUProbeResult(k, u, uc, d, r, a) }
func (b *Balancer) SetMaxActiveResolvers(m int) { b.pool.SetMaxActive(m) }
func (b *Balancer) MaxActiveResolvers() int { return b.pool.MaxActive() }
func (b *Balancer) SetSessionSynchronizedMTU(u, d int) { b.pool.SetSessionMTU(u, d) }
func (b *Balancer) SessionSynchronizedMTU() (int, int) { return b.pool.SessionMTU() }
func (b *Balancer) OptimizeActivePool() bool { return b.pool.Optimize() }
func (b *Balancer) GetRankedEndpoints(m int) []config.ResolverAddress { return b.pool.RankedEndpoints(m) }
func (b *Balancer) NextInactiveConnectionForHealthCheck(now time.Time, minInterval time.Duration) (Connection, bool) {
	return b.pool.AcquireNextInactiveForRecheck(now, minInterval)
}
func (b *Balancer) SeedBurstStats(k string, s, a int, r time.Duration) { b.pool.SeedBurstStats(k, s, a, r) }
func (b *Balancer) SeedConservativeStats(k string) { b.pool.SeedConservativeStats(k) }
```

---

## 7. Call Sites & Impact Analysis

| File | Current Call | Refactored Call / Action |
|---|---|---|
| `internal/client/client.go:39` | `balancer *Balancer` | Add `pool *ResolverPool` field to `Client` struct. |
| `internal/client/client.go:90` | `resolverMaintenanceStarted atomic.Bool` | Remove atomic flag per R4. |
| `internal/client/client.go:253` | `NewBalancer(...)` | Instantiate `pool := NewResolverPool(cfg.MaxActiveResolvers, log)`, then `balancer := NewBalancer(..., pool)`. Wire `pool.SetOnPoolChanged(func() { c.SaveRankedResolversToFile() })`. |
| `internal/client/client.go:439` | `c.ensureResolverMaintenance(ctx)` | Remove invocation per R4 (event-driven persistence takes over). |
| `internal/client/client_utils.go:648` | `c.balancer.SetConnections(pointers)` | Call `c.pool.SetConnections(pointers)`. |
| `internal/client/client_utils.go:671` | `c.balancer.GetRankedEndpoints(maxRanked)` | Call `c.pool.RankedEndpoints(50)` per R4. |
| `internal/client/micro_burst.go:451` | `c.balancer.admitQualifiedBatch(...)` | Call `c.pool.AdmitStartupBatch(...)`. |
| `internal/client/mtu.go:563` | `c.balancer.finalizeFastStart(...)` | Call `c.pool.FinalizeFastStart(...)`. |
| `internal/client/mtu.go:807` | `c.balancer.NextInactiveConnectionForHealthCheck(...)` | Call `c.pool.AcquireNextInactiveForRecheck(...)`. |
| `internal/client/mtu.go:822` | `c.balancer.beginConnectionRecheck(...)` | Replaced by `AcquireNextInactiveForRecheck` (already sets `StateRechecking`). |
| `internal/client/mtu.go:828` | Error on transport dial | Call `c.pool.ReleaseRecheck(conn.Key, conn.StandbyEligible)` to release recheck lease cleanly. |
| `internal/client/mtu.go:834, 838, 866` | `c.balancer.completeConnectionRecheck(...)` | Call `c.pool.CompleteRecheck(...)`. |
| `internal/client/runtime_stats.go:39` | `c.balancer.GetStatsSnapshot()` | Call `c.pool.GetStatsSnapshot()` (or `c.balancer.GetStatsSnapshot()` with stream counts merged). |
| `internal/client/balancer_admission.go` | Entire file | **DELETE** file; logic absorbed into `resolver_pool.go`. |
| `internal/client/balancer_admission_test.go` | Entire file | **DELETE** file; test cases absorbed into `resolver_pool_test.go`. |
| `internal/client/resolver_maintenance.go` | Entire file | **DELETE** file per R4. |
| `internal/client/resolver_maintenance_test.go` | Entire file | **DELETE** file per R4. |

---

## 8. Test Strategy & Plan for `internal/client/resolver_pool_test.go`

`resolver_pool_test.go` must be created to provide comprehensive unit test coverage for `ResolverPool` without any network dependency.

### Test Matrix

1. **`TestResolverPool_CapacityBounding`**:
   - Verify that adding active connections respects `maxActive`.
   - Verify that incoming connections beyond capacity are rejected or demoted to standby unless their score strictly beats the lowest active score.
2. **`TestResolverPool_AdmissionBatchReplacesSaturatedPool`** (Absorbed):
   - Verify batch admission when active pool is saturated.
   - Verify incumbents lose capacity when lower-ranked, winners are admitted, and runners-up become standby.
3. **`TestResolverPool_AdmissionBatchPreservesOtherBatches`** (Absorbed):
   - Verify that successive batches do not displace prior qualified active resolvers if capacity permits.
4. **`TestResolverPool_SnapshotsNeverExposeIntermediatePlacement`** (Absorbed):
   - Concurrently admit startup batches while reading snapshots in a background goroutine.
   - Assert `snapshot.IsValid && snapshot.StandbyEligible` is never true.
5. **`TestResolverPool_RecheckLifecycle`** (Absorbed):
   - Verify scheduled and direct acquisition sets `StateRechecking` (`StandbyEligible = false`).
   - Verify `Optimize()` cannot promote a candidate in `StateRechecking`.
   - Verify `CompleteRecheck` commits new MTU and promotes if qualified.
6. **`TestResolverPool_RecheckRejectionAndConservativeStats`** (Absorbed):
   - Test MTU failure (demoted to inactive).
   - Test burst rejection (retains MTU, demoted to inactive).
   - Test recheck without burst (seeds conservative 10/8 stats).
7. **`TestResolverPool_RecheckPreservesReplacementThreshold`** (Absorbed):
   - Immediate recheck admission accepts strictly better scores, whereas `Optimize()` enforces the 25% margin.
8. **`TestResolverPool_ReleaseRecheck_RestoresStandby`**:
   - Acquire candidate for recheck from standby (`wasStandby=true`).
   - Call `ReleaseRecheck(key, true)`.
   - Verify candidate state is restored to `StateStandby` with `StandbyEligible=true`.
9. **`TestResolverPool_FinalizeFastStart_QuotaAndStandby`**:
   - Populate pool with multiple active connections across unique and shared endpoints.
   - Call `FinalizeFastStart(qualifiedKeys, target)`.
   - Verify non-qualified keys are disabled.
   - Verify surplus endpoints beyond `target` are demoted to `StateStandby`.
10. **`TestResolverPool_Optimize_SessionMTUVerification`**:
    - Degraded active resolver exists.
    - Standby candidate has high score but download MTU < `syncedDownloadMTU`.
    - Verify `Optimize()` refuses swap due to MTU deficiency.
    - Update candidate MTU to meet session MTU; verify `Optimize()` executes swap.
11. **`TestResolverPool_RankedEndpoints_OrderingAndBoost`**:
    - Verify sorting descending by composite score.
    - Verify `+1000.0` boost for active resolvers.
    - Verify deduplication by unique `ResolverAddress`.
12. **`TestResolverPool_EventDrivenOnPoolChanged`**:
    - Register `SetOnPoolChanged(func() { changedCount++ })`.
    - Trigger `AdmitStartupBatch`, `FinalizeFastStart`, `Optimize`, and `CompleteRecheck`.
    - Verify callback fires exactly when placement changes.

---

## 9. Verification & Acceptance Criteria Alignment

| Acceptance Criterion | Verification Command | Expected Outcome |
|---|---|---|
| `TestResolverPool.*` | `go test -v ./internal/client -run "TestResolverPool.*"` | PASS with all 12+ pool unit tests |
| `TestEmpirical.*` | `go test -v ./internal/client -run "TestEmpirical.*"` | PASS across all concurrency & FSM stress tests |
| `TestRunInitialMTUTests.*` | `go test -v ./internal/client -run "TestRunInitialMTUTests.*"` | PASS |
| Full client package | `go test ./internal/client` | PASS |
| Full project tests | `go test ./...` | PASS |
| Client binary build | `go build ./cmd/client` | Exit code 0 |
| Server binary build | `go build ./cmd/server` | Exit code 0 |
| Immutability guard | `git diff -- go.mod go.sum` | Empty diff |
| File scope guard | `git status -s` | No files touched outside `internal/client/` and `internal/config/` |
| File deletion verification | `test ! -f internal/client/balancer_admission.go` | File deleted |
| File deletion verification | `test ! -f internal/client/balancer_admission_test.go` | File deleted |
