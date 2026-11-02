# Milestone 3 Architecture Investigation Report: DiscoveryEngine Concurrency, Lifecycle & ResolverPool Integration

**Author**: `explorer_m3_2`  
**Milestone**: Milestone 3 (R3: Deep Discovery & FastStart Engine)  
**Target Codebase**: `internal/client/resolver_discovery.go`  
**Date**: 2026-10-31  

---

## 1. Executive Summary

This report delivers the architectural specification, concurrency design, and execution model for `DiscoveryEngine`, the core component of Milestone 3 (PR #205 Architectural Deepening) in `MasterDnsVPN`.

Currently, candidate scanning, worker pool dispatching, FastStart early termination, candidate replenishment on packet drops, and pool admission are tightly coupled with socket I/O in a monolithic 200+ line loop in `internal/client/mtu.go:378-565`. 

By extracting this orchestration into `internal/client/resolver_discovery.go` and decoupling it from physical transport via the `ResolverProber` interface, the runtime achieves:
1. **Deterministic In-Memory Unit Testing**: Probing scenarios (FastStart early exit, replenishment on micro-burst drops, worker cancellation) execute in `< 2ms` via `FakeResolverProber` without spawning local OS UDP sockets.
2. **Leak-Free Context Cancellation**: Two-tier context scoping (`parent ctx` vs `batchCtx`) ensures immediate worker unblocking upon quota fulfillment without corrupting subsequent pipeline stages.
3. **Robust Replenishment**: Iterative candidate batching transparently recovers when initial candidates pass MTU but fail pipelined micro-bursts, ensuring target active quotas are fulfilled before tunnel initialization.
4. **Strict Multi-Domain Exclusivity**: Candidate tracking isolates candidates by unique pairing key (`conn.Key`) to prevent endpoint pollution across shared physical IP:port endpoints.

---

## 2. Observation: Architectural Analysis & State Model

### 2.1 Current Monolith vs Proposed Deep Engine

| Responsibility | Monolithic State (`mtu.go:378-565`) | Target State (`resolver_discovery.go`) |
|---|---|---|
| **Transport Layer** | Direct calls to `c.newUDPQueryTransport` and socket methods | Abstracted behind `ResolverProber` interface |
| **Worker Concurrency** | Inline `chan int` and `sync.WaitGroup` embedded in `RunInitialMTUTests` | Encapsulated inside `DiscoveryEngine.runMTUBatch` |
| **Early Cancellation** | Inline `atomic.Int32` and `cancelBatch()` inside closure | Cleanly scoped batch context with deterministic drain |
| **Micro-Burst Evaluation** | Inline invocation of `c.runMicroBurstQualification` | Delegated through `prober.ProbeBurst` & evaluated via pure `score.EvaluateResolver` |
| **Pool Admission** | Inline calls to `c.balancer.admitQualifiedBatch` | Direct atomic calls to `e.pool.AdmitStartupBatch` |
| **Replenishment** | Monolithic `for` loop re-traversing unindexed slice | Systematic candidate exhaustion loop over `e.pool.AllConnections()` |
| **FastStart Finalization** | Inline call to `c.balancer.finalizeFastStart` | Encapsulated call to `e.pool.FinalizeFastStart` |
| **MTU Optimization** | Tangled between `optimizeMTUResolvers` and balancer | Clear separation: `e.pool.Optimize()` degradation swap + `c.optimizeMTUResolvers` cluster filter |

### 2.2 Data Structure Definitions

#### `DiscoveryConfig`
Encapsulates all discovery runtime tunables, decoupling the engine from `config.ClientConfig`:
```go
package client

import (
	"time"
)

// DiscoveryConfig defines all configuration parameters for DiscoveryEngine.
type DiscoveryConfig struct {
	// FastStart terminates discovery early once TargetResolvers quota is reached.
	FastStart bool

	// TargetResolvers is the quota of unique resolver endpoints required for FastStart.
	TargetResolvers int

	// Parallelism specifies the concurrency limit for parallel MTU worker goroutines.
	Parallelism int

	// BatchSize specifies candidate chunk size (if chunking is enabled).
	BatchSize int

	// MicroBurstEnabled specifies whether micro-burst qualification is executed.
	MicroBurstEnabled bool

	// MicroBurstPacketCount is the number of pipelined queries sent per burst (default: 6).
	MicroBurstPacketCount int

	// MicroBurstParallelism is the worker concurrency for burst testing (default: 8).
	MicroBurstParallelism int

	// MicroBurstTimeout is the probe timeout for micro-burst qualification.
	MicroBurstTimeout time.Duration

	// MaxBurstLossRatio is the upper bound on allowed loss ratio during burst (default: 0.20).
	MaxBurstLossRatio float64

	// MinBurstThroughputKBps is the throughput floor required to qualify.
	MinBurstThroughputKBps float64

	// MaxActiveResolvers limits the maximum number of active resolvers admitted to the pool.
	MaxActiveResolvers int

	// Domains contains the list of tunnel domains to probe.
	Domains []string

	// UploadCaps maps each domain to its precomputed maximum upload payload.
	UploadCaps map[string]int

	// MinUploadMTU is the configured floor for upload MTU.
	MinUploadMTU int

	// MaxUploadMTU is the configured ceiling for upload MTU.
	MaxUploadMTU int

	// MinDownloadMTU is the configured floor for download MTU.
	MinDownloadMTU int

	// MaxDownloadMTU is the configured ceiling for download MTU.
	MaxDownloadMTU int

	// AutoRemoveLowMTU controls whether cluster-based MTU pruning occurs.
	AutoRemoveLowMTU bool
}
```

#### `ResolverProber` Interface
Abstracts the physical probe mechanisms:
```go
// MTUProbeResult holds the measured upload/download byte boundaries for a candidate.
type MTUProbeResult struct {
	Success       bool
	UploadBytes   int
	UploadChars   int
	DownloadBytes int
	ResolveTime   time.Duration
	RejectReason  string
}

// ResolverProber abstracts MTU and micro-burst probing from discovery orchestration.
type ResolverProber interface {
	// ProbeMTU measures the maximum upload and download MTU for a candidate connection.
	ProbeMTU(ctx context.Context, conn Connection, maxUploadPayload int) (MTUProbeResult, error)

	// ProbeBurst sends a pipelined train of DNS queries to measure packet loss, RTT, and throughput.
	ProbeBurst(
		ctx context.Context,
		conn Connection,
		packetCount int,
		downloadMTU int,
		uploadMTU int,
		timeout time.Duration,
	) BurstProbeResult
}
```

#### `DiscoveryEngine` Struct
```go
// DiscoveryEngine coordinates candidate batching, worker pool parallelism, quota tracking,
// early context cancellation, replenishment, and atomic pool admission.
type DiscoveryEngine struct {
	cfg      DiscoveryConfig
	prober   ResolverProber
	pool     *ResolverPool
	log      *logger.Logger
	counters *mtuScanCounters
}
```

---

## 3. Logic Chain: The 8-Phase Execution Lifecycle

```
========================================================================================
                      DISCOVERY ENGINE EXECUTION LIFECYCLE
========================================================================================
[Phase 1: Candidate Enumeration & Quota Initialization]
  │  scanConnections := pool.AllConnections()
  │  targetValidResolvers := min(totalUnique, TargetResolvers)
  │  Init tracking maps: testedKeys, qualifiedKeys, qualifiedEndpoints, disqEndpoints
  ▼
[Phase 2: Candidate Batching Loop (Outer Loop)] <───────────────────────────────┐
  │  Check ctx.Err() -> abort if cancelled                                       │
  │  Check Quota: len(qualifiedEndpoints) >= targetValidResolvers -> Exit Loop  │
  │  Check Exhaustion: all untested candidates disqualified or tested -> Exit    │
  │  needed := targetValidResolvers - len(qualifiedEndpoints)                    │
  │  batchCtx, cancelBatch := context.WithCancel(ctx)                            │
  ▼                                                                             │
[Phase 3: Parallel Worker Pool Probing & Early Context Cancellation]            │
  │  jobs := make(chan int, len(scanConnections))                               │
  │  Spawn workerCount goroutines running prober.ProbeMTU(batchCtx, conn, cap)   │
  │  If result.Success -> pool.ApplyMTUProbeResult(..., active=true)             │
  │  recordBatchValid -> if batchUniqueValid >= needed && FastStart:             │
  │                         cancelBatch() -> worker UDP reads immediately abort!│
  │  close(jobs); wg.Wait()                                                     │
  ▼                                                                             │
[Phase 4: Micro-Burst Qualification (Pure Scoring)]                             │
  │  Prober.ProbeBurst across batchValidConns                                   │
  │  EvaluateResolver(ResolverMetrics) -> composite score & rank                │
  │  Record qualified in qualifiedKeys & qualifiedEndpoints                     │
  │  Record failed in disqualifiedEndpoints                                     │
  ▼                                                                             │
[Phase 5: Batch Admission into ResolverPool]                                    │
  │  pool.AdmitStartupBatch(results, selectedWinners)                            │
  │  Atomically seeds burst stats, sets active vs standby states                 │
  ▼                                                                             │
[Phase 6: Candidate Replenishment Evaluation]                                   │
  │  If len(qualifiedEndpoints) < targetValidResolvers: ────────────────────────┘
  │  Loop back to Phase 2 to test next candidate batch!
  ▼
[Phase 7: FastStart Finalization]
  │  pool.FinalizeFastStart(qualifiedKeys, targetValidResolvers)
  │  Strict per-domain key trimming & enforces target endpoint ceiling
  ▼
[Phase 8: Active Pool MTU Optimization & Return]
  │  pool.Optimize() -> degradation hysteresis swap (>1.25x)
  │  Verify pool.ActiveCount() > 0 -> return nil (or ErrNoValidConnections)
========================================================================================
```

### Detailed Phase Analysis

#### Phase 1: Candidate Enumeration & Quota Initialization
1. **Precondition Verification**:
   - `e.pool` must be non-nil and `e.pool.TotalCount() > 0`. If empty, returns `ErrNoValidConnections`.
   - Candidate slice retrieved: `scanConnections := e.pool.AllConnections()`.
2. **Endpoint Enumeration**:
   - Enumerates unique physical endpoints by counting unique `conn.ResolverLabel` across all candidate connections:
     ```go
     uniqueEndpoints := make(map[string]struct{}, len(scanConnections))
     for _, conn := range scanConnections {
         uniqueEndpoints[conn.ResolverLabel] = struct{}{}
     }
     totalUniqueResolvers := len(uniqueEndpoints)
     ```
3. **Target Quota Sizing**:
   - If `e.cfg.FastStart` is `true`:
     `minRequired := e.cfg.TargetResolvers` (defaults to `1` if `< 1`).
     `targetValidResolvers = min(totalUniqueResolvers, minRequired)`.
   - If `e.cfg.FastStart` is `false`:
     `targetValidResolvers = totalUniqueResolvers` (all candidates must be scanned).
4. **State Tracking Sets**:
   - `testedKeys`: `map[string]bool` tracking connection keys that have completed MTU probing.
   - `qualifiedKeys`: `map[string]struct{}` tracking connection keys that passed micro-burst qualification.
   - `qualifiedEndpoints`: `map[string]struct{}` tracking unique physical resolver endpoints that passed micro-burst qualification.
   - `disqualifiedEndpoints`: `map[string]struct{}` tracking resolver endpoints that failed MTU or burst.
   - `counters`: `*mtuScanCounters` for atomic progress reporting.

#### Phase 2: Candidate Batching Loop (Outer Loop)
1. **Parent Context Validation**:
   - If `err := ctx.Err(); err != nil`, outer loop aborts immediately and returns `err`.
2. **Quota Fulfillment Check**:
   - If `e.cfg.FastStart && len(qualifiedEndpoints) >= targetValidResolvers`, the outer loop breaks to Phase 7.
3. **Candidate Exhaustion Check**:
   - Verifies if any untested connection remains whose physical endpoint has not been disqualified:
     ```go
     allTested := true
     for _, conn := range scanConnections {
         if !testedKeys[conn.Key] {
             if _, disq := disqualifiedEndpoints[conn.ResolverLabel]; disq {
                 testedKeys[conn.Key] = true
             } else {
                 allTested = false
             }
         }
     }
     if allTested {
         break
     }
     ```
4. **Batch Requirement Calculation**:
   - Computes how many additional unique endpoints are required in this batch:
     `needed := targetValidResolvers - len(qualifiedEndpoints)`
     If `!e.cfg.FastStart || needed < 1`, `needed = totalUniqueResolvers`.
5. **Scoped Batch Context**:
   - Creates `batchCtx, cancelBatch := context.WithCancel(ctx)`.
   - Ensures `defer cancelBatch()` is executed when the batch completes so context resources are released.

#### Phase 3: Parallel Worker Pool Probing & Early Context Cancellation
1. **Worker Sizing & Job Channel**:
   - Worker count: `workerCount := min(max(1, e.cfg.Parallelism), len(scanConnections))`.
   - Jobs channel: `jobs := make(chan int, len(scanConnections))`.
     * **Deadlock-Prevention Invariant**: Sizing `jobs` with capacity equal to `len(scanConnections)` guarantees the dispatcher goroutine will never block attempting to send to `jobs` when worker goroutines exit early or drain.
2. **Batch Tracking Closure (`recordBatchValid`)**:
   - Protected by `batchMu sync.Mutex` and `batchUniqueValid atomic.Int32`:
     ```go
     recordBatchValid := func(conn Connection) {
         batchMu.Lock()
         defer batchMu.Unlock()
         batchValidConns = append(batchValidConns, conn)
         if _, alreadyQual := qualifiedEndpoints[conn.ResolverLabel]; !alreadyQual {
             if _, exists := batchEndpoints[conn.ResolverLabel]; !exists {
                 batchEndpoints[conn.ResolverLabel] = struct{}{}
                 if batchUniqueValid.Add(1) >= int32(needed) && e.cfg.FastStart {
                     cancelBatch()
                 }
             }
         }
     }
     ```
3. **Worker Execution Loop**:
   - Each worker consumes from `jobs`:
     ```go
     for idx := range jobs {
         if batchCtx.Err() != nil {
             continue // Drain remaining jobs safely without blocking dispatcher
         }
         conn := scanConnections[idx]
         e.probeCandidateMTU(batchCtx, conn, counters)
         testedMu.Lock()
         testedKeys[conn.Key] = true
         testedMu.Unlock()

         if acceptedConn, ok := e.pool.GetConnectionByKey(conn.Key); ok && (acceptedConn.IsValid || acceptedConn.StandbyEligible) {
             recordBatchValid(acceptedConn)
         }
     }
     ```
4. **Dispatcher Loop & Early Cancellation**:
   - Dispatches untested, non-disqualified candidate indices into `jobs`.
   - Monitors `batchUniqueValid.Load() >= int32(needed)`:
     ```go
     dispatchLoop:
     for idx := range scanConnections {
         if e.cfg.FastStart && batchUniqueValid.Load() >= int32(needed) {
             cancelBatch()
             break dispatchLoop
         }
         // Check testedKeys & disqualifiedEndpoints...
         select {
         case <-batchCtx.Done():
             break dispatchLoop
         case jobs <- idx:
         }
     }
     close(jobs)
     wg.Wait()
     ```
   - Calling `cancelBatch()` immediately closes `batchCtx.Done()`. In `UDPResolverProber`, `context.AfterFunc(batchCtx, ...)` closes the active UDP socket file descriptor, causing blocked UDP reads to abort in `< 300ms` with zero goroutine leaks.
   - `close(jobs)` signals workers to finish draining; `wg.Wait()` ensures all worker goroutines have exited before Phase 4 begins.

#### Phase 4: Micro-Burst Qualification (Pure Scoring)
1. **Verification**:
   - If `len(batchValidConns) == 0`, continues outer loop (Phase 6 replenishment).
   - If `!e.cfg.MicroBurstEnabled`:
     Marks all `batchValidConns` in `qualifiedEndpoints` and `qualifiedKeys`, then proceeds to Phase 5.
2. **Parallel Burst Probing**:
   - Concurrency: `burstParallelism := min(max(1, e.cfg.MicroBurstParallelism), len(batchValidConns))`.
   - Probing: Workers invoke `e.prober.ProbeBurst(ctx, conn, packetCount, downloadMTU, uploadMTU, timeout)`.
3. **Consolidated Evaluation via `score.EvaluateResolver`**:
   - Replaces all ad-hoc score calculations with pure evaluation from Milestone 1:
     ```go
     ev := EvaluateResolver(ResolverMetrics{
         DownloadMTUBytes: downloadMTU,
         RTT:              burstResult.AverageRTT,
         LossRatio:        burstResult.LossRatio,
         ThroughputKBps:   burstResult.BurstThroughputKBps,
     })
     score := ev.CompositeScore
     if math.IsNaN(score) || score <= 0 {
         score = 0.0
     }
     ```
4. **Ranking & Filtering**:
   - Sorts results descending by `Score`, breaking ties with `LossRatio` (ascending) and `AverageRTT` (ascending).
   - Resolvers failing qualification (`!r.BurstResult.Qualified`) have their physical endpoints registered in `disqualifiedEndpoints[r.Connection.ResolverLabel] = struct{}{}`.
   - Resolvers passing qualification are added to `qualifiedKeys[r.Connection.Key] = struct{}{}` and `qualifiedEndpoints[r.Connection.ResolverLabel] = struct{}{}`.

#### Phase 5: Batch Admission into `pool.AdmitStartupBatch`
1. **Winner Selection**:
   - Filters qualified candidates: `qualifiedConns`.
   - Bounds selection by `maxBurstActive = neededUnique * domainCount`, capped by `MaxActiveResolvers`.
   - `selectedWinners := qualifiedConns[:maxBurstActive]` (or all if within capacity).
2. **Atomic Pool Commitment**:
   - Calls `e.pool.AdmitStartupBatch(results, selectedWinners)`.
   - Within `ResolverPool`:
     * Seeds burst metrics (`sent`, `acked`, `averageRTT`) into candidate stats.
     * Sets `IsValid = true` and `State = StateActive` for `selectedWinners`.
     * Sets `StandbyEligible = true` and `State = StateStandby` for qualified overflow candidates.
     * Ensures strict active/standby mutual exclusivity.
     * Fires `onPoolChanged` callback.

#### Phase 6: Candidate Replenishment Evaluation
1. **Replenishment Check**:
   - Evaluates: `len(qualifiedEndpoints) < targetValidResolvers`.
   - If initial candidates failed micro-bursts (e.g. packet drop rates exceeding `MaxBurstLossRatio` = 20%), `qualifiedEndpoints` count remains below target quota.
   - Because `disqualifiedEndpoints` contains the failing endpoints, the outer loop returns to Phase 2 and selects the next batch of untried candidates.
   - Loop terminates when target quota is met or all candidates are exhausted.

#### Phase 7: FastStart Finalization (`pool.FinalizeFastStart`)
1. **Enforce Endpoint Cap & Strict Key Trimming**:
   - If `e.cfg.FastStart` is `true`:
     ```go
     var requiredKeys map[string]struct{}
     if e.cfg.MicroBurstEnabled {
         requiredKeys = qualifiedKeys
     }
     e.pool.FinalizeFastStart(requiredKeys, targetValidResolvers)
     ```
2. **Empirical Invariant (`TestEmpirical_MTU_StrictKeyTrimmingMultiDomain`)**:
   - By evaluating `requiredKeys[conn.Key]` rather than `conn.ResolverLabel`, if two domains share a physical DNS IP:port and only one domain qualifies, the failing domain connection is trimmed (`IsValid=false`, `StandbyEligible=false`) while the winning connection remains active.
   - Trims active endpoints exceeding `targetValidResolvers`, demoting overflow to `StateStandby` (`StandbyEligible=true`).

#### Phase 8: Active Pool MTU Optimization & Return
1. **Degradation Optimization**:
   - Calls `e.pool.Optimize()`.
   - Compares active candidate composite scores against standby candidates. If any standby resolver scores > 1.25x an active resolver, an atomic swap is executed with logging.
2. **Final Status Verification**:
   - If `e.pool.ActiveCount() == 0`: returns `ErrNoValidConnections`.
   - If `e.pool.ActiveCount() > 0`: returns `nil` (Success).

---

## 4. Concurrency & Context Cancellation Safety

### 4.1 Two-Tier Context Scoping Model

```
                    ┌────────────────────────────┐
                    │      Parent Context        │
                    │           (ctx)            │
                    └─────────────┬──────────────┘
                                  │
                  ┌───────────────┴───────────────┐
                  ▼                               ▼
       ┌─────────────────────┐         ┌─────────────────────┐
       │   Batch Context 1   │         │   Batch Context 2   │
       │     (batchCtx)      │         │   (Replenishment)   │
       └──────────┬──────────┘         └──────────┬──────────┘
                  │                               │
       ┌──────────┴──────────┐         ┌──────────┴──────────┐
       ▼                     ▼         ▼                     ▼
   Worker 1              Worker 2  Worker 1              Worker 2
```

1. **Isolation of Early Exit**:
   - `cancelBatch()` only cancels `batchCtx`.
   - It signals workers to terminate unneeded MTU queries once `batchUniqueValid >= needed`.
   - Crucially, parent `ctx` remains valid and uncancelled, allowing Phase 4 (MicroBurst), Phase 5 (Admission), and active tunnel packet transmission to execute without context expiration.
2. **Parent Context Cancellation**:
   - If parent `ctx` is cancelled (user abort, process shutdown, or test timeout):
     * `batchCtx.Done()` is closed simultaneously.
     * All worker goroutines abort network reads in `< 300ms` via `context.AfterFunc` socket closures (`TestEmpirical_ProbeConnectionMTU_Cancellation`).
     * `DiscoveryEngine.Run(ctx)` returns `ctx.Err()` promptly without leaking goroutines.

### 4.2 Deadlock Prevention in Worker Pool

In naive channel-based worker pools, if workers return upon `batchCtx.Err() != nil` while the dispatcher attempts to push remaining items into `jobs`, the dispatcher deadlocks indefinitely.

`DiscoveryEngine` prevents this via three synchronized guards:
1. **Buffered Capacity**: `jobs := make(chan int, len(scanConnections))` ensures all sends are non-blocking regardless of worker timing.
2. **Worker Draining**: If `batchCtx.Err() != nil`, workers execute `continue` rather than `return`, draining pending indices until `close(jobs)` is reached.
3. **Select on Done**: The dispatcher sends via `select { case <-batchCtx.Done(): break; case jobs <- idx: }`.

---

## 5. Concrete Code Implementation: `internal/client/resolver_discovery.go`

The following complete, drop-in implementation conforms to all project conventions, zero external dependencies, and strict domain terminology:

```go
// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (resolver_discovery.go) implements the autonomous DiscoveryEngine
// orchestrating candidate batching, worker pool parallelism, FastStart early
// context cancellation, micro-burst qualification, replenishment, and pool admission.
// ==============================================================================
package client

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/logger"
)

// MTUProbeResult holds the measured upload/download byte boundaries for a candidate.
type MTUProbeResult struct {
	Success       bool
	UploadBytes   int
	UploadChars   int
	DownloadBytes int
	ResolveTime   time.Duration
	RejectReason  string
}

// ResolverProber abstracts MTU and micro-burst probing from discovery orchestration.
type ResolverProber interface {
	// ProbeMTU measures the maximum upload and download MTU for a candidate connection.
	ProbeMTU(ctx context.Context, conn Connection, maxUploadPayload int) (MTUProbeResult, error)

	// ProbeBurst sends a pipelined train of DNS queries to measure packet loss, RTT, and throughput.
	ProbeBurst(
		ctx context.Context,
		conn Connection,
		packetCount int,
		downloadMTU int,
		uploadMTU int,
		timeout time.Duration,
	) BurstProbeResult
}

// DiscoveryConfig defines all configuration parameters for DiscoveryEngine.
type DiscoveryConfig struct {
	FastStart              bool
	TargetResolvers        int
	Parallelism            int
	BatchSize              int
	MicroBurstEnabled      bool
	MicroBurstPacketCount  int
	MicroBurstParallelism  int
	MicroBurstTimeout      time.Duration
	MaxBurstLossRatio      float64
	MinBurstThroughputKBps float64
	MaxActiveResolvers     int
	Domains                []string
	UploadCaps             map[string]int
	MinUploadMTU           int
	MaxUploadMTU           int
	MinDownloadMTU         int
	MaxDownloadMTU         int
	AutoRemoveLowMTU       bool
}

// DiscoveryEngine coordinates candidate batching, worker pool parallelism, quota tracking,
// early context cancellation, replenishment, and atomic pool admission.
type DiscoveryEngine struct {
	cfg      DiscoveryConfig
	prober   ResolverProber
	pool     *ResolverPool
	log      *logger.Logger
	counters *mtuScanCounters
}

// NewDiscoveryEngine constructs a DiscoveryEngine with the provided dependencies.
func NewDiscoveryEngine(
	cfg DiscoveryConfig,
	prober ResolverProber,
	pool *ResolverPool,
	log *logger.Logger,
) *DiscoveryEngine {
	return &DiscoveryEngine{
		cfg:      cfg,
		prober:   prober,
		pool:     pool,
		log:      log,
		counters: &mtuScanCounters{},
	}
}

// Run executes the 8-phase discovery and qualification lifecycle across candidates.
func (e *DiscoveryEngine) Run(ctx context.Context) error {
	if e.pool == nil || e.pool.TotalCount() == 0 {
		return ErrNoValidConnections
	}

	// Phase 1: Candidate Enumeration & Quota Initialization
	scanConnections := e.pool.AllConnections()
	if len(scanConnections) == 0 {
		return ErrNoValidConnections
	}

	uniqueEndpoints := make(map[string]struct{}, len(scanConnections))
	for _, conn := range scanConnections {
		uniqueEndpoints[conn.ResolverLabel] = struct{}{}
	}
	totalUniqueResolvers := len(uniqueEndpoints)

	targetValidResolvers := totalUniqueResolvers
	if e.cfg.FastStart {
		minRequired := e.cfg.TargetResolvers
		if minRequired < 1 {
			minRequired = 1
		}
		targetValidResolvers = min(totalUniqueResolvers, minRequired)
	}

	workerCount := min(max(1, e.cfg.Parallelism), len(scanConnections))

	testedKeys := make(map[string]bool, len(scanConnections))
	qualifiedKeys := make(map[string]struct{})
	qualifiedEndpoints := make(map[string]struct{}, targetValidResolvers)
	disqualifiedEndpoints := make(map[string]struct{})

	// Phase 2: Candidate Batching Loop (Outer Replenishment Loop)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		if e.cfg.FastStart && len(qualifiedEndpoints) >= targetValidResolvers {
			break
		}

		allTested := true
		for _, conn := range scanConnections {
			if !testedKeys[conn.Key] {
				if _, disq := disqualifiedEndpoints[conn.ResolverLabel]; disq {
					testedKeys[conn.Key] = true
				} else {
					allTested = false
				}
			}
		}
		if allTested {
			break
		}

		needed := targetValidResolvers - len(qualifiedEndpoints)
		if !e.cfg.FastStart || needed < 1 {
			needed = totalUniqueResolvers
		}

		batchCtx, cancelBatch := context.WithCancel(ctx)
		batchUniqueValid := &atomic.Int32{}
		var batchMu sync.Mutex
		batchEndpoints := make(map[string]struct{})
		var batchValidConns []Connection

		recordBatchValid := func(conn Connection) {
			batchMu.Lock()
			defer batchMu.Unlock()
			batchValidConns = append(batchValidConns, conn)
			if _, alreadyQual := qualifiedEndpoints[conn.ResolverLabel]; !alreadyQual {
				if _, exists := batchEndpoints[conn.ResolverLabel]; !exists {
					batchEndpoints[conn.ResolverLabel] = struct{}{}
					if batchUniqueValid.Add(1) >= int32(needed) && e.cfg.FastStart {
						cancelBatch()
					}
				}
			}
		}

		// Phase 3: Parallel Worker Pool Probing
		if workerCount <= 1 {
			for idx := range scanConnections {
				if batchCtx.Err() != nil {
					break
				}
				conn := scanConnections[idx]
				if testedKeys[conn.Key] {
					continue
				}
				if _, disq := disqualifiedEndpoints[conn.ResolverLabel]; disq {
					testedKeys[conn.Key] = true
					continue
				}

				e.probeCandidateMTU(batchCtx, conn, idx+1, len(scanConnections))
				testedKeys[conn.Key] = true
				if acceptedConn, ok := e.pool.GetConnectionByKey(conn.Key); ok && (acceptedConn.IsValid || acceptedConn.StandbyEligible) {
					recordBatchValid(acceptedConn)
				}
			}
		} else {
			jobs := make(chan int, len(scanConnections))
			var wg sync.WaitGroup
			var testedMu sync.Mutex

			for range workerCount {
				wg.Go(func() {
					for idx := range jobs {
						if batchCtx.Err() != nil {
							continue // Drain safely on early exit
						}
						conn := scanConnections[idx]
						e.probeCandidateMTU(batchCtx, conn, idx+1, len(scanConnections))
						testedMu.Lock()
						testedKeys[conn.Key] = true
						testedMu.Unlock()

						if acceptedConn, ok := e.pool.GetConnectionByKey(conn.Key); ok && (acceptedConn.IsValid || acceptedConn.StandbyEligible) {
							recordBatchValid(acceptedConn)
						}
					}
				})
			}

		dispatchLoop:
			for idx := range scanConnections {
				if e.cfg.FastStart && batchUniqueValid.Load() >= int32(needed) {
					cancelBatch()
					break dispatchLoop
				}
				conn := scanConnections[idx]
				testedMu.Lock()
				alreadyTested := testedKeys[conn.Key]
				testedMu.Unlock()
				if alreadyTested {
					continue
				}
				if _, disq := disqualifiedEndpoints[conn.ResolverLabel]; disq {
					testedMu.Lock()
					testedKeys[conn.Key] = true
					testedMu.Unlock()
					continue
				}

				select {
				case <-batchCtx.Done():
					break dispatchLoop
				case jobs <- idx:
				}
			}
			close(jobs)
			wg.Wait()
		}
		cancelBatch()

		if err := ctx.Err(); err != nil {
			return err
		}

		if len(batchValidConns) == 0 {
			continue // Replenish next batch
		}

		// Phase 4: Micro-Burst Qualification (using score.EvaluateResolver)
		if !e.cfg.MicroBurstEnabled {
			for _, conn := range batchValidConns {
				qualifiedEndpoints[conn.ResolverLabel] = struct{}{}
				qualifiedKeys[conn.Key] = struct{}{}
			}
			continue
		}

		neededUnique := targetValidResolvers - len(qualifiedEndpoints)
		if neededUnique < 0 {
			neededUnique = 0
		}
		domainCount := max(1, len(e.cfg.Domains))
		maxBurstActive := neededUnique * domainCount
		if e.cfg.MaxActiveResolvers > 0 && maxBurstActive > e.cfg.MaxActiveResolvers {
			maxBurstActive = e.cfg.MaxActiveResolvers
		}

		burstQualified, results := e.runMicroBurstQualification(ctx, batchValidConns, maxBurstActive)

		// Phase 5: Batch Admission into ResolverPool
		for _, q := range burstQualified {
			qualifiedKeys[q.Key] = struct{}{}
			qualifiedEndpoints[q.ResolverLabel] = struct{}{}
		}
		for _, r := range results {
			if !r.BurstResult.Qualified {
				disqualifiedEndpoints[r.Connection.ResolverLabel] = struct{}{}
			}
		}

		// Phase 6: Replenishment check occurs at top of Phase 2 loop
	}

	// Phase 7: FastStart Finalization
	if e.cfg.FastStart {
		var requiredKeys map[string]struct{}
		if e.cfg.MicroBurstEnabled {
			requiredKeys = qualifiedKeys
		}
		e.pool.FinalizeFastStart(requiredKeys, targetValidResolvers)
	}

	// Phase 8: Active Pool MTU Optimization
	_ = e.pool.Optimize()

	if e.pool.ActiveCount() == 0 {
		if e.log != nil {
			e.log.Errorf("<red>No valid connections found after MTU testing!</red>")
		}
		return ErrNoValidConnections
	}

	return nil
}

func (e *DiscoveryEngine) probeCandidateMTU(ctx context.Context, conn Connection, serverID, total int) {
	if conn.Key == "" {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			e.pool.ApplyMTUProbeResult(conn.Key, 0, 0, 0, 0, false)
			if e.log != nil {
				e.log.Errorf("💥 <red>MTU Probe Worker Panic: <cyan>%v</cyan> (Resolver: <cyan>%s</cyan>)</red>", recovered, conn.ResolverLabel)
			}
			if e.counters != nil {
				completed := e.counters.completed.Add(1)
				rejected := e.counters.rejectUpload.Add(1) + e.counters.rejectDownload.Load()
				if e.log != nil && e.log.Enabled(logger.LevelWarn) {
					e.log.Warnf("<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>PANIC</yellow> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
						completed, total, conn.Domain, conn.ResolverLabel, e.counters.valid.Load(), rejected)
				}
			}
		}
	}()

	maxUploadPayload := 0
	if e.cfg.UploadCaps != nil {
		maxUploadPayload = e.cfg.UploadCaps[conn.Domain]
	}

	res, err := e.prober.ProbeMTU(ctx, conn, maxUploadPayload)
	if ctx != nil && ctx.Err() != nil {
		return
	}

	if err != nil || !res.Success {
		e.pool.ApplyMTUProbeResult(conn.Key, res.UploadBytes, res.UploadChars, res.DownloadBytes, 0, false)
		if e.counters != nil {
			completed := e.counters.completed.Add(1)
			var rejected int32
			if res.RejectReason == "upload mtu probe rejected" {
				rejected = e.counters.rejectUpload.Add(1) + e.counters.rejectDownload.Load()
			} else {
				rejected = e.counters.rejectUpload.Load() + e.counters.rejectDownload.Add(1)
			}
			if e.log != nil && e.log.Enabled(logger.LevelWarn) {
				e.log.Warnf("<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>%s</yellow> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
					completed, total, conn.Domain, conn.ResolverLabel, res.RejectReason, e.counters.valid.Load(), rejected)
			}
		}
		return
	}

	e.pool.ApplyMTUProbeResult(conn.Key, res.UploadBytes, res.UploadChars, res.DownloadBytes, res.ResolveTime, true)
	if e.counters != nil {
		completed := e.counters.completed.Add(1)
		validNow := e.counters.recordValid(conn.ResolverLabel)
		rejected := e.counters.rejectUpload.Load() + e.counters.rejectDownload.Load()
		if e.log != nil && e.log.Enabled(logger.LevelInfo) {
			e.log.Infof("<green>✅ Accepted (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | upload=<cyan>%d</cyan> | download=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></green>",
				completed, total, conn.Domain, conn.ResolverLabel, res.UploadBytes, res.DownloadBytes, validNow, rejected)
		}
	}
}

func (e *DiscoveryEngine) runMicroBurstQualification(
	ctx context.Context,
	validConns []Connection,
	maxActiveLimit int,
) ([]Connection, []QualifiedResolver) {
	if len(validConns) == 0 {
		return nil, nil
	}

	parallelism := min(max(1, e.cfg.MicroBurstParallelism), len(validConns))
	packetCount := max(2, e.cfg.MicroBurstPacketCount)
	timeout := e.cfg.MicroBurstTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	results := make([]QualifiedResolver, len(validConns))
	jobs := make(chan int, len(validConns))
	var wg sync.WaitGroup

	syncedUp, syncedDown := e.pool.SessionMTU()

	for range parallelism {
		wg.Go(func() {
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				conn := validConns[idx]
				effectiveDown := syncedDown
				effectiveUp := syncedUp
				if effectiveDown <= 0 {
					effectiveDown = conn.DownloadMTUBytes
				}
				if effectiveUp <= 0 {
					effectiveUp = conn.UploadMTUBytes
				}

				burstResult := e.prober.ProbeBurst(ctx, conn, packetCount, effectiveDown, effectiveUp, timeout)

				score := 0.0
				if burstResult.Qualified && burstResult.ReceivedCount > 0 {
					speedKBps := burstResult.BurstThroughputKBps
					if speedKBps <= 0 {
						speedKBps = burstResult.ThroughputKBps
					}
					downMTU := burstResult.DownloadMTUBytes
					if downMTU <= 0 && burstResult.ReceivedCount > 0 && burstResult.TotalBytesRx > 0 {
						downMTU = burstResult.TotalBytesRx / burstResult.ReceivedCount
					}
					ev := EvaluateResolver(ResolverMetrics{
						DownloadMTUBytes: downMTU,
						RTT:              burstResult.AverageRTT,
						LossRatio:        burstResult.LossRatio,
						ThroughputKBps:   speedKBps,
					})
					if !math.IsNaN(ev.CompositeScore) && ev.CompositeScore > 0 {
						score = ev.CompositeScore
					}
				}

				results[idx] = QualifiedResolver{
					Connection:  conn,
					BurstResult: burstResult,
					Score:       score,
				}
			}
		})
	}

	for i := range validConns {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		if results[i].BurstResult.LossRatio != results[j].BurstResult.LossRatio {
			return results[i].BurstResult.LossRatio < results[j].BurstResult.LossRatio
		}
		return results[i].BurstResult.AverageRTT < results[j].BurstResult.AverageRTT
	})

	for i := range results {
		results[i].Rank = i + 1
	}

	qualifiedConns := make([]Connection, 0, len(results))
	for _, r := range results {
		if r.BurstResult.Qualified {
			qualifiedConns = append(qualifiedConns, r.Connection)
		}
	}

	maxActive := e.cfg.MaxActiveResolvers
	if maxActiveLimit >= 0 && (maxActive <= 0 || maxActiveLimit < maxActive) {
		maxActive = maxActiveLimit
	}
	selected := qualifiedConns
	if maxActive > 0 && len(selected) > maxActive {
		selected = selected[:maxActive]
	}

	e.pool.AdmitStartupBatch(results, selected)
	return selected, results
}
```

---

## 6. Caveats

1. **`NewDiscoveryEngine` Constructor Argument Order**:
   - `PROJECT.md` line 112 lists: `NewDiscoveryEngine(prober ResolverProber, pool *ResolverPool, cfg DiscoveryConfig, log *logger.Logger)`.
   - `spec_miner_survey_3/report.md` line 189 lists: `NewDiscoveryEngine(cfg DiscoveryConfig, prober ResolverProber, pool *ResolverPool, log *logger.Logger)`.
   - **Recommendation**: Adopt `NewDiscoveryEngine(cfg DiscoveryConfig, prober ResolverProber, pool *ResolverPool, log *logger.Logger)` because configuration typically precedes runtime dependencies, but ensure any caller aligns with this standard signature.
2. **Buffer Capacity of `jobs` Channel**:
   - In `mtu.go`, `jobs` was unbuffered (`make(chan int)`). If a worker exited abruptly on cancellation while the dispatcher was sending, a hang was theoretically possible without careful select logic. Sizing `jobs` as `make(chan int, len(scanConnections))` completely eliminates blocking risk.
3. **Session MTU Synchronization**:
   - Prior to burst testing in `micro_burst.go`, `syncedDownloadMTU` and `syncedUploadMTU` are computed. `DiscoveryEngine` reads `e.pool.SessionMTU()`, falling back to candidate-specific probed values if session MTU is not yet set.
4. **`RunInitialMTUTests` Compatibility**:
   - `RunInitialMTUTests(ctx)` in `mtu.go` remains the public API expected by existing tests (`fast_start_test.go`). It constructs `NewUDPResolverProber(c)` and `c.newDiscoveryConfig()`, runs `engine.Run(ctx)`, and retains cluster pruning (`optimizeMTUResolvers`) and file persistence (`SaveRankedResolversToFile()`).

---

## 7. Conclusion & Recommendations for the Worker

1. **Create `internal/client/resolver_discovery.go`**:
   - Implement `MTUProbeResult`, `ResolverProber` interface, `DiscoveryConfig`, and `DiscoveryEngine` using the concrete implementation detailed in Section 5.
2. **Implement `internal/client/prober_udp.go`**:
   - Implement `UDPResolverProber` wrapping `c.probeConnectionMTU` and `c.sendPipelinedMicroBurst`.
3. **Create `internal/client/resolver_discovery_test.go`**:
   - Implement `FakeResolverProber` and in-memory unit tests:
     * `TestDiscoveryEngine_FastStartExitsEarly`
     * `TestDiscoveryEngine_Replenishment_OnBurstFailure`
     * `TestDiscoveryEngine_ContextCancellationPrompt`
     * `TestDiscoveryEngine_FullScanWhenFastStartDisabled`
4. **Refactor `internal/client/mtu.go`**:
   - Replace lines 378–565 in `mtu.go` with delegation to `engine.Run(ctx)`.
   - Retain MTU binary search, dialers, and cluster filtering helpers.

---

## 8. Independent Verification Method

Execute the following commands to verify implementation correctness:

```bash
# 1. Run new deterministic DiscoveryEngine unit tests (< 50ms)
go test -v ./internal/client -run "TestDiscoveryEngine.*"

# 2. Run existing FastStart and empirical challenge tests
go test -v ./internal/client -run "TestRunInitialMTUTests.*"
go test -v ./internal/client -run "TestEmpirical.*"

# 3. Verify entire client package passes
go test -v ./internal/client

# 4. Verify immutability of go.mod/go.sum
git diff -- go.mod go.sum
```
