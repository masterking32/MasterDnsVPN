# Technical Specification & Survey Report: R3 (Discovery & FastStart Engine), Test Suites & R5 (Invariants)

**Author**: teamwork_spec_miner instance 3  
**Date**: 2026-10-31  
**Target Branch**: `feat/fast-start-resolvers` (PR #205 Architectural Deepening)  
**Scope**: R3 (Deep Discovery & FastStart Engine), Existing Test Suites, and R5 (Invariants & Domain Vocabulary)

---

## 1. Executive Summary & Architectural Motivation

In the MasterDnsVPN client runtime, resolver discovery and MTU probing are foundational to establishing a functioning session. Currently, this process is encapsulated inside `internal/client/mtu.go` in the monolithic `RunInitialMTUTests(ctx)` method (~250 lines of complex loop logic) and distributed helper routines.

### Key Architectural Deficiencies in Current Implementation
1. **Tight Coupling to Network I/O**: The orchestration logic (concurrency, worker channels, FastStart target tracking, candidate batching, early context cancellation, micro-burst qualification, pool admission, and replenishment) is tangled directly with concrete UDP socket operations, DNS query serialization, and binary-search algorithms.
2. **Untestable Orchestration Without Sockets**: Unit testing FastStart behavior (early termination upon meeting target quota, candidate replenishment when initial bursts drop packets, and worker cancellation) currently requires spawning live OS UDP sockets on localhost (`startMockMTUDNSListener`), which adds 10–25 seconds of test execution time and introduces potential OS port flakiness.
3. **Violation of Single Responsibility Principle**: `internal/client/mtu.go` currently spans 1,822 lines handling MTU binary search, UDP dialers, DNS query parsing, multi-threaded worker pools, batching, micro-burst qualification, health loops, auto-disable checks, and file persistence.

### Objective of R3 (Deep Discovery & FastStart Engine)
1. Extract the probing operations into a decoupled interface: `ResolverProber` (`ProbeMTU` and `ProbeBurst`).
2. Provide a concrete network implementation: `prober_udp.go` using live UDP queries with `context.AfterFunc` immediate cancellation.
3. Provide a deterministic in-memory mock: `FakeResolverProber` in `internal/client/resolver_discovery_test.go` allowing microsecond-fast testing of early exit, replenishment, and cancellation.
4. Encapsulate all candidate batching, worker pool parallelism, quota tracking, FastStart context cancellation, replenishment, and pool admission into `DiscoveryEngine` in `internal/client/resolver_discovery.go`.
5. Refactor `internal/client/mtu.go` so `RunInitialMTUTests(ctx)` becomes a clean coordinator delegating execution to `DiscoveryEngine.Run(ctx)`.

---

## 2. R3 Specification: Deep Discovery & FastStart Engine

### 2.1 The `ResolverProber` Interface

The `ResolverProber` interface abstracts the physical probing of a DNS resolver from the engine that decides which candidates to probe, in what order, and with what concurrency.

```go
package client

import (
	"context"
	"time"
)

// MTUProbeResult holds the outcome of a single candidate's MTU discovery probe.
type MTUProbeResult struct {
	Success       bool
	UploadBytes   int
	UploadChars   int
	DownloadBytes int
	ResolveTime   time.Duration
	RejectReason  string
}

// ResolverProber abstracts MTU and micro-burst probing from the discovery orchestration engine.
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

#### Method Specifications
- **`ProbeMTU(ctx, conn, maxUploadPayload)`**:
  - **Inputs**: Active context `ctx`, candidate pairing `conn Connection`, precomputed upload limit `maxUploadPayload int`.
  - **Outputs**: `MTUProbeResult` containing verified byte limits and latency; `error` if aborted by context cancellation.
  - **Semantics**: If the candidate fails upload MTU or download MTU discovery, `Success` is `false` and `RejectReason` details whether upload or download limits failed.
- **`ProbeBurst(ctx, conn, packetCount, downloadMTU, uploadMTU, timeout)`**:
  - **Inputs**: Active context `ctx`, candidate pairing `conn Connection`, packet count (typically 6), verified MTU values, timeout duration.
  - **Outputs**: `BurstProbeResult` (defined in `micro_burst.go`) containing `SentCount`, `ReceivedCount`, `LossRatio`, `AverageRTT`, `ThroughputKBps`, `Qualified`, and `RejectReason`.
  - **Semantics**: Non-blocking on network stalls; respects `ctx` cancellation.

---

### 2.2 `DiscoveryConfig` Definition

`DiscoveryConfig` holds all configuration parameters required by `DiscoveryEngine`. It is constructed from `config.ClientConfig` and client runtime parameters.

```go
// DiscoveryConfig contains all configuration parameters for DiscoveryEngine.
type DiscoveryConfig struct {
	// FastStart indicates whether discovery should terminate early once TargetResolvers are qualified.
	FastStart bool

	// TargetResolvers is the quota of unique resolver endpoints required before FastStart can complete.
	TargetResolvers int

	// Parallelism specifies the number of concurrent worker goroutines.
	Parallelism int

	// MicroBurstEnabled indicates whether micro-burst qualification is executed on MTU-valid candidates.
	MicroBurstEnabled bool

	// MicroBurstPacketCount is the number of pipelined queries sent per burst (default: 6).
	MicroBurstPacketCount int

	// MicroBurstParallelism is the concurrency limit for burst qualification (default: 8).
	MicroBurstParallelism int

	// MicroBurstTimeout is the probe timeout for micro-burst qualification.
	MicroBurstTimeout time.Duration

	// MaxActiveResolvers caps the total number of admitted active resolvers in the pool.
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

	// AutoRemoveLowMTU controls whether MTU optimization prunes lower-tier resolvers.
	AutoRemoveLowMTU bool
}
```

#### Helper Constructor on `Client`:
```go
func (c *Client) newDiscoveryConfig() DiscoveryConfig {
	uniqueEndpoints := make(map[string]struct{}, len(c.cfg.Resolvers))
	for _, r := range c.cfg.Resolvers {
		uniqueEndpoints[r.String()] = struct{}{}
	}
	totalUnique := len(uniqueEndpoints)

	targetResolvers := totalUnique
	fastStart := c.cfg.RecheckInactiveServersEnabled
	if fastStart {
		minRequired := c.cfg.RX_TX_Workers
		if minRequired < 1 {
			minRequired = 1
		}
		targetResolvers = min(totalUnique, minRequired)
	}

	return DiscoveryConfig{
		FastStart:             fastStart,
		TargetResolvers:       targetResolvers,
		Parallelism:           min(max(1, c.cfg.EffectiveMTUTestParallelism()), totalUnique),
		MicroBurstEnabled:     c.cfg.MicroBurstTestEnabled,
		MicroBurstPacketCount: c.cfg.MicroBurstPacketCount,
		MicroBurstParallelism: c.cfg.MicroBurstParallelism,
		MicroBurstTimeout:     c.resolverHealthProbeTimeout(),
		MaxActiveResolvers:    c.cfg.MaxActiveResolvers,
		Domains:               c.cfg.Domains,
		UploadCaps:            c.precomputeUploadCaps(),
		MinUploadMTU:          c.cfg.MinUploadMTU,
		MaxUploadMTU:          c.cfg.MaxUploadMTU,
		MinDownloadMTU:        c.cfg.MinDownloadMTU,
		MaxDownloadMTU:        c.cfg.MaxDownloadMTU,
		AutoRemoveLowMTU:      c.cfg.AutoRemoveLowMTUServers,
	}
}
```

---

### 2.3 `DiscoveryEngine` Architecture & Execution Lifecycle

`DiscoveryEngine` coordinates candidate scanning, worker pools, batching, early exit cancellation, micro-burst ranking, replenishment, and pool admission.

```go
type DiscoveryEngine struct {
	cfg      DiscoveryConfig
	prober   ResolverProber
	pool     *ResolverPool
	log      *logger.Logger
	counters *mtuScanCounters
}

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
```

#### Execution Lifecycle: `DiscoveryEngine.Run(ctx context.Context) error`

The lifecycle of `Run(ctx)` proceeds through 8 deterministic phases:

```
+-----------------------------------------------------------------------------+
| Phase 1: Candidate Enumeration & Quota Initialization                       |
|   - scanConnections = pool.AllConnections()                                 |
|   - targetValidResolvers = min(totalUnique, RX_TX_Workers) (if FastStart)   |
|   - Initialize testedKeys, qualifiedKeys, qualifiedEndpoints, disqEndpoints|
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Phase 2: Candidate Batching Loop (Outer Loop)                               |
|   - Check ctx.Err() -> return early if cancelled                            |
|   - Check quota: if FastStart && len(qualifiedEndpoints) >= target -> break|
|   - Check candidate exhaustion: if all candidates tested/disqualified -> brk|
|   - needed = targetValidResolvers - len(qualifiedEndpoints)                 |
|   - Create batchCtx, cancelBatch = context.WithCancel(ctx)                  |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Phase 3: Parallel Worker Pool Probing (Inner MTU Batch)                     |
|   - Spawn workerCount goroutines consuming from `jobs chan int`             |
|   - Workers invoke prober.ProbeMTU(batchCtx, conn, uploadCap)               |
|   - Update connection MTU in pool / apply decision                          |
|   - Record valid connection: batchValidConns = append(batchValidConns, conn)|
|   - Dispatcher loops over scanConnections, pushing to jobs chan             |
|   - Early Cancellation Trigger:                                             |
|       If FastStart && batchUniqueValid >= needed:                           |
|           cancelBatch() -> terminates unneeded worker queries immediately!  |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Phase 4: Micro-Burst Qualification (Optional)                               |
|   - If MicroBurstEnabled:                                                   |
|       - Run prober.ProbeBurst across batchValidConns                        |
|       - Calculate score for each candidate (via score.go pure evaluator)    |
|       - Filter qualified candidates; record disqualifiedEndpoints           |
|       - Update qualifiedKeys and qualifiedEndpoints                         |
|   - If MicroBurst disabled:                                                 |
|       - All batchValidConns endpoints added to qualifiedEndpoints           |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Phase 5: Batch Admission into ResolverPool                                  |
|   - pool.AdmitStartupBatch(results, selectedWinners)                        |
|   - Winners admitted as StateActive; overflow admitted as StateStandby      |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Phase 6: Replenishment Evaluation                                           |
|   - Check if len(qualifiedEndpoints) < targetValidResolvers                 |
|   - If quota not met, loop back to Phase 2 for next batch of candidates!   |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Phase 7: FastStart Finalization                                             |
|   - If FastStart: pool.FinalizeFastStart(requiredKeys, targetValidResolvers)|
|   - Ensures strict per-domain trimming & enforces target endpoint cap       |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
| Phase 8: Active Pool MTU Optimization & Return                              |
|   - Optimize active pool MTU floor; verify activeCount > 0                  |
|   - If 0 active: return ErrNoValidConnections                               |
|   - Else: return nil (Success)                                              |
+-----------------------------------------------------------------------------+
```

---

### 2.4 Live Network Implementation: `internal/client/prober_udp.go`

`prober_udp.go` implements `ResolverProber` using live UDP queries.

```go
package client

import (
	"context"
	"fmt"
	"time"
)

// UDPResolverProber implements ResolverProber via live UDP DNS exchanges.
type UDPResolverProber struct {
	client *Client
}

// NewUDPResolverProber constructs a UDPResolverProber wrapping the given client.
func NewUDPResolverProber(client *Client) *UDPResolverProber {
	return &UDPResolverProber{client: client}
}

func (p *UDPResolverProber) ProbeMTU(ctx context.Context, conn Connection, maxUploadPayload int) (MTUProbeResult, error) {
	result, reason := p.client.probeConnectionMTU(ctx, conn, maxUploadPayload)
	if ctx != nil && ctx.Err() != nil {
		return MTUProbeResult{RejectReason: "context cancelled"}, ctx.Err()
	}

	switch reason {
	case mtuRejectUpload:
		return MTUProbeResult{
			Success:      false,
			UploadBytes:  result.UploadBytes,
			RejectReason: "upload mtu probe rejected",
		}, nil
	case mtuRejectDownload:
		return MTUProbeResult{
			Success:       false,
			UploadBytes:   result.UploadBytes,
			UploadChars:   result.UploadChars,
			DownloadBytes: result.DownloadBytes,
			RejectReason:  "download mtu probe rejected",
		}, nil
	default:
		return MTUProbeResult{
			Success:       true,
			UploadBytes:   result.UploadBytes,
			UploadChars:   result.UploadChars,
			DownloadBytes: result.DownloadBytes,
			ResolveTime:   result.ResolveTime,
		}, nil
	}
}

func (p *UDPResolverProber) ProbeBurst(
	ctx context.Context,
	conn Connection,
	packetCount int,
	downloadMTU int,
	uploadMTU int,
	timeout time.Duration,
) BurstProbeResult {
	transport, err := p.client.newUDPQueryTransport(ctx, conn.ResolverLabel)
	if err != nil {
		return BurstProbeResult{
			SentCount:    packetCount,
			RejectReason: fmt.Sprintf("dial error: %v", err),
		}
	}
	defer func() {
		if transport.conn != nil {
			_ = transport.conn.Close()
		}
	}()

	return p.client.sendPipelinedMicroBurst(
		ctx,
		conn,
		transport,
		packetCount,
		downloadMTU,
		uploadMTU,
		timeout,
	)
}
```

#### Empirical Invariant Preservation
- In `probeConnectionMTU`, `context.AfterFunc(ctx, func() { probeTransport.conn.Close() })` ensures that any active blocked UDP read immediately returns with an error when `batchCtx` or `ctx` is cancelled.
- This preserves the empirical requirement tested in `TestEmpirical_ProbeConnectionMTU_Cancellation`: probe cancellation occurs in `< 300ms` with zero goroutine leaks.

---

### 2.5 Deterministic In-Memory Testing: `FakeResolverProber`

Located in `internal/client/resolver_discovery_test.go`:

```go
package client

import (
	"context"
	"sync"
	"time"
)

// FakeResolverProber provides deterministic, in-memory resolver probing for unit testing.
type FakeResolverProber struct {
	mu             sync.Mutex
	mtuResponses   map[string]MTUProbeResult
	burstResponses map[string]BurstProbeResult
	defaultMTU     MTUProbeResult
	defaultBurst   BurstProbeResult
	mtuProbedKeys  []string
	burstProbedKeys []string
	mtuDelay       time.Duration
	burstDelay     time.Duration
	onProbeMTU     func(conn Connection)
	onProbeBurst   func(conn Connection)
}

func NewFakeResolverProber() *FakeResolverProber {
	return &FakeResolverProber{
		mtuResponses:   make(map[string]MTUProbeResult),
		burstResponses: make(map[string]BurstProbeResult),
		defaultMTU: MTUProbeResult{
			Success:       true,
			UploadBytes:   200,
			UploadChars:   250,
			DownloadBytes: 500,
			ResolveTime:   10 * time.Millisecond,
		},
		defaultBurst: BurstProbeResult{
			SentCount:           6,
			ReceivedCount:       6,
			LossRatio:           0.0,
			AverageRTT:          15 * time.Millisecond,
			BurstThroughputKBps: 250.0,
			Qualified:           true,
		},
	}
}

func (f *FakeResolverProber) SetMTUResponse(key string, res MTUProbeResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mtuResponses[key] = res
}

func (f *FakeResolverProber) SetBurstResponse(key string, res BurstProbeResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.burstResponses[key] = res
}

func (f *FakeResolverProber) ProbeMTU(ctx context.Context, conn Connection, maxUploadPayload int) (MTUProbeResult, error) {
	if f.mtuDelay > 0 {
		select {
		case <-ctx.Done():
			return MTUProbeResult{RejectReason: "context cancelled"}, ctx.Err()
		case <-time.After(f.mtuDelay):
		}
	}
	if ctx != nil && ctx.Err() != nil {
		return MTUProbeResult{RejectReason: "context cancelled"}, ctx.Err()
	}

	f.mu.Lock()
	f.mtuProbedKeys = append(f.mtuProbedKeys, conn.Key)
	res, ok := f.mtuResponses[conn.Key]
	if !ok {
		res = f.defaultMTU
	}
	cb := f.onProbeMTU
	f.mu.Unlock()

	if cb != nil {
		cb(conn)
	}
	return res, nil
}

func (f *FakeResolverProber) ProbeBurst(
	ctx context.Context,
	conn Connection,
	packetCount int,
	downloadMTU int,
	uploadMTU int,
	timeout time.Duration,
) BurstProbeResult {
	if f.burstDelay > 0 {
		select {
		case <-ctx.Done():
			return BurstProbeResult{Qualified: false, RejectReason: "context cancelled"}
		case <-time.After(f.burstDelay):
		}
	}
	if ctx != nil && ctx.Err() != nil {
		return BurstProbeResult{Qualified: false, RejectReason: "context cancelled"}
	}

	f.mu.Lock()
	f.burstProbedKeys = append(f.burstProbedKeys, conn.Key)
	res, ok := f.burstResponses[conn.Key]
	if !ok {
		res = f.defaultBurst
	}
	cb := f.onProbeBurst
	f.mu.Unlock()

	if cb != nil {
		cb(conn)
	}
	return res
}

func (f *FakeResolverProber) ProbedMTUCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.mtuProbedKeys)
}
```

#### Test Scenarios Enabled by `FakeResolverProber`
1. **`TestDiscoveryEngine_FastStartExitsEarly`**:
   - 10 candidate connections configured. Target quota = 2.
   - Prober configured with instant successful probes.
   - Assert `engine.Run(ctx)` terminates having probed only 2–3 endpoints instead of 10.
   - Execution time: `< 1ms`.
2. **`TestDiscoveryEngine_Replenishment_OnBurstFailure`**:
   - 5 candidate connections: endpoints 0 & 1 pass MTU but fail burst. Endpoints 2 & 3 pass both.
   - Assert `DiscoveryEngine` batches 0 & 1, detects burst failure, replenishes by batching 2 & 3, and successfully admits 2 & 3 as active.
   - Execution time: `< 2ms`.
3. **`TestDiscoveryEngine_ContextCancellationPrompt`**:
   - Set `mtuDelay = 50 * time.Millisecond`.
   - Cancel context after 5ms.
   - Assert `engine.Run(ctx)` returns in `< 20ms` with zero goroutine leaks.
4. **`TestDiscoveryEngine_FullScanWhenFastStartDisabled`**:
   - 4 candidates, `FastStart: false`.
   - Assert all 4 candidates are probed.

---

### 2.6 Refactoring Map for `internal/client/mtu.go`

In `internal/client/mtu.go`:
- **Lines 378–565 are removed**:
  - The outer discovery loop: `for { if err := ctx.Err(); err != nil ... }`
  - Batch context creation and cancellation: `batchCtx, cancelBatch := context.WithCancel(ctx)`, `batchUniqueValid`, `recordBatchValid`
  - Worker channel dispatch and wait group: `jobs := make(chan int)`, `dispatchLoop: for idx := range scanConnections`
  - Candidate replenishment loops and inline micro-burst orchestration
  - FastStart finalization call
- **`RunInitialMTUTests(ctx)` is refactored into a lean delegator**:

```go
func (c *Client) RunInitialMTUTests(ctx context.Context) error {
	if c.pool == nil || c.pool.TotalCount() == 0 {
		return ErrNoValidConnections
	}

	prober := NewUDPResolverProber(c)
	engine := NewDiscoveryEngine(c.newDiscoveryConfig(), prober, c.pool, c.log)

	c.logMTUStart(engine.cfg.Parallelism)
	c.prepareMTUSuccessOutputFile()

	if err := engine.Run(ctx); err != nil {
		return err
	}

	activeConns := c.pool.ActiveResolvers()
	validConns, minUpload, minDownload, minUploadChars := c.optimizeMTUResolvers(activeConns)
	if len(validConns) == 0 {
		if c.log != nil {
			c.log.Errorf("<red>No valid connections found after MTU testing!</red>")
		}
		return ErrNoValidConnections
	}

	c.applySyncedMTUState(minUpload, minDownload, minUploadChars)
	c.appendMTUUsageSeparatorOnce()
	c.logMTUCompletion(validConns)

	if c.cfg.RecheckInactiveServersEnabled && len(validConns) < c.pool.TotalCount() {
		remaining := c.pool.TotalCount() - len(validConns)
		if c.log != nil {
			c.log.Infof("⚡ <green>FastStart:</green> Initial connection ready with <cyan>%d</cyan> resolver(s). Background recheck will discover and test remaining <cyan>%d</cyan> resolver(s).", len(validConns), remaining)
		}
	}

	c.SaveRankedResolversToFile()
	return nil
}
```

- **Routines Retained in `mtu.go`**:
  - `optimizeMTUResolvers`, `summarizeValidMTUConnections`
  - `probeConnectionMTU`, `runConnectionMTUTest`, `applyMTUDecision`
  - `testUploadMTU`, `testDownloadMTU`, `binarySearchMTU`, `sendUploadMTUProbe`, `sendDownloadMTUProbe`
  - `buildMTUProbeQuery`, `buildMTUProbePayload`, `maxUploadMTUPayload`, `canBuildUploadPayload`
  - `runResolverHealthLoop`, `runResolverHealthBatch`, `recheckInactiveResolver` (updated to call `pool.AcquireNextInactiveForRecheck` in R2)

---

## 3. Existing Test Suites Analysis & Migration Requirements

### 3.1 Inventory of `TestRunInitialMTUTests.*` in `fast_start_test.go`

| Test Function | Target Feature | Key Invariants Verified | Notes for R3 Refactor |
|---|---|---|---|
| `TestRunInitialMTUTests_FastStartExitsEarly` | FastStart early exit | 10 resolvers configured, target=2. Active count >= 2 and < 10. | Must pass without changes when delegating to `DiscoveryEngine`. |
| `TestRunInitialMTUTests_FullScanWhenRecheckDisabled` | FastStart disabled | `RecheckInactiveServersEnabled=false`. All 4 resolvers must be tested and active. | Must verify `DiscoveryConfig.FastStart=false` tests all candidates. |
| `TestRunInitialMTUTests_FallbackWhenFewerResolversWork` | Fault tolerance | Only 1 of 3 resolvers responds. Sockets return 1 active resolver successfully. | Proves fallback when fewer than target resolvers are available. |
| `TestRunInitialMTUTests_BurstRetryScanning` | Replenishment on burst drop | 4 resolvers: 0 & 1 drop burst packets, 2 & 3 are healthy. Target=2. Only 2 & 3 must become active. | Exercises candidate replenishment loop across batches. |
| `TestAdversarial_RunInitialMTUTests_Replenishment_2InitialBurstFailures` | Adversarial replenishment | 5 resolvers: 0 & 1 drop bursts, 2, 3, 4 healthy. StandbyEligible verified false for active connections. | Validates mutual exclusivity between Active and Standby pools. |
| `TestAdversarial_RunInitialMTUTests_ContextCancellationPrompt` | Prompt cancellation | Blackhole UDP listener. Timeout=3s. Cancel after 50ms. Must return in < 2s. | Validates non-blocking context propagation and goroutine termination. |

### 3.2 Inventory of `TestEmpirical.*` in `empirical_challenge_test.go`

All 11 empirical challenge tests pass against current baseline. The table below details what each test tests and what invariants R3 must maintain:

| Test Function | Scope & Challenge Verified | Required Invariant for R3 |
|---|---|---|
| `TestEmpirical_ProbeConnectionMTU_Cancellation` | Measures cancellation across 0s, 10ms, 25ms, 50ms, 100ms, 150ms delays against blackhole UDP. | Must return in `< 300ms` with zero goroutine leaks. `probeConnectionMTU` must keep `context.AfterFunc` socket closing. |
| `TestEmpirical_OptimizeActivePool_DegradedAndPartialMTU` | Tests pool optimization under mixed MTU floors and degraded latencies. | Output of `optimizeMTUResolvers` must not regress. |
| `TestEmpirical_RapidValidityFlipsStress` | Concurrently toggles connection validity across multiple threads (2.2M operations). | Zero deadlocks, mutex inversions, or panics in pool state transitions. |
| `TestEmpirical_MicroBurst_ActivePoolFullPromotion` | Tests micro-burst promotion of qualified resolvers. | Ranks and promotes winners according to `score.go` metrics. |
| `TestEmpirical_ActiveStandbyMutualExclusivity` | Asserts no connection has `IsValid=true && StandbyEligible=true`. | `AdmitStartupBatch` and `FinalizeFastStart` must enforce strict exclusivity. |
| `TestEmpirical_RuntimeStats_MonotonicCounterGating` | Verifies monotonic decay of packet sent stats. | Zero regression on stats counters. |
| `TestEmpirical_MicroBurst_ActivePoolSaturationAdmission` | 4-phase pool admission under capacity saturation. | Qualified overflow must be placed into Standby pool. |
| `TestEmpirical_MicroBurst_PacingAndQueueDelayElimination` | Verifies pipelined burst eliminates queue and pacing delays. | `sendPipelinedMicroBurst` in `prober_udp.go` sends train without inter-packet sleeps. |
| `TestEmpirical_ConcurrentBalancerStress` | Multi-goroutine stress across all subsystems (2M operations). | Zero race conditions in active pool querying during packet dispatch. |
| `TestEmpirical_MTU_BatchStandbyEligibilityPreserved` | Standby candidates evaluated in micro-burst even when active pool capacity is saturated. | Batch evaluation preserves `(acceptedConn.IsValid \|\| acceptedConn.StandbyEligible)`. |
| `TestEmpirical_MTU_StrictKeyTrimmingMultiDomain` | Tests that fast-start trimming checks `qualifiedKeys[conn.Key]` rather than `conn.ResolverLabel`. | Prevents multi-domain domain bleeding on shared physical resolver endpoints. |
| `TestEmpirical_RecheckRevokesStandby_NoRaceWithOptimize` | Concurrent recheck revocation and `OptimizeActivePool` execution. | Candidate in recheck has `StandbyEligible=false` to prevent duplicate promotion. |

### 3.3 Test Compatibility & Migration Strategy
1. **Preserve Method Entrypoints**:
   - `client.RunInitialMTUTests(ctx)` must remain exported with the exact same signature.
   - `client.probeConnectionMTU` must remain accessible to package tests.
   - `client.runMicroBurstQualification` must remain accessible to package tests.
2. **Balancer Forwarding Shims for R2**:
   - Existing tests make assertions like `client.balancer.ActiveCount()`, `client.balancer.TotalCount()`, and `client.balancer.ActiveConnections()`.
   - When R2 moves pool state from `Balancer` to `ResolverPool`, `Balancer` must forward these methods:
     ```go
     func (b *Balancer) ActiveCount() int { return b.pool.ActiveCount() }
     func (b *Balancer) TotalCount() int { return b.pool.TotalCount() }
     func (b *Balancer) ActiveConnections() []Connection { return b.pool.ActiveResolvers() }
     ```
   - This prevents breaking any existing test in `fast_start_test.go` or `empirical_challenge_test.go`.

---

## 4. R5 Invariants & Domain Vocabulary Analysis

### 4.1 Strict Domain Vocabulary Mapping (`CONTEXT.md`)

MasterDnsVPN maintains an authoritative domain language in `CONTEXT.md`. All newly authored code, types, comments, and test names must adhere strictly to these terms:

| Entity | Canonical Term (`CONTEXT.md`) | Strictly Prohibited Aliases (_Avoid_) | Usage in R3 & PR #205 |
|---|---|---|---|
| End-to-end transport | **Tunnel** | Proxy, VPN, Pipe | System transport name |
| Local process | **Client** | Agent, Consumer, Local host | Client daemon / process |
| Authoritative process | **Server** | Upstream server, Relay, Gateway | Server daemon |
| Upstream DNS forwarder | **Resolver** | Nameserver, Upstream DNS, Target | The external DNS server endpoint |
| Client-Server relationship | **Session** | Connection, Socket, Channel | Authenticated tunnel relationship |
| Bidirectional stream | **Stream** | Flow, Tunnel, Sub-session | Multiplexed stream inside Session |
| Protocol unit | **Packet** | Frame, Message, Datagram | Packet header + payload |
| DNS payload slice | **Fragment** | Chunk, Segment, Packet part | Fragment encoded into DNS labels |
| Available resolvers set | **Resolver Pool** | - | Complete set of candidate pairings |
| Active candidate | **Active Resolver** | - | Admitted to carry traffic |
| Standby candidate | **Standby Resolver** | - | Qualified inactive candidate eligible for promotion |
| Reliability layer | **ARQ** | Retrier, TCP retransmit, Handshake | Selective repeat reliability |
| Unacknowledged query | **In-flight** | Pending, Unresolved, Open | Query awaiting response |
| Redundant query | **Duplication** | Multipath, Cloning, Redundancy | Multi-path packet sending |
| Priority scheduler | **MLQ** | Balancer, Priority queue, Scheduler | Multi-Level Queue scheduler |

### 4.2 Scope Boundaries & Immutability Invariants
1. **`go.mod` and `go.sum` are IMMUTABLE**:
   - `git diff -- go.mod go.sum` MUST produce zero lines of diff.
   - No new external Go dependencies may be introduced.
2. **Prohibited Directories**:
   - `cmd/`: No edits permitted.
   - `internal/` outside `internal/client/` and `internal/config/`: No edits permitted (`internal/vpnproto`, `internal/arq`, `internal/mlq`, etc. must remain untouched).
3. **Deletions Planned**:
   - `internal/client/balancer_admission.go` and `internal/client/balancer_admission_test.go` (absorbed by R2 into `resolver_pool.go`).
   - `internal/client/resolver_maintenance.go` and `internal/client/resolver_maintenance_test.go` (replaced by R4 event-driven persistence).

---

## 5. Features Discovered & Edge Cases

### Features Discovered
| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | Probing | `ResolverProber.ProbeMTU` | Discovers upload and download MTU floor for a candidate | `ctx`, `conn Connection`, `maxUploadPayload int` | `MTUProbeResult`, `error` | Returns `Success=false` with `RejectReason` on failure; error on ctx cancel | `internal/client/mtu.go:1012-1163` |
| 2 | Probing | `ResolverProber.ProbeBurst` | Measures loss, RTT, and pipelined throughput | `ctx`, `conn Connection`, `packetCount`, `downloadMTU`, `uploadMTU`, `timeout` | `BurstProbeResult` | Sets `Qualified=false` with `RejectReason` if loss > max loss or throughput < min | `internal/client/micro_burst.go:63-283` |
| 3 | Probing | `UDPResolverProber` | Live UDP queries implementation of `ResolverProber` | Network sockets, DNS queries | Live probe metrics | Closes socket on `ctx` cancel via `context.AfterFunc` | `internal/client/mtu.go` & `micro_burst.go` |
| 4 | Probing | `FakeResolverProber` | In-memory mock implementation of `ResolverProber` | In-memory canned maps, delays, callbacks | Programmed probe metrics | Non-blocking, zero OS socket calls | Specification requirement R3 |
| 5 | Discovery | `DiscoveryConfig` | Unified configuration parameters for discovery | Values from `config.ClientConfig` | Config struct | Validated bounds | `internal/config/client.go` |
| 6 | Discovery | `DiscoveryEngine` | Worker pool orchestration, batching, quota tracking | `DiscoveryConfig`, `ResolverProber`, `ResolverPool` | Admitted resolvers in `ResolverPool` | Returns `ErrNoValidConnections` if active count is 0 | Specification requirement R3 |
| 7 | Discovery | FastStart Early Exit | Cancels batch probe context once target unique resolvers are found | `batchUniqueValid >= needed` | Batch context cancellation | Clean worker termination | `internal/client/mtu.go:420-424, 479-482` |
| 8 | Discovery | Candidate Replenishment | Dispatches subsequent batches if initial candidates fail MTU or burst | Remaining unscanned candidates | Replenished candidate pool | Exhausts all candidates before giving up | `internal/client/mtu.go:378-556` |
| 9 | Discovery | Batch Admission | Commits startup batch winners and standby overflow | `results []QualifiedResolver`, `selected []Connection` | Updated `ResolverPool` | Exclusivity between active and standby | `internal/client/balancer_admission.go:7-37` |
| 10 | Discovery | FastStart Finalization | Trims active pool to target unique endpoints | `qualifiedKeys map[string]struct{}`, `target int` | Trimmed active pool, standby overflow | Strict per-domain checking | `internal/client/balancer_admission.go:41-69` |
| 11 | Integration | `RunInitialMTUTests` Delegation | Delegates discovery to `DiscoveryEngine.Run(ctx)` | `ctx context.Context` | `error` | Returns `ErrNoValidConnections` if pool has 0 valid connections | `internal/client/mtu.go:338-588` |

### Edge Cases
| # | Feature | Input / Condition | Observed / Required Behavior |
|---|---------|-------------------|-----------------------------|
| 1 | FastStart Cancellation | Outer context cancelled during UDP MTU probe | Probe must return immediately (< 300ms) with zero goroutine leaks (`TestEmpirical_ProbeConnectionMTU_Cancellation`). |
| 2 | FastStart Target Quota | 10 candidates configured, target = 2 | Prober cancels batch context as soon as 2 unique endpoints qualify; unprobed candidates remain untested (`TestRunInitialMTUTests_FastStartExitsEarly`). |
| 3 | Burst Failure Replenishment | Initial candidates pass MTU but fail micro-burst | Discovery engine must disqualify failing candidates, replenish by batching remaining candidates, and satisfy quota (`TestRunInitialMTUTests_BurstRetryScanning`). |
| 4 | Multi-domain Endpoint Sharing | 2 domains share 1 physical resolver IP:port; domain 1 qualifies, domain 2 fails burst | Trimming must evaluate `qualifiedKeys[conn.Key]` rather than `conn.ResolverLabel`, preventing domain 2 from remaining active (`TestEmpirical_MTU_StrictKeyTrimmingMultiDomain`). |
| 5 | Active/Standby Exclusivity | Candidate admitted to active pool | Connection must have `IsValid=true` and `StandbyEligible=false`; connection overflow has `IsValid=false` and `StandbyEligible=true` (`TestEmpirical_ActiveStandbyMutualExclusivity`). |
| 6 | Full Scan on Recheck Disabled | `RecheckInactiveServersEnabled=false` | Discovery engine disables early exit and scans all candidate connections (`TestRunInitialMTUTests_FullScanWhenRecheckDisabled`). |
| 7 | Fewer Resolvers Than Target | Total functional resolvers < `RX_TX_Workers` | Discovery engine tests all available candidates and successfully starts with whatever resolvers qualify (`TestRunInitialMTUTests_FallbackWhenFewerResolversWork`). |
| 8 | Zero Valid Resolvers | All candidates fail MTU or burst | Discovery engine returns `ErrNoValidConnections` without panicking. |
| 9 | Worker Goroutine Panic | Prober worker encounters panic on corrupt query | Panic is caught with `recover()`, candidate rejected, total counter updated, other workers continue safely (`mtu.go:1016-1043`). |
| 10 | Low MTU Optimizer | `AutoRemoveLowMTUServers=true` | After pool qualification, `optimizeMTUResolvers` trims resolvers with upload MTU significantly below the top cluster, lifting the floor. |
