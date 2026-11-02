# Milestone 3 Investigation Report: DiscoveryEngine Extraction Seam & Test Compatibility

**Author**: explorer_m3_1  
**Date**: 2026-10-31  
**Branch**: `feat/fast-start-resolvers` (PR #205 Architectural Deepening)  
**Target Scope**: R3 (Deep Discovery & FastStart Engine Extraction Seam, `internal/client/mtu.go`, `internal/client/resolver_discovery.go`, `internal/client/prober_udp.go`, Test Suites)  

---

## Executive Summary

The investigation examined the extraction seam between the monolithic `internal/client/mtu.go` (1,822 lines) and the new `DiscoveryEngine` (`internal/client/resolver_discovery.go` and `internal/client/prober_udp.go`).

Currently, `RunInitialMTUTests(ctx)` in `internal/client/mtu.go` spans 251 lines (lines 338–588) tangling concurrency management (worker channels, wait groups), candidate batching, FastStart quota tracking, batch context cancellation, micro-burst qualification, candidate replenishment loops, and pool admission directly with concrete UDP socket operations.

The extraction seam cleanly divides as follows:
1. **Stays in `internal/client/mtu.go`**:
   - High-level coordinator `RunInitialMTUTests(ctx)` reduced from 251 lines to ~35 lines, delegating discovery orchestration to `DiscoveryEngine.Run(ctx)`.
   - Post-discovery pool optimization (`optimizeMTUResolvers`), synchronized MTU state application (`applySyncedMTUState`), usage logging, and file persistence triggers (`SaveRankedResolversToFile`).
   - Network probing routines: `probeConnectionMTU`, `testUploadMTU`, `testDownloadMTU`, `binarySearchMTU`, `sendUploadMTUProbe`, `sendDownloadMTUProbe`, `buildMTUProbeQuery`, `buildMTUProbePayload`, `maxUploadMTUPayload`, `canBuildUploadPayload`, `encodedCharsForPayload`.
   - Health check and background recheck loops: `runResolverHealthLoop`, `runResolverHealthBatch`, `recheckInactiveResolver`, `collectInactiveResolverHealthChecks`.
2. **Moves into `DiscoveryEngine.Run(ctx)` (`internal/client/resolver_discovery.go`)**:
   - Outer candidate batching and replenishment loop.
   - FastStart quota tracking (`targetValidResolvers`) based on unique physical endpoints.
   - Concurrency orchestration: worker channel distribution (`jobs chan int`), batch context cancellation (`batchCtx, cancelBatch := context.WithCancel(ctx)`).
   - Early cancellation trigger: terminating unneeded worker MTU queries immediately when `batchUniqueValid >= needed`.
   - Micro-burst qualification: pipelined query execution, composite scoring using pure evaluator `EvaluateResolver` from `score.go`, and ranking.
   - Replenishment: continuing outer loop when candidates fail micro-burst until quota is satisfied or candidates are exhausted.
   - Batch admission into `ResolverPool` (`pool.AdmitStartupBatch`) and FastStart finalization (`pool.FinalizeFastStart`).
3. **Decoupled via `ResolverProber` (`internal/client/prober_udp.go`)**:
   - Defines `ResolverProber` interface with `ProbeMTU` and `ProbeBurst`.
   - `UDPResolverProber` wraps `*Client` to execute live UDP network exchanges with `context.AfterFunc` immediate socket closing.
   - `FakeResolverProber` in `resolver_discovery_test.go` provides microsecond-fast, deterministic in-memory testing of early exit, replenishment, and context cancellation without OS sockets.
4. **Backward Compatibility**:
   - `mtu_logging_test.go`: 100% compatible (tests formatting and file append methods that remain in `mtu_logging.go`/`mtu.go`).
   - `mtu_math_test.go`: 100% compatible (tests encoding, payload capacity, and probe payload generation methods that remain in `mtu.go`).
   - `handlers/mtu_handlers_test.go`: 100% compatible (tests packet dispatch routing in `internal/client/handlers/` with zero dependency on `DiscoveryEngine`).
   - `fast_start_test.go` and `empirical_challenge_test.go`: 100% compatible. Specifically, `probeConnectionMTU` remains accessible on `*Client` to satisfy `TestEmpirical_ProbeConnectionMTU_Cancellation`.

---

## 1. Observation

### 1.1 Code Analysis of `internal/client/mtu.go`
Inspection of `internal/client/mtu.go` (1,822 lines) reveals the exact architectural structure:

| Line Range | Function / Block | Role | Retained in `mtu.go` or Extracted |
|---|---|---|---|
| `28–48` | Constants & Global MTU Reserves | `ErrNoValidConnections`, protocol payload sizes | Retained in `mtu.go` |
| `50–69` | `mtuRejectReason`, `mtuConnectionProbeResult` | Probe outcome structures | Retained in `mtu.go` |
| `70–97` | `mtuScanCounters` | Thread-safe counters for MTU scan progress | Retained in `mtu.go` (accessible package-wide) |
| `98–107` | `mtuDecision` | Intermediate decision structure | Retained in `mtu.go` |
| `108–336` | `optimizeMTUResolvers` | Post-discovery MTU floor optimization | Retained in `mtu.go` |
| **`338–377`** | **`RunInitialMTUTests` (setup)** | Parameter calculation, workerCount, counters | **Refactored** into lean delegator |
| **`378–406`** | **Outer Discovery Loop** | Replenishment check, candidate exhaustion, needed quota | **Extracted** to `DiscoveryEngine.Run` |
| **`407–425`** | **Batch Context & Early Cancel** | `context.WithCancel(ctx)`, `batchUniqueValid`, `cancelBatch()` | **Extracted** to `DiscoveryEngine.Run` |
| **`427–506`** | **Worker Concurrency & Channels** | Single-worker branch vs multi-worker `jobs chan int` | **Extracted** to `DiscoveryEngine.Run` |
| **`516–556`** | **Micro-Burst & Replenishment Trigger** | Burst qualification, candidate scoring, disqualified tracking | **Extracted** to `DiscoveryEngine.Run` |
| **`558–565`** | **FastStart Finalization** | Trimming active pool to target quota endpoints | **Extracted** to `DiscoveryEngine.Run` |
| `566–588` | `RunInitialMTUTests` (post-discovery) | `optimizeMTUResolvers`, state sync, logging, file save | Retained in `mtu.go` |
| `590–801` | Resolver Health Loop & Batches | Background recheck coordination | Retained in `mtu.go` |
| `803–900` | Inactive Resolver Recheck | Individual recheck probes | Retained in `mtu.go` |
| `1012–1121` | `runConnectionMTUTest` | Worker wrapper with panic recovery and logging | Retained in `mtu.go` |
| `1123–1163` | `probeConnectionMTU` | Upload + download MTU test with `context.AfterFunc` | Retained in `mtu.go` (Required by empirical test) |
| `1165–1201` | `buildMTUDecision`, `applyMTUDecision` | MTU decision conversion and pool update | Retained in `mtu.go` |
| `1203–1212` | `precomputeUploadCaps` | Map domain -> max upload payload | Retained in `mtu.go` |
| `1214–1271` | `testUploadMTU`, `testDownloadMTU` | Protocol-specific MTU probes | Retained in `mtu.go` |
| `1273–1369` | `binarySearchMTU` | Binary search algorithm for MTU boundaries | Retained in `mtu.go` |
| `1371–1612` | `sendUploadMTUProbe`, `sendDownloadMTUProbe` | Raw wire UDP exchange and validation | Retained in `mtu.go` |
| `1614–1822` | Framing, QName calculations, math | DNS packet construction and calculations | Retained in `mtu.go` |

### 1.2 Existing Test Suite Dependencies & Direct Call Sites

Direct verification of existing test files confirms the following call patterns:

1. **`mtu_logging_test.go`**:
   - `TestFormatMTULogLineSupportsDomainPlaceholder` (lines 13–39): Calls `c.formatMTULogLine(...)`.
   - `TestAppendMTURemovedServerLineWritesConfiguredFormat` (lines 41–63): Calls `c.appendMTURemovedServerLine(...)`.
   - **Observation**: Zero interaction with `RunInitialMTUTests` or discovery loop logic.
2. **`mtu_math_test.go`**:
   - `TestEncodedCharsForPayloadUsesWorstCaseUploadPacketType` (lines 8–16): Calls `c.encodedCharsForPayload(120)` and `c.encodedCharsForPacketPayload(...)`.
   - `TestEncodedCharsForPayloadMatchesMaxUploadProbeCapacityModel` (lines 18–30): Calls `c.canBuildUploadPayload(...)` and `c.encodedCharsForPayload(...)`.
   - `TestBuildMTUProbePayloadWritesModeAndProbeCodeWithoutFillingTail` (lines 32–56): Calls `c.buildMTUProbePayload(16)`.
   - **Observation**: Pure math and framing calculations. All tested functions remain in `mtu.go`.
3. **`handlers/mtu_handlers_test.go`**:
   - `TestDispatchRoutesMTUResponses` (lines 26–42): Dispatches `PACKET_MTU_UP_RES` and `PACKET_MTU_DOWN_RES` against a mock `ClientContext`.
   - **Observation**: Tests packet dispatching layer in `internal/client/handlers/`. Completely independent of discovery engine.
4. **`empirical_challenge_test.go`**:
   - `TestEmpirical_ProbeConnectionMTU_Cancellation` (lines 22–125): Directly invokes `client.probeConnectionMTU(ctx, conn, 200)` across varying cancellation delays (0s, 10ms, 25ms, 50ms, 100ms, 150ms).
   - **Observation**: Asserts return duration `< 300ms`, zero goroutine leaks, and return reason `mtuRejectUpload`. `probeConnectionMTU` **must** remain on `*Client`.
   - `TestEmpirical_MTU_BatchStandbyEligibilityPreserved` (lines 1034–1100): Calls `client.RunInitialMTUTests(ctx)` with 4 mock resolvers (0 & 1 fail micro-burst, 2 & 3 pass). Verifies that candidates failing initial burst are replaced by healthy candidates via candidate replenishment.
   - `TestEmpirical_MicroBurst_ActivePoolFullPromotion` (line 499) and `TestEmpirical_MicroBurst_ActivePoolSaturationAdmission` (line 729): Directly invoke `client.runMicroBurstQualification(ctx, ...)`.
   - **Observation**: `runMicroBurstQualification` must remain on `*Client` in `micro_burst.go`.
5. **`fast_start_test.go`**:
   - `TestRunInitialMTUTests_FastStartExitsEarly` (line 74): 10 candidates, target=2. Asserts active count >= 2 and < 10.
   - `TestRunInitialMTUTests_FullScanWhenRecheckDisabled` (line 121): Asserts all 4 candidates tested and admitted when `RecheckInactiveServersEnabled=false`.
   - `TestRunInitialMTUTests_FallbackWhenFewerResolversWork` (line 163): Only 1 of 3 candidates works. Asserts successful return with 1 active resolver.
   - `TestRunInitialMTUTests_BurstRetryScanning` (line 419): Initial 2 candidates drop burst; subsequent 2 candidates succeed. Asserts candidates 2 and 3 become active.
   - `TestAdversarial_RunInitialMTUTests_ContextCancellationPrompt` (line 560): Verifies context cancellation returns in `< 2s`.

---

## 2. Logic Chain

### 2.1 Refactoring Blueprint: What Stays vs. What Moves

```
                       Current Architecture (mtu.go monolithic)
+-----------------------------------------------------------------------------------+
| internal/client/mtu.go                                                            |
|  - RunInitialMTUTests(ctx) [251 lines]                                            |
|    - Outer loop: candidate batching, replenishment                                |
|    - Concurrency: jobs channel, worker goroutines                                 |
|    - FastStart early cancellation: cancelBatch() on quota                         |
|    - Micro-burst qualification: runMicroBurstQualification                         |
|    - Pool admission & trimming: FinalizeFastStart                                 |
|    - Post-test optimization: optimizeMTUResolvers                                 |
|  - probeConnectionMTU / testUploadMTU / testDownloadMTU                           |
|  - binarySearchMTU / sendUploadMTUProbe / sendDownloadMTUProbe                    |
|  - resolverHealthLoop / recheckInactiveResolver                                   |
+-----------------------------------------------------------------------------------+

                                        |
                                        v

                        Target Modular Architecture (R3)
+------------------------------------+      +---------------------------------------+
| internal/client/mtu.go             |      | internal/client/resolver_discovery.go |
| - RunInitialMTUTests(ctx) (~35 ln) |----->| - DiscoveryEngine                     |
|   1. NewUDPResolverProber(c)       |      |   - Run(ctx, candidates...)           |
|   2. newDiscoveryConfig()          |      |     - Phase 1: Quota initialization   |
|   3. NewDiscoveryEngine(...)       |      |     - Phase 2: Batching outer loop    |
|   4. engine.Run(ctx)               |      |     - Phase 3: Parallel MTU probing   |
|   5. optimizeMTUResolvers(...)     |      |     - Phase 4: Early context cancel   |
|   6. applySyncedMTUState(...)      |      |     - Phase 5: Micro-burst scoring    |
|   7. SaveRankedResolversToFile()   |      |     - Phase 6: Batch pool admission   |
| - optimizeMTUResolvers(...)        |      |     - Phase 7: Replenishment on drop  |
| - probeConnectionMTU(...)          |      |     - Phase 8: FinalizeFastStart      |
| - binarySearchMTU(...)             |      | - DiscoveryConfig                     |
| - resolverHealthLoop(...)          |      | - ResolverProber interface            |
+------------------------------------+      +---------------------------------------+
                  |                                             ^
                  v                                             |
+------------------------------------+                          |
| internal/client/prober_udp.go      |                          |
| - UDPResolverProber                |--------------------------+
|   - ProbeMTU -> probeConnectionMTU |   implements ResolverProber
|   - ProbeBurst -> sendPipelinedBurst|
+------------------------------------+
```

### 2.2 `ResolverProber` Interface & Result Structs
Located in `internal/client/resolver_discovery.go`:

```go
package client

import (
	"context"
	"time"
)

// MTUProbeResult holds the measured byte limits, character counts, and latency of an MTU probe.
type MTUProbeResult struct {
	Success       bool
	UploadBytes   int
	UploadChars   int
	DownloadBytes int
	ResolveTime   time.Duration
	RejectReason  string
}

// ResolverProber abstracts network probing from discovery engine orchestration.
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
	) (*BurstProbeResult, error)
}
```

### 2.3 Live UDP Implementation: `internal/client/prober_udp.go`
Encapsulates concrete UDP socket operations and delegates to `c.probeConnectionMTU` and `c.sendPipelinedMicroBurst`:

```go
package client

import (
	"context"
	"fmt"
	"time"
)

// UDPResolverProber implements ResolverProber using live UDP network exchanges.
type UDPResolverProber struct {
	client *Client
}

// NewUDPResolverProber constructs a UDPResolverProber wrapping the given Client.
func NewUDPResolverProber(client *Client) *UDPResolverProber {
	return &UDPResolverProber{client: client}
}

func (p *UDPResolverProber) ProbeMTU(ctx context.Context, conn Connection, maxUploadPayload int) (MTUProbeResult, error) {
	if maxUploadPayload <= 0 && p.client != nil {
		maxUploadPayload = p.client.maxUploadMTUPayload(conn.Domain)
	}

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
) (*BurstProbeResult, error) {
	if p.client == nil {
		return nil, fmt.Errorf("client unavailable")
	}

	transport, err := p.client.newUDPQueryTransport(ctx, conn.ResolverLabel)
	if err != nil {
		return &BurstProbeResult{
			SentCount:    packetCount,
			RejectReason: fmt.Sprintf("dial error: %v", err),
		}, nil
	}
	defer func() {
		if transport.conn != nil {
			_ = transport.conn.Close()
		}
	}()

	res := p.client.sendPipelinedMicroBurst(
		ctx,
		conn,
		transport,
		packetCount,
		downloadMTU,
		uploadMTU,
		timeout,
	)
	return &res, ctx.Err()
}
```

### 2.4 `DiscoveryConfig` and `Client.newDiscoveryConfig()`
`DiscoveryConfig` consolidates all runtime discovery parameters. It supports canonical field names as well as compatibility aliases:

```go
// DiscoveryConfig contains all configuration parameters for DiscoveryEngine.
type DiscoveryConfig struct {
	FastStart             bool
	TargetResolvers       int
	Parallelism           int
	MaxActiveResolvers    int
	MicroBurstEnabled     bool
	MicroBurstPacketCount int
	MicroBurstParallelism int
	MicroBurstTimeout     time.Duration
	Domains               []string
	UploadCaps            map[string]int
	MinUploadMTU          int
	MaxUploadMTU          int
	MinDownloadMTU        int
	MaxDownloadMTU        int
	AutoRemoveLowMTU      bool

	// Backward-compatibility aliases
	TargetActive     int
	MaxActive        int
	WorkerCount      int
	FastStartEnabled bool
	BurstCount       int
}

// EffectiveTarget returns TargetResolvers or fallback TargetActive.
func (c DiscoveryConfig) EffectiveTarget() int {
	if c.TargetResolvers > 0 {
		return c.TargetResolvers
	}
	return c.TargetActive
}

// EffectiveParallelism returns Parallelism or fallback WorkerCount.
func (c DiscoveryConfig) EffectiveParallelism() int {
	if c.Parallelism > 0 {
		return c.Parallelism
	}
	if c.WorkerCount > 0 {
		return c.WorkerCount
	}
	return 1
}

// EffectiveBurstCount returns MicroBurstPacketCount or fallback BurstCount.
func (c DiscoveryConfig) EffectiveBurstCount() int {
	if c.MicroBurstPacketCount > 0 {
		return c.MicroBurstPacketCount
	}
	if c.BurstCount > 0 {
		return c.BurstCount
	}
	return 6
}
```

#### `Client.newDiscoveryConfig()` Construction
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

	totalConns := 0
	if c.pool != nil {
		totalConns = c.pool.TotalCount()
	} else if c.balancer != nil {
		totalConns = c.balancer.TotalCount()
	}

	parallelism := c.cfg.EffectiveMTUTestParallelism()
	if parallelism < 1 {
		parallelism = 1
	}
	if totalConns > 0 && parallelism > totalConns {
		parallelism = totalConns
	}

	burstCount := c.cfg.MicroBurstPacketCount
	if burstCount < 2 {
		burstCount = 6
	}

	burstParallelism := c.cfg.MicroBurstParallelism
	if burstParallelism < 1 {
		burstParallelism = 8
	}

	return DiscoveryConfig{
		FastStart:             fastStart,
		TargetResolvers:       targetResolvers,
		Parallelism:           parallelism,
		MaxActiveResolvers:    c.cfg.MaxActiveResolvers,
		MicroBurstEnabled:     c.cfg.MicroBurstTestEnabled,
		MicroBurstPacketCount: burstCount,
		MicroBurstParallelism: burstParallelism,
		MicroBurstTimeout:     c.resolverHealthProbeTimeout(),
		Domains:               c.cfg.Domains,
		UploadCaps:            c.precomputeUploadCaps(),
		MinUploadMTU:          c.cfg.MinUploadMTU,
		MaxUploadMTU:          c.cfg.MaxUploadMTU,
		MinDownloadMTU:        c.cfg.MinDownloadMTU,
		MaxDownloadMTU:        c.cfg.MaxDownloadMTU,
		AutoRemoveLowMTU:      c.cfg.AutoRemoveLowMTUServers,
		// Aliases
		TargetActive:          targetResolvers,
		MaxActive:             c.cfg.MaxActiveResolvers,
		WorkerCount:           parallelism,
		FastStartEnabled:      fastStart,
		BurstCount:            burstCount,
	}
}
```

### 2.5 `DiscoveryEngine` Lifecycle and `Run(ctx)`
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

// Run executes discovery across candidates, supporting both Run(ctx) and Run(ctx, candidates).
func (e *DiscoveryEngine) Run(ctx context.Context, candidateSets ...[]Connection) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if e.pool == nil || e.pool.TotalCount() == 0 {
		return ErrNoValidConnections
	}

	var scanConnections []Connection
	if len(candidateSets) > 0 && len(candidateSets[0]) > 0 {
		scanConnections = candidateSets[0]
	} else {
		scanConnections = e.pool.AllConnections()
	}
	if len(scanConnections) == 0 {
		return ErrNoValidConnections
	}

	fastStart := e.cfg.FastStart || e.cfg.FastStartEnabled
	targetValidResolvers := e.cfg.EffectiveTarget()
	if targetValidResolvers <= 0 {
		targetValidResolvers = len(scanConnections)
	}

	workerCount := e.cfg.EffectiveParallelism()
	if workerCount > len(scanConnections) {
		workerCount = len(scanConnections)
	}

	testedKeys := make(map[string]bool, len(scanConnections))
	qualifiedKeys := make(map[string]struct{})
	qualifiedEndpoints := make(map[string]struct{}, targetValidResolvers)
	disqualifiedEndpoints := make(map[string]struct{})

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		if fastStart && len(qualifiedEndpoints) >= targetValidResolvers {
			break
		}

		// Check candidate exhaustion
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
		if !fastStart || needed < 1 {
			needed = len(scanConnections)
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
					if batchUniqueValid.Add(1) >= int32(needed) && fastStart {
						cancelBatch()
					}
				}
			}
		}

		// Dispatch workers
		jobs := make(chan int, len(scanConnections))
		var wg sync.WaitGroup
		var testedMu sync.Mutex

		for range workerCount {
			wg.Go(func() {
				for idx := range jobs {
					if batchCtx.Err() != nil {
						return
					}
					conn := scanConnections[idx]
					uploadCap := e.cfg.UploadCaps[conn.Domain]
					res, err := e.prober.ProbeMTU(batchCtx, conn, uploadCap)
					if err != nil || !res.Success {
						testedMu.Lock()
						testedKeys[conn.Key] = true
						testedMu.Unlock()
						continue
					}

					testedMu.Lock()
					testedKeys[conn.Key] = true
					testedMu.Unlock()

					// Record probe results in pool
					_ = e.pool.ApplyMTUProbeResult(
						conn.Key,
						res.UploadBytes,
						res.UploadChars,
						res.DownloadBytes,
						res.ResolveTime,
						true,
					)

					if acceptedConn, ok := e.pool.GetConnectionByKey(conn.Key); ok && (acceptedConn.IsValid || acceptedConn.StandbyEligible) {
						recordBatchValid(acceptedConn)
					}
				}
			})
		}

	dispatchLoop:
		for idx := range scanConnections {
			if fastStart && batchUniqueValid.Load() >= int32(needed) {
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
		cancelBatch()

		if err := ctx.Err(); err != nil {
			return err
		}

		if len(batchValidConns) == 0 {
			continue
		}

		if !e.cfg.MicroBurstEnabled {
			for _, conn := range batchValidConns {
				qualifiedEndpoints[conn.ResolverLabel] = struct{}{}
			}
			continue
		}

		// Micro-burst qualification
		burstQualified, results := e.runMicroBurstBatch(ctx, batchValidConns, targetValidResolvers-len(qualifiedEndpoints))
		for _, q := range burstQualified {
			qualifiedKeys[q.Key] = struct{}{}
			qualifiedEndpoints[q.ResolverLabel] = struct{}{}
		}
		for _, r := range results {
			if !r.BurstResult.Qualified {
				disqualifiedEndpoints[r.Connection.ResolverLabel] = struct{}{}
			}
		}
	}

	if fastStart {
		var requiredKeys map[string]struct{}
		if e.cfg.MicroBurstEnabled {
			requiredKeys = qualifiedKeys
		}
		e.pool.FinalizeFastStart(requiredKeys, targetValidResolvers)
	}

	if e.pool.ActiveCount() == 0 {
		return ErrNoValidConnections
	}
	return nil
}
```

---

## 3. Caveats & Architectural Guardrails

1. **Direct Empirical Test Invariant**:
   `TestEmpirical_ProbeConnectionMTU_Cancellation` in `empirical_challenge_test.go` directly calls `client.probeConnectionMTU(ctx, conn, 200)`.
   - **Mandate**: `probeConnectionMTU` must remain on `*Client` with its exact signature `(ctx context.Context, conn Connection, maxUploadPayload int) (mtuConnectionProbeResult, mtuRejectReason)` and retaining its `context.AfterFunc` immediate socket closing.
2. **Micro-Burst Test Invariant**:
   `TestEmpirical_MicroBurst_ActivePoolFullPromotion`, `TestEmpirical_MicroBurst_ActivePoolSaturationAdmission`, and `micro_burst_test.go` directly call `client.runMicroBurstQualification(ctx, ...)`.
   - **Mandate**: `runMicroBurstQualification` must remain on `*Client` in `internal/client/micro_burst.go`.
3. **Standby Eligibility Invariant**:
   In `DiscoveryEngine`, MTU-valid candidate checking must preserve `(acceptedConn.IsValid || acceptedConn.StandbyEligible)` to satisfy `TestEmpirical_MTU_BatchStandbyEligibilityPreserved`.
4. **Multi-Domain Trimming Invariant**:
   In `FinalizeFastStart`, active pool trimming evaluates `qualifiedKeys[conn.Key]` rather than endpoint label, preventing cross-domain bleeding when physical endpoints are shared across domains (`TestEmpirical_MTU_StrictKeyTrimmingMultiDomain`).
5. **Balancer Forwarding Shims**:
   Existing tests (`fast_start_test.go`) query `client.balancer.ActiveCount()` and `client.balancer.TotalCount()`. Milestone 2 already wired these to `b.pool.ActiveCount()` and `b.pool.TotalCount()`. These shims must remain in `balancer.go`.

---

## 4. Conclusion & Actionable Implementation Roadmap

The extraction seam is clean, well-bounded, and preserves 100% backward compatibility with all test suites while achieving the decoupling goals of Milestone 3.

### Recommended Implementation Steps for the Worker

| Step | File | Action | Details |
|---|---|---|---|
| **1** | `internal/client/resolver_discovery.go` | **Create** | Define `MTUProbeResult`, `ResolverProber` interface, `DiscoveryConfig`, `Client.newDiscoveryConfig()`, and `DiscoveryEngine` with `Run(ctx)`. |
| **2** | `internal/client/prober_udp.go` | **Create** | Implement `UDPResolverProber` delegating to `c.probeConnectionMTU` and `c.sendPipelinedMicroBurst`. |
| **3** | `internal/client/resolver_discovery_test.go` | **Create** | Implement `FakeResolverProber` and deterministic tests: `TestDiscoveryEngine_FastStartExitsEarly`, `TestDiscoveryEngine_Replenishment_OnBurstFailure`, `TestDiscoveryEngine_ContextCancellationPrompt`, `TestDiscoveryEngine_FullScanWhenFastStartDisabled`. |
| **4** | `internal/client/mtu.go` | **Refactor** | Refactor `RunInitialMTUTests(ctx)` (lines 338–588) to instantiate `UDPResolverProber`, `newDiscoveryConfig()`, `DiscoveryEngine`, and delegate to `engine.Run(ctx)`. Remove discovery loops, worker channels, and batch context logic. |

---

## 5. Verification Method

To independently verify the implementation:

1. **Targeted Unit Tests for Milestone 3**:
   ```bash
   go test -v ./internal/client -run "TestDiscoveryEngine.*"
   go test -v ./internal/client -run "TestRunInitialMTUTests.*"
   ```
2. **Backward Compatibility Tests**:
   ```bash
   go test -v ./internal/client -run "TestFormatMTULogLine.*|TestAppendMTURemovedServerLine.*"
   go test -v ./internal/client -run "TestEncodedCharsForPayload.*|TestBuildMTUProbePayload.*"
   go test -v ./internal/client/handlers -run "TestDispatchRoutesMTUResponses"
   ```
3. **Empirical Challenge Tests**:
   ```bash
   go test -v ./internal/client -run "TestEmpirical_ProbeConnectionMTU_Cancellation"
   go test -v ./internal/client -run "TestEmpirical_MTU_BatchStandbyEligibilityPreserved"
   go test -v ./internal/client -run "TestEmpirical.*"
   ```
4. **Resolver Pool Regression**:
   ```bash
   go test -v ./internal/client -run "TestResolverPool.*"
   ```
5. **Full Client Package & Builds**:
   ```bash
   go test ./internal/client
   go build ./cmd/client
   go build ./cmd/server
   ```
