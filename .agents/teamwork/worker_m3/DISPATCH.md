# Dispatch Task: Milestone 3 Implementation (Deep Discovery & FastStart Engine)

## 2026-10-31T18:35:00Z
- **Assigned Worker**: worker_m3
- **Working Directory**: `c:\Dev\Projects\DNStunnel\.agents\teamwork\worker_m3\`
- **Parent Conversation ID**: `8a518c3b-4b52-4082-8487-66e423f24169`

## Mandatory Files to Read First
1. `c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md` (authoritative specification, R3)
2. `c:\Dev\Projects\DNStunnel\.agents\teamwork\orchestrator\PROJECT.md` (architecture, Feature Inventory, interface contracts)
3. `c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_m3_1\report.md` (extraction seam analysis)
4. `c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_m3_2\report.md` (DiscoveryEngine complete code design)
5. `c:\Dev\Projects\DNStunnel\.agents\teamwork\spec_miner_m3_3\report.md` (ResolverProber interface & test suite design)

## MANDATORY INTEGRITY WARNING
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

## Write Ownership Boundaries
You exclusively own and may edit or create:
- `internal/client/resolver_discovery.go` (create)
- `internal/client/prober_udp.go` (create)
- `internal/client/resolver_discovery_test.go` (create)
- `internal/client/mtu.go` (refactor `RunInitialMTUTests` & add `newDiscoveryConfig`)
- `internal/client/micro_burst.go` (add `probeConnectionMicroBurst` helper on `*Client` if needed)
DO NOT edit files outside `internal/client/` and `internal/config/`.
`go.mod` and `go.sum` are STRICTLY IMMUTABLE (`git diff -- go.mod go.sum` must remain empty).

## Implementation Tasks

### 1. Create `internal/client/resolver_discovery.go`
- Define `MTUProbeResult`:
  ```go
  type MTUProbeResult struct {
      Success       bool
      UploadBytes   int
      UploadChars   int
      DownloadBytes int
      ResolveTime   time.Duration
      RejectReason  string
  }
  ```
- Define `ResolverProber` interface:
  ```go
  type ResolverProber interface {
      ProbeMTU(ctx context.Context, conn Connection, maxUploadPayload int) (MTUProbeResult, error)
      ProbeBurst(ctx context.Context, conn Connection, packetCount int, downloadMTU int, uploadMTU int, timeout time.Duration) BurstProbeResult
  }
  ```
- Define `DiscoveryConfig` struct with all fields (FastStart, TargetResolvers, Parallelism, BatchSize, MicroBurstEnabled, MicroBurstPacketCount, MicroBurstParallelism, MicroBurstTimeout, MaxBurstLossRatio, MinBurstThroughputKBps, MaxActiveResolvers, Domains, UploadCaps, MinUploadMTU, MaxUploadMTU, MinDownloadMTU, MaxDownloadMTU, AutoRemoveLowMTU).
- Define `DiscoveryEngine` struct:
  ```go
  type DiscoveryEngine struct { ... }
  func NewDiscoveryEngine(cfg DiscoveryConfig, prober ResolverProber, pool *ResolverPool, log *logger.Logger) *DiscoveryEngine
  ```
- Implement `DiscoveryEngine.Run(ctx context.Context) error` following the 8-phase lifecycle from `explorer_m3_2/report.md`:
  - Phase 1: Candidate Enumeration & Quota Initialization (`pool.AllConnections()`).
  - Phase 2: Candidate Batching Loop with `batchCtx, cancelBatch := context.WithCancel(ctx)`.
  - Phase 3: Parallel Worker Pool Probing (`jobs := make(chan int, len(scanConnections))`), invoking `prober.ProbeMTU`, updating `pool.ApplyMTUProbeResult`, and triggering `cancelBatch()` when `batchUniqueValid >= needed && FastStart`.
  - Phase 4: Micro-Burst Qualification via `prober.ProbeBurst`, scoring via pure `score.EvaluateResolver(ResolverMetrics)`, filtering qualified vs disqualified.
  - Phase 5: Batch Admission into `pool.AdmitStartupBatch(results, selectedWinners)`.
  - Phase 6: Candidate Replenishment Loop if `len(qualifiedEndpoints) < targetValidResolvers`.
  - Phase 7: FastStart Finalization via `pool.FinalizeFastStart(qualifiedKeys, targetValidResolvers)`.
  - Phase 8: MTU Optimization via `pool.Optimize()`; return `nil` if `pool.ActiveCount() > 0`, else `ErrNoValidConnections`.

### 2. Create `internal/client/prober_udp.go`
- Define `UDPResolverProber` struct wrapping `*Client`.
- `NewUDPResolverProber(client *Client) *UDPResolverProber`.
- Implement `ProbeMTU(ctx, conn, maxUploadPayload)` delegating to `p.client.probeConnectionMTU(ctx, conn, maxUploadPayload)`.
- Implement `ProbeBurst(ctx, conn, packetCount, downloadMTU, uploadMTU, timeout)` delegating to `p.client.probeConnectionMicroBurst(ctx, conn, packetCount, downloadMTU, uploadMTU, timeout)`. Ensure `context.AfterFunc` socket teardown is preserved.

### 3. Create `internal/client/resolver_discovery_test.go`
- Implement thread-safe `FakeResolverProber` with in-memory canned responses and telemetry.
- Implement at least 8 comprehensive unit tests:
  - `TestDiscoveryEngine_FastStartExitsEarly`
  - `TestDiscoveryEngine_Replenishment_OnBurstFailure`
  - `TestDiscoveryEngine_ContextCancellationPrompt`
  - `TestDiscoveryEngine_FullScanWhenFastStartDisabled`
  - `TestDiscoveryEngine_ActiveStandbyAllocation`
  - `TestDiscoveryEngine_MultiDomainExclusivity`
  - `TestDiscoveryEngine_CapacityBounding`
  - `TestDiscoveryEngine_ZeroValidReturnsError`

### 4. Refactor `internal/client/mtu.go`
- Add `(c *Client) newDiscoveryConfig() DiscoveryConfig`.
- Refactor `RunInitialMTUTests(ctx)` to construct `newDiscoveryConfig()`, `NewUDPResolverProber(c)`, `NewDiscoveryEngine(...)`, delegate to `engine.Run(ctx)`, and perform post-discovery logging/session MTU application.
- Retain `probeConnectionMTU` and all helper functions in `mtu.go` so empirical tests and low-level routines continue to work seamlessly.

## Verification Requirements
You MUST execute and document passing results for:
1. `go test -v -count=1 ./internal/client -run "TestDiscoveryEngine.*"` (all unit tests PASS in <50ms)
2. `go test -v -count=1 ./internal/client -run "TestRunInitialMTUTests.*"` (PASS)
3. `go test -v -count=1 ./internal/client -run "TestEmpirical_ProbeConnectionMTU_Cancellation"` (PASS in <300ms)
4. `go test -v -count=1 ./internal/client -run "TestEmpirical.*"` (PASS)
5. `go test -v -count=1 ./internal/client -run "TestResolverPool.*"` (13/13 PASS)
6. `go test -v -count=1 ./internal/client -run "TestBalancer.*"` (28/28 PASS)
7. `go build ./cmd/client` & `go build ./cmd/server` (exit code 0)
8. `git diff --exit-code -- go.mod go.sum` (clean, 0 diff)

Write your handoff report to `c:\Dev\Projects\DNStunnel\.agents\teamwork\worker_m3\handoff.md` and notify orchestrator via `send_message`.


## 2026-10-31T18:45:09Z
**Context**: Milestone 3 Implementation Status
**Content**: I see that `internal/client/resolver_discovery.go`, `prober_udp.go`, and `resolver_discovery_test.go` have been created. Please update on current status (e.g. `mtu.go` refactoring, test suite runs).
**Action**: Update `progress.md` and complete handoff report when finished.
