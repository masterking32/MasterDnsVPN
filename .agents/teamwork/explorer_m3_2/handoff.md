# Handoff Report: Milestone 3 DiscoveryEngine Architecture & Concurrency

**Agent**: `explorer_m3_2`  
**Working Directory**: `c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_m3_2\`  
**Date**: 2026-10-31  
**Target Milestone**: Milestone 3 (R3: Deep Discovery & FastStart Engine)  

---

## 1. Observation

1. **Monolithic Probing in `internal/client/mtu.go`**:
   - Lines 378–565 contain a monolithic `for` loop executing MTU scanning, worker channel dispatching (`jobs := make(chan int)`), FastStart batch context creation (`batchCtx, cancelBatch := context.WithCancel(ctx)`), atomic quota check (`batchUniqueValid.Add(1) >= int32(needed)`), micro-burst qualification (`c.runMicroBurstQualification`), replenishment scanning, and pool finalization (`c.balancer.finalizeFastStart`).
   - Testing FastStart behavior currently requires spinning up physical UDP listener sockets (`startMockMTUDNSListener` in `fast_start_test.go:22-59`), adding 10–25s of test runtime and potential OS port conflict flakiness.

2. **Completed `ResolverPool` API in `internal/client/resolver_pool.go` (Milestone 2)**:
   - Line 82: `NewResolverPool(maxActive int, log *logger.Logger) *ResolverPool`
   - Line 129: `SetSessionMTU(uploadMTU, downloadMTU int)`
   - Line 139: `SessionMTU() (int, int)`
   - Line 170: `ActiveResolvers() []Connection`
   - Line 190: `AllConnections() []Connection`
   - Line 205: `ActiveCount() int`
   - Line 215: `TotalCount() int`
   - Line 349: `ApplyMTUProbeResult(key string, uploadBytes int, uploadChars int, downloadBytes int, resolveTime time.Duration, active bool) bool`
   - Line 393: `AdmitStartupBatch(results []QualifiedResolver, selected []Connection)`
   - Line 436: `FinalizeFastStart(qualifiedKeys map[string]struct{}, target int)`
   - Line 602: `Optimize() bool`

3. **Consolidated Pure Scoring in `internal/client/score.go` (Milestone 1)**:
   - Line 57: `EvaluateResolver(m ResolverMetrics) ResolverEvaluation` provides pure composite scoring without mutexes or network dependencies.
   - `micro_burst.go:301-310` consumes `EvaluateResolver(ResolverMetrics)` to score candidates.

4. **Multi-Domain Strict Key Trimming Invariant**:
   - `TestEmpirical_MTU_StrictKeyTrimmingMultiDomain` in `empirical_challenge_test.go:1106-1199` verifies that `FinalizeFastStart` trims strictly by `qualifiedKeys[conn.Key]` rather than `conn.ResolverLabel`, preventing domain bleeding on shared physical DNS endpoints.

5. **Prompt Context Cancellation Invariant**:
   - `TestEmpirical_ProbeConnectionMTU_Cancellation` in `empirical_challenge_test.go:22-60` verifies that context cancellation aborts blocked UDP reads in `< 300ms` with zero goroutine leaks via `context.AfterFunc`.

---

## 2. Logic Chain

1. **Extraction Seam**:
   - Extracting lines 378–565 of `internal/client/mtu.go` into `DiscoveryEngine.Run(ctx)` in `internal/client/resolver_discovery.go` strips candidate batching, worker channels, and quota-based early context cancellation from `mtu.go`.
   - Decoupling socket I/O behind the `ResolverProber` interface (`ProbeMTU` and `ProbeBurst`) enables instant deterministic in-memory testing via `FakeResolverProber` without local OS UDP sockets.

2. **The 8-Phase Lifecycle**:
   - **Phase 1 (Enumeration & Quota)**: Retrieves candidates from `pool.AllConnections()`; enumerates unique physical endpoints by `ResolverLabel`; computes target quota `targetValidResolvers = min(totalUnique, TargetResolvers)` if `FastStart`.
   - **Phase 2 (Candidate Batching Loop)**: Outer loop verifies `ctx.Err()`; exits early if quota is fulfilled; verifies candidate exhaustion; computes `needed = target - qualified`; creates scoped `batchCtx, cancelBatch := context.WithCancel(ctx)`.
   - **Phase 3 (Parallel Worker Pool & Early Cancellation)**: Spawns `workerCount` workers consuming from buffered `jobs chan int`; workers invoke `prober.ProbeMTU`; updates candidate in `pool.ApplyMTUProbeResult`; `recordBatchValid` calls `cancelBatch()` as soon as `batchUniqueValid >= needed && FastStart`. Unprobed candidates are skipped, unblocking the worker pool cleanly.
   - **Phase 4 (Micro-Burst Qualification)**: Runs `prober.ProbeBurst` across `batchValidConns`; evaluates composite score via pure `score.EvaluateResolver`; ranks results; records qualified in `qualifiedKeys` and failed in `disqualifiedEndpoints`.
   - **Phase 5 (Batch Admission)**: Calls `pool.AdmitStartupBatch(results, selectedWinners)` under atomic lock; seeds burst stats; sets `StateActive` on winners and `StateStandby` on qualified overflow.
   - **Phase 6 (Replenishment Evaluation)**: If `len(qualifiedEndpoints) < targetValidResolvers`, outer loop restarts Phase 2, picking the next batch of untried candidates while skipping `disqualifiedEndpoints`.
   - **Phase 7 (FastStart Finalization)**: Calls `pool.FinalizeFastStart(qualifiedKeys, targetValidResolvers)` to enforce endpoint quota and execute strict multi-domain key trimming.
   - **Phase 8 (Active Pool MTU Optimization)**: Calls `pool.Optimize()` to perform degradation hysteresis swaps (>1.25x); verifies `pool.ActiveCount() > 0`; returns `nil` (or `ErrNoValidConnections`).

3. **Concurrency and Leak Prevention**:
   - Sizing `jobs` channel with capacity `len(scanConnections)` guarantees workers and the dispatcher cannot deadlock on early exit.
   - Workers execute `continue` on `batchCtx.Err() != nil` to drain pending queue items until `close(jobs)` is called by the dispatcher.
   - `wg.Wait()` ensures all worker goroutines terminate before the batch context is closed and before Phase 4 begins.
   - Parent `ctx` is never cancelled by `cancelBatch()`, preserving its validity for subsequent micro-burst and session operations.

---

## 3. Caveats

1. **Constructor Signature Alignment**:
   - `PROJECT.md` line 112 documented `NewDiscoveryEngine(prober, pool, cfg, log)` whereas `spec_miner_survey_3` used `NewDiscoveryEngine(cfg, prober, pool, log)`. Section 5 of `report.md` specifies `NewDiscoveryEngine(cfg, prober, pool, log)` as the canonical signature.
2. **Channel Capacity**:
   - `jobs` must be buffered to `len(scanConnections)` to completely eliminate dispatcher blockages upon early cancellation.
3. **Session MTU Precedence**:
   - When evaluating micro-bursts, session MTU from `pool.SessionMTU()` takes precedence; if zero, the candidate's individually probed MTU is used.

---

## 4. Conclusion

The architectural design, concurrency model, and complete code implementation for `internal/client/resolver_discovery.go` are fully formulated and validated against all project invariants. The Worker agent can copy the drop-in implementation directly from Section 5 of `report.md` to implement Milestone 3 without ambiguity.

---

## 5. Verification Method

To independently verify the architecture and its implementation:

```bash
# 1. Run deterministic DiscoveryEngine unit tests (in-memory, < 50ms)
go test -v ./internal/client -run "TestDiscoveryEngine.*"

# 2. Run existing FastStart and empirical challenge test suites
go test -v ./internal/client -run "TestRunInitialMTUTests.*"
go test -v ./internal/client -run "TestEmpirical.*"

# 3. Run full client package tests
go test -v ./internal/client

# 4. Verify go.mod and go.sum immutability
git diff -- go.mod go.sum
```
