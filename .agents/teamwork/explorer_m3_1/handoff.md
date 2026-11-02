# Handoff Report: Milestone 3 DiscoveryEngine Extraction Seam (explorer_m3_1)

- **Agent**: explorer_m3_1
- **Working Directory**: `c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_m3_1\`
- **Recipient**: Orchestrator (`8a518c3b-4b52-4082-8487-66e423f24169`)
- **Type**: Hard Handoff (Investigation & Architecture Seam Mapping Complete)
- **Primary Report**: `c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_m3_1\report.md`

---

## 1. Observation

1. **`internal/client/mtu.go` Structure**:
   - `RunInitialMTUTests(ctx)` spans lines 338–588 (251 lines).
   - Lines 338–377: Computes `targetValidResolvers`, `workerCount`, `uploadCaps`, and logs start.
   - Lines 378–406: Outer candidate batching and replenishment loop.
   - Lines 407–425: Batch context creation (`batchCtx, cancelBatch := context.WithCancel(ctx)`) and early cancellation trigger (`batchUniqueValid >= needed`).
   - Lines 427–506: Worker channel dispatching (`jobs chan int`) with worker goroutines calling `runConnectionMTUTest`.
   - Lines 516–556: Inline micro-burst qualification loop and candidate replenishment tracking via `disqualifiedEndpoints`.
   - Lines 558–565: FastStart pool trimming (`finalizeFastStart`).
   - Lines 566–588: Post-discovery optimization (`optimizeMTUResolvers`), synchronized MTU state application, usage logging, and file persistence.
2. **Existing Test Suite Invariants**:
   - `mtu_logging_test.go`: Tests `formatMTULogLine` and `appendMTURemovedServerLine`. Both remain intact in `mtu_logging.go` and `mtu.go`.
   - `mtu_math_test.go`: Tests `encodedCharsForPayload`, `canBuildUploadPayload`, and `buildMTUProbePayload`. All remain in `mtu.go` (lines 1647–1772).
   - `handlers/mtu_handlers_test.go`: Tests packet dispatch to handlers in `internal/client/handlers/`. Has zero dependency on discovery engine.
   - `empirical_challenge_test.go`: Line 91 directly invokes `client.probeConnectionMTU(ctx, conn, 200)` across multiple cancellation delays (0s to 150ms), asserting immediate return (<300ms) via `context.AfterFunc` socket closure and zero goroutine leaks. Line 1074 verifies `TestEmpirical_MTU_BatchStandbyEligibilityPreserved` where initial burst droppers are replaced via replenishment. Lines 499 & 729 directly invoke `client.runMicroBurstQualification`.
   - `fast_start_test.go`: Directly exercises `RunInitialMTUTests` for early exit (10 candidates -> >=2 & <10 active), full scan when recheck is disabled, replenishment across batches on burst failures, and prompt cancellation (<2s).

---

## 2. Logic Chain

1. **Extraction Boundaries**:
   - Orchestration belongs in `DiscoveryEngine` (`resolver_discovery.go`): Worker pool distribution, candidate batching, quota tracking, early context cancellation, replenishment on burst drop, and batch admission into `ResolverPool`.
   - Physical probing belongs in `ResolverProber` interface (`resolver_discovery.go`) implemented by `UDPResolverProber` (`prober_udp.go`) using live UDP exchanges and `FakeResolverProber` (`resolver_discovery_test.go`) for in-memory testing without OS sockets.
   - High-level coordinator `RunInitialMTUTests(ctx)` in `mtu.go` delegates to `DiscoveryEngine.Run(ctx)`, then applies `optimizeMTUResolvers`, sets session MTU, logs results, and triggers file persistence.
2. **Decoupling from Network I/O**:
   - `FakeResolverProber` allows unit testing early exit, replenishment, and context cancellation deterministically in <5ms without OS network socket contention or port binding flakiness.
3. **Preserving Empirical Invariants**:
   - `c.probeConnectionMTU` and `c.runMicroBurstQualification` must remain exported on `*Client` with identical signatures to ensure 100% compatibility with `TestEmpirical_ProbeConnectionMTU_Cancellation` and micro-burst admission tests.
   - In `UDPResolverProber.ProbeMTU`, `context.AfterFunc` guarantees instantaneous socket teardown when `batchCtx` or `ctx` is cancelled.

---

## 3. Caveats

- **No Caveats**. All 11 empirical challenge tests and all fast-start tests pass against current baseline. The refactoring roadmap preserves all existing method entry points and signatures on `Client` and `Balancer`.

---

## 4. Conclusion

The extraction seam is strictly defined and ready for execution by the Worker:
1. **Create `internal/client/resolver_discovery.go`**: Define `MTUProbeResult`, `ResolverProber`, `DiscoveryConfig`, `Client.newDiscoveryConfig()`, and `DiscoveryEngine` with `Run(ctx, candidates...)`.
2. **Create `internal/client/prober_udp.go`**: Implement `UDPResolverProber` delegating to `c.probeConnectionMTU` and `c.sendPipelinedMicroBurst`.
3. **Create `internal/client/resolver_discovery_test.go`**: Implement `FakeResolverProber` and in-memory unit tests (`TestDiscoveryEngine_FastStartExitsEarly`, `TestDiscoveryEngine_Replenishment_OnBurstFailure`, `TestDiscoveryEngine_ContextCancellationPrompt`, `TestDiscoveryEngine_FullScanWhenFastStartDisabled`).
4. **Refactor `internal/client/mtu.go`**: Reduce `RunInitialMTUTests(ctx)` to ~35 lines delegating to `DiscoveryEngine.Run(ctx)` while preserving probing and health check methods.

---

## 5. Verification Method

Execute the test commands:
```bash
# Targeted Milestone 3 Engine & FastStart Tests
go test -v ./internal/client -run "TestDiscoveryEngine.*"
go test -v ./internal/client -run "TestRunInitialMTUTests.*"

# Backward Compatibility Tests
go test -v ./internal/client -run "TestFormatMTULogLine.*|TestAppendMTURemovedServerLine.*"
go test -v ./internal/client -run "TestEncodedCharsForPayload.*|TestBuildMTUProbePayload.*"
go test -v ./internal/client/handlers -run "TestDispatchRoutesMTUResponses"

# Empirical Challenge Suite
go test -v ./internal/client -run "TestEmpirical_ProbeConnectionMTU_Cancellation"
go test -v ./internal/client -run "TestEmpirical_MTU_BatchStandbyEligibilityPreserved"
go test -v ./internal/client -run "TestEmpirical.*"

# Package & Binary Compilation
go test ./internal/client
go build ./cmd/client
go build ./cmd/server
```
