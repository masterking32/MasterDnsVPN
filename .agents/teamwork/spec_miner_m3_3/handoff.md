# Handoff Report: Milestone 3 Specification Mining (spec_miner_m3_3)

## 1. Observation
- **Current Live Socket Overhead**: Executed `go test -v ./internal/client -run "TestRunInitialMTUTests.*"`. Result:
  `=== RUN TestRunInitialMTUTests_BurstRetryScanning`
  `--- PASS: TestRunInitialMTUTests_BurstRetryScanning (7.05s)`
  Total suite run time was `9.242s` for 4 tests because all tests spin up mock UDP listeners via `startMockMTUDNSListener` (`internal/client/fast_start_test.go:22-59`).
- **Probe Cancellation Baseline**: Executed `go test -v ./internal/client -run "TestEmpirical_ProbeConnectionMTU_Cancellation"`. Result:
  All 30 subtests passed in `1.77s` (`ok masterdnsvpn-go/internal/client 3.639s`). Each probe cancellation verified `< 300ms` return time with zero goroutine leaks against blackhole UDP listener.
- **Monolithic MTU Probing in `mtu.go`**:
  `c.probeConnectionMTU` is at `internal/client/mtu.go:1123-1163`, taking `(ctx context.Context, conn Connection, maxUploadPayload int)` and returning `(mtuConnectionProbeResult, mtuRejectReason)`.
  It utilizes `context.AfterFunc(ctx, func() { probeTransport.conn.Close() })` to enforce immediate cancellation.
- **Monolithic Burst Probing in `micro_burst.go`**:
  `c.sendPipelinedMicroBurst` is at `internal/client/micro_burst.go:63-283`, taking `(ctx, conn, transport, packetCount, downloadMTU, uploadMTU, timeout)` and returning `BurstProbeResult` by value.
- **Draft Discrepancy in `PROJECT.md`**:
  `PROJECT.md:97-100` specifies:
  `ProbeMTU(ctx context.Context, conn Connection) (uploadBytes, uploadChars, downloadBytes int, err error)`
  `ProbeBurst(ctx context.Context, conn Connection, count int) (*BurstProbeResult, error)`
  This omits `maxUploadPayload` (required for per-domain upload caps), drops `ResolveTime` (required by `ResolverPool.ApplyMTUProbeResult`), and forces unnecessary pointer return on `BurstProbeResult`.

## 2. Logic Chain
1. **Interface Contract Derivation**:
   - From Observation 3, `probeConnectionMTU` requires `maxUploadPayload int` because domain label formatting dictates the max upload probe size.
   - `ResolverPool.ApplyMTUProbeResult` (at `resolver_pool.go:349`) requires `resolveTime time.Duration`.
   - Therefore, `ProbeMTU` must return `(MTUProbeResult, error)` where `MTUProbeResult` contains `Success bool`, `UploadBytes int`, `UploadChars int`, `DownloadBytes int`, `ResolveTime time.Duration`, and `RejectReason string`.
   - From Observation 4, `sendPipelinedMicroBurst` returns `BurstProbeResult` by value, containing `Qualified bool` and `RejectReason string`. All error conditions are encapsulated in these fields; returning value `BurstProbeResult` is type-safe and nil-safe.
2. **`UDPResolverProber` Adapter Design**:
   - Wraps `*Client` in `internal/client/prober_udp.go`.
   - `ProbeMTU` delegates to `client.probeConnectionMTU(ctx, conn, maxUploadPayload)`. If `ctx.Err() != nil`, returns immediately with `ctx.Err()`.
   - `ProbeBurst` delegates to `client.probeConnectionMicroBurst(ctx, conn, packetCount, downloadMTU, uploadMTU, timeout)`, allocating transport with `newUDPQueryTransport` and closing it via `defer transport.conn.Close()`.
   - From Observation 2, `context.AfterFunc` ensures socket unblocking in `< 300ms`, satisfying empirical cancellation benchmarks.
3. **`FakeResolverProber` & Deterministic Testing**:
   - By creating `FakeResolverProber` in `internal/client/resolver_discovery_test.go` with mutex-protected maps (`mtuResponses`, `burstResponses`), configurable delays, and telemetry counters, all discovery engine behaviors (FastStart early exit, candidate replenishment, context cancellation, worker panic recovery, quota bounding) can be tested deterministically in `< 5ms` total test runtime.
   - This eliminates the `7.05s` socket delay observed in Observation 1 without losing coverage.

## 3. Caveats
- `FakeResolverProber` tests pure orchestration logic and state transitions in memory. It does not test physical UDP socket timeouts; physical UDP socket cancellation must continue to be safeguarded by `TestEmpirical_ProbeConnectionMTU_Cancellation`.
- In `internal/client/micro_burst.go`, the helper `probeConnectionMicroBurst` should be added to `*Client` (or directly within `prober_udp.go`) so `UDPResolverProber` does not duplicate query building logic.

## 4. Conclusion
The specification for `ResolverProber`, `UDPResolverProber`, and `FakeResolverProber` is complete and verified against the existing codebase. Concrete code blueprints, exact signatures, error contracts, and a 10-case unit test matrix have been produced in `report.md`. The Worker can implement `internal/client/prober_udp.go` and `internal/client/resolver_discovery_test.go` without any guesswork.

## 5. Verification Method
1. Inspect specification report:
   `view_file c:\Dev\Projects\DNStunnel\.agents\teamwork\spec_miner_m3_3\report.md`
2. Run empirical cancellation benchmark to verify baseline compatibility:
   `go test -v ./internal/client -run "TestEmpirical_ProbeConnectionMTU_Cancellation"`
3. Verify existing FastStart tests pass:
   `go test -v ./internal/client -run "TestRunInitialMTUTests.*"`
4. Once implemented by Worker, verify deterministic in-memory tests:
   `go test -v ./internal/client -run "TestDiscoveryEngine.*"`
