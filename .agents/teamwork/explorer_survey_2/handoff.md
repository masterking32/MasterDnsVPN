# Handoff Report: Explorer Survey 2 — R2 (Deep Resolver Pool Module & Balancer Refactor)

## 1. Observation
- `internal/client/balancer_admission.go` (123 lines) contains `admitQualifiedBatch` (lines 7–37), `finalizeFastStart` (lines 41–69), `beginConnectionRecheck` / `beginConnectionRecheckLocked` (lines 73–86), `resolverRecheckResult` (lines 90–94), and `completeConnectionRecheck` (lines 98–122).
- `internal/client/balancer_admission_test.go` (190 lines) contains 6 unit tests verifying admission replacement, batch preservation, intermediate placement atomicity, recheck lifecycle, conservative stats, and replacement thresholds.
- `internal/client/balancer.go` (2654 lines) currently mixes candidate pool management (`connections`, `indexByKey`, `activeIDs`, `inactiveIDs`, `maxActiveResolvers`, `syncedUploadMTU`, `syncedDownloadMTU`, `OptimizeActivePool`, `GetRankedEndpoints`) with packet dispatching (`SelectTargets`, `ReportSend`, `ReportSuccess`, `ReportTimeout`, `RetractTimeout`, `TrackResolverSend`, `TrackResolverSuccess`, `TrackResolverFailure`, `CollectExpiredResolverTimeouts`, `TotalPacketsSent`).
- In `internal/client/balancer.go:1220–1265`, `SelectTargets` dispatches outbound packets across active connections by checking `len(b.activeIDs)` and querying `b.getUniqueConnectionsLocked(...)` or sticky `streamRoutes`.
- In `internal/client/balancer.go:1453–1531`, `moveConnectionStateLocked` handles capacity displacement (`candScore > worstActiveScore`) and demotes displaced incumbents to `StandbyEligible = true`.
- In `internal/client/balancer.go:1533–1602`, `OptimizeActivePool` swaps degraded active resolvers for standby candidates that have verified MTU satisfying session MTU and beat the active score by >1.25x.
- In `internal/client/balancer.go:1151–1182`, `NextInactiveConnectionForHealthCheck` round-robins inactive/standby candidates and calls `beginConnectionRecheckLocked`, setting `StandbyEligible = false`.
- In `internal/client/empirical_challenge_test.go:519–542`, `TestEmpirical_ActiveStandbyMutualExclusivity` asserts `conn.IsValid && conn.StandbyEligible` is never true.
- In `internal/client/empirical_challenge_test.go:1206–1330`, `TestEmpirical_RecheckRevokesStandby_NoRaceWithOptimize` verified that `AcquireNextInactiveForRecheck` revoking `StandbyEligible` withstands 440,187 concurrent calls to `OptimizeActivePool()` without racing.
- Running `go test -v ./internal/client -run "TestAdmission.*"` and `go test -v ./internal/client -run "TestEmpirical_ActiveStandbyMutualExclusivity|TestEmpirical_RecheckRevokesStandby_NoRaceWithOptimize"` confirmed 100% PASS on the current codebase.

## 2. Logic Chain
1. *From Observation of `balancer_admission.go` and `balancer.go`*: All pool membership, candidate states, MTU tracking, and optimization logic operate on candidate slices and indices (`connections`, `activeIDs`, `inactiveIDs`) protected by `b.mu`.
2. *From Observation of `SelectTargets` and packet tracking in `balancer.go`*: Packet dispatching only requires knowledge of active resolvers (`ActiveResolvers() []Connection`) and per-candidate stats/reporting (`ReportSuccess`, `ReportTimeout`, `ReportSend`).
3. *Therefore*: Pool management can be completely extracted into `internal/client/resolver_pool.go` as a deep, cohesive module owning the 4-state candidate FSM (`StateInactive`, `StateActive`, `StateStandby`, `StateRechecking`).
4. *From Observation of `balancer_admission_test.go` and `empirical_challenge_test.go`*: The 6 tests in `balancer_admission_test.go` can be directly mapped to `internal/client/resolver_pool_test.go` testing `ResolverPool` directly, allowing `balancer_admission.go` and `balancer_admission_test.go` to be safely deleted without losing test coverage.
5. *From Observation of callers across `client.go`, `client_utils.go`, `mtu.go`, `micro_burst.go`, and test files*: Retaining backward-compatible delegation methods on `Balancer` (e.g. `b.ActiveCount() -> b.pool.ActiveCount()`, `b.OptimizeActivePool() -> b.pool.Optimize()`) ensures that existing extensive tests in `balancer_test.go` and `empirical_challenge_test.go` continue to pass without breaking changes.
6. *From Observation of `resolver_maintenance.go` and R4*: By providing `pool.SetOnPoolChanged(func())`, active pool modifications (`AdmitStartupBatch`, `FinalizeFastStart`, `CompleteRecheck`, `Optimize`, timeout auto-disable) trigger `SaveRankedResolversToFile()` event-driven, eliminating the periodic maintenance loop.

## 3. Caveats
- `score.go` consolidation (R1) will provide `EvaluateResolver(m ResolverMetrics) ResolverEvaluation`. When `ResolverPool` calculates composite scores for `Optimize()` and `RankedEndpoints()`, it should use the consolidated formula from R1 (or `CalculateResolverScore`).
- In `ReleaseRecheck`, if an in-flight probe is cancelled/aborted (e.g. `transport` dial error in `mtu.go:828`), the candidate must be released back to its prior standby state (`wasStandby=true`) or inactive (`wasStandby=false`) so it is not permanently stuck in `StateRechecking`.

## 4. Conclusion
1. `internal/client/resolver_pool.go` will export all 13 required methods: `NewResolverPool`, `SetSessionMTU`, `ActiveResolvers`, `AllConnections`, `ActiveCount`, `TotalCount`, `AdmitStartupBatch`, `FinalizeFastStart`, `AcquireNextInactiveForRecheck`, `ReleaseRecheck`, `Optimize`, `RankedEndpoints`, and `SetOnPoolChanged`.
2. `balancer_admission.go` and `balancer_admission_test.go` will be completely absorbed into `resolver_pool.go` and `resolver_pool_test.go`, and deleted from disk.
3. `balancer.go` will retain packet dispatching (`SelectTargets`), sticky stream routing, in-flight DNS query sample tracking across 16 pending shards, timeout sliding-window evaluation, and `TotalPacketsSent`, delegating pool queries to `b.pool`.
4. `Client` in `client.go` will hold `pool *ResolverPool` and wire `c.pool.SetOnPoolChanged(func() { c.SaveRankedResolversToFile() })`.

## 5. Verification Method
- Independent command verification:
  ```bash
  # 1. Run all ResolverPool unit tests
  go test -v ./internal/client -run "TestResolverPool.*"

  # 2. Run all empirical challenge stress & invariant tests
  go test -v ./internal/client -run "TestEmpirical.*"

  # 3. Run all client package unit tests
  go test ./internal/client

  # 4. Verify no files outside internal/client/ and internal/config/ were modified
  git diff -- go.mod go.sum
  ```
- File presence verification:
  - `internal/client/resolver_pool.go` exists
  - `internal/client/resolver_pool_test.go` exists
  - `internal/client/balancer_admission.go` DOES NOT exist
  - `internal/client/balancer_admission_test.go` DOES NOT exist
