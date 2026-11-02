# Task Assignment: Milestone 2 — Deep Resolver Pool Module & Balancer Refactor

You are teamwork_worker instance 3 (worker_m2).
Your working directory: c:\Dev\Projects\DNStunnel\.agents\teamwork\worker_m2

## Context & Inputs
- Authoritative request: `c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md` (read Requirement R2)
- Project scope & contracts: `c:\Dev\Projects\DNStunnel\.agents\teamwork\orchestrator\PROJECT.md`
- Detailed architectural survey & design: `c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_2\report.md`
- Completed M1 evaluation module: `internal/client/score.go` (use `EvaluateResolver` for scoring)

## Mandatory Integrity Warning
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

## Write Ownership
- `internal/client/resolver_pool.go` (NEW)
- `internal/client/resolver_pool_test.go` (NEW)
- `internal/client/balancer_admission.go` (DELETE after absorbing into resolver_pool.go)
- `internal/client/balancer_admission_test.go` (DELETE after absorbing into resolver_pool_test.go)
- `internal/client/balancer.go` (refactor to consume ResolverPool and retain packet dispatching)
- `internal/client/client.go` (initialize ResolverPool and wire to Balancer)

DO NOT edit any files outside `internal/client/`. `go.mod` and `go.sum` are strictly immutable.

## Objective
Implement Milestone 2:
1. **Create `internal/client/resolver_pool.go`**:
   - Define candidate states:
     ```go
     type CandidateState int
     const (
         StateInactive CandidateState = iota
         StateActive
         StateStandby
         StateRechecking
     )
     ```
   - Encapsulate the 4-state candidate FSM, capacity bounding (`maxActive`), admission, recheck lifecycle, and optimization.
   - Enforce invariants:
     - Mutual exclusivity: `IsValid != StandbyEligible` (never both true).
     - Recheck revocation: `AcquireNextInactiveForRecheck` synchronously clears `StandbyEligible = false`.
     - Atomic snapshots: write-locked batch transitions.
   - Export all 13 methods:
     `NewResolverPool`, `SetSessionMTU`, `ActiveResolvers`, `AllConnections`, `ActiveCount`, `TotalCount`, `AdmitStartupBatch`, `FinalizeFastStart`, `AcquireNextInactiveForRecheck`, `ReleaseRecheck`, `Optimize`, `RankedEndpoints`, `SetOnPoolChanged`.
     Also include helper methods needed by callers: `SetConnections`, `SessionMTU`, `SetMaxActive`, `MaxActive`, `GetConnectionByKey`, `SetConnectionValidity`, `SetConnectionStandbyEligible`, `IsConnectionStandbyEligible`, `SetConnectionMTU`, `ApplyMTUProbeResult`, `CompleteRecheck`, `SeedBurstStats`, `SeedConservativeStats`, `GetStatsSnapshot`.
2. **Absorb and Delete `balancer_admission.go` and `balancer_admission_test.go`**:
   - Absorb all logic from `internal/client/balancer_admission.go` into `internal/client/resolver_pool.go`.
   - Delete `internal/client/balancer_admission.go`.
   - Absorb all tests from `internal/client/balancer_admission_test.go` into `internal/client/resolver_pool_test.go`.
   - Delete `internal/client/balancer_admission_test.go`.
3. **Create `internal/client/resolver_pool_test.go`**:
   - Implement comprehensive tests covering capacity bounding, batch admission, FastStart quota trimming, recheck lifecycle, degradation swap hysteresis (>1.25x), session MTU compliance, ranked endpoint ordering with active boost, and event-driven `SetOnPoolChanged` notifications.
4. **Refactor `internal/client/balancer.go`**:
   - Retain packet dispatching (`SelectTargets`), sticky stream routing with failover cooldowns, sliding-window timeout tracking (`ReportSuccess`, `ReportTimeout`, `RetractTimeout`), and 16-shard in-flight query tracking.
   - Remove pool management fields (`connections`, `activeIDs`, `inactiveIDs`, `maxActiveResolvers`, `syncedUploadMTU`, `syncedDownloadMTU`), embedding `pool *ResolverPool`.
   - Consume active resolvers directly via `b.pool.ActiveResolvers()`.
   - Retain backward-compatible delegation methods on `Balancer` (e.g. `ActiveCount()`, `TotalCount()`, `ActiveConnections()`, `GetConnectionByKey()`, etc.) so existing suites (`balancer_test.go`, `empirical_challenge_test.go`) pass without regressions.
5. **Update `client.go`**:
   - Add `pool *ResolverPool` to `Client` struct.
   - In initialization, instantiate `pool := NewResolverPool(cfg.MaxActiveResolvers, log)` and pass `pool` into `NewBalancer(..., pool)`.
6. **Build & Test Verification**:
   - `go test -v ./internal/client -run "TestResolverPool.*"`
   - `go test -v ./internal/client -run "TestEmpirical.*"`
   - `go test ./internal/client`
   - `go build ./cmd/client` and `go build ./cmd/server`
   - `git diff -- go.mod go.sum` (must be empty)
   - Verify `balancer_admission.go` and `balancer_admission_test.go` are deleted.

## Deliverables
Write handoff to `c:\Dev\Projects\DNStunnel\.agents\teamwork\worker_m2\handoff.md` and notify orchestrator.


## 2026-10-31T17:31:27Z
You are teamwork_worker instance 3 (worker_m2).
Your working directory: c:\Dev\Projects\DNStunnel\.agents\teamwork\worker_m2.
Your instructions are in c:\Dev\Projects\DNStunnel\.agents\teamwork\worker_m2\DISPATCH.md.
Also read the authoritative user request at c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md and the survey report at c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_2\report.md.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Implement Milestone 2:
1. Create internal/client/resolver_pool.go exporting all 13 required methods and encapsulating candidate FSM.
2. Absorb and delete balancer_admission.go and balancer_admission_test.go.
3. Create internal/client/resolver_pool_test.go.
4. Refactor balancer.go to retain packet dispatching while consuming ResolverPool.
5. Update client.go.
6. Verify TestResolverPool.*, TestEmpirical.*, full package tests, and binary builds.
Write your complete handoff report to c:\Dev\Projects\DNStunnel\.agents\teamwork\worker_m2\handoff.md.
When finished, notify the orchestrator via send_message.
