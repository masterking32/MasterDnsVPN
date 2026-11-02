# DISPATCH

## 2026-10-31T16:33:02Z
Sender: 69846dd2-f9c1-49aa-8b51-d0b852613585

Implement the approved PR #205 Architectural Deepening Plan for MasterDnsVPN on branch `feat/fast-start-resolvers`.

Working directory: .agents/teamwork/orchestrator/
Project Workspace: c:\Dev\Projects\DNStunnel
Original request record: c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md
Integrity mode: development

## Requirements

### R1. Consolidated Resolver Evaluation
Consolidate all evaluation, score calculation, latency penalty, loss handling, and tier badge generation currently fragmented across `score.go`, `micro_burst.go`, `balancer.go`, and `runtime_stats.go` into a pure module in `internal/client/score.go` with zero network dependencies and zero mutexes. Define `ResolverMetrics` (DownloadMTUBytes, RTT, LossRatio, ThroughputKBps) and `ResolverEvaluation` (CompositeScore, ThroughputKBps, Tier, ColoredBadge), export `EvaluateResolver(m ResolverMetrics) ResolverEvaluation`, and deduplicate scoring calculations across `micro_burst.go`, `balancer.go`, and `runtime_stats.go`.

### R2. Deep Resolver Pool Module
Create `internal/client/resolver_pool.go` encapsulating candidate state transitions across the 3-state finite state machine (StateInactive, StateActive, StateStandby, StateRechecking), capacity bounding, admission, and active pool optimization. Export methods: `NewResolverPool`, `SetSessionMTU`, `ActiveResolvers`, `AllConnections`, `ActiveCount`, `TotalCount`, `AdmitStartupBatch`, `FinalizeFastStart`, `AcquireNextInactiveForRecheck`, `ReleaseRecheck`, `Optimize`, `RankedEndpoints`, and `SetOnPoolChanged`. Create `internal/client/resolver_pool_test.go`. Absorb and delete `internal/client/balancer_admission.go` and `internal/client/balancer_admission_test.go`. Refactor `internal/client/balancer.go` to retain packet dispatching (`SelectTargets`, `ReportSuccess`, `ReportTimeout`, `RetractTimeout`, `TotalPacketsSent`, and in-flight sample tracking) while removing pool management fields and consuming active resolvers directly from `ResolverPool`.

### R3. Deep Discovery & FastStart Engine
Create `internal/client/resolver_discovery.go` defining the `ResolverProber` interface (`ProbeMTU` and `ProbeBurst`), `DiscoveryConfig`, and `DiscoveryEngine`, encapsulating candidate batching, worker pool parallelism, context cancellation on FastStart target quota fulfillment, and batch admission into `ResolverPool`. Create `prober_udp.go` implementing `ResolverProber` using live UDP queries. Create `internal/client/resolver_discovery_test.go` with `FakeResolverProber` for deterministic in-memory testing of FastStart early exit and replenishment. Refactor `internal/client/mtu.go` so `RunInitialMTUTests` delegates orchestration to `DiscoveryEngine.Run(ctx)`, stripping discovery loops, worker channels, and batch context cancellation from `mtu.go`.

### R4. Event-Driven Persistence & Maintenance Cleanup
Delete `internal/client/resolver_maintenance.go` and `internal/client/resolver_maintenance_test.go`. In `internal/client/client.go`, remove the `resolverMaintenanceStarted` atomic flag and register `SaveRankedResolversToFile()` with `pool.SetOnPoolChanged(...)` during initialization so inactive recheck completion triggers persistence automatically. In `internal/client/client_utils.go` and `internal/client/runtime_stats.go`, connect `SaveRankedResolversToFile` directly to `pool.RankedEndpoints(50)`.

### R5. Invariants & Scope Constraints
Do NOT edit `cmd/` or `internal/` outside `internal/client/` and `internal/config/`. `go.mod` and `go.sum` are immutable. Adhere strictly to domain vocabulary in `CONTEXT.md` (Resolver, Resolver Pool, Active Resolver, Standby Resolver, Session, Client, Tunnel, MLQ).

## Acceptance Criteria

### Test Verification
- [ ] `go test -v ./internal/client -run "TestResolverPool.*"` passes
- [ ] `go test -v ./internal/client -run "TestDiscoveryEngine.*"` passes
- [ ] `go test -v ./internal/client -run "TestRunInitialMTUTests.*"` passes
- [ ] `go test -v ./internal/client -run "TestEmpirical.*"` passes
- [ ] `go test ./internal/client` passes
- [ ] `go test ./...` passes
- [ ] `go build ./cmd/client` and `go build ./cmd/server` succeed without errors

### Structural Verification
- [ ] `git diff -- go.mod go.sum` produces no diff
- [ ] No files outside `internal/client/` and `internal/config/` are modified
- [ ] `internal/client/balancer_admission.go` and `internal/client/balancer_admission_test.go` are removed
- [ ] `internal/client/resolver_maintenance.go` and `internal/client/resolver_maintenance_test.go` are removed
