# Project: MasterDnsVPN Fast-Start Resolvers (PR #205 Architectural Deepening)

## Architecture
- **Resolver Evaluation Subsystem (`internal/client/score.go`)**: Pure mathematical module with zero network dependencies and zero mutexes. Computes composite scoring, effective throughput under packet loss and latency penalties, and tier badge generation for resolvers.
- **Resolver Pool Module (`internal/client/resolver_pool.go`)**: Deep encapsulation of resolver-domain candidate pairings across a 4-state finite state machine (`StateInactive`, `StateActive`, `StateStandby`, `StateRechecking`). Enforces capacity bounding, startup batch admission, FastStart quota finalization, periodic recheck lease acquisition/release, degradation swap optimization (>1.25x hysteresis), and event-driven notifications (`SetOnPoolChanged`).
- **Packet Balancer (`internal/client/balancer.go`)**: Dedicated packet dispatching engine. Consumes active resolvers directly from `ResolverPool`. Retains multi-path target selection, sticky stream routing with failover cooldowns, sliding-window timeout tracking with auto-disable, 16-shard in-flight query tracking, and sent/received counters.
- **Discovery & FastStart Engine (`internal/client/resolver_discovery.go`, `prober_udp.go`)**: Orchestration of parallel MTU and micro-burst probing decoupled from network I/O via the `ResolverProber` interface. Features worker pool parallelism, candidate batching, context cancellation on target quota fulfillment, candidate replenishment on burst failures, and batch admission into `ResolverPool`.
- **Event-Driven Persistence**: Replaces 60-second polling maintenance loop with reactive event notifications from `ResolverPool` to `SaveRankedResolversToFile()` and `RankedEndpoints(50)`.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Consolidated Resolver Evaluation | Pure module in `score.go` exporting `ResolverMetrics`, `ResolverEvaluation`, and `EvaluateResolver`. | M1 | ORIGINAL_REQUEST §R1 |
| 2 | Deduplicated Scoring in MicroBurst & Balancer | Replace duplicated latency penalty and effective throughput calculations in `micro_burst.go` and `balancer.go` with `EvaluateResolver`. | M1 | ORIGINAL_REQUEST §R1 |
| 3 | Sscanf Elimination in RuntimeStats | Use `ResolverEvaluation.Tier` and `ResolverEvaluation.ThroughputKBps` directly in `runtime_stats.go`, eliminating string parsing round-trip. | M1 | ORIGINAL_REQUEST §R1 |
| 4 | Deep ResolverPool FSM | 4-state candidate FSM (`StateInactive`, `StateActive`, `StateStandby`, `StateRechecking`) with mutual exclusivity and recheck revocation in `resolver_pool.go`. | M2 | ORIGINAL_REQUEST §R2 |
| 5 | ResolverPool Public API | Export 13 methods (`NewResolverPool`, `SetSessionMTU`, `ActiveResolvers`, `AllConnections`, `ActiveCount`, `TotalCount`, `AdmitStartupBatch`, `FinalizeFastStart`, `AcquireNextInactiveForRecheck`, `ReleaseRecheck`, `Optimize`, `RankedEndpoints`, `SetOnPoolChanged`). | M2 | ORIGINAL_REQUEST §R2 |
| 6 | Absorption & Deletion of BalancerAdmission | Absorb all logic from `balancer_admission.go` and `balancer_admission_test.go` into `resolver_pool.go` and `resolver_pool_test.go`, and delete old files. | M2 | ORIGINAL_REQUEST §R2 |
| 7 | Balancer Refactoring | Retain packet dispatching (`SelectTargets`), timeout tracking (`ReportSuccess`, `ReportTimeout`, `RetractTimeout`), and 16-shard tracking in `balancer.go` while consuming `ResolverPool`. | M2 | ORIGINAL_REQUEST §R2 |
| 8 | ResolverProber Interface & UDP Implementation | Define `ResolverProber` (`ProbeMTU`, `ProbeBurst`), `DiscoveryConfig`, and implement live UDP probing in `prober_udp.go`. | M3 | ORIGINAL_REQUEST §R3 |
| 9 | DiscoveryEngine Orchestration | Worker pool parallelism, batching, quota-based context cancellation, replenishment on burst failure, and pool admission in `resolver_discovery.go`. | M3 | ORIGINAL_REQUEST §R3 |
| 10 | Deterministic In-Memory Prober Testing | `FakeResolverProber` in `resolver_discovery_test.go` testing FastStart early exit, replenishment, and cancellation in <5ms without network sockets. | M3 | ORIGINAL_REQUEST §R3 |
| 11 | MTU.go Refactor | Refactor `RunInitialMTUTests` in `mtu.go` to delegate orchestration to `DiscoveryEngine.Run(ctx)` while stripping discovery loops and worker channels. | M3 | ORIGINAL_REQUEST §R3 |
| 12 | Maintenance Loop Cleanup & Deletion | Delete `resolver_maintenance.go` and `resolver_maintenance_test.go`. Remove `resolverMaintenanceStarted` atomic flag in `client.go`. | M4 | ORIGINAL_REQUEST §R4 |
| 13 | Event-Driven Persistence Registration | Hook `SaveRankedResolversToFile()` into `pool.SetOnPoolChanged(...)` during initialization in `client.go`. | M4 | ORIGINAL_REQUEST §R4 |
| 14 | Ranked Endpoints Connection | Connect `SaveRankedResolversToFile()` in `client_utils.go` and stats dumping directly to `pool.RankedEndpoints(50)`. | M4 | ORIGINAL_REQUEST §R4 |
| 15 | Scope & Immutability Invariants | Preserve `go.mod`/`go.sum` immutability, confine modifications to `internal/client/` and `internal/config/`, and enforce `CONTEXT.md` domain language. | M1-M5 | ORIGINAL_REQUEST §R5 |
| 16 | Full Test & Build Verification | Pass all unit tests (`TestResolverPool.*`, `TestDiscoveryEngine.*`, `TestRunInitialMTUTests.*`, `TestEmpirical.*`), full package tests, full project tests, and binary builds. | M5 | ORIGINAL_REQUEST Acceptance Criteria |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Consolidated Resolver Evaluation | Features 1, 2, 3 (`score.go`, `micro_burst.go`, `balancer.go`, `runtime_stats.go`) | none | DONE |
| M2 | Deep Resolver Pool Module | Features 4, 5, 6, 7 (`resolver_pool.go`, `resolver_pool_test.go`, `balancer.go`, absorption/deletion of `balancer_admission.go` and its tests) | M1 | DONE |
| M3 | Deep Discovery & FastStart Engine | Features 8, 9, 10, 11 (`resolver_discovery.go`, `prober_udp.go`, `resolver_discovery_test.go`, `mtu.go` refactoring) | M2 | PLANNED |
| M4 | Event-Driven Persistence & Maintenance Cleanup | Features 12, 13, 14 (`client.go`, `client_utils.go`, `runtime_stats.go`, deletion of `resolver_maintenance.go` and its tests) | M2 | PLANNED |
| M5 | Final Acceptance & Adversarial Verification | Features 15, 16 (Full test suite execution, adversarial coverage hardening, forensic integrity audit) | M1, M2, M3, M4 | PLANNED |

## Interface Contracts

### Evaluation Subsystem (`score.go`)
```go
type ResolverMetrics struct {
    DownloadMTUBytes int
    RTT              time.Duration
    LossRatio        float64
    ThroughputKBps   float64
}

type ResolverEvaluation struct {
    CompositeScore float64
    ThroughputKBps float64
    Tier           string
    ColoredBadge   string
}

func EvaluateResolver(m ResolverMetrics) ResolverEvaluation
```

### Resolver Pool (`resolver_pool.go`)
```go
type CandidateState int
const (
    StateInactive CandidateState = iota
    StateActive
    StateStandby
    StateRechecking
)

type ResolverRecheckResult struct {
    Connection  Connection
    MTUVerified bool
    Burst       *BurstProbeResult
}

type ResolverPool struct { ... }

func NewResolverPool(maxActive int, log *logger.Logger) *ResolverPool
func (p *ResolverPool) SetSessionMTU(uploadMTU, downloadMTU int)
func (p *ResolverPool) SessionMTU() (int, int)
func (p *ResolverPool) ActiveResolvers() []Connection
func (p *ResolverPool) AllConnections() []Connection
func (p *ResolverPool) ActiveCount() int
func (p *ResolverPool) TotalCount() int
func (p *ResolverPool) AdmitStartupBatch(results []QualifiedResolver, selected []Connection)
func (p *ResolverPool) FinalizeFastStart(qualifiedKeys map[string]struct{}, target int)
func (p *ResolverPool) AcquireNextInactiveForRecheck(now time.Time, minInterval time.Duration) (Connection, bool)
func (p *ResolverPool) ReleaseRecheck(key string, wasStandby bool)
func (p *ResolverPool) CompleteRecheck(result ResolverRecheckResult) (Connection, bool)
func (p *ResolverPool) Optimize() bool
func (p *ResolverPool) RankedEndpoints(maxCount int) []config.ResolverAddress
func (p *ResolverPool) SetOnPoolChanged(cb func())
```

### Discovery Engine & Prober (`resolver_discovery.go`, `prober_udp.go`)
```go
type ResolverProber interface {
    ProbeMTU(ctx context.Context, conn Connection) (uploadBytes, uploadChars, downloadBytes int, err error)
    ProbeBurst(ctx context.Context, conn Connection, count int) (*BurstProbeResult, error)
}

type DiscoveryConfig struct {
    TargetActive     int
    MaxActive        int
    BatchSize        int
    WorkerCount      int
    FastStartEnabled bool
    BurstCount       int
}

type DiscoveryEngine struct { ... }
func NewDiscoveryEngine(prober ResolverProber, pool *ResolverPool, cfg DiscoveryConfig, log *logger.Logger) *DiscoveryEngine
func (e *DiscoveryEngine) Run(ctx context.Context, candidates []Connection) error
```

## Code Layout
- `internal/client/score.go`: Consolidated pure evaluation module.
- `internal/client/score_test.go`: Unit tests for evaluation, latency penalty, loss ratios, and badges.
- `internal/client/resolver_pool.go`: Deep resolver pool module and 4-state candidate FSM.
- `internal/client/resolver_pool_test.go`: Unit tests for resolver pool capacity, admission, FSM, and optimization.
- `internal/client/resolver_discovery.go`: Discovery engine, batching, cancellation, and replenishment.
- `internal/client/prober_udp.go`: Production UDP implementation of `ResolverProber`.
- `internal/client/resolver_discovery_test.go`: Deterministic in-memory unit tests using `FakeResolverProber`.
- `internal/client/balancer.go`: Lean packet dispatcher delegating pool queries to `ResolverPool`.
- `internal/client/mtu.go`: Refactored entry point delegating to `DiscoveryEngine`.
- `internal/client/client.go`: Client initialization wiring `ResolverPool`, `Balancer`, and reactive persistence.
- `internal/client/client_utils.go`: Persistence connecting to `pool.RankedEndpoints(50)`.
- `internal/client/runtime_stats.go`: Stats reporting consuming `EvaluateResolver` and `ResolverPool`.
