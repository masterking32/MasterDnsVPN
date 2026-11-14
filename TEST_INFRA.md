# TEST_INFRA.md — E2E & Integration Test Architecture for PR #205

## 1. Overview & Architecture

This document defines the End-to-End (E2E) and Integration Test Architecture for MasterDnsVPN PR #205 ("Architectural Deepening Plan").

The test infrastructure establishes a 4-Tier verification hierarchy designed to guarantee correctness, thread safety, boundary resilience, and strict adherence to architectural invariants across all subsystems:
- **Consolidated Resolver Evaluation** (`score.go`)
- **Deep Resolver Pool Module & FSM** (`resolver_pool.go`, `balancer.go`)
- **Discovery & FastStart Engine** (`resolver_discovery.go`, `prober_udp.go`, `mtu.go`)
- **Event-Driven Persistence** (`client.go`, `client_utils.go`, `runtime_stats.go`)

### 1.1 Guiding Principles
1. **Zero External Flakiness**: Integration and E2E tests are self-contained and run in-memory or loopback, decoupled from external network dependencies.
2. **Deterministic Execution**: Avoid unbounded sleeps; utilize synchronizers, deterministic seed statistics, and explicit context cancellations.
3. **Progressive Testability**: Verification suites validate functionality at every milestone without breaking backward compatibility.
4. **Invariant Enforcement**: Explicit adversarial audits continuously enforce domain invariants (`!(IsValid && StandbyEligible)`, recheck revocation, `go.mod`/`go.sum` immutability).

---

## 2. Test Runner Commands

### 2.1 Fast Scoped E2E Suite Execution (Recommended for Tight Feedback Loops)
Runs all 17 E2E test cases across the 4 tiers in under 5 seconds:
```bash
go test -v ./internal/client -run "TestE2E_Tier.*"
```

### 2.2 By Tier
```bash
# Tier 1: Feature Coverage
go test -v ./internal/client -run "TestE2E_Tier1_.*"

# Tier 2: Boundary & Corner Cases
go test -v ./internal/client -run "TestE2E_Tier2_.*"

# Tier 3: Cross-Feature Pairwise
go test -v ./internal/client -run "TestE2E_Tier3_.*"

# Tier 4: Real-World Workloads & Adversarial Invariants
go test -v ./internal/client -run "TestE2E_Tier4_.*"
```

### 2.3 Comprehensive Client Test Suites (Acceptance Criteria)
```bash
# Empirical stress and regression challenges
go test -v ./internal/client -run "TestEmpirical.*"

# FastStart & MTU orchestration tests
go test -v ./internal/client -run "TestRunInitialMTUTests.*"

# Complete client package test suite
go test ./internal/client

# Full repository test suite
go test ./...

# Binary builds
go build ./cmd/client
go build ./cmd/server
```

---

## 3. Four-Tier Test Methodology

```
+-------------------------------------------------------------------------+
|                  TIER 4: REAL-WORLD WORKLOADS & ADVERSARIAL             |
|   High-Concurrency Discovery, Burst Loss Swaps, Invariant Audits        |
+-------------------------------------------------------------------------+
                                    ^
+-------------------------------------------------------------------------+
|                  TIER 3: CROSS-FEATURE PAIRWISE                         |
|   Discovery -> Pool -> Balancer, Recheck -> Swap -> Persistence         |
+-------------------------------------------------------------------------+
                                    ^
+-------------------------------------------------------------------------+
|                  TIER 2: BOUNDARY & CORNER CASES                        |
|   Zero/Negative RTT & Loss, Empty Pools, Lease Expiration, All Fail     |
+-------------------------------------------------------------------------+
                                    ^
+-------------------------------------------------------------------------+
|                  TIER 1: FEATURE COVERAGE                               |
|   Pure Evaluation Math, Capacity Bounding, 5-State FSM, Hysteresis      |
+-------------------------------------------------------------------------+
```

### Tier 1: Feature Coverage
Validates the happy path and primary specifications of each individual architectural component:
- **`TestE2E_Tier1_ResolverEvaluation_Calculations`**: Verifies baseline theoretical speed, loss ratio impact, latency penalty scaling ($1.0 + RTT_{ms}/500$), speed string formatting, and 4-tier classification (Excellent $\ge 15$, Good $\ge 8$, Fair $\ge 4$, Poor $< 4$).
- **`TestE2E_Tier1_ResolverPool_CapacityBounding`**: Enforces strict pool capacity limits under sequential candidate admissions and saturated pools.
- **`TestE2E_Tier1_ResolverPool_CandidateStateTransitions`**: Exercises the 5-state Finite State Machine (`StateInactive`, `StateActive`, `StateStandby`, `StateRechecking`, `StateRejected`).
- **`TestE2E_Tier1_ResolverPool_OptimizationSwaps`**: Verifies degradation swaps with $>1.25\times$ hysteresis requirement ($25\%$ improvement threshold).
- **`TestE2E_Tier1_Discovery_WorkerParallelismAndBatching`**: Verifies concurrent worker execution and candidate batching without race conditions.
- **`TestE2E_Tier1_Discovery_FastStartEarlyExitAndReplenishment`**: Verifies early context cancellation when target quota is reached, and candidate replenishment when initial burst probes fail.
- **`TestE2E_Tier1_Persistence_EventDrivenTriggers`**: Verifies that pool modifications produce ranked endpoints with active members prioritized.

### Tier 2: Boundary & Corner Cases
Validates arithmetic edges, invalid inputs, resource exhaustion, and failure paths:
- **`TestE2E_Tier2_Boundary_ZeroNegativeRTTAndLoss`**: Tests $RTT \le 0$, negative RTT, $MTU \le 0$ default fallback to $500$, loss ratio clamping ($<0 \to 0.0$, $>1.0 \to 1.0$), and extreme RTT ($100\text{s}$) latency penalties.
- **`TestE2E_Tier2_Boundary_PoolCapacityLimits`**: Tests empty candidate sets, single candidate pools, $MaxActive = 1$, and optimization behavior when no standbys exist.
- **`TestE2E_Tier2_Boundary_RecheckCooldown`**: Tests recheck cooldown timing ($60\text{s}$ cooldown gating), interval gating, and candidate re-acquisition after cooldown expiration.
- **`TestE2E_Tier2_Boundary_AllCandidatesProbeFailure`**: Tests catastrophic network failure where all candidates fail MTU and burst probes, ensuring clean error returns without panics or routing to dead endpoints.

### Tier 3: Cross-Feature Pairwise Interactions
Validates state and data flow between connected subsystems:
- **`TestE2E_Tier3_Pairwise_DiscoveryToPoolAdmission`**: Tests discovery results $\to$ startup batch admission $\to$ active/standby pool partitioning $\to$ Balancer target selection routing.
- **`TestE2E_Tier3_Pairwise_RecheckDegradationSwapPersistence`**: Tests Active Path degradation $\to$ inactive candidate recheck $\to$ degradation swap $\to$ ranked endpoint persistence update.
- **`TestE2E_Tier3_Pairwise_StandbyRecheckFailureRevocation`**: Tests standby candidate leased for recheck $\to$ immediate revocation of `StandbyEligible` $\to$ probe failure $\to$ verification that concurrent `OptimizeActivePool()` does NOT promote leased candidate.

### Tier 4: Real-World Workloads & Adversarial Stress
Validates system resilience under high concurrency, rapid state flips, and invariant integrity audits:
- **`TestE2E_Tier4_Workload_HighConcurrencyDiscoveryStress`**: Simulates 30 candidates with 8 concurrent worker goroutines rapidly updating statistics, validity, standby eligibility, and optimizing the pool simultaneously under high load.
- **`TestE2E_Tier4_Workload_RapidDegradationSwapsUnderLoss`**: Simulates 50 rounds of alternating burst packet loss across Active Paths, verifying continuous standby promotions, zero packet routing to inactive candidates, and strict adherence to `MaxActive`.
- **`TestE2E_Tier4_Adversarial_InvariantAudit_MutualExclusivity`**: Continuous forensic assertion across thousands of operations verifying `conn.IsValid` and `conn.StandbyEligible` are NEVER simultaneously true (`!(IsValid && StandbyEligible)`).

---

## 4. Feature Coverage Mapping

Mapping of core architecture components to specific test cases:

| Feature # | Feature Name | Primary Test Coverage | Secondary / Stress Coverage |
|---|---|---|---|
| **1** | Consolidated Resolver Evaluation | `TestE2E_Tier1_ResolverEvaluation_Calculations` | `TestE2E_Tier2_Boundary_ZeroNegativeRTTAndLoss` |
| **2** | Deduplicated Scoring in MicroBurst & Balancer | `TestE2E_Tier1_ResolverEvaluation_Calculations`, `TestCalculateBurstScoreRanking` | `TestEmpirical_MicroBurst_ActivePoolSaturationAdmission` |
| **3** | Sscanf Elimination in RuntimeStats | `TestE2E_Tier1_ResolverEvaluation_Calculations`, `TestFormatResolverSpeed` | `TestEmpirical_RuntimeStats_MonotonicCounterGating` |
| **4** | Deep ResolverPool FSM | `TestE2E_Tier1_ResolverPool_CandidateStateTransitions` | `TestE2E_Tier4_Adversarial_InvariantAudit_MutualExclusivity` |
| **5** | ResolverPool Public API | `TestE2E_Tier1_ResolverPool_CapacityBounding`, `TestE2E_Tier1_ResolverPool_OptimizationSwaps` | `TestE2E_Tier2_Boundary_PoolCapacityLimits` |
| **6** | Absorption & Deletion of BalancerAdmission | `TestE2E_Tier3_Pairwise_DiscoveryToPoolAdmission`, `TestAdmissionBatchReplacesSaturatedPool` | `TestAdmissionRecheckLifecycle` |
| **7** | Balancer Refactoring | `TestE2E_Tier3_Pairwise_DiscoveryToPoolAdmission`, `TestBalancerHybrid*` | `TestE2E_Tier4_Workload_RapidDegradationSwapsUnderLoss` |
| **8** | ResolverProber Interface & UDP Implementation | `TestE2E_Tier1_Discovery_WorkerParallelismAndBatching` | `TestEmpirical_ProbeConnectionMTU_Cancellation` |
| **9** | DiscoveryEngine Orchestration | `TestE2E_Tier1_Discovery_FastStartEarlyExitAndReplenishment` | `TestRunInitialMTUTests_FastStartExitsEarly` |
| **10** | Deterministic In-Memory Prober Testing | `TestE2E_Tier1_Discovery_FastStartEarlyExitAndReplenishment` | `TestRunInitialMTUTests_FallbackWhenFewerResolversWork` |
| **11** | MTU.go Refactor | `TestE2E_Tier3_Pairwise_DiscoveryToPoolAdmission` | `TestRunInitialMTUTests_BurstRetryScanning` |
| **12** | Maintenance Loop Cleanup & Deletion | `TestE2E_Tier1_Persistence_EventDrivenTriggers` | `TestE2E_Tier3_Pairwise_RecheckDegradationSwapPersistence` |
| **13** | Event-Driven Persistence Registration | `TestE2E_Tier1_Persistence_EventDrivenTriggers` | `TestE2E_Tier3_Pairwise_RecheckDegradationSwapPersistence` |
| **14** | Ranked Endpoints Connection | `TestE2E_Tier1_Persistence_EventDrivenTriggers` | `TestBalancerGetRankedEndpoints` |
| **15** | Pool Invariant Integrity | `TestE2E_Tier4_Adversarial_InvariantAudit_MutualExclusivity` | Continuous CI & test suite execution |
| **16** | Full Test & Build Verification | `TestE2E_Tier4_Workload_HighConcurrencyDiscoveryStress` | Complete test suite & binary builds (`cmd/client`, `cmd/server`) |

---

## 5. Test Suite Verification & Quality Gates

The E2E test suite adheres to the following quality gates:
1. **Zero Data Races**: Thread safety verified across concurrent operations (`-race` clean).
2. **Speed & Efficiency**: Standard run duration is $< 5.0\text{s}$ for the complete 17-test suite.
3. **Immutability Guarantee**: Automated scope checks ensure zero changes to external dependencies in `go.mod`/`go.sum` and strictly scoped changes across repository subsystems.
