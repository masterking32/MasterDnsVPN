# Task Assignment: Milestone 1 — Consolidated Resolver Evaluation

You are teamwork_worker instance 1.
Your working directory: c:\Dev\Projects\DNStunnel\.agents\teamwork\worker_m1

## Context & Inputs
- Authoritative request: `c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md`
- Project scope & interfaces: `c:\Dev\Projects\DNStunnel\.agents\teamwork\orchestrator\PROJECT.md`
- Detailed architectural survey & design: `c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_1\report.md` (read Section 2)

## Mandatory Integrity Warning
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

## Write Ownership
You have exclusive write ownership of:
- `internal/client/score.go`
- `internal/client/score_test.go`
- `internal/client/micro_burst.go` (only lines around `calculateBurstScore`)
- `internal/client/balancer.go` (only lines around `calculateConnectionScoreLocked`)
- `internal/client/runtime_stats.go` (only lines around `calculateResolverRuntimeSpeedAndScore` and `DumpRuntimeStats`)

DO NOT edit any files outside `internal/client/`. `go.mod` and `go.sum` are strictly immutable.

## Objective
Implement Milestone 1: Consolidated Resolver Evaluation:
1. In `internal/client/score.go`:
   - Consolidate all evaluation, score calculation, latency penalty, loss handling, and tier badge generation into a pure module with zero network dependencies and zero mutexes.
   - Define:
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
   - Retain backward compatibility shims: `CalculateResolverScore`, `FormatResolverSpeed`, `ResolverQualityTier`.
2. In `internal/client/score_test.go`:
   - Create comprehensive unit tests covering:
     - Zero/negative MTU defaults (defaults to 500)
     - Loss ratio clamping ([0.0, 1.0])
     - Zero/negative RTT handling (CompositeScore = 0.0, Tier = "Poor")
     - Empirical ThroughputKBps override over baseline
     - Latency penalty calculation (500ms -> 2.0x, 1000ms -> 3.0x)
     - Quality tier and badge mapping (Excellent, Good, Fair, Poor)
     - Speed formatting (<1000 KB/s vs >=1000 MB/s)
3. In `internal/client/micro_burst.go`:
   - Refactor `calculateBurstScore` to delegate to `EvaluateResolver`, deleting duplicated math.
4. In `internal/client/balancer.go`:
   - Refactor `calculateConnectionScoreLocked` to use `EvaluateResolver`.
5. In `internal/client/runtime_stats.go`:
   - Refactor `calculateResolverRuntimeSpeedAndScore` and `DumpRuntimeStats` to consume `EvaluateResolver` directly, eliminating `fmt.Sscanf`.
6. Run build and tests:
   - `go test -v ./internal/client -run "TestScore.*|TestCalculateBurstScoreRanking"`
   - `go test ./internal/client`
   - `go build ./cmd/client` and `go build ./cmd/server`
   - `git diff -- go.mod go.sum` (must be empty)

## Deliverables
Write your handoff report to `c:\Dev\Projects\DNStunnel\.agents\teamwork\worker_m1\handoff.md` with:
- Summary of changes made
- Exact test commands run and their verbatim output
- Layout & invariant compliance
Then send a completion message to the orchestrator.


## 2026-10-31T16:47:20Z
[Message] sender=8a518c3b-4b52-4082-8487-66e423f24169
Implement Milestone 1 (Consolidated Resolver Evaluation in score.go, score_test.go, micro_burst.go, balancer.go, runtime_stats.go).
Run all required tests and builds.
Write your complete handoff report to c:\Dev\Projects\DNStunnel\.agents\teamwork\worker_m1\handoff.md.
When finished, notify the orchestrator via send_message.
