# Task Assignment: Milestone 1 Remediation (Iteration 2) — IEEE 754 NaN/Inf Sanitization

You are teamwork_worker instance 2 (worker_m1_iter2).
Your working directory: c:\Dev\Projects\DNStunnel\.agents\teamwork\worker_m1_iter2

## Context & Inputs
- Authoritative request: `c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md`
- Project scope & contracts: `c:\Dev\Projects\DNStunnel\.agents\teamwork\orchestrator\PROJECT.md`
- Gate failure feedback:
  - Challenger 1 handoff: `c:\Dev\Projects\DNStunnel\.agents\teamwork\challenger_m1_1\handoff.md`
  - Challenger 2 handoff: `c:\Dev\Projects\DNStunnel\.agents\teamwork\challenger_m1_2\handoff.md`

## Mandatory Integrity Warning
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

## Write Ownership
- `internal/client/score.go`
- `internal/client/score_test.go`
- `internal/client/micro_burst.go`
- `internal/client/balancer.go`
- `internal/client/runtime_stats.go`

DO NOT edit any files outside `internal/client/`. `go.mod` and `go.sum` are strictly immutable.

## Objective & Actionable Remediation
Milestone 1 failed Gate 1 because `EvaluateResolver` lacked IEEE-754 `NaN` and `Inf` floating-point sanitization.
When `m.LossRatio` or `m.ThroughputKBps` is `math.NaN()`, comparisons like `< 0` and `> 1` evaluate to false in IEEE 754, causing `CompositeScore` to become `NaN`. In `micro_burst.go`, `sort.Slice`'s strict weak ordering is broken, ranking broken resolvers with `NaN` score at #1 ahead of fast resolvers (`TestScore_Adversarial_BurstScoreNaNPropagation` failed). In `balancer.go`, `NaN <= 0` evaluates to false, bypassing the fallback floor and making the resolver immune to demotion.

Remediate this completely:
1. In `internal/client/score.go`:
   - Import `"math"`.
   - In `EvaluateResolver(m ResolverMetrics) ResolverEvaluation`:
     - Sanitize `lossRatio`:
       ```go
       lossRatio := m.LossRatio
       if math.IsNaN(lossRatio) || lossRatio > 1.0 {
           lossRatio = 1.0
       } else if lossRatio < 0.0 {
           lossRatio = 0.0
       }
       ```
     - Sanitize `speedKBps`:
       ```go
       speedKBps := m.ThroughputKBps
       if math.IsNaN(speedKBps) || math.IsInf(speedKBps, 0) || speedKBps <= 0.0 {
           if m.RTT > 0 {
               rttSec := m.RTT.Seconds()
               if rttSec > 0.0 {
                   speedKBps = (float64(downloadMTU) / 1024.0) / rttSec
               }
           }
       }
       if math.IsNaN(speedKBps) || speedKBps < 0.0 {
           speedKBps = 0.0
       }
       ```
     - Guard `latencyPenalty`:
       ```go
       if latencyPenalty < 1.0 || math.IsNaN(latencyPenalty) {
           latencyPenalty = 1.0
       }
       ```
     - Guard `effectiveThroughput`:
       ```go
       effectiveThroughput := speedKBps * (1.0 - lossRatio)
       if math.IsNaN(effectiveThroughput) || effectiveThroughput < 0.0 {
           effectiveThroughput = 0.0
       }
       ```
     - Guard `compositeScore`:
       ```go
       compositeScore := effectiveThroughput / latencyPenalty
       if math.IsNaN(compositeScore) || math.IsInf(compositeScore, 0) || compositeScore < 0.0 {
           compositeScore = 0.0
       }
       ```
   - In `FormatResolverSpeed(speedKBps float64)`:
     ```go
     if math.IsNaN(speedKBps) || math.IsInf(speedKBps, 0) || speedKBps <= 0 {
         return "n/a"
     }
     ```
2. In `internal/client/micro_burst.go`:
   - In `calculateBurstScore`:
     ```go
     if math.IsNaN(ev.CompositeScore) || ev.CompositeScore <= 0 {
         return 0.0
     }
     ```
3. In `internal/client/balancer.go`:
   - In `calculateConnectionScoreLocked`:
     ```go
     if math.IsNaN(ev.CompositeScore) || ev.CompositeScore <= 0 {
         return 1.0
     }
     ```
4. Verify by running:
   - `go test -v ./internal/client -run "TestScore.*"` (ensure `TestScore_Adversarial_BurstScoreNaNPropagation` and all other score tests PASS)
   - `go test ./internal/client`
   - `go build ./cmd/client` and `go build ./cmd/server`
   - `git diff -- go.mod go.sum` (must be empty)

## Deliverables
Write handoff to `c:\Dev\Projects\DNStunnel\.agents\teamwork\worker_m1_iter2\handoff.md` and notify orchestrator.


## 2026-10-31T17:12:08Z
You are teamwork_worker instance 2 (worker_m1_iter2).
Your working directory: c:\Dev\Projects\DNStunnel\.agents\teamwork\worker_m1_iter2.
Your instructions are in c:\Dev\Projects\DNStunnel\.agents\teamwork\worker_m1_iter2\DISPATCH.md.
Also read the authoritative user request at c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Remediate the IEEE 754 NaN/Inf sanitization defect in score.go, FormatResolverSpeed, micro_burst.go, and balancer.go.
Verify that TestScore_Adversarial_BurstScoreNaNPropagation and all internal/client tests pass cleanly.
Write your handoff to c:\Dev\Projects\DNStunnel\.agents\teamwork\worker_m1_iter2\handoff.md.
When finished, notify the orchestrator via send_message.
