# Task Assignment: Survey R1 & R4 (Resolver Evaluation & Maintenance Cleanup)

You are teamwork_explorer instance 1.
Your working directory: c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_1

## Objective
Read `c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md` and survey the codebase for:
1. R1: Consolidated Resolver Evaluation in `internal/client/score.go`
   - Investigate all evaluation, score calculation, latency penalty, loss handling, and tier badge generation currently in `score.go`, `micro_burst.go`, `balancer.go`, and `runtime_stats.go`.
   - Detail existing formulas, weights, types, and mutex usages.
   - Specify the exact design for `ResolverMetrics` and `ResolverEvaluation`, and `EvaluateResolver(m ResolverMetrics) ResolverEvaluation`.
   - List all call sites to update.
2. R4: Event-Driven Persistence & Maintenance Cleanup
   - Investigate `internal/client/resolver_maintenance.go`, `resolver_maintenance_test.go`, `client.go` (`resolverMaintenanceStarted`), `client_utils.go`, and `runtime_stats.go`.
   - Detail how `SaveRankedResolversToFile` works, what calls it, and how it should hook into `pool.SetOnPoolChanged(...)` and `pool.RankedEndpoints(50)`.
3. Check existing tests touching score, evaluation, and maintenance.

## Deliverables
Write your comprehensive investigation report to:
`c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_1\report.md`
and deliver your handoff via `c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_1\handoff.md`.
Then send a completion message back to the orchestrator.


## 2026-10-31T16:35:01Z
[Message] timestamp=2026-10-31T16:35:01Z sender=8a518c3b-4b52-4082-8487-66e423f24169 priority=MESSAGE_PRIORITY_HIGH content=You are teamwork_explorer instance 1.
Your working directory is c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_1.
Your instructions are in c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_1\DISPATCH.md.
Also read the authoritative user request at c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md.

Perform a thorough investigation of R1 (Consolidated Resolver Evaluation) and R4 (Event-Driven Persistence & Maintenance Cleanup).
Map all existing implementations in score.go, micro_burst.go, balancer.go, runtime_stats.go, resolver_maintenance.go, client.go, and client_utils.go.
Write your detailed technical report to c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_1\report.md.
Write your handoff to c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_1\handoff.md.
When finished, notify the orchestrator via send_message.
