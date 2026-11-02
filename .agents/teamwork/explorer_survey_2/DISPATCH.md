# Task Assignment: Survey R2 (Deep Resolver Pool Module & Balancer Refactor)

You are teamwork_explorer instance 2.
Your working directory: c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_2

## Objective
Read `c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md` and survey the codebase for:
1. R2: Deep Resolver Pool Module
   - Investigate `internal/client/balancer_admission.go`, `balancer_admission_test.go`, and `balancer.go`.
   - Map candidate state transitions across the 3-state finite state machine (StateInactive, StateActive, StateStandby, StateRechecking).
   - Document capacity bounding, admission, and active pool optimization.
   - Detail the required methods for `internal/client/resolver_pool.go`: `NewResolverPool`, `SetSessionMTU`, `ActiveResolvers`, `AllConnections`, `ActiveCount`, `TotalCount`, `AdmitStartupBatch`, `FinalizeFastStart`, `AcquireNextInactiveForRecheck`, `ReleaseRecheck`, `Optimize`, `RankedEndpoints`, `SetOnPoolChanged`.
   - Analyze how `internal/client/balancer.go` will be refactored: retaining packet dispatching (`SelectTargets`, `ReportSuccess`, `ReportTimeout`, `RetractTimeout`, `TotalPacketsSent`, and in-flight sample tracking) while removing pool management fields and consuming active resolvers directly from `ResolverPool`.
   - Check all call sites of balancer admission in `client.go`, `balancer.go`, and tests.
2. Absorption & Deletion of `balancer_admission.go` and `balancer_admission_test.go`.
3. Plan tests for `internal/client/resolver_pool_test.go`.

## Deliverables
Write your comprehensive investigation report to:
`c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_2\report.md`
and deliver your handoff via `c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_2\handoff.md`.
Then send a completion message back to the orchestrator.


## 2026-10-31T16:35:05Z
You are teamwork_explorer instance 2.
Your working directory is c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_2.
Your instructions are in c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_2\DISPATCH.md.
Also read the authoritative user request at c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md.

Perform a thorough investigation of R2 (Deep Resolver Pool Module & Balancer Refactor).
Map existing balancer_admission.go, balancer_admission_test.go, balancer.go, and client.go.
Detail the FSM transitions (StateInactive, StateActive, StateStandby, StateRechecking), pool capacity, admission, and optimization.
Map all required methods for internal/client/resolver_pool.go and refactoring of balancer.go.
Write your detailed technical report to c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_2\report.md.
Write your handoff to c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_2\handoff.md.
When finished, notify the orchestrator via send_message.
