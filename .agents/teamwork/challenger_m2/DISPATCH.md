# Task Assignment: Adversarial Challenge — Milestone 2 (Deep Resolver Pool Module)

You are teamwork_challenger.
Your working directory: c:\Dev\Projects\DNStunnel\.agents\teamwork\challenger_m2

## Context & Inputs
- Authoritative request: `c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md` (R2)
- Project scope & contracts: `c:\Dev\Projects\DNStunnel\.agents\teamwork\orchestrator\PROJECT.md`
- Worker handoff: `c:\Dev\Projects\DNStunnel\.agents\teamwork\worker_m2\handoff.md`

## Mission
Adversarially challenge Milestone 2:
1. Verify candidate state invariants:
   - Concurrently execute `Optimize()` and `AcquireNextInactiveForRecheck` (stress test for race conditions).
   - Verify `IsValid != StandbyEligible` is never violated.
2. Stress test capacity bounding:
   - Overflow active pool beyond `maxActive`.
   - Verify degradation swap hysteresis (>1.25x).
   - Test session MTU compliance under optimization.
3. Verify event-driven persistence callback `SetOnPoolChanged` deadlock freedom under concurrent calls.
4. Run all empirical stress suites: `go test -v ./internal/client -run "TestEmpirical.*"`.

## Deliverables
Write handoff to `c:\Dev\Projects\DNStunnel\.agents\teamwork\challenger_m2\handoff.md` with verdict (APPROVE or REQUEST_CHANGES).

## 2026-10-31T17:57:49Z
You are teamwork_challenger instance 4 (challenger_m2).
Your working directory: c:\Dev\Projects\DNStunnel\.agents\teamwork\challenger_m2.
Your instructions are in c:\Dev\Projects\DNStunnel\.agents\teamwork\challenger_m2\DISPATCH.md.
Also read the authoritative user request at c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md.

Adversarially challenge Milestone 2 (Deep Resolver Pool Module).
Stress test candidate FSM invariants (IsValid != StandbyEligible), recheck revocation under high concurrency, capacity bounding, and deadlock-free callback execution.
Record your verdict (APPROVE or REQUEST_CHANGES) in c:\Dev\Projects\DNStunnel\.agents\teamwork\challenger_m2\handoff.md.
When finished, notify the orchestrator via send_message.

