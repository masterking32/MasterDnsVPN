# Task Assignment: Survey R3 & R5 (Discovery & FastStart Engine, Tests, Invariants)

You are teamwork_spec_miner instance 3.
Your working directory: c:\Dev\Projects\DNStunnel\.agents\teamwork\spec_miner_survey_3

## Objective
Read `c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md` and survey the codebase for:
1. R3: Deep Discovery & FastStart Engine
   - Investigate `internal/client/mtu.go`, `client.go`, and existing discovery/MTU probing mechanisms.
   - Define the `ResolverProber` interface (`ProbeMTU` and `ProbeBurst`), `DiscoveryConfig`, and `DiscoveryEngine` in `internal/client/resolver_discovery.go`.
   - Specify worker pool parallelism, candidate batching, context cancellation on FastStart target quota fulfillment, and batch admission into `ResolverPool`.
   - Design `prober_udp.go` implementing `ResolverProber` using live UDP queries.
   - Design `FakeResolverProber` in `internal/client/resolver_discovery_test.go` for deterministic in-memory testing of FastStart early exit and replenishment.
   - Map refactoring of `internal/client/mtu.go` so `RunInitialMTUTests` delegates orchestration to `DiscoveryEngine.Run(ctx)`, stripping discovery loops, worker channels, and batch context cancellation from `mtu.go`.
2. Existing test suites:
   - Investigate `TestRunInitialMTUTests.*`, `TestEmpirical.*`, and client package tests.
   - Note any test breakage or migration requirements.
3. R5 Invariants & Domain Vocabulary:
   - Check `CONTEXT.md` for domain vocabulary (Resolver, Resolver Pool, Active Resolver, Standby Resolver, Session, Client, Tunnel, MLQ).
   - Verify scope boundaries (no edits to `cmd/` or `internal/` outside `internal/client/` and `internal/config/`, `go.mod`/`go.sum` immutable).

## Deliverables
Write your comprehensive investigation report to:
`c:\Dev\Projects\DNStunnel\.agents\teamwork\spec_miner_survey_3\report.md`
and deliver your handoff via `c:\Dev\Projects\DNStunnel\.agents\teamwork\spec_miner_survey_3\handoff.md`.
Then send a completion message back to the orchestrator.

## 2026-10-31T16:35:10Z
[Message] timestamp=2026-10-31T16:35:10Z sender=8a518c3b-4b52-4082-8487-66e423f24169 priority=MESSAGE_PRIORITY_HIGH content=You are teamwork_spec_miner instance 3.
Your working directory is c:\Dev\Projects\DNStunnel\.agents\teamwork\spec_miner_survey_3.
Your instructions are in c:\Dev\Projects\DNStunnel\.agents\teamwork\spec_miner_survey_3\DISPATCH.md.
Also read the authoritative user request at c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md.

Perform a thorough investigation of R3 (Discovery & FastStart Engine), test suites, and R5 (Invariants & CONTEXT.md domain vocabulary).
Analyze internal/client/mtu.go, existing tests (TestRunInitialMTUTests, TestEmpirical), and requirements for ResolverProber, DiscoveryConfig, DiscoveryEngine, prober_udp.go, and FakeResolverProber.
Write your detailed technical report to c:\Dev\Projects\DNStunnel\.agents\teamwork\spec_miner_survey_3\report.md.
Write your handoff to c:\Dev\Projects\DNStunnel\.agents\teamwork\spec_miner_survey_3\handoff.md.
When finished, notify the orchestrator via send_message.
