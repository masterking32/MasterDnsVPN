# Dispatch Task: Milestone 3 Investigation (explorer_m3_2)

## 2026-10-31T18:25:00Z
- **Assigned Explorer**: explorer_m3_2
- **Working Directory**: `c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_m3_2\`
- **Parent Conversation ID**: `8a518c3b-4b52-4082-8487-66e423f24169`

## Mandatory Files to Read First
1. `c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md` (authoritative specification, R3)
2. `c:\Dev\Projects\DNStunnel\.agents\teamwork\orchestrator\PROJECT.md` (architecture, Feature Inventory, interface contracts)
3. `c:\Dev\Projects\DNStunnel\.agents\teamwork\spec_miner_survey_3\report.md` (detailed R3 architectural survey)
4. `internal/client/resolver_pool.go` (completed M2 ResolverPool API)

## Scope & Investigation Objective
Investigate `DiscoveryEngine` internal concurrency, batching, context cancellation, and `ResolverPool` integration:
1. Examine `DiscoveryConfig` and `DiscoveryEngine` struct definitions.
2. Detail the 8-phase lifecycle of `DiscoveryEngine.Run(ctx)`:
   - Phase 1: Candidate Enumeration & Quota
   - Phase 2: Candidate Batching Loop
   - Phase 3: Parallel Worker Pool Probing & Early Context Cancellation (`cancelBatch()`)
   - Phase 4: Micro-Burst Qualification (using `score.EvaluateResolver`)
   - Phase 5: Batch Admission into `pool.AdmitStartupBatch`
   - Phase 6: Candidate Replenishment Loop if quota < target
   - Phase 7: FastStart Finalization (`pool.FinalizeFastStart`)
   - Phase 8: MTU Optimization (`pool.Optimize()`)
3. Detail how context cancellation (both parent `ctx` and batch-level `cancelBatch()`) works cleanly without goroutine leaks.
4. Produce a structured implementation roadmap with concrete code design for `internal/client/resolver_discovery.go`.

## Output
Write report to `c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_m3_2\report.md` with:
- Observation (architecture, state flow, concurrency model)
- Logic Chain (exact method definitions, mutex usage, channel lifecycle)
- Caveats
- Conclusion & concrete recommendations for the Worker
Notify orchestrator via `send_message`.
