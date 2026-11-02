# Dispatch Task: Milestone 3 Specification Mining (spec_miner_m3_3)

## 2026-10-31T18:25:00Z
- **Assigned Spec Miner**: spec_miner_m3_3
- **Working Directory**: `c:\Dev\Projects\DNStunnel\.agents\teamwork\spec_miner_m3_3\`
- **Parent Conversation ID**: `8a518c3b-4b52-4082-8487-66e423f24169`

## Mandatory Files to Read First
1. `c:\Dev\Projects\DNStunnel\.agents\teamwork\ORIGINAL_REQUEST.md` (authoritative specification, R3)
2. `c:\Dev\Projects\DNStunnel\.agents\teamwork\orchestrator\PROJECT.md` (architecture, Feature Inventory, interface contracts)
3. `c:\Dev\Projects\DNStunnel\.agents\teamwork\spec_miner_survey_3\report.md` (detailed R3 architectural survey)
4. `internal/client/micro_burst.go` (`BurstProbeResult`, `probeConnectionMicroBurst`)

## Scope & Investigation Objective
Investigate and specify the `ResolverProber` interface, concrete UDP prober, and in-memory test prober:
1. Specify `ResolverProber` interface methods:
   - `ProbeMTU(ctx context.Context, conn Connection, maxUploadPayload int) (MTUProbeResult, error)`
   - `ProbeBurst(ctx context.Context, conn Connection, packetCount int, downloadMTU int, uploadMTU int, timeout time.Duration) BurstProbeResult`
2. Specify concrete `UDPResolverProber` in `internal/client/prober_udp.go`:
   - Wrapping `*Client` methods `probeConnectionMTU` and `probeConnectionMicroBurst`.
   - Handling context cancellation (`context.AfterFunc` or `ctx.Err() != nil`).
3. Specify `FakeResolverProber` and comprehensive unit test suite in `internal/client/resolver_discovery_test.go`:
   - Fast deterministic in-memory tests (no OS UDP sockets needed).
   - Test cases: FastStart early exit, candidate replenishment on burst failure, worker cancellation, quota calculation, batch admission, and pool overflow.
4. Produce exact type definitions, method signatures, error handling contracts, and test cases.

## Output
Write report to `c:\Dev\Projects\DNStunnel\.agents\teamwork\spec_miner_m3_3\report.md` with:
- Observation (interface requirements, contract definitions)
- Logic Chain (UDP adapter design, fake prober design, test matrix)
- Caveats
- Conclusion & concrete recommendations for the Worker
Notify orchestrator via `send_message`.

## 2026-10-31T18:25:43Z
You are spec_miner_m3_3. Your working directory is c:\Dev\Projects\DNStunnel\.agents\teamwork\spec_miner_m3_3\.
Read DISPATCH.md in your working directory, ORIGINAL_REQUEST.md, PROJECT.md, spec_miner_survey_3/report.md, and internal/client/micro_burst.go.
Specify the ResolverProber interface, concrete UDPResolverProber in internal/client/prober_udp.go, and deterministic FakeResolverProber test suite in internal/client/resolver_discovery_test.go. Provide exact method signatures, error contracts, and unit test designs.
Write your report to c:\Dev\Projects\DNStunnel\.agents\teamwork\spec_miner_m3_3\report.md and notify the orchestrator via send_message.
