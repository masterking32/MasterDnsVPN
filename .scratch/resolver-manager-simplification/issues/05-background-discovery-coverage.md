# 05: Finish bounded background discovery after FastStart readiness

**What to build:** Initialize the Client Session as soon as enough qualified endpoints are ready, while discovery continues until every configured Tunnel Path has received a bounded initial qualification attempt. Maintain the pool afterward without allowing probes to dominate traffic or repeated checks to starve untested candidates.

**Blocked by:** 03 — Apply one pool admission and replacement policy throughout the Client lifecycle.

**Status:** resolved

This follows [PR #205](https://github.com/masterking32/MasterDnsVPN/pull/205). FastStart ends the foreground wait, not discovery. Reuse existing discovery/health machinery rather than introducing a competing maintenance loop.

## Acceptance criteria

- [x] Readiness counts distinct qualified endpoints under the configured worker and active-path limits. Exhausting candidates below the target can still permit startup when at least one usable Active Resolver remains; zero usable paths preserve failure/retry behavior.
- [x] Readiness permits Session initialization and traffic runtime startup before first-pass coverage completes. Remaining configured paths continue being tested in the background.
- [x] Every configured path eventually receives a completed bounded attempt during a continuing healthy Client run; a timeout or explicit rejection is an outcome. Cancelled work is rescheduled, not falsely counted as completed. Failed endpoints cannot hold initial completion open forever.
- [x] Track readiness separately from cumulative initial coverage. Diagnostics show configured paths, completed initial attempts, remaining untested paths, and distinct qualified endpoints. Current qualification/state is separate from initial-attempt history.
- [x] Background qualification verifies the current Session's packet sizes plus the enabled recovery burst. It need not search each path's maximum MTU or renegotiate Session MTU to admit it.
- [x] Bound actual background DNS query starts and concurrent probes. Query limits include MTU retries and burst queries, not just candidate launches. Use a monotonic, cancellation-aware limiter and document a conservative default and its scope. Do not unintentionally throttle foreground tunnel traffic or startup probing through the background budget.
- [x] When the working set is sufficient, prioritize untested first-pass work over repeated rejected/standby refreshes. When insufficient, prioritize finding/promoting usable candidates within the same budget. Fair scheduling prevents recovery attempts from indefinitely starving untested candidates.
- [x] After initial coverage, retry Rejected candidates with capped backoff and periodically refresh Standby Resolvers. Reuse suitable timing configuration, avoid an unbounded set of new options, and reset backoff after successful recovery.
- [x] All membership decisions use the common pool policy. Session requirement changes during checks cannot admit incompatible paths.
- [x] Preserve the switch: disabling inactive rechecking performs the full initial startup scan and disables continuing background inactive discovery. Other resolver-management features retain independent configuration.
- [x] Tests using controlled probes, time, and packet accounting demonstrate early readiness, eventual full initial coverage, query-rate/concurrency bounds, recovery priority without starvation, backoff, cancellation, and progress during tunnel traffic. Avoid public DNS dependencies and long wall-clock sleeps.

## Answer

Implemented bounded background discovery and coverage tracking:
1. Created monotonic, cancellation-aware `BackgroundQueryLimiter` (default 15 QPS) bounding all background probe starts, retries, and burst query trains without throttling foreground tunnel traffic or startup probing.
2. In `ResolverPool`, tracked `initialAttemptDone` and `failStreak` per candidate. Outcomes (success or failure/timeout) mark initial attempts done; context cancellations release the lease without marking complete, allowing rescheduling.
3. Added `CoverageStats()` reporting configured paths, completed initial attempts, remaining untested paths, and distinct qualified endpoints, integrated into `DumpRuntimeStats`.
4. Prioritized untested first-pass work when active pool meets target, and applied fair 1:1 scheduling between untested and recovery candidates when active pool is insufficient.
5. Applied exponential backoff (capped at 5 minutes) to `StateRejected` candidates, resetting to 0 on recovery.
6. Preserved `RecheckInactiveServersEnabled` switch for disabling background rechecking and doing full initial startup scan.
7. Verified with comprehensive unit test suite in `internal/client/discovery_coverage_test.go`.
