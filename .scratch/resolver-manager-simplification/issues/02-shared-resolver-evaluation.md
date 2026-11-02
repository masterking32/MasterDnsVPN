# 02: Use one Resolver evaluation for ranking and diagnostics

**What to build:** Give startup ranking, Resolver Pool comparisons, saved endpoint ordering, and runtime diagnostics the same explanation of candidate quality. The same measurements produce the same score regardless of caller. Diagnostics distinguish measured burst throughput from packet-size/response-time estimates.

**Blocked by:** None (can start immediately).

**Status:** resolved

This follows [PR #205](https://github.com/masterking32/MasterDnsVPN/pull/205). Candidates are Resolver/domain pairings; saved rankings contain distinct Resolver endpoints.

## Acceptance criteria

- [x] Expose a common immutable evaluation snapshot containing upload/download MTU, response time, loss, throughput, measurement source, measurement time, and relevant sample counts. Distinguish unavailable data from measured zero values.
- [x] Keep eligibility separate from numerical quality: a high score cannot override failed qualification or Session MTU incompatibility.
- [x] Centralize input selection as well as score calculation. Retain the existing composite formula and quality-tier thresholds; do not introduce a new collection of arbitrary metric weights.
- [x] Use valid measured burst throughput when available, otherwise the existing download-MTU/response-time throughput estimate. Use available live response-time/loss observations with documented fallback to qualification measurements. Record the sources and ages of the values used. Missing, nonfinite, or invalid measurements never silently mean a perfect pairing.
- [x] Startup ranking, pool comparison, saved ranking, and displayed score consume the same evaluation for the same snapshot. Later measurements may change the score; caller identity cannot.
- [x] Remove the artificial Active Resolver numerical bonus from the exported quality score. If saved ordering deliberately prioritizes Active over Standby membership, implement and document that ordering separately rather than altering quality scores.
- [x] Runtime output labels estimated versus measured throughput and the sample-based nature of counters. Neither is presented as measured application download speed.
- [x] Saved rankings deduplicate endpoints deterministically, using the best eligible pairing for each endpoint under the documented ordering. Configured endpoint authority and managed-block parsing remain intact.
- [x] Existing explicitly selected traffic strategies retain their behavior in this ticket. Common-score default traffic selection is a separate dependent ticket.
- [x] Tests pass controlled snapshots through startup ranking, pool comparison, saved ordering, and diagnostic formatting and assert consistent scores and evidence sources. Cover measured/estimated fallback, unavailable data, full loss, invalid numeric input, and deterministic ties.
- [x] Update scoring descriptions to distinguish shared ranking, throughput estimates, and optional traffic policies.

## Answer

Implemented shared evaluation and diagnostic snapshot consistency:
1. Introduced `MeasurementSource`, `CandidateObservationInput`, and `ResolverEvaluationSnapshot` in `score.go`.
2. Created `EvaluateCandidateObservation` as the centralized authority for input selection and score calculation across all callers.
3. Distinguishes empirical micro-burst measured throughput from MTU/RTT estimated throughput, labeling estimated throughput in runtime diagnostics.
4. Bound full loss (100% loss -> score 0.0) and sanitized all nonfinite (NaN/Inf) metrics.
5. Removed artificial `+1000.0` boost from candidate scores. In `RankedEndpoints`, Active candidates are prioritized over Standby in the sort comparator rather than distorting quality scores.
6. Implemented deterministic endpoint deduplication and tie-breaking.
7. Added unit tests in `score_shared_evaluation_test.go` verifying consistent scores across pool comparison, runtime stats, and direct evaluation. All existing score suites remain green.
