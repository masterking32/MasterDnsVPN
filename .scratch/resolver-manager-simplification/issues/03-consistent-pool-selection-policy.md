# 03: Apply one pool admission and replacement policy throughout the Client lifecycle

**What to build:** Make startup admission, background recovery, vacancy filling, and ongoing optimization follow one Resolver Pool policy. Promotions repair eligibility, capacity, or endpoint coverage, or make sufficiently valuable performance improvements. Different execution paths no longer apply different optional replacement thresholds.

**Blocked by:** 01 — Make Resolver Pool candidate state authoritative; 02 — Use one Resolver evaluation for ranking and diagnostics.

**Status:** resolved

This follows [PR #205](https://github.com/masterking32/MasterDnsVPN/pull/205). Pool capacity counts Active Paths; endpoint coverage counts distinct Resolver addresses and ports.

## Acceptance criteria

- [x] Centralize the complete policy in the Resolver Pool. Discovery and recovery submit observations and request reconciliation instead of independently choosing winners or applying alternative replacement thresholds.
- [x] Apply these priorities: exclude unqualified or Session-incompatible candidates; fill vacancies from eligible candidates; establish required distinct-endpoint coverage when eligible candidates permit it; then consider optional performance replacements.
- [x] Use the FastStart endpoint target as the continuing minimum coverage goal: configured endpoint count limited by max(1, RX_TX_WORKERS), and by a positive active-path capacity. Too few qualified endpoints reduce achievable coverage rather than invalidate an otherwise usable pool. Capacity 0 retains its unlimited meaning.
- [x] Coverage is a continuing requirement, not a startup-only override. A qualified unrepresented endpoint may displace a duplicate endpoint path to repair missing coverage. Once coverage is satisfied, a slower endpoint is not admitted merely because it is distinct. Optional swaps do not break achievable minimum coverage.
- [x] Apply one margin to every optional replacement, including direct recovery admission: the incoming common score must be strictly greater than 1.25 times the displaced score. Vacancies, invalidation, and required coverage repair do not require that margin. Equal scores and exactly 25% improvement do not cause optional churn.
- [x] Use deterministic, stable tie handling. Concurrent completions never exceed active-path capacity, and Checking candidates are never promoted.
- [x] Reevaluate current Session compatibility before committing membership. Only qualified displaced candidates become Standby; failures do not become qualified reserves.
- [x] Startup and recovery using the same eligibility, observations, capacity, and coverage requirements produce equivalent decisions. No startup-mode switch changes admission or replacement policy; readiness is handled separately.
- [x] Logs identify vacancy filling, eligibility failure, endpoint coverage repair, or performance improvement as the actual decision reason. Comparisons use the common evaluation.
- [x] Tests cover duplicate endpoints across domains, slow distinct endpoints before/after coverage is met, recovery into full pools, margin boundaries including zero scores, vacancies, insufficient endpoints, unlimited capacity, and concurrent admissions. Keep existing tests green.

## Answer

Implemented unified pool admission and replacement policy:
1. Centralized selection priorities in `ResolverPool`:
   - Priority 1: Exclude unqualified or Session-incompatible candidates.
   - Priority 2: Fill vacancies from eligible Standbys without margin requirement.
   - Priority 3: Repair missing distinct-endpoint coverage by displacing duplicate endpoint paths.
   - Priority 4: Optional performance replacements strictly requiring incoming score > 1.25x displaced score.
2. Added `SetTargetEndpoints` to `ResolverPool` maintaining continuing coverage invariants.
3. Ensured that once coverage is satisfied, slower endpoints are not admitted merely for diversity, and performance swaps cannot break achievable coverage.
4. Structured structured log messages specifying the exact decision reason (`Vacancy Filling`, `Endpoint Coverage Repair`, `Performance Improvement`).
5. Added comprehensive behavioral tests in `internal/client/resolver_pool_policy_test.go` and verified all existing pool test suites pass.
