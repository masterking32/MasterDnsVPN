# 04: Route by the common Resolver ranking by default while preserving explicit strategies

**What to build:** Make default Client traffic selection use the Resolver evaluation shown in diagnostics and used for pool quality comparisons. Users explicitly selecting round robin, lowest latency, least loss, loss then latency, or another supported strategy retain that deliberate policy.

**Blocked by:** 02 — Use one Resolver evaluation for ranking and diagnostics.

**Status:** resolved

This follows [PR #205](https://github.com/masterking32/MasterDnsVPN/pull/205). The pool supplies Active Resolvers; the Balancer selects traffic destinations among them.

## Acceptance criteria

- [x] Provide a clearly named common-score traffic strategy and use it when configuration omits an explicit strategy. Do not repurpose existing strategy identifiers or change meanings of explicitly selected strategies, including loss then latency.
- [x] Configuration loading, validation, command-line overrides, sample configurations, startup output, and documentation agree on the default and explicit-strategy compatibility behavior.
- [x] The default selects eligible Active Resolvers using the common ranking, rotating deterministically among equally ranked candidates rather than introducing an accidental insertion-order preference.
- [x] Preserve existing per-Stream preferred routing and failover where applicable. Ranking does not bypass a deliberate preferred pairing until routing/failover rules require reselection.
- [x] Preserve requested Duplication counts when enough distinct endpoints exist. Select additional endpoints under the chosen policy without treating several domains on one endpoint as independent duplicated routes.
- [x] Explicit alternatives operate on the pool's Active Resolvers and do not introduce separate admission, qualification, scoring, or persistence implementations.
- [x] Controlled traffic tests demonstrate the default favoring higher common scores and explicit alternatives retaining their documented behavior. Cover ties, Stream preference, failover, insufficient distinct endpoints for Duplication, and multiple domains on one endpoint.
- [x] Release-facing documentation identifies the observable default change and explains why routing requirements can select a candidate other than the highest-scoring one.

## Answer

### Implementation Summary
1. **Named Common-Score Strategy**:
   - Introduced `BalancingCommonScore = 9` (aliased as `BalancingDefault`) in `internal/client/balancer.go`.
   - Updated `DefaultClientConfig()` in `internal/config/client.go` to set `ResolverBalancingStrategy: 9` when omitted.
   - Updated configuration validation to accept `0..9` and reject out-of-range strategies.
   - Updated CLI flag binder, sample configs (`client_config.toml.simple`), startup summary (`client_utils.go`), and README documentation.
   - Explicit strategy identifiers `0..8` (including `6` = Loss Then Latency) are completely preserved without changing their meanings.

2. **Deterministic Tie-Breaking & Score Ranking**:
   - In `BalancingCommonScore`, candidates are ordered by common composite evaluation scores computed via `pool.CalculateConnectionScore(key)`.
   - Before stable sorting, candidates are rotated by `b.rrCounter`. Equal scores preserve rotated order, ensuring deterministic round-robin alternation across calls with no insertion-order bias.

3. **Duplication & Distinct-Endpoint Preservation**:
   - Implemented `filterDistinctEndpoints` across all duplication selection paths (`selectRoundRobinLocked`, `selectRandomLocked`, `selectLowestScoreLocked`, `limitConnectionPoolLocked`, and `selectCommonScoreLocked`).
   - When sufficient distinct endpoints exist, packet duplication selects candidates across distinct endpoints, preventing multiple domains on one endpoint from being treated as independent duplicated routes.
   - When insufficient distinct endpoints exist, duplication yields only the available distinct endpoints.
   - Multi-path stream routing (`getUniqueConnectionsExcludingLocked`) excludes the preferred endpoint from secondary routes when distinct endpoints exist.

4. **Per-Stream Preferred Routing & Failover**:
   - Per-stream sticky routing preserves the established preferred candidate across subsequent stream data packets.
   - Failover reselection triggers when resend streak reaches the configured threshold and cooldown elapses, selecting the highest-scoring alternate candidate.

### Validation
- Created comprehensive unit test suite in `internal/client/balancer_common_score_test.go`:
  - `TestBalancerDefaultCommonScore_FavorsHigherScore`
  - `TestBalancerCommonScore_DeterministicTieRotation`
  - `TestBalancerCommonScore_StreamPreferencePreserved`
  - `TestBalancerCommonScore_FailoverReselection`
  - `TestBalancerCommonScore_DuplicationDistinctEndpoints`
  - `TestBalancerCommonScore_InsufficientDistinctEndpoints`
  - `TestBalancerExplicitStrategies_DocumentedBehaviorPreserved`
- Added configuration loading and override tests in `internal/config/client_test.go`:
  - `TestLoadClientConfigResolverBalancingStrategyDefaultAndExplicit`
  - `TestLoadClientConfigRejectsInvalidResolverBalancingStrategy`
- Verified all client and balancer test suites pass cleanly.
