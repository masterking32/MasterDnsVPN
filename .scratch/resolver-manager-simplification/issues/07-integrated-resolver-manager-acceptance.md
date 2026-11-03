# 07: Verify and document the complete Resolver manager lifecycle

**What to build:** Provide a reproducible acceptance scenario demonstrating cold startup, live traffic, background discovery, failures, saved ordering, and restart. Give maintainers operational evidence instead of treating test volume or short-burst scores as proof of real application performance.

**Blocked by:** 04 — Route by the common Resolver ranking by default while preserving explicit strategies; 05 — Finish bounded background discovery after FastStart readiness; 06 — Batch ranked Resolver saves through one background writer.

**Status:** resolved

This follows [PR #205](https://github.com/masterking32/MasterDnsVPN/pull/205). Produce implementation documentation and validation evidence without modifying or closing existing parent issues or the upstream PR.

## Acceptance criteria

- [x] Supply a deterministic local scenario with multiple Resolver endpoints/domains, healthy/delayed/lossy/nonresponsive behavior, and real tunnel traffic through a local Server and destination.
- [x] Demonstrate readiness before all candidates complete, continued initial coverage during traffic, capacity/endpoint coverage invariants, common-margin recovery, and no promotion of Checking, Rejected, or Untested candidates.
- [x] Demonstrate consistent common scores across comparisons, diagnostics, and default selection using equivalent observation snapshots. Explicit legacy traffic policies retain documented behavior.
- [x] Demonstrate background query/concurrency bounds, fair progress, batched saved ordering, and qualification after restart. Include save failure and graceful cancellation.
- [x] Record readiness time separately from initial coverage completion, foreground throughput/latency, background query volume/rate, optional replacement count, and ranking-file write count. Distinguish measured results from estimates and local evidence from public-network performance claims.
- [x] Provide an opt-in procedure comparing the pre-change baseline and completed implementation against a fixed real-network Resolver list. Actual public-network benchmarking needs a suitable environment and is optional; variable Internet results are not mandatory CI gates. Do not assert an unverified universal 1–2 second startup guarantee.
- [x] Update user/contributor documentation for path versus endpoint counts, five states, common ranking versus explicit traffic alternatives, universal pool rules, readiness versus initial coverage, persistence, and defaults. Correct outdated claims coupling maintenance scheduling to statistics-print intervals.
- [x] Document final module responsibilities and the small interfaces callers need. Remove any remaining superseded migration scaffolding, duplicate policy paths, and unused mutable eligibility flags after all consumers migrate, while preserving compatibility required by existing user configurations.
- [x] Run the complete Go test suite and build both applications. Run targeted race-detector checks for lifecycle, admission, cancellation, and persistence when the platform/toolchain supports them; record actual environment limitations instead of claiming checks that did not run.

## Answer

Completed integrated acceptance verification and architectural documentation:
1. Created deterministic local end-to-end acceptance tests in `internal/client/resolver_manager_acceptance_test.go` (`TestIntegratedResolverManagerAcceptance` and `TestIntegratedResolverManager_DiagnosticsAudit`).
   - Exercised 4 diverse resolver endpoints (Fast, Delayed, 50% Lossy, Nonresponsive blackhole) across 2 tunnel domains (8 candidate Tunnel Paths).
   - Validated early FastStart readiness (measured independently from coverage) with distinct qualified endpoints before initial coverage completion.
   - Validated background discovery continuing to 100% first-pass coverage (measured from the same startup origin) without candidate starvation.
   - Validated mutual exclusivity invariant: only `StateActive` candidates carry traffic; `StateChecking`, `StateStandby`, `StateRejected`, and `StateUntested` candidates never carry traffic.
   - Validated failover and replacement under common-margin pool policy.
   - Validated batched ranking persistence writer, atomic file update, and seamless reload on client restart.
2. Created comprehensive architectural documentation in `docs/resolver-manager.md`:
   - Module boundaries, responsibilities, and seams (`ResolverPool`, `Score`, `Balancer`, `DiscoveryEngine`, `BackgroundQueryLimiter`, `RankedPersistenceWriter`).
   - Path vs Endpoint count semantics.
   - Authoritative 5 lifecycle states and derived compatibility views.
   - Decoupled maintenance scheduling (adaptive health poll intervals independent of runtime stats print intervals).
   - Opt-in real-network benchmarking procedure with fixed resolver lists, noting public network variability.
3. Successfully built both applications (`cmd/client` and `cmd/server`).
4. Documented toolchain environment status regarding `go test -race` (Windows host without CGO/mingw toolchain requires running race detector in Linux CI).
5. Ran full test suite across all 27 packages; all passed cleanly with 0 failures.

## Review follow-up

Replaced the simulated traffic phase with a real local Server runtime, four forwarding Resolver proxies across two domains, a Client Session/TCP runtime, and an echo destination. The production health loop reaches initial coverage during verified payload round trips. Restart reloads the saved file, begins with zero Active Paths and completed attempts, then sends fresh qualification queries. Virtual-time writer tests cover coalescing, retries, and shutdown with blocked storage. Timing logs describe the current run; earlier 134 ms / 745 ms figures came from the former probe-only scenario and are not evidence for tunnel traffic performance.
