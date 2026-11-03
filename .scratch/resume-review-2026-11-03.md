# Resolver manager review — 2026-11-03

## Resumed work status

The earlier review findings below are historical evidence. On resumption, the three pool/recovery defects, the measurement provenance/age defect, the cancellation assertion, both documented Standards categories, and the two optional refactoring smells were addressed. The earlier independent Standards/Spec reviews have not been rerun on this updated tree.

- Continuing coverage is installed before first admission and no longer depends on FastStart/full-scan mode.
- FastStart finalization validates qualification and reconciles membership without discarding qualified capacity to enforce a maximum endpoint count.
- Recovery sufficiency counts distinct compatible Active endpoints.
- Evaluation keeps qualification and live samples separate, records per-metric observation timestamps, and uses the same snapshot for pool scoring and diagnostics. Aggregate seeded counters remain available for explicit legacy traffic strategies.
- Strengthened the cancellation assertion to require `errors.Is(err, context.Canceled)`. Cancellation errors carry wrapped operation context; tests use `errors.Is`.
- Added Path terminology for new pool APIs and coverage consumers, retaining exported compatibility aliases. Consolidated replacement bookkeeping and made bundled MTU parameters the commit implementation interface.
- Added regressions for full-scan continuing policy (MTU-only and burst), recovery fairness with duplicate Active Paths, and qualification-to-live provenance/age transitions and diagnostic consistency. Updated old expectations that required finalization to discard usable capacity.
- Focused discovery/pool/scoring/regression checks passed three runs (`8.218s`). Fresh `go test ./...` passed (client `41.020s`); both Client and Server builds and `git diff --check` passed. Temporary build outputs were removed. No fresh race-detector run was performed. The first resumed CodeRabbit pass completed; its verified follow-up fixes and verification pass are recorded below.

## Scope and completed fixes

Branch `feat/fast-start-resolvers`, HEAD `4b3bb3df7331df82206a7f5fae4fad533f34db8a`; merge base `407348244cbb06606b5625f220d5ecd3fa3371a2` against `origin/main`.

Committed comparison: `git diff 407348244cbb06606b5625f220d5ecd3fa3371a2...HEAD`. Reviews also considered the effective working tree against that base and untracked `internal/client/resolver_review_regression_test.go`.

Applied the three fixes identified in the handoff:

- Removed `TestE2E_Tier4_Adversarial_Immutability_ScopeAudit` and its unused imports. Package tests no longer invoke Git to enforce repository edit scope.
- Common-score selection now receives the normalized requested count, including the default of one for zero/negative input.
- `BackgroundQueryLimiter.Acquire` normalizes a nil context to `context.Background()` before waiting.
- Added regression tests for count normalization and nil-context acquisition after token exhaustion.

No commits or external review comments were created. Existing user and earlier-session edits were preserved.

## Historical defect review (review-agent)

### [P2] Keep the continuing endpoint quota independent of startup mode — internal/client/resolver_discovery.go:154

When FastStart is disabled, discovery uses every configured endpoint as its target, and later passes that value into `ResolverPool.Optimize`. With one worker and capacity two, a slow distinct endpoint can therefore replace a fast duplicate path after the worker-bounded minimum coverage is already met. Disabling inactive rechecking should require a full initial scan without changing the continuing pool admission policy. Client configuration translation in `internal/client/mtu.go:363` makes the same coupling.

### [P2] Preserve admitted paths when readiness ends the foreground wait — internal/client/resolver_pool.go:759

`FinalizeFastStart` demotes successfully qualified Active Paths merely because their endpoint count exceeds the readiness target, even when active-path capacity is available. The existing `TestResolverPool_FinalizeFastStart_QuotaAndStandby` demonstrates this with four qualified paths and capacity ten. This leaves usable capacity vacant until later reconciliation, unlike the vacancy-first policy used by recovery.

### [P2] Count distinct Active endpoints before deprioritizing recovery — internal/client/resolver_pool.go:848

`AcquireNextInactiveForRecheck` compares the number of Active Paths with an endpoint target. If endpoint B fails while two domains on A survive, target two is treated as satisfied. Recovery of B is then deferred behind all Untested candidates rather than sharing the budget fairly with them, prolonging loss of endpoint diversity.

Overall: the three handoff fixes passed validation, but the broader branch still has actionable pool-policy and recovery defects. No new race-detector run was performed; earlier race results are recorded in the handoff and are not evidence for this turn's checks.

## Historical Standards

Independent Standards reviewer: **2 documented-standard violation categories; 2 heuristic smells**.

1. **Domain terminology — documented violation.** `AGENTS.md` requires `CONTEXT.md` terminology, which avoids “Pairing”, “Active Resolver”, and “Standby Resolver” for Tunnel Paths. New examples include `StandbyPairings` (`resolver_pool.go:269`), `ConfiguredPairings` (`:1021`), and user-visible “Active Pairing” / “Standby Pairings” logs (`:1500`, `:1553`, `:1568`). Use Path/Paths in new identifiers, comments and logs; retain compatibility aliases where necessary.
2. **Unwrapped propagated errors — documented violation.** `AGENTS.md` requires wrapped errors for actionable call chains. New cancellation paths return raw errors in `background_limiter.go:64`, `:74`, `:87`; `resolver_discovery.go:130`, `:177`, `:303`, `:337`; and `prober_udp.go:40–56`. Add operation context with `%w`, preserving `errors.Is` semantics.
3. **Possible Duplicated Code — judgment call.** `resolver_pool.go:1487–1497` and `:1540–1550` repeat the demote/promote bookkeeping, beginning with `demotedCand.state = StateStandby`. A single locked replacement operation would keep lifecycle/index invariants together.
4. **Possible Data Clumps — judgment call.** `resolver_pool.go:451`, `:612`, `:644` repeatedly pass upload bytes, upload characters, download bytes and resolve time separately. `CandidateMTUParams` already exists, but `CommitCandidateOutcomeWithParams` immediately unpacks it. Consider making the bundled form the implementation interface and retaining primitive wrappers only for compatibility.

No additional actionable Standards findings were reported from the scanned configuration, regression test or skill artifacts. Tool-enforced formatting issues were excluded.

## Historical Spec

Independent Spec reviewer: **4 findings**.

1. **[P2] Inactive-recheck switch changes pool policy.** Ticket 03: “No startup-mode switch changes admission or replacement policy; readiness is handled separately.” `mtu.go:363` and `resolver_discovery.go:154` use all configured endpoints as the coverage target when FastStart is disabled, then pass it into `Optimize`. Calculate the continuing coverage target independently of the full-scan switch.
2. **[P2] Startup finalization bypasses vacancy-first reconciliation.** Ticket 03: “fill vacancies from eligible candidates”; “Startup and recovery … produce equivalent decisions.” `resolver_pool.go:759–774` demotes qualified Active Paths solely because their endpoint count exceeds the readiness target, leaving vacant capacity. Readiness should stop waiting without changing admission policy.
3. **[P2] Duplicate paths falsely make recovery scheduling sufficient.** Ticket 05: “When insufficient, prioritize finding/promoting usable candidates within the same budget.” `resolver_pool.go:848` compares Active path count with the endpoint target. Count distinct compatible Active endpoints when choosing the scheduling branch.
4. **[P2] Measurement provenance and ages remain incomplete.** Ticket 02: “Record the sources and ages of the values used.” Startup/recovery `seedBurst` populates counters subsequently supplied as `LiveRTT`/`LiveSentCount` (`resolver_pool.go:717`, `:1422`), so `score.go:98` labels qualification observations `LiveTraffic` before traffic occurs. `ObservedAt` uses lease-start `LastHealthCheckAt`, including for subsequent live observations. Track provenance and measurement timestamps separately.

No additional scope-creep finding was reported.

Standards: 4 findings (2 violation categories, 2 heuristic smells), worst: domain terminology. Spec: 4 findings, worst: startup-dependent pool policy.

## Validation

- Both new regression tests passed five runs.
- `go test ./...` passed; the client package completed in 39.653 seconds after the nil-context fix (prior session).
- Client and server builds passed with outputs under `.scratch/`; temporary binaries were removed afterward.
- `git diff --check` passed.
- Windows Go emitted a telemetry upload-token permission message; command exit codes and test/build results were successful.

## CodeRabbit status

Trusted canonical executable: `C:\Users\iqlib\AppData\Local\Programs\coderabbit\coderabbit.exe`. Authenticode validation and `auth status --agent` succeeded.

Attempted scope: `review --agent --base-commit 407348244cbb06606b5625f220d5ecd3fa3371a2 --include-untracked --dir internal`. This scope was explicitly disclosed because the earlier whole-repository review exceeded the 150-file limit.

Automatic approval review initially rejected the command before execution because uploading this payload required explicit approval. The user subsequently approved sending the `internal` diff and untracked regression test to CodeRabbit.

The first run completed successfully with `status: review_completed`, 47 reviewed Go files, and one **minor** finding: `DiscoveryEngine.Run` partly checked for nil contexts but passed nil to `context.WithCancel`, which panics. This is a defensive API fix; current production callers supply contexts.

The finding was verified and fixed by normalizing a nil context at entry and removing redundant nil checks within `Run`. Added `TestDiscoveryEngine_NilContext`, exercising both MTU-only and MTU-plus-burst discovery. This test and selected cancellation/count/limiter regressions passed five runs. The second CodeRabbit review completed successfully with `status: review_completed`, 47 Go files, and one **minor** finding: the cancellation assertion could accept nil or unrelated errors after cancellation. That assertion was strengthened on resumption. A fresh CodeRabbit review with the same scope is now running after the additional local fixes described above.


## First resumed CodeRabbit pass and follow-up fixes

The requested review completed with `status: review_completed`, 47 reviewed Go files, and five findings (three **major**, two **minor**):

1. **Major — discovery spins on unavailable leases:** verified and fixed. Candidates already Active or leased elsewhere are consumed for the current scan; a no-progress guard prevents empty repeated batches. Existing compatible Active Paths seed readiness/qualification so finalization preserves them. Added sequential/parallel and FastStart/full-scan regressions proving another owner's lease stays intact and available candidates still complete.
2. **Major — common-score traffic concentrates on the top score:** retained the intended behavior. Ticket 04 explicitly requires common ranking with deterministic rotation among ties; introducing random selection across a top-ten tier would change that policy. Corrected the misleading Top 10 Random comment. Existing common-score/explicit-strategy tests passed.
3. **Major — isolated live timeout overrides qualification loss:** verified and fixed. Loss retains qualification evidence until the live sample count reaches the qualification sample count; live-only paths still score immediately. This reuses the existing probe sample count rather than introducing a new numeric tuning threshold. Added assertions for isolated timeout fallback, sustained live loss, late timeout retraction, and live-only scoring.
4. **Minor — untested-priority test has no actual Standby competitor:** verified and fixed by limiting capacity to two and asserting the Standby precondition.
5. **Minor — minimum live-loss evidence:** duplicate of finding 3, addressed by the same fix. The earlier claim that zero score is permanent was stronger than the evidence; late replies can retract a timeout.

After these fixes, focused discovery/scoring/common-score/regression checks passed three runs (`7.510s`), and `git diff --check` passed. A fresh full test suite, both builds, and a verification CodeRabbit review with the identical scope are running. No commits or external review comments were created.


### Verification progress

The first post-review full-suite attempt failed on a remaining old exact-count assertion in `TestAdversarial_RunInitialMTUTests_Replenishment_2InitialBurstFailures`: three healthy concurrent completions were preserved while the test required exactly two Active Paths. Updated only the assertion to require readiness from two or three healthy paths, preserving rejection checks for both failed endpoints. This test passed five runs (`5.541s`). The subsequent `go test ./...` passed (client `37.859s`), both builds passed, and `git diff --check` passed. Temporary build outputs were removed.

The verification CodeRabbit pass started before this last test-only assertion edit. Its production-code scope remains current; the assertion edit will be validated locally without starting an unbounded review loop.


## Verification CodeRabbit result and final local fixes

The second resumed pass completed with exit code 0, `status: review_completed`, `outcome: completed_with_warnings` (message: unverified findings), 47 reviewed files, and three **minor** findings representing two issues:

- **Strategy synchronization (reported twice):** verified as a conditional API race when callers change strategy during selection. Added a dedicated strategy RWMutex; public selection entry points hold its read lock across the entire selection and helper chain, and `SetStrategy` holds its write lock. This preserves one strategy throughout each selection rather than taking inconsistent independent atomic loads. No current production caller changes strategy at runtime, so this is a defensive API fix.
- **Failover endpoint preference:** verified and fixed. Stream failover prefers another Resolver Endpoint; if none remains, it can still try another Tunnel Domain on the same endpoint. Added regressions for both cases.

The new concurrent strategy/selection and failover regressions, plus common-score/explicit-strategy checks, passed three runs (`3.176s`). Final validation passed: `go test ./...` (client `39.140s`), Client and Server builds, and `git diff --check`. Focused WSL `go test -race ./internal/client -run "TestBalancerStrategyChanges|TestStreamFailover|TestPoolEvaluation|TestDiscoverySkips" -count=3` passed (`1.784s`). The missing temporary Linux Go toolchain was restored from the previously downloaded cached archive. This was a targeted race check, not a full race suite. Temporary Windows build outputs were removed.

No third external review is being started: these final minor fixes are being validated locally. The most recent external result therefore describes the preceding snapshot, not an externally certified clean final tree. The earlier Standards/Spec reviewers were not rerun. No commits or external comments were created.


## Final status

All verified handoff defects and actionable findings from both resumed CodeRabbit passes have fixes and local validation. The common-score top-tier randomization proposal was deliberately declined because ticket 04 requires common ranking and deterministic tie rotation. Two resumed external passes completed over the disclosed 47-file `internal` scope; no whole-repository external review or third verification pass is claimed. The final strategy synchronization, endpoint failover fixes, and last test-only assertion edit were validated locally after their reviewed snapshots. Existing unrelated edits remain unstaged and no commits were created.
