# 01: Make Resolver Pool candidate state authoritative

**What to build:** Make the Client consistently distinguish untested Resolver/domain pairings, candidates being checked, Active Resolvers, Standby Resolvers, and rejected candidates throughout startup and background recovery. A candidate cannot be promoted while qualification is deciding whether it works. Interrupted work must not be reported as a network failure.

**Blocked by:** None (can start immediately).

**Status:** resolved

This follows [PR #205](https://github.com/masterking32/MasterDnsVPN/pull/205), analyzed at commit 8615f90197f1188e36bc4e5185f15b03f1c99a04. Check the current implementation before editing. A candidate is a Resolver endpoint paired with a tunnel domain; it is not a Session.

## Acceptance criteria

- [x] Use exactly five authoritative lifecycle states: Untested, Checking, Active, Standby, and Rejected. All transitions are owned by the Resolver Pool.
- [x] Untested means no completed qualification; Checking reserves a candidate for initial qualification or recheck; Active means qualified and selected for traffic; Standby means qualified, compatible with current Session requirements, and eligible for promotion; Rejected means qualification failed or the pairing became unsuitable.
- [x] Initial qualification and background rechecking both use Checking. Active candidates are invalidated through observed failures or Session incompatibility; this change does not introduce background testing of Active Resolvers.
- [x] Store lifecycle state once. Compatibility views such as IsValid and StandbyEligible are derived from authoritative state and eligibility requirements rather than independently mutable flags. Keep callers compiling during migration and remove obsolete internal flag-based decisions in this ticket.
- [x] A passing check leads to Active or Standby through existing admission behavior; a failed check leads to Rejected. Rejected candidates can be retried. Displaced but still qualified Active Resolvers become Standby.
- [x] Cancellation is distinct from failure: interrupted initial work returns to Untested; an interrupted recheck may restore prior Standby qualification only if it remains valid for the current Session. Otherwise the candidate stays ineligible and can be retried. Cancellation does not fabricate a completed successful check.
- [x] Failure reason, retry timing, measurements, and qualification context are metadata, not additional states. Validate results against current Session requirements before committing eligibility. Late or duplicate completions cannot overwrite newer lifecycle decisions.
- [x] Reader snapshots, runtime diagnostics, and ranking eligibility agree with authoritative state. Rejected, Untested, and Checking candidates cannot enter saved eligible rankings or be promoted.
- [x] Deterministic tests cover startup success/failure, displacement, background success/failure, cancellation, retry, Session requirement changes during checks, and concurrent checking versus promotion. Existing scoped tests remain green.
- [x] Update domain documentation to describe the states and distinguish inactive candidates from qualified Standby Resolvers.

## Answer

Implemented the five authoritative lifecycle states (`StateUntested`, `StateChecking`, `StateActive`, `StateStandby`, `StateRejected`) in `ResolverPool`. Key changes:
1. Candidate lifecycle is strictly state-machine driven: `SetConnections` initializes candidates as `StateUntested`.
2. Checking acquisition leases candidate in `StateChecking`, revoking promotion and ranking eligibility.
3. Cancellation restores `StateUntested` for initial qualification, and restores `StateStandby` only if the candidate still satisfies current session MTU.
4. Failures transition to `StateRejected`. Rejected candidates remain ineligible for promotion or ranked saving, but are eligible for retry.
5. `IsValid` and `StandbyEligible` flags on `Connection` are derived views computed from authoritative state and session MTU compatibility, rather than independently mutable flags.
6. Displacement preserves qualified candidates as `StateStandby`.
7. Added deterministic behavioral unit tests in `internal/client/resolver_pool_lifecycle_test.go` covering all transition edges, cancellations, late completions, displacement, and invalidations.
8. Updated `CONTEXT.md` defining the 5 states and clarifying the distinction between inactive and qualified standby candidates.
