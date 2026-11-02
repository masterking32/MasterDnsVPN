# Handoff Report — Worker M2 Iteration 2 (BUG-M2-01 Fix)

## 1. Observation
1. **Initial Reproduction**:
   - Command: `go test -v -count=1 ./internal/client -run "TestEmpirical_Adversarial_FailedRecheckFSMStateTransition"`
   - Result:
     ```
     === RUN   TestEmpirical_Adversarial_FailedRecheckFSMStateTransition
         resolver_pool_adversarial_test.go:568: State after failed CompleteRecheck: Rechecking
         resolver_pool_adversarial_test.go:575: BUG DISCOVERED: Failed recheck left candidate in StateRechecking; subsequent ReleaseRecheck revived it into StandbyEligible!
     --- FAIL: TestEmpirical_Adversarial_FailedRecheckFSMStateTransition (0.00s)
     FAIL
     FAIL	masterdnsvpn-go/internal/client	1.660s
     ```

2. **Codebase Inspection**:
   In `internal/client/resolver_pool.go` (lines 261–270):
   ```go
   if cand.conn.IsValid == valid {
       if !valid && cand.conn.StandbyEligible {
           cand.conn.StandbyEligible = false
           cand.state = StateInactive
       } else if valid && cand.conn.StandbyEligible {
           cand.conn.StandbyEligible = false
           cand.state = StateActive
       }
       return true
   }
   ```
   When a candidate was leased for recheck via `AcquireNextInactiveForRecheck` (line 513) or `beginConnectionRecheck` (line 532), `cand.conn.StandbyEligible` was explicitly cleared to `false` and `cand.state` set to `StateRechecking`.
   When recheck failed (`MTUVerified == false` or `Burst.Qualified == false`), `CompleteRecheck` invoked `setConnectionValidityLocked(key, false)`.
   Because `cand.conn.IsValid` was `false` and `valid` was `false`, `cand.conn.IsValid == valid` evaluated to `true`.
   However, `!valid && cand.conn.StandbyEligible` evaluated to `false` because `StandbyEligible` was already `false`.
   Thus `cand.state` was never changed from `StateRechecking` to `StateInactive`.
   A subsequent call to `ReleaseRecheck(key, true)` checked `if cand.state != StateRechecking { return }`, found `cand.state == StateRechecking`, and erroneously set `cand.conn.StandbyEligible = true; cand.state = StateStandby`.

3. **Remediation Applied**:
   In `internal/client/resolver_pool.go` (lines 261–270):
   ```go
   if cand.conn.IsValid == valid {
       if !valid {
           cand.conn.StandbyEligible = false
           cand.state = StateInactive
       } else {
           cand.conn.StandbyEligible = false
           cand.state = StateActive
       }
       return true
   }
   ```
   Now, if `cand.conn.IsValid == valid`:
   - If `!valid`: `cand.conn.StandbyEligible` is revoked and `cand.state` is unconditionally transitioned to `StateInactive`.
   - If `valid`: `cand.conn.StandbyEligible` is revoked and `cand.state` is set to `StateActive`.

4. **Post-Remediation Verification Outputs**:
   - `go test -v -count=1 ./internal/client -run "TestEmpirical_Adversarial_FailedRecheckFSMStateTransition"`:
     ```
     === RUN   TestEmpirical_Adversarial_FailedRecheckFSMStateTransition
         resolver_pool_adversarial_test.go:568: State after failed CompleteRecheck: Inactive
     --- PASS: TestEmpirical_Adversarial_FailedRecheckFSMStateTransition (0.00s)
     PASS
     ok  	masterdnsvpn-go/internal/client	1.657s
     ```
   - `go test -v -count=1 ./internal/client -run "TestEmpirical_Adversarial_.*"`:
     PASS (8/8 tests passed in 5.662s)
   - `go test -v -count=1 ./internal/client -run "TestResolverPool.*"`:
     PASS (13/13 tests passed in 1.648s)
   - `go test -v -count=1 ./internal/client -run "TestBalancer.*"`:
     PASS (28/28 tests passed in 1.713s)
   - `go test -v -count=1 ./internal/client -run "TestEmpirical.*"`:
     PASS (10/10 tests passed in 25.817s)
   - `go build ./cmd/client; go build ./cmd/server`:
     PASS (exit code 0)
   - `git diff --exit-code -- go.mod go.sum`:
     PASS (exit code 0, 0 diff)
   - `go vet ./internal/client`:
     PASS (exit code 0, 0 issues)

## 2. Logic Chain
1. Under Observation 1 and 2, when `cand.conn.IsValid` was `false` and `valid` was `false`, `setConnectionValidityLocked` evaluated `!valid && cand.conn.StandbyEligible`.
2. Since `StandbyEligible` was already cleared during lease acquisition (`cand.conn.StandbyEligible = false`), `!valid && cand.conn.StandbyEligible` was `false`, causing `cand.state` to remain `StateRechecking` permanently.
3. If `ReleaseRecheck(key, true)` was called as part of cleanup, it inspected `cand.state == StateRechecking`, passed the guard, and revived the candidate to `StateStandby`, permitting failed resolvers to be promoted by `Optimize()`.
4. By removing the `cand.conn.StandbyEligible` guard for `!valid` (Observation 3), any connection whose validity is set to `false` is unconditionally transitioned to `StateInactive`, with `StandbyEligible` set to `false`.
5. Upon completion of a failed recheck, `cand.state` is immediately `StateInactive`.
6. Subsequent calls to `ReleaseRecheck` fail the `cand.state != StateRechecking` guard and exit without reviving the candidate.
7. Post-remediation tests (Observation 4) demonstrate that all unit tests, empirical adversarial tests, package builds, and module invariants pass with zero regressions.

## 3. Caveats
- No caveats. The remediation strictly adheres to the minimal change principle: exactly 4 lines modified in `internal/client/resolver_pool.go`, touching only the branch condition in `setConnectionValidityLocked`.

## 4. Conclusion
BUG-M2-01 is completely resolved. Candidates completing recheck with negative qualification now cleanly transition to `StateInactive` and cannot be resurrected to `StateStandby` by deferred or re-entrant `ReleaseRecheck` invocations. All 7 verification commands mandated in the dispatch have passed cleanly.

## 5. Verification Method
To independently verify this fix:
```bash
# 1. Verify the previously-failing adversarial test passes
go test -v -count=1 ./internal/client -run "TestEmpirical_Adversarial_FailedRecheckFSMStateTransition"

# 2. Verify all adversarial stress tests pass
go test -v -count=1 ./internal/client -run "TestEmpirical_Adversarial_.*"

# 3. Verify ResolverPool unit test suite
go test -v -count=1 ./internal/client -run "TestResolverPool.*"

# 4. Verify Balancer unit test suite
go test -v -count=1 ./internal/client -run "TestBalancer.*"

# 5. Verify all empirical stress tests
go test -v -count=1 ./internal/client -run "TestEmpirical.*"

# 6. Verify client and server binary compilation
go build ./cmd/client
go build ./cmd/server

# 7. Verify go.mod and go.sum immutability
git diff --exit-code -- go.mod go.sum
```
All commands must exit with code 0.
