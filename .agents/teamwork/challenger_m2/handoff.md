# Handoff Report — Milestone 2 Adversarial Challenge

**Verdict**: **REQUEST_CHANGES**

## 1. Observation
1. **Existing Test Suite Execution**:
   - `go test -v ./internal/client -run "TestResolverPool.*"`: PASS (13/13 passed in 1.668s).
   - `go test -v ./internal/client -run "TestBalancer.*"`: PASS (28/28 passed in 1.680s).
   - `go test -v ./internal/client -run "TestEmpirical.*"`: PASS (10/10 passed in 25.485s).
   - `go build ./cmd/client; go build ./cmd/server`: PASS (exit code 0).
   - `git diff -- go.mod go.sum`: Clean (0 diff).

2. **Empirical Adversarial Stress Suite**:
   Created `internal/client/resolver_pool_adversarial_test.go` containing 8 targeted stress tests:
   - `TestEmpirical_Adversarial_MutualExclusivityConcurrentStress`: PASS (63,985 concurrent mutator and reader operations across 16 goroutines; 0 mutual exclusivity violations).
   - `TestEmpirical_Adversarial_OptimizeVsRecheckRace`: PASS (standby candidate acquired for recheck cannot be promoted by concurrent `Optimize()` calls during lease).
   - `TestEmpirical_Adversarial_CapacityBoundingOverflow`: PASS (active pool strictly bounded at `maxActive=3` when admitting 20 candidates; displaced candidates become standby).
   - `TestEmpirical_Adversarial_HysteresisThreshold`: PASS (degradation swap hysteresis strictly requires >1.25x composite score improvement; 83ms rejected at 1.2399x, 81ms swapped at 1.275x).
   - `TestEmpirical_Adversarial_SessionMTUComplianceUnderOptimization`: PASS (candidates with partial, sub-session, or unprobed MTUs rejected by `Optimize()` despite 50x lower latency).
   - `TestEmpirical_Adversarial_PersistenceCallbackDeadlockFreedom`: PASS (187,636 operations triggered 116,996 re-entrant `SetOnPoolChanged` callbacks with zero deadlocks).
   - `TestEmpirical_Adversarial_DuplicateKeysInSetConnections`: PASS with observation (duplicate connection keys in `SetConnections` overwrite `indexByKey`, silently orphaning duplicate entries in `inactiveIDs`).

3. **Failed Empirical Test & Bug Discovery**:
   - Executed: `go test -v ./internal/client -run "TestEmpirical_Adversarial_FailedRecheckFSMStateTransition"`
   - Result:
     ```
     === RUN   TestEmpirical_Adversarial_FailedRecheckFSMStateTransition
         resolver_pool_adversarial_test.go:568: State after failed CompleteRecheck: Rechecking
         resolver_pool_adversarial_test.go:575: BUG DISCOVERED: Failed recheck left candidate in StateRechecking; subsequent ReleaseRecheck revived it into StandbyEligible!
     --- FAIL: TestEmpirical_Adversarial_FailedRecheckFSMStateTransition (0.00s)
     ```
   - In `internal/client/resolver_pool.go:580-590`:
     ```go
     qualified := result.MTUVerified && (result.Burst == nil || result.Burst.Qualified)
     if qualified {
         // ...
     }
     p.setConnectionValidityLocked(cand.conn.Key, qualified)
     ```
   - In `internal/client/resolver_pool.go:255-270`:
     ```go
     func (p *ResolverPool) setConnectionValidityLocked(key string, valid bool) bool {
         idx, ok := p.indexByKey[key]
         if !ok || idx < 0 || idx >= len(p.candidates) {
             return false
         }
         cand := &p.candidates[idx]
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
         // ...
     ```

## 2. Logic Chain
1. When `AcquireNextInactiveForRecheck` (lines 484–519) leases an inactive/standby candidate, it sets `cand.conn.StandbyEligible = false` and `cand.state = StateRechecking`. `cand.conn.IsValid` remains `false`.
2. When probing fails (e.g., `MTUVerified = false` or `Burst.Qualified = false`), `CompleteRecheck` is invoked with `qualified = false` and calls `setConnectionValidityLocked(key, false)`.
3. In `setConnectionValidityLocked`, `cand.conn.IsValid` is `false` and `valid` is `false`. Therefore, the early guard `if cand.conn.IsValid == valid` evaluates to `true`.
4. Inside this guard, `!valid && cand.conn.StandbyEligible` evaluates to `false` because `StandbyEligible` was already revoked upon lease acquisition.
5. Consequently, `setConnectionValidityLocked` returns `true` without altering `cand.state`.
6. As proven by `TestEmpirical_Adversarial_FailedRecheckFSMStateTransition`, `cand.state` remains `StateRechecking` permanently after recheck completion.
7. **Blast Radius**:
   - If a caller, recheck worker, or deferred cleanup subsequently calls `ReleaseRecheck(key, true)` (e.g. `defer pool.ReleaseRecheck(conn.Key, wasStandby)` or error handling paths), `ReleaseRecheck` checks `if cand.state != StateRechecking { return }`. Because `cand.state` leaked as `StateRechecking`, `ReleaseRecheck` executes `cand.conn.StandbyEligible = true; cand.state = StateStandby`.
   - This resurrects a failed candidate into `StateStandby`, making it eligible for promotion into the active pool during subsequent `Optimize()` calls.
   - If `ReleaseRecheck` is not called, the candidate remains permanently stuck in `StateRechecking`, corrupting candidate FSM tracking and preventing future recheck leases under certain intervals.

## 3. Caveats
- In normal happy-path operation where all resolvers verify successfully (`MTUVerified = true` and `Burst.Qualified = true`), `CompleteRecheck` calls `setConnectionValidityLocked(key, true)` where `cand.conn.IsValid == false != valid == true`, so `cand.state` is properly transitioned to `StateActive` (or `StateStandby` if pool is saturated). The bug only triggers on failed rechecks.
- In `SetConnections`, passing duplicate keys in `connections` silently overwrites `indexByKey` and leaves the earlier entry orphaned in `inactiveIDs`. While not causing immediate runtime panics, `SetConnections` should ideally deduplicate or reject duplicate keys.
- No modifications were made to implementation code; per challenger protocol, all findings are documented for worker remediation.

## 4. Conclusion
Milestone 2 implementation is well-architected and demonstrates robust concurrency characteristics across capacity bounding, mutual exclusivity, deadlock-free callbacks, and optimization hysteresis. However, the candidate 4-state FSM contains a state leak bug where failed rechecks remain in `StateRechecking` and can be revived into `StateStandby`.

Verdict: **REQUEST_CHANGES**

**Required Worker Remediation**:
In `internal/client/resolver_pool.go`:
1. In `CompleteRecheck` or `setConnectionValidityLocked`, ensure that when a recheck completes with `qualified == false` (or whenever `!valid` is passed to `setConnectionValidityLocked`), `cand.state` is unconditionally transitioned from `StateRechecking` to `StateInactive`.
   For example, in `setConnectionValidityLocked`:
   ```go
   if cand.conn.IsValid == valid {
       if !valid {
           cand.conn.StandbyEligible = false
           cand.state = StateInactive
       } else if valid && cand.conn.StandbyEligible {
           cand.conn.StandbyEligible = false
           cand.state = StateActive
       }
       return true
   }
   ```
2. Verify that `go test -v ./internal/client -run "TestEmpirical_Adversarial_.*"` passes completely.

## 5. Verification Method
To independently verify this bug and the entire adversarial test suite:
```bash
# 1. Run the failing adversarial FSM test reproducing BUG-M2-01
go test -v ./internal/client -run "TestEmpirical_Adversarial_FailedRecheckFSMStateTransition"

# 2. Run all adversarial stress tests
go test -v ./internal/client -run "TestEmpirical_Adversarial_.*"

# 3. Invalidation condition:
# After applying the suggested remediation, TestEmpirical_Adversarial_FailedRecheckFSMStateTransition
# must pass with exit code 0, confirming cand.state transitions to StateInactive and cannot be revived.
```
