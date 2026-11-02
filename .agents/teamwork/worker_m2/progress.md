# Progress — Milestone 2 Implementation

Last visited: 2026-10-31T17:56:00Z

## Status
Completed: 100%

## Completed Steps
1. Created `internal/client/resolver_pool.go` encapsulating candidate state machine (StateInactive, StateActive, StateStandby, StateRechecking), admission, FastStart quota trimming, health recheck leases, active optimization, ranked endpoints, and event callbacks.
2. Created `internal/client/resolver_pool_test.go` with 13 comprehensive unit tests.
3. Absorbed all admission logic and deleted `internal/client/balancer_admission.go` and `internal/client/balancer_admission_test.go`.
4. Refactored `internal/client/balancer.go`: retained packet dispatching (`SelectTargets`), sticky stream routing, sliding-window timeouts, and in-flight samples; delegated candidate pool management to `ResolverPool`.
5. Updated `internal/client/client.go`: added `pool *ResolverPool` to `Client`, instantiated `pool := NewResolverPool(cfg.MaxActiveResolvers, log)` in `New`, passed `pool` to `NewBalancer`, and assigned `c.pool = pool`.
6. Verified builds and tests:
   - `TestResolverPool.*`: 13/13 passed.
   - `TestBalancer.*`: 28/28 passed.
   - `TestEmpirical.*`: 10/10 passed.
   - `go build ./cmd/client`: passed.
   - `go build ./cmd/server`: passed.
   - `git diff -- go.mod go.sum`: clean / empty.
