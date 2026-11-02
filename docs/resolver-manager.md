# Resolver Manager Architecture & Lifecycle Guide

## 1. Overview & Architectural Boundaries

MasterDnsVPN client resolver management coordinates how candidate DNS resolvers are discovered, qualified, ranked, admitted, routed, and persisted. Following the PR #205 simplification, resolver management is structured into distinct, cohesive modules with minimal interfaces:

```mermaid
flowchart TD
    Config["Client Configuration\n(resolvers, domains, workers)"] --> Discovery["DiscoveryEngine\n(Parallel startup scan)"]
    Config --> Pool["ResolverPool\n(Authoritative state & admission)"]
    Config --> Balancer["Balancer\n(Packet routing & multi-path)"]
    
    Discovery -->|FastStart readiness| Traffic["Client Session & Traffic Runtime"]
    Discovery -->|Admit startup batch| Pool
    
    Traffic -->|Outgoing queries| Balancer
    Balancer -->|Active candidate set| Pool
    Balancer -->|Route via Common Score| ActivePairings["Active Pairings"]
    
    Traffic -->|Background health loop| Health["Background Maintenance\n(RecheckInactiveResolver)"]
    Health -->|Token Bucket Limiter\n(15 QPS default)| Net["DNS Probes (MTU & Bursts)"]
    Health -->|Complete/Release recheck| Pool
    
    Pool -->|Notify on membership change| Writer["RankedPersistenceWriter\n(Batched, debounced, serialized)"]
    Writer -->|Flush on shutdown| File["resolvers.txt"]
```

### Module Responsibilities

1. **`ResolverPool` (`internal/client/resolver_pool.go`)**:
   - Owns the single authoritative candidate lifecycle state machine (`StateUntested`, `StateChecking`, `StateActive`, `StateStandby`, `StateRejected`).
   - Enforces the universal pool policy: vacancy filling, distinct-endpoint quota repair, and performance replacement (requiring score strictly $> 1.25\times$ displaced candidate score).
   - Computes derived compatibility views (`IsValid`, `StandbyEligible`) for callers without maintaining independently mutable flags.
   - Tracks cumulative initial coverage (`CoverageStats`) separately from current readiness.
   - Manages capped exponential backoff for `StateRejected` candidates and fair 1:1 scheduling between untested and recovery candidates.

2. **`Score` (`internal/client/score.go`)**:
   - Provides pure, deterministic candidate observation snapshot evaluation (`EvaluateCandidateObservation`, `CalculateResolverScore`, `ResolverQualityTier`).
   - Shared universally between diagnostics, pool ranking, and default balancer routing.

3. **`Balancer` (`internal/client/balancer.go`)**:
   - Routes outgoing packets across the active working set.
   - Implements `BalancingCommonScore = 9` (aliased as `BalancingDefault`) as the default strategy, using composite score with round-robin tie-breaking and distinct physical endpoint filtering (`filterDistinctEndpoints`).
   - Preserves all explicit user-selected balancing strategies (`0` = Round Robin, `1` = Lowest Latency, `2` = Least Loss, `6` = Loss Then Latency, etc.).

4. **`DiscoveryEngine` (`internal/client/resolver_discovery.go`)**:
   - Executes parallel initial MTU and burst qualification at startup.
   - Exits early as soon as required distinct endpoints qualify (`FastStart`), permitting immediate Session initialization and tunnel runtime startup.

5. **`BackgroundQueryLimiter` (`internal/client/background_limiter.go`)**:
   - Monotonic, cancellation-aware token bucket rate limiter (conservative default: 15 QPS).
   - Throttles all background discovery and recheck DNS queries (including retries and burst trains) without throttling foreground tunnel traffic or startup probes.

6. **`RankedPersistenceWriter` (`internal/client/ranked_writer.go`)**:
   - Batched, serialized, debounced background writer that persists ranked endpoint ordering to `resolvers.txt`.
   - Prevents disk I/O thrashing during rapid pool promotions, handles write failures gracefully, and performs a clean bounded flush on client shutdown.

---

## 2. Invariants & Core Definitions

### Pairing vs. Endpoint Counts
- **Resolver Endpoint**: The physical network address (`IP:Port`) of a recursive DNS server.
- **Tunnel Domain**: The delegated domain name (e.g. `v.example.com`) served by the authoritative DNS tunnel server.
- **Candidate Pairing**: The combination of one Resolver Endpoint and one Tunnel Domain.
- **Pool Capacity**: Bounded by `MaxActiveResolvers`, counting total active candidate pairings.
- **Endpoint Quota**: Bounded by `TargetEndpoints` (or `RX_TX_Workers`), ensuring the active set contains distinct physical resolver endpoints to guarantee physical path diversity rather than concentrating traffic across multiple domains on a single resolver.

### Five Authoritative Lifecycle States
Every configured pairing exists in exactly one state:
1. **`StateUntested`**: Initial state before completed qualification attempt.
2. **`StateChecking`**: Leased exclusively for qualification or background rechecking. Checking candidates cannot be promoted or saved to ranked files while in flight.
3. **`StateActive`**: Qualified and admitted into the active pool to carry live tunnel traffic.
4. **`StateStandby`**: Qualified, compatible with current Session requirements, and eligible for promotion into active duty.
5. **`StateRejected`**: Qualification failed, timed out, or became incompatible with session requirements. Subject to capped exponential backoff.

### Readiness vs. Cumulative Initial Coverage
- **FastStart Readiness**: Reached when at least `min(RX_TX_Workers, totalUniqueEndpoints)` distinct endpoints have qualified. The client unblocks foreground startup and initializes the VPN session immediately.
- **Initial Coverage**: Discovery continues concurrently in the background until 100% of configured pairings have received at least one bounded attempt (`CoverageStats.IsFirstPassComplete == true`). Cancelled attempts return to `StateUntested` and are rescheduled; failed attempts transition to `StateRejected`. Both count toward first-pass completion.

### Decoupled Maintenance Scheduling
Background health loop polling (`resolverHealthPollInterval`) is dynamically computed based on `AutoDisableTimeoutWindowSeconds` and active pool size. It is completely independent of runtime statistics display intervals (`DumpRuntimeStats`).

---

## 3. Opt-In Real-Network Benchmarking Procedure

While deterministic local loopback tests (such as `TestIntegratedResolverManagerAcceptance`) verify functional correctness and state machine invariants without external dependencies, maintainers may optionally run real-network benchmarks against fixed resolver lists.

> [!NOTE]
> Public internet latency, censorship interference, and packet loss vary widely across networks. Internet benchmark results are operational diagnostics, not hard CI gates. Do not assert universal 1–2 second startup guarantees across lossy or adversarial networks.

### Benchmark Setup Steps

1. **Prepare Fixed Resolver List**:
   Create a test resolver file (e.g. `test_resolvers.txt`) containing 20–50 known recursive DNS endpoints:
   ```text
   1.1.1.1:53
   8.8.8.8:53
   9.9.9.9:53
   208.67.222.222:53
   ...
   ```

2. **Run Comparative Profiling**:
   Execute the benchmark comparing baseline and simplified resolver management:
   ```bash
   # Run with FastStart enabled (default)
   go test -v -run TestBenchmark_RealNetwork_FastStart ./internal/client -args -resolvers=test_resolvers.txt -domain=tunnel.example.com
   ```

3. **Metrics Recorded**:
   - $T_{\text{ready}}$: Time elapsed from startup until Session initialization begins.
   - $T_{\text{coverage}}$: Time elapsed until 100% of configured pairings receive initial qualification.
   - $Q_{\text{bg}}$: Total background DNS queries sent (bounded by 15 QPS limiter).
   - $N_{\text{swaps}}$: Number of pool replacements performed under live traffic.
   - $W_{\text{disk}}$: Number of ranked file writes performed (verified to be debounced).
