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
    Balancer -->|Route via Common Score| ActivePaths["Active Paths"]
    
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
   - Keeps qualification samples separate from live traffic. RTT prefers live observations when available. Loss switches to live evidence once its sample count reaches the qualification burst count; paths without qualification samples use live loss immediately. This prevents one live timeout from erasing a larger qualification sample. Snapshots carry separate RTT, loss, and throughput observation timestamps; health-check lease times are used only for scheduling. Estimated throughput inherits the older timestamp of its MTU and RTT inputs.

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
   - Prevents disk I/O thrashing during rapid pool promotions, handles write failures gracefully, and performs a bounded flush and joins its scheduler on client shutdown. A filesystem syscall cannot be forcibly cancelled by Go; at most one storage operation can finish after the two-second shutdown deadline.

---

## 2. Invariants & Core Definitions

### Path vs. Endpoint Counts
- **Resolver Endpoint**: The physical network address (`IP:Port`) of a recursive DNS server.
- **Tunnel Domain**: The delegated domain name (e.g. `v.example.com`) served by the authoritative DNS tunnel server.
- **Tunnel Path** (or **Path**): The distinct transmission path formed by one Resolver Endpoint and one Tunnel Domain.
- **Pool Capacity**: Bounded by `MaxActiveResolvers`, counting total active Tunnel Paths.
- **Endpoint Quota**: Bounded by `TargetEndpoints` (or `RX_TX_Workers`), ensuring the active set contains distinct physical resolver endpoints to guarantee physical path diversity rather than concentrating traffic across multiple domains on a single resolver.

### Five Authoritative Lifecycle States
Every configured Tunnel Path exists in exactly one state:
1. **`StateUntested`**: Initial state before completed qualification attempt.
2. **`StateChecking`**: Leased exclusively for qualification or background rechecking. Checking candidates cannot be promoted or saved to ranked files while in flight. Pool-issued generations reject late completions and cleanup from older attempts, including after cancellation and reacquisition.
3. **`StateActive`**: Qualified and admitted into the active pool to carry live tunnel traffic.
4. **`StateStandby`**: Qualified, compatible with current Session requirements, and eligible for promotion into active duty.
5. **`StateRejected`**: Qualification failed, timed out, or became incompatible with session requirements. Subject to capped exponential backoff.

### Readiness vs. Cumulative Initial Coverage
- **FastStart Readiness**: Reached when at least `min(RX_TX_Workers, totalUniqueEndpoints)` distinct endpoints have qualified. The client unblocks foreground startup and initializes the VPN session immediately.
- **Continuing Coverage**: The endpoint goal is `min(configured endpoints, max(1, RX_TX_Workers))`, capped by positive Active Path capacity. Disabling FastStart requires a full initial scan while retaining this goal. Reaching readiness preserves all qualified admitted paths within capacity; it does not trim endpoints to the minimum goal.
- **Initial Coverage**: Discovery continues concurrently in the background until 100% of configured paths have received at least one bounded attempt (`CoverageStats.IsFirstPassComplete == true`). Cancelled attempts return to `StateUntested` and are rescheduled; failed attempts transition to `StateRejected`. Both count toward first-pass completion.

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
   - $T_{\text{coverage}}$: Time elapsed until 100% of configured paths receive initial qualification.

## Review regression coverage

Snapshot readers derive compatibility flags on copies under shared locks. Startup burst workers release cancelled leases without recording completed initial attempts. Startup batches submit observations to the pool; discovery does not choose membership independently. Admission and reconciliation share the vacancy, coverage-repair and strict 1.25-margin policy.

`TestIntegratedResolverManagerAcceptance` runs one authoritative Server, four local Resolver proxies, two tunnel domains, a real Client Session and TCP runtime, and a TCP echo destination. The production health loop completes initial coverage while echoed bytes cross the tunnel. The test logs readiness and coverage separately, actual echoed payload throughput and round-trip latency, then loads the saved resolver file and verifies network qualification after restart. These are local measurements, not public-network performance guarantees. Persistence timing and blocked-storage shutdown tests use `testing/synctest` virtual time.

The opt-in real-network command above reports probe readiness and initial coverage only. Run equivalent configuration and the same fixed resolver list on the pre-change revision and the completed revision, preserving raw logs for comparison. The local acceptance scenario supplies foreground traffic evidence; the probe-only command does not measure application throughput, replacement counts, or disk-write counts.

Recovery bursts acquire a token immediately before each UDP send, including trains larger than the bucket capacity. Their bounded deadline includes an allowance for the shared health batch's token waits. Sent/lost counters use actual writes; a budget-interrupted train releases its lease for retry rather than fabricating network loss. When the budget paces a train, its throughput is not treated as measured endpoint capacity or used to fail the minimum measured-throughput threshold; RTT and loss observations still apply, and common evaluation can use its labeled estimate.
