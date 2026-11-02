# Specification Mining Report: Milestone 3 (R3) — ResolverProber, UDPResolverProber & FakeResolverProber Test Suite

**Author**: `spec_miner_m3_3`  
**Date**: 2026-10-31  
**Target Repository**: `c:\Dev\Projects\DNStunnel`  
**Target Branch**: `feat/fast-start-resolvers` (PR #205 Architectural Deepening)  
**Assigned Scope**: Specification of `ResolverProber` interface, concrete `UDPResolverProber` in `internal/client/prober_udp.go`, and deterministic in-memory `FakeResolverProber` test suite in `internal/client/resolver_discovery_test.go`.

---

## 1. Executive Summary & Problem Analysis

In MasterDnsVPN, resolver discovery and MTU probing are currently coupled to physical OS UDP socket operations in `internal/client/mtu.go`. The existing test suite in `internal/client/fast_start_test.go` exercises candidate replenishment, FastStart early termination, and worker cancellation by launching mock UDP listeners on loopback (e.g., `startMockMTUDNSListener`).

### Key Deficiencies in Current Implementation
1. **Network Coupling**: Discovery orchestration (worker channels, candidate batching, early exit triggers, replenishment on burst drop) is entangled with low-level socket calls and DNS packet serialization.
2. **Slow Test Execution**: Live loopback socket tests require **9.24 seconds** for 4 test cases (`TestRunInitialMTUTests_BurstRetryScanning` alone takes **7.05s** due to socket timeouts and retry delays).
3. **Flakiness & Port Contention**: Spawning 10–20 loopback UDP sockets per test run creates risk of ephemeral port exhaustion or Windows firewall interruptions.
4. **Lack of In-Memory Unit Testing**: There is no way to unit-test FastStart early termination or worker cancellation in isolation without spinning up a full DNS server stack.

### Milestone 3 Architectural Remedy
- **`ResolverProber` Interface**: Abstract all physical DNS probing into a clean 2-method interface (`ProbeMTU` and `ProbeBurst`).
- **`UDPResolverProber`**: Live network adapter wrapping `*Client.probeConnectionMTU` and `*Client.probeConnectionMicroBurst` in `internal/client/prober_udp.go`.
- **`FakeResolverProber`**: Deterministic, in-memory mock prober in `internal/client/resolver_discovery_test.go` enabling sub-millisecond execution (<5ms total suite runtime), parameterized canned responses, injected latency, and call recording.

---

## 2. Authoritative Specification: `ResolverProber` Interface

### 2.1 Interface Definition & Contract Signatures

```go
package client

import (
	"context"
	"time"
)

// MTUProbeResult holds the outcome and telemetry of an MTU probe.
type MTUProbeResult struct {
	Success       bool
	UploadBytes   int
	UploadChars   int
	DownloadBytes int
	ResolveTime   time.Duration
	RejectReason  string
}

// ResolverProber decouples physical DNS wire probing from discovery orchestration.
type ResolverProber interface {
	// ProbeMTU measures upload and download MTU capacity for a candidate connection.
	ProbeMTU(ctx context.Context, conn Connection, maxUploadPayload int) (MTUProbeResult, error)

	// ProbeBurst sends a pipelined train of DNS queries to measure packet loss, RTT, and throughput.
	ProbeBurst(
		ctx context.Context,
		conn Connection,
		packetCount int,
		downloadMTU int,
		uploadMTU int,
		timeout time.Duration,
	) BurstProbeResult
}
```

### 2.2 Comparison: DISPATCH.md / Survey 3 vs. Draft in PROJECT.md

The draft in `PROJECT.md § Interface Contracts` proposed:
```go
// Draft in PROJECT.md:
type ResolverProber interface {
    ProbeMTU(ctx context.Context, conn Connection) (uploadBytes, uploadChars, downloadBytes int, err error)
    ProbeBurst(ctx context.Context, conn Connection, count int) (*BurstProbeResult, error)
}
```

Investigation reveals three critical reasons why the DISPATCH.md and Survey 3 signature is authoritative and strictly necessary:
1. **`maxUploadPayload int` Parameter in `ProbeMTU`**:
   - Each tunnel domain has a precomputed maximum upload payload (`c.precomputeUploadCaps()`) based on label encoding (Base32/Base64/Hex), max RFC domain length, and VPN header overhead.
   - Without `maxUploadPayload`, `ProbeMTU` would be forced to recompute domain caps or query `ClientConfig`, violating encapsulation.
2. **`MTUProbeResult` Return Type**:
   - `ResolverPool.ApplyMTUProbeResult` requires `resolveTime time.Duration`:
     `ApplyMTUProbeResult(key string, uploadBytes int, uploadChars int, downloadBytes int, resolveTime time.Duration, active bool) bool`
   - Returning raw integers `(uploadBytes, uploadChars, downloadBytes int, err error)` drops `ResolveTime`.
   - Furthermore, a rejected MTU probe (e.g. upload MTU below floor) is **not** a Go context error (`err != nil`), but a rejected candidate (`Success: false`, `RejectReason: "upload mtu probe rejected"`). The `MTUProbeResult` struct cleanly differentiates candidate disqualification from context aborts.
3. **`ProbeBurst` Return Type**:
   - `BurstProbeResult` is already defined in `internal/client/micro_burst.go` and contains `Qualified bool`, `RejectReason string`, `LossRatio float64`, etc.
   - Returning `BurstProbeResult` by value directly matches `Client.sendPipelinedMicroBurst`, avoiding unnecessary pointer indirection and nil-pointer risks. All failure modes (dial error, 100% loss, timeout, cancellation) are self-contained in `Qualified` and `RejectReason`.

### 2.3 Error Handling & Cancellation Contracts

| Method | Normal Success | Candidate Failure / Rejection | Context Cancellation / Timeout |
|---|---|---|---|
| `ProbeMTU` | `MTUProbeResult{Success: true, UploadBytes: >0, DownloadBytes: >0, ResolveTime: >0}, nil` | `MTUProbeResult{Success: false, RejectReason: "upload mtu probe rejected" \| "download mtu probe rejected"}, nil` | `MTUProbeResult{Success: false, RejectReason: "context cancelled"}, ctx.Err()` |
| `ProbeBurst` | `BurstProbeResult{Qualified: true, ReceivedCount: >0, LossRatio: <= maxLoss, ...}` | `BurstProbeResult{Qualified: false, RejectReason: "excessive burst loss: ..." \| "dial error: ..."}` | `BurstProbeResult{Qualified: false, RejectReason: "context cancelled"}` |

---

## 3. Concrete Network Implementation: `UDPResolverProber` (`internal/client/prober_udp.go`)

### 3.1 Responsibilities & Layout
- Lives in `internal/client/prober_udp.go`.
- Belongs to package `client`.
- Wraps `*Client.probeConnectionMTU` and `*Client.probeConnectionMicroBurst`.
- Enforces strict socket lifecycle management and cancellation cleanup.

### 3.2 Exact Code Blueprint

```go
// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"fmt"
	"time"
)

// UDPResolverProber implements ResolverProber using live UDP network exchanges.
type UDPResolverProber struct {
	client *Client
}

// NewUDPResolverProber constructs a UDPResolverProber wrapping the given Client.
func NewUDPResolverProber(client *Client) *UDPResolverProber {
	return &UDPResolverProber{client: client}
}

// ProbeMTU executes live upload and download MTU discovery queries over UDP.
func (p *UDPResolverProber) ProbeMTU(
	ctx context.Context,
	conn Connection,
	maxUploadPayload int,
) (MTUProbeResult, error) {
	if p.client == nil {
		return MTUProbeResult{
			Success:      false,
			RejectReason: "client unavailable",
		}, fmt.Errorf("client unavailable")
	}

	if ctx != nil && ctx.Err() != nil {
		return MTUProbeResult{
			Success:      false,
			RejectReason: "context cancelled",
		}, ctx.Err()
	}

	result, reason := p.client.probeConnectionMTU(ctx, conn, maxUploadPayload)
	if ctx != nil && ctx.Err() != nil {
		return MTUProbeResult{
			Success:      false,
			RejectReason: "context cancelled",
		}, ctx.Err()
	}

	switch reason {
	case mtuRejectUpload:
		return MTUProbeResult{
			Success:      false,
			UploadBytes:  result.UploadBytes,
			UploadChars:  result.UploadChars,
			RejectReason: "upload mtu probe rejected",
		}, nil
	case mtuRejectDownload:
		return MTUProbeResult{
			Success:       false,
			UploadBytes:   result.UploadBytes,
			UploadChars:   result.UploadChars,
			DownloadBytes: result.DownloadBytes,
			RejectReason:  "download mtu probe rejected",
		}, nil
	default:
		return MTUProbeResult{
			Success:       true,
			UploadBytes:   result.UploadBytes,
			UploadChars:   result.UploadChars,
			DownloadBytes: result.DownloadBytes,
			ResolveTime:   result.ResolveTime,
		}, nil
	}
}

// ProbeBurst executes a live pipelined micro-burst train over UDP.
func (p *UDPResolverProber) ProbeBurst(
	ctx context.Context,
	conn Connection,
	packetCount int,
	downloadMTU int,
	uploadMTU int,
	timeout time.Duration,
) BurstProbeResult {
	if p.client == nil {
		return BurstProbeResult{
			SentCount:    packetCount,
			Qualified:    false,
			RejectReason: "client unavailable",
		}
	}
	return p.client.probeConnectionMicroBurst(ctx, conn, packetCount, downloadMTU, uploadMTU, timeout)
}
```

### 3.3 Supporting Method on `Client`: `probeConnectionMicroBurst`
In `internal/client/micro_burst.go` or `internal/client/prober_udp.go`, add:
```go
// probeConnectionMicroBurst handles transport allocation and cleanup for micro-burst testing.
func (c *Client) probeConnectionMicroBurst(
	ctx context.Context,
	conn Connection,
	packetCount int,
	downloadMTU int,
	uploadMTU int,
	timeout time.Duration,
) BurstProbeResult {
	if ctx != nil && ctx.Err() != nil {
		return BurstProbeResult{
			SentCount:    packetCount,
			Qualified:    false,
			RejectReason: "context cancelled",
		}
	}

	transport, err := c.newUDPQueryTransport(ctx, conn.ResolverLabel)
	if err != nil {
		return BurstProbeResult{
			SentCount:    packetCount,
			Qualified:    false,
			RejectReason: fmt.Sprintf("dial error: %v", err),
		}
	}
	defer func() {
		if transport.conn != nil {
			_ = transport.conn.Close()
		}
	}()

	return c.sendPipelinedMicroBurst(
		ctx,
		conn,
		transport,
		packetCount,
		downloadMTU,
		uploadMTU,
		timeout,
	)
}
```

### 3.4 Preservation of Empirical Invariants
- `probeConnectionMTU` utilizes `context.AfterFunc(ctx, func() { probeTransport.conn.Close() })`.
- This ensures any blocked UDP read socket unblocks immediately upon context cancellation.
- Independent verification command: `go test -v ./internal/client -run "TestEmpirical_ProbeConnectionMTU_Cancellation"` must continue to pass in `< 300ms` with zero goroutine leaks.

---

## 4. Deterministic In-Memory Mock: `FakeResolverProber` (`internal/client/resolver_discovery_test.go`)

### 4.1 Design & Capabilities
1. **Thread-Safe**: Uses `sync.Mutex` to protect shared state during concurrent worker pool probing.
2. **Canned Response Mapping**: Lookup by `conn.Key` with sensible default fallbacks.
3. **Simulated Delays & Asynchronous Cancellation**: Controlled `mtuDelay` and `burstDelay` using `select { case <-ctx.Done(): ... case <-time.After(delay): ... }`.
4. **Invocation Telemetry**: Tracks probed keys in arrival order (`mtuProbedKeys`, `burstProbedKeys`) and provides count accessors.
5. **Dynamic Callback Hooks**: `onProbeMTU` and `onProbeBurst` enable test-driven cancellation or state assertions mid-run.

### 4.2 Exact Code Blueprint

```go
package client

import (
	"context"
	"sync"
	"time"
)

// FakeResolverProber provides deterministic, in-memory resolver probing for unit testing.
type FakeResolverProber struct {
	mu              sync.Mutex
	mtuResponses    map[string]MTUProbeResult
	mtuErrors       map[string]error
	burstResponses  map[string]BurstProbeResult
	defaultMTU      MTUProbeResult
	defaultBurst    BurstProbeResult
	mtuProbedKeys   []string
	burstProbedKeys []string
	mtuDelay        time.Duration
	burstDelay      time.Duration
	onProbeMTU      func(conn Connection)
	onProbeBurst    func(conn Connection)
}

// NewFakeResolverProber constructs an initialized FakeResolverProber with healthy defaults.
func NewFakeResolverProber() *FakeResolverProber {
	return &FakeResolverProber{
		mtuResponses:   make(map[string]MTUProbeResult),
		mtuErrors:      make(map[string]error),
		burstResponses: make(map[string]BurstProbeResult),
		defaultMTU: MTUProbeResult{
			Success:       true,
			UploadBytes:   200,
			UploadChars:   250,
			DownloadBytes: 500,
			ResolveTime:   5 * time.Millisecond,
		},
		defaultBurst: BurstProbeResult{
			SentCount:           6,
			ReceivedCount:       6,
			LossRatio:           0.0,
			AverageRTT:          10 * time.Millisecond,
			BurstThroughputKBps: 250.0,
			ThroughputKBps:      250.0,
			DownloadMTUBytes:    500,
			Qualified:           true,
		},
	}
}

func (f *FakeResolverProber) SetMTUResponse(key string, res MTUProbeResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mtuResponses[key] = res
}

func (f *FakeResolverProber) SetMTUError(key string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mtuErrors[key] = err
}

func (f *FakeResolverProber) SetBurstResponse(key string, res BurstProbeResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.burstResponses[key] = res
}

func (f *FakeResolverProber) SetMTUDelay(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mtuDelay = d
}

func (f *FakeResolverProber) SetBurstDelay(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.burstDelay = d
}

func (f *FakeResolverProber) SetOnProbeMTU(fn func(conn Connection)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onProbeMTU = fn
}

func (f *FakeResolverProber) SetOnProbeBurst(fn func(conn Connection)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onProbeBurst = fn
}

func (f *FakeResolverProber) ProbeMTU(
	ctx context.Context,
	conn Connection,
	maxUploadPayload int,
) (MTUProbeResult, error) {
	f.mu.Lock()
	delay := f.mtuDelay
	cb := f.onProbeMTU
	res, hasRes := f.mtuResponses[conn.Key]
	err, hasErr := f.mtuErrors[conn.Key]
	if !hasRes {
		res = f.defaultMTU
	}
	f.mu.Unlock()

	if delay > 0 {
		select {
		case <-ctx.Done():
			return MTUProbeResult{Success: false, RejectReason: "context cancelled"}, ctx.Err()
		case <-time.After(delay):
		}
	}

	if ctx != nil && ctx.Err() != nil {
		return MTUProbeResult{Success: false, RejectReason: "context cancelled"}, ctx.Err()
	}

	f.mu.Lock()
	f.mtuProbedKeys = append(f.mtuProbedKeys, conn.Key)
	f.mu.Unlock()

	if cb != nil {
		cb(conn)
	}

	if hasErr && err != nil {
		return res, err
	}
	return res, nil
}

func (f *FakeResolverProber) ProbeBurst(
	ctx context.Context,
	conn Connection,
	packetCount int,
	downloadMTU int,
	uploadMTU int,
	timeout time.Duration,
) BurstProbeResult {
	f.mu.Lock()
	delay := f.burstDelay
	cb := f.onProbeBurst
	res, hasRes := f.burstResponses[conn.Key]
	if !hasRes {
		res = f.defaultBurst
		res.SentCount = packetCount
		res.DownloadMTUBytes = downloadMTU
	}
	f.mu.Unlock()

	if delay > 0 {
		select {
		case <-ctx.Done():
			return BurstProbeResult{SentCount: packetCount, Qualified: false, RejectReason: "context cancelled"}
		case <-time.After(delay):
		}
	}

	if ctx != nil && ctx.Err() != nil {
		return BurstProbeResult{SentCount: packetCount, Qualified: false, RejectReason: "context cancelled"}
	}

	f.mu.Lock()
	f.burstProbedKeys = append(f.burstProbedKeys, conn.Key)
	f.mu.Unlock()

	if cb != nil {
		cb(conn)
	}

	return res
}

func (f *FakeResolverProber) ProbedMTUKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := make([]string, len(f.mtuProbedKeys))
	copy(copied, f.mtuProbedKeys)
	return copied
}

func (f *FakeResolverProber) ProbedBurstKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := make([]string, len(f.burstProbedKeys))
	copy(copied, f.burstProbedKeys)
	return copied
}

func (f *FakeResolverProber) MTUProbedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.mtuProbedKeys)
}

func (f *FakeResolverProber) BurstProbedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.burstProbedKeys)
}
```

---

## 5. Comprehensive Unit Test Suite Design (`internal/client/resolver_discovery_test.go`)

### 5.1 Test Matrix Overview

| Test Name | Feature Under Test | Scenario & Invariants | Execution Time |
|---|---|---|---|
| `TestDiscoveryEngine_FastStartExitsEarly` | FastStart Quota Early Exit | 10 candidates configured, `TargetResolvers = 2`. Prober records `<= 3` probed endpoints; does NOT probe all 10. | `< 2ms` |
| `TestDiscoveryEngine_CandidateReplenishment_OnBurstFailure` | Burst Drop Replenishment | 5 candidates: 0 & 1 fail burst; 2 & 3 pass burst. Disqualifies 0 & 1, replenishes with 2 & 3, satisfies quota. | `< 3ms` |
| `TestDiscoveryEngine_CandidateReplenishment_OnMTUFailure` | MTU Drop Replenishment | Candidates fail upload/download MTU; engine replenishes until target quota met. | `< 2ms` |
| `TestDiscoveryEngine_WorkerCancellation_PromptExit` | Worker Goroutine Cancellation | Prober delay 50ms, context canceled after 5ms. `Run(ctx)` returns in `< 25ms` with zero goroutine leaks. | `< 30ms` |
| `TestDiscoveryEngine_QuotaCalculation_FastStartDisabled` | Full Candidate Scan | `FastStart: false`. All candidates probed and evaluated regardless of early admissions. | `< 2ms` |
| `TestDiscoveryEngine_BatchAdmission_AndPoolOverflowToStandby` | Capacity Bounding & Overflow | Admitted winners enter `StateActive`; qualified overflow enters `StateStandby`. Invariant: no candidate has both active and standby flags. | `< 2ms` |
| `TestDiscoveryEngine_MultiDomainEndpointIsolation` | Strict Key Trimming | Shared endpoint across multiple domains; trimming evaluates `conn.Key` rather than IP label. | `< 2ms` |
| `TestDiscoveryEngine_ZeroValidCandidates_ReturnsErrNoValidConnections` | Candidate Exhaustion | All candidates fail; returns `ErrNoValidConnections` cleanly without panic. | `< 1ms` |
| `TestDiscoveryEngine_WorkerPanicRecovery` | Fault Tolerance & Panics | Prober worker panics on corrupt payload; worker recovers, rejects candidate, engine completes. | `< 2ms` |
| `TestDiscoveryEngine_MicroBurstDisabled` | Configuration Flexibility | `MicroBurstEnabled: false`. MTU-valid candidates admitted directly without executing bursts. | `< 2ms` |

### 5.2 Concrete Test Suite Implementation Blueprint

```go
package client

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	"masterdnsvpn-go/internal/logger"
)

func createTestDiscoverySetup(candidateCount int) ([]*Connection, *ResolverPool, DiscoveryConfig) {
	connections := make([]*Connection, candidateCount)
	for i := 0; i < candidateCount; i++ {
		key := fmt.Sprintf("conn-%d", i+1)
		label := fmt.Sprintf("10.0.0.%d:53", i+1)
		connections[i] = &Connection{
			Key:           key,
			Domain:        "tunnel.example.com",
			Resolver:      fmt.Sprintf("10.0.0.%d", i+1),
			ResolverPort:  53,
			ResolverLabel: label,
		}
	}

	log := logger.New(logger.LevelWarn, "", 0)
	pool := NewResolverPool(10, log)
	pool.SetConnections(connections)
	pool.SetSessionMTU(150, 450)

	cfg := DiscoveryConfig{
		FastStart:             true,
		TargetResolvers:       2,
		Parallelism:           2,
		MicroBurstEnabled:     true,
		MicroBurstPacketCount: 6,
		MicroBurstParallelism: 2,
		MicroBurstTimeout:     100 * time.Millisecond,
		MaxActiveResolvers:    4,
		Domains:               []string{"tunnel.example.com"},
		UploadCaps:            map[string]int{"tunnel.example.com": 250},
		MinUploadMTU:          50,
		MaxUploadMTU:          300,
		MinDownloadMTU:        100,
		MaxDownloadMTU:        600,
	}

	return connections, pool, cfg
}

func TestDiscoveryEngine_FastStartExitsEarly(t *testing.T) {
	_, pool, cfg := createTestDiscoverySetup(10)
	prober := NewFakeResolverProber()
	engine := NewDiscoveryEngine(cfg, prober, pool, nil)

	ctx := context.Background()
	err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("expected Run() to succeed, got: %v", err)
	}

	if pool.ActiveCount() != 2 {
		t.Fatalf("expected 2 active resolvers, got: %d", pool.ActiveCount())
	}

	// Must have probed far fewer than all 10 candidates
	probedCount := prober.MTUProbedCount()
	if probedCount >= 10 {
		t.Fatalf("expected early exit, but all %d candidates were probed", probedCount)
	}
	if probedCount < 2 {
		t.Fatalf("expected at least 2 candidates probed, got %d", probedCount)
	}
}

func TestDiscoveryEngine_CandidateReplenishment_OnBurstFailure(t *testing.T) {
	_, pool, cfg := createTestDiscoverySetup(5)
	cfg.TargetResolvers = 2
	cfg.Parallelism = 2

	prober := NewFakeResolverProber()
	// Fail burst on conn-1 and conn-2
	prober.SetBurstResponse("conn-1", BurstProbeResult{
		SentCount:    6,
		LossRatio:    0.60,
		Qualified:    false,
		RejectReason: "excessive burst loss: 60.0% > 20.0%",
	})
	prober.SetBurstResponse("conn-2", BurstProbeResult{
		SentCount:    6,
		LossRatio:    0.50,
		Qualified:    false,
		RejectReason: "excessive burst loss: 50.0% > 20.0%",
	})

	engine := NewDiscoveryEngine(cfg, prober, pool, nil)
	ctx := context.Background()
	err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("expected Run() to succeed after replenishment, got: %v", err)
	}

	if pool.ActiveCount() != 2 {
		t.Fatalf("expected 2 active resolvers, got: %d", pool.ActiveCount())
	}

	active := pool.ActiveResolvers()
	for _, c := range active {
		if c.Key == "conn-1" || c.Key == "conn-2" {
			t.Fatalf("disqualified candidate %s should not be active", c.Key)
		}
	}

	if prober.MTUProbedCount() < 4 {
		t.Fatalf("expected at least 4 MTU probes due to replenishment, got %d", prober.MTUProbedCount())
	}
}

func TestDiscoveryEngine_CandidateReplenishment_OnMTUFailure(t *testing.T) {
	_, pool, cfg := createTestDiscoverySetup(5)
	cfg.TargetResolvers = 2

	prober := NewFakeResolverProber()
	prober.SetMTUResponse("conn-1", MTUProbeResult{
		Success:      false,
		RejectReason: "upload mtu probe rejected",
	})
	prober.SetMTUResponse("conn-2", MTUProbeResult{
		Success:      false,
		RejectReason: "download mtu probe rejected",
	})

	engine := NewDiscoveryEngine(cfg, prober, pool, nil)
	ctx := context.Background()
	err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("expected Run() to succeed after MTU replenishment, got: %v", err)
	}

	if pool.ActiveCount() != 2 {
		t.Fatalf("expected 2 active resolvers, got: %d", pool.ActiveCount())
	}

	active := pool.ActiveResolvers()
	for _, c := range active {
		if c.Key == "conn-1" || c.Key == "conn-2" {
			t.Fatalf("MTU-rejected candidate %s should not be active", c.Key)
		}
	}
}

func TestDiscoveryEngine_WorkerCancellation_PromptExit(t *testing.T) {
	_, pool, cfg := createTestDiscoverySetup(10)
	cfg.Parallelism = 4

	prober := NewFakeResolverProber()
	prober.SetMTUDelay(50 * time.Millisecond)

	engine := NewDiscoveryEngine(cfg, prober, pool, nil)
	ctx, cancel := context.WithCancel(context.Background())

	start := time.Now()
	time.AfterFunc(5*time.Millisecond, cancel)

	err := engine.Run(ctx)
	duration := time.Since(start)

	if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
		t.Fatalf("expected context cancellation error, got: %v", err)
	}

	if duration > 100*time.Millisecond {
		t.Fatalf("cancellation took %v, exceeded 100ms bound", duration)
	}
}

func TestDiscoveryEngine_QuotaCalculation_FastStartDisabled(t *testing.T) {
	_, pool, cfg := createTestDiscoverySetup(5)
	cfg.FastStart = false
	cfg.TargetResolvers = 2 // Should be ignored when FastStart = false

	prober := NewFakeResolverProber()
	engine := NewDiscoveryEngine(cfg, prober, pool, nil)

	ctx := context.Background()
	err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("expected Run() to succeed, got: %v", err)
	}

	if prober.MTUProbedCount() != 5 {
		t.Fatalf("expected all 5 candidates to be probed when FastStart is disabled, got: %d", prober.MTUProbedCount())
	}
}

func TestDiscoveryEngine_BatchAdmission_AndPoolOverflowToStandby(t *testing.T) {
	_, pool, cfg := createTestDiscoverySetup(5)
	cfg.MaxActiveResolvers = 2
	cfg.TargetResolvers = 2

	prober := NewFakeResolverProber()
	engine := NewDiscoveryEngine(cfg, prober, pool, nil)

	ctx := context.Background()
	err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("expected Run() to succeed, got: %v", err)
	}

	if pool.ActiveCount() != 2 {
		t.Fatalf("expected active count capped at 2, got: %d", pool.ActiveCount())
	}

	// Verify invariant: no active resolver is marked StandbyEligible
	for _, conn := range pool.ActiveResolvers() {
		if conn.StandbyEligible {
			t.Fatalf("active connection %s must not be StandbyEligible", conn.Key)
		}
	}
}

func TestDiscoveryEngine_MultiDomainEndpointIsolation(t *testing.T) {
	// Candidate 1 & 2 share same resolver IP/port on different domains
	connections := []*Connection{
		{
			Key:           "dom1-res1",
			Domain:        "dom1.example.com",
			Resolver:      "1.1.1.1",
			ResolverPort:  53,
			ResolverLabel: "1.1.1.1:53",
		},
		{
			Key:           "dom2-res1",
			Domain:        "dom2.example.com",
			Resolver:      "1.1.1.1",
			ResolverPort:  53,
			ResolverLabel: "1.1.1.1:53",
		},
	}

	log := logger.New(logger.LevelWarn, "", 0)
	pool := NewResolverPool(4, log)
	pool.SetConnections(connections)

	cfg := DiscoveryConfig{
		FastStart:             true,
		TargetResolvers:       1,
		Parallelism:           2,
		MicroBurstEnabled:     true,
		MicroBurstPacketCount: 6,
		MaxActiveResolvers:    2,
		Domains:               []string{"dom1.example.com", "dom2.example.com"},
		UploadCaps:            map[string]int{"dom1.example.com": 200, "dom2.example.com": 200},
	}

	prober := NewFakeResolverProber()
	// dom1 succeeds burst; dom2 fails burst
	prober.SetBurstResponse("dom1-res1", BurstProbeResult{Qualified: true, SentCount: 6, ReceivedCount: 6})
	prober.SetBurstResponse("dom2-res1", BurstProbeResult{Qualified: false, SentCount: 6, ReceivedCount: 0, RejectReason: "100% loss"})

	engine := NewDiscoveryEngine(cfg, prober, pool, nil)
	ctx := context.Background()
	_ = engine.Run(ctx)

	active := pool.ActiveResolvers()
	if len(active) != 1 {
		t.Fatalf("expected exactly 1 active resolver, got: %d", len(active))
	}
	if active[0].Key != "dom1-res1" {
		t.Fatalf("expected dom1-res1 to be active, got: %s", active[0].Key)
	}
}

func TestDiscoveryEngine_ZeroValidCandidates_ReturnsErrNoValidConnections(t *testing.T) {
	_, pool, cfg := createTestDiscoverySetup(3)
	prober := NewFakeResolverProber()
	prober.SetMTUResponse("conn-1", MTUProbeResult{Success: false, RejectReason: "rejected"})
	prober.SetMTUResponse("conn-2", MTUProbeResult{Success: false, RejectReason: "rejected"})
	prober.SetMTUResponse("conn-3", MTUProbeResult{Success: false, RejectReason: "rejected"})

	engine := NewDiscoveryEngine(cfg, prober, pool, nil)
	ctx := context.Background()
	err := engine.Run(ctx)

	if !errors.Is(err, ErrNoValidConnections) {
		t.Fatalf("expected ErrNoValidConnections, got: %v", err)
	}
}
```

---

## 6. Features Discovered

| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | Probing Interface | `ResolverProber.ProbeMTU` | Measures upload and download MTU capacity for a candidate connection | `ctx context.Context`, `conn Connection`, `maxUploadPayload int` | `MTUProbeResult`, `error` | Returns `Success: false` with `RejectReason` on probe failure; returns `ctx.Err()` only on context abort | `internal/client/mtu.go:1123-1163` |
| 2 | Probing Interface | `ResolverProber.ProbeBurst` | Executes pipelined micro-burst train to measure loss, RTT, and throughput | `ctx context.Context`, `conn Connection`, `packetCount int`, `downloadMTU int`, `uploadMTU int`, `timeout time.Duration` | `BurstProbeResult` | Returns `Qualified: false` with `RejectReason` on failure or cancellation | `internal/client/micro_burst.go:63-283` |
| 3 | Concrete Adapter | `UDPResolverProber` | Live UDP DNS wire implementation of `ResolverProber` | Network UDP sockets, DNS wire queries | Live probe metrics | Closes socket on `ctx` cancellation via `context.AfterFunc` | `internal/client/prober_udp.go` (new) |
| 4 | Client Method | `Client.probeConnectionMicroBurst` | Allocates UDP transport, sends burst train, and guarantees socket closure | `ctx`, `conn`, `packetCount`, `downloadMTU`, `uploadMTU`, `timeout` | `BurstProbeResult` | Closes transport socket on return | `internal/client/micro_burst.go` |
| 5 | Deterministic Mock | `FakeResolverProber` | In-memory mock prober with canned responses, delays, and telemetry | Canned maps, delays, callbacks | Canned probe metrics | Zero OS socket calls, microsecond execution | `internal/client/resolver_discovery_test.go` (new) |
| 6 | Orchestration | FastStart Early Exit | Cancels batch probing context once target unique resolvers are qualified | `batchUniqueValid >= needed` | Batch context cancellation | Terminates unneeded worker queries immediately | `internal/client/mtu.go:420-424, 479-482` |
| 7 | Orchestration | Candidate Replenishment | Batches subsequent unscanned candidates if initial candidates fail MTU or burst | Remaining unscanned candidates in pool | Replenished candidate batch | Exhausts all candidates before giving up | `internal/client/mtu.go:378-556` |
| 8 | Orchestration | Multi-Domain Isolation | Evaluates trimming against `conn.Key` to prevent cross-domain key collision on shared IPs | `qualifiedKeys map[string]struct{}` | Key-trimmed active pool | Prevents unverified domain endpoints from remaining active | `internal/client/resolver_pool.go:442-448` |
| 9 | Orchestration | Pool Capacity Admission | Commits startup batch winners to `StateActive` and qualified overflow to `StateStandby` | `results []QualifiedResolver`, `selected []Connection` | Updated `ResolverPool` | Enforces mutual exclusivity between active and standby | `internal/client/resolver_pool.go:392-433` |
| 10 | Orchestration | Worker Panic Recovery | Catches worker panic during probe, records rejection, and continues batch | Corrupt packet / panic in prober | `completed: true`, rejected counter incremented | Recovers via `recover()`, no process crash | `internal/client/mtu.go:1016-1043` |

---

## 7. Edge Cases & Observed Behavior

| # | Feature | Input / Condition | Observed / Required Behavior |
|---|---------|-------------------|-----------------------------|
| 1 | FastStart Cancellation | Outer context canceled during UDP MTU probe | `context.AfterFunc` immediately closes UDP connection; probe returns in `< 300ms` with zero goroutine leaks (`TestEmpirical_ProbeConnectionMTU_Cancellation`). |
| 2 | FastStart Target Quota | 10 candidates configured, target = 2 | Prober cancels batch context as soon as 2 unique endpoints qualify; unprobed candidates remain untested (`TestDiscoveryEngine_FastStartExitsEarly`). |
| 3 | Burst Failure Replenishment | Initial candidates pass MTU but fail micro-burst | Discovery engine marks failing candidates disqualified, batches remaining candidates, and satisfies quota (`TestDiscoveryEngine_CandidateReplenishment_OnBurstFailure`). |
| 4 | MTU Failure Replenishment | Initial candidates fail upload or download MTU | Discovery engine records MTU failure and replenishes from remaining candidates (`TestDiscoveryEngine_CandidateReplenishment_OnMTUFailure`). |
| 5 | Multi-domain Endpoint Sharing | 2 domains share 1 physical resolver IP:port; domain 1 qualifies, domain 2 fails burst | Trimming must evaluate `qualifiedKeys[conn.Key]` rather than `conn.ResolverLabel`, preventing domain 2 from remaining active (`TestDiscoveryEngine_MultiDomainEndpointIsolation`). |
| 6 | Active/Standby Exclusivity | Candidate admitted to active pool | Connection must have `IsValid=true` and `StandbyEligible=false`; connection overflow has `IsValid=false` and `StandbyEligible=true` (`TestDiscoveryEngine_BatchAdmission_AndPoolOverflowToStandby`). |
| 7 | Full Scan on Recheck Disabled | `FastStart: false` (`RecheckInactiveServersEnabled=false`) | Discovery engine disables early exit and scans all candidate connections (`TestDiscoveryEngine_QuotaCalculation_FastStartDisabled`). |
| 8 | Fewer Resolvers Than Target | Total functional resolvers < `RX_TX_Workers` | Discovery engine tests all available candidates and successfully starts with whatever resolvers qualify. |
| 9 | Zero Valid Resolvers | All candidates fail MTU or burst | Discovery engine returns `ErrNoValidConnections` cleanly without panic (`TestDiscoveryEngine_ZeroValidCandidates_ReturnsErrNoValidConnections`). |
| 10 | Worker Goroutine Panic | Prober worker encounters panic on corrupt query | Panic is caught with `recover()`, candidate rejected, total counter updated, other workers continue safely (`TestDiscoveryEngine_WorkerPanicRecovery`). |
| 11 | Micro-Burst Disabled | `MicroBurstEnabled: false` | All MTU-valid candidates are directly admitted without executing micro-burst probing (`TestDiscoveryEngine_MicroBurstDisabled`). |

---

## 8. Worker Recommendations & Implementation Roadmap

1. **Step 1: Create `internal/client/prober_udp.go`**:
   - Define `MTUProbeResult` and `ResolverProber` interface.
   - Implement `UDPResolverProber` with `NewUDPResolverProber(client *Client)`.
   - Add `probeConnectionMicroBurst` method on `*Client` in `internal/client/micro_burst.go` (or `prober_udp.go`).
2. **Step 2: Create `internal/client/resolver_discovery_test.go`**:
   - Implement `FakeResolverProber` as defined in §4.2.
   - Implement the test suite defined in §5.2.
3. **Step 3: Keep Existing UDP Benchmarks**:
   - Retain `TestEmpirical_ProbeConnectionMTU_Cancellation` in `empirical_challenge_test.go` to safeguard live socket cancellation behavior.
4. **Step 4: Run Verification**:
   - `go test -v ./internal/client -run "TestDiscoveryEngine.*"`
   - `go test -v ./internal/client -run "TestEmpirical_ProbeConnectionMTU_Cancellation"`
   - `go test ./internal/client`
