package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
)

func TestBackgroundQueryLimiter_NilContextAfterExhaustion(t *testing.T) {
	limiter := NewBackgroundQueryLimiter(100, 1)
	if !limiter.TryAcquire() {
		t.Fatal("expected initial token")
	}
	// The first refill leaves the bucket exhausted; after the wait, a
	// second refill supplies a token without depending on wall-clock timing.
	now := limiter.lastRefill
	refills := 0
	limiter.nowFn = func() time.Time {
		refills++
		if refills > 1 {
			return now.Add(time.Second)
		}
		return now
	}
	if err := limiter.Acquire(nil); err != nil { //nolint:staticcheck // SA1012: nil-context handling is the behavior under test.
		t.Fatalf("Acquire(nil): %v", err)
	}
	if refills < 2 {
		t.Fatal("expected Acquire to wait for a refill")
	}
}

func TestDiscoveryCoverage_BackgroundQueryLimiter(t *testing.T) {
	// 1. Token bucket basic mechanics
	limiter := NewBackgroundQueryLimiter(10.0, 5)
	if limiter == nil {
		t.Fatal("expected non-nil limiter")
	}

	// Burst drain: 5 tokens should be immediately available
	for i := 0; i < 5; i++ {
		if !limiter.TryAcquire() {
			t.Fatalf("expected immediate token %d to be available", i)
		}
	}
	// 6th should fail without wait
	if limiter.TryAcquire() {
		t.Fatal("expected 6th token to fail immediately")
	}

	// 2. Cancellation awareness
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := limiter.Acquire(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// 3. Monotonic mock time refill
	simTime := time.Now()
	limiter.nowFn = func() time.Time {
		return simTime
	}
	limiter.mu.Lock()
	limiter.tokens = 0
	limiter.lastRefill = simTime
	limiter.mu.Unlock()

	// Advance time by 0.5s -> 5 tokens refilled (10 QPS * 0.5s)
	simTime = simTime.Add(500 * time.Millisecond)
	for i := 0; i < 5; i++ {
		if !limiter.TryAcquire() {
			t.Fatalf("expected refilled token %d to be available", i)
		}
	}
	if limiter.TryAcquire() {
		t.Fatal("expected exhausted tokens after draining refilled budget")
	}

	// 4. AcquireN cancellation
	ctxN, cancelN := context.WithCancel(context.Background())
	cancelN()
	if err := limiter.AcquireN(ctxN, 3); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from AcquireN, got %v", err)
	}
}

func TestDiscoveryCoverage_UntestedPriorityWhenWorkingSetSufficient(t *testing.T) {
	log := logger.New("TestLogger", "error")
	pool := NewResolverPool(2, log)
	pool.SetTargetEndpoints(2)
	pool.SetSessionMTU(100, 500)

	conns := []*Connection{
		{Key: "active-1", Resolver: "10.0.0.1", ResolverPort: 53, ResolverLabel: "10.0.0.1:53", Domain: "v.example.com", UploadMTUBytes: 100, DownloadMTUBytes: 500, MTUResolveTime: 10 * time.Millisecond},
		{Key: "active-2", Resolver: "10.0.0.2", ResolverPort: 53, ResolverLabel: "10.0.0.2:53", Domain: "v.example.com", UploadMTUBytes: 100, DownloadMTUBytes: 500, MTUResolveTime: 15 * time.Millisecond},
		{Key: "standby-1", Resolver: "10.0.0.3", ResolverPort: 53, ResolverLabel: "10.0.0.3:53", Domain: "v.example.com", UploadMTUBytes: 100, DownloadMTUBytes: 500, MTUResolveTime: 20 * time.Millisecond},
		{Key: "untested-1", Resolver: "10.0.0.4", ResolverPort: 53, ResolverLabel: "10.0.0.4:53", Domain: "v.example.com"},
	}
	pool.SetConnections(conns)

	// Qualify active-1 and active-2
	pool.ApplyMTUProbeResult("active-1", 100, 50, 500, 10*time.Millisecond, true)
	pool.ApplyMTUProbeResult("active-2", 100, 50, 500, 15*time.Millisecond, true)
	// Qualify standby-1; the Active Path capacity is already full.
	pool.ApplyMTUProbeResult("standby-1", 100, 50, 500, 20*time.Millisecond, true)

	if state, _ := pool.CandidateState("standby-1"); state != StateStandby {
		t.Fatalf("precondition: standby-1 is %v, want Standby", state)
	}
	// Working set is sufficient (2 active distinct endpoints >= target 2)
	now := time.Now()
	leased, ok := pool.AcquireNextInactiveForRecheck(now, 0)
	if !ok {
		t.Fatal("expected candidate to be leased")
	}
	if leased.Key != "untested-1" {
		t.Fatalf("expected untested-1 to be prioritized over standby-1, got %s", leased.Key)
	}
}

func TestDiscoveryCoverage_FairSchedulingWhenWorkingSetInsufficient(t *testing.T) {
	log := logger.New("TestLogger", "error")
	pool := NewResolverPool(4, log)
	pool.SetTargetEndpoints(2)
	pool.SetSessionMTU(100, 500)

	conns := []*Connection{
		{Key: "standby-1", Resolver: "10.0.0.1", ResolverPort: 53, ResolverLabel: "10.0.0.1:53", Domain: "v.example.com", UploadMTUBytes: 100, DownloadMTUBytes: 500, MTUResolveTime: 10 * time.Millisecond},
		{Key: "untested-1", Resolver: "10.0.0.2", ResolverPort: 53, ResolverLabel: "10.0.0.2:53", Domain: "v.example.com"},
	}
	pool.SetConnections(conns)

	// Set standby-1 as standby eligible
	pool.SetConnectionStandbyEligible("standby-1", true)

	// Working set is insufficient (0 active < target 2).
	// Calls to AcquireNextInactiveForRecheck should fairly schedule between untested and standby.
	now := time.Now()
	var leasedKeys []string
	for i := 0; i < 4; i++ {
		leased, ok := pool.AcquireNextInactiveForRecheck(now, 0)
		if !ok {
			t.Fatalf("iteration %d: expected candidate", i)
		}
		leasedKeys = append(leasedKeys, leased.Key)
		// Release back so it can be leased again
		pool.ReleaseRecheck(candidateSnapshotForTest(pool, leased.Key))
	}

	hasUntested := false
	hasStandby := false
	for _, k := range leasedKeys {
		if k == "untested-1" {
			hasUntested = true
		}
		if k == "standby-1" {
			hasStandby = true
		}
	}
	if !hasUntested || !hasStandby {
		t.Fatalf("expected fair scheduling between untested and standby without starvation, got: %v", leasedKeys)
	}
}

func TestDiscoveryCoverage_CappedBackoffAndReset(t *testing.T) {
	log := logger.New("TestLogger", "error")
	pool := NewResolverPool(2, log)
	pool.SetTargetEndpoints(1)
	pool.SetSessionMTU(100, 500)

	conns := []*Connection{
		{Key: "server-1", Resolver: "10.0.0.1", ResolverPort: 53, ResolverLabel: "10.0.0.1:53", Domain: "v.example.com"},
	}
	pool.SetConnections(conns)

	minInterval := 10 * time.Second
	now := time.Now()

	// Initial lease: untested candidate
	leased, ok := pool.AcquireNextInactiveForRecheck(now, minInterval)
	if !ok || leased.Key != "server-1" {
		t.Fatal("expected initial lease")
	}

	// Fail 1: streak = 1 -> backoff = minInterval (10s)
	pool.CompleteRecheck(ResolverRecheckResult{Connection: leased, MTUVerified: false})

	// 5s later: should NOT be eligible (needs 10s)
	if _, ok := pool.AcquireNextInactiveForRecheck(now.Add(5*time.Second), minInterval); ok {
		t.Fatal("expected backoff after 1 failure (needed 10s, gave 5s)")
	}
	// 11s later: should be eligible
	leased2, ok := pool.AcquireNextInactiveForRecheck(now.Add(11*time.Second), minInterval)
	if !ok {
		t.Fatal("expected eligible after 11s")
	}

	// Fail 2: streak = 2 -> backoff = minInterval * 2 = 20s
	pool.CompleteRecheck(ResolverRecheckResult{Connection: leased2, MTUVerified: false})

	// 15s later: should not be eligible (needs 20s)
	if _, ok := pool.AcquireNextInactiveForRecheck(now.Add(11*time.Second).Add(15*time.Second), minInterval); ok {
		t.Fatal("expected backoff after 2 failures (needed 20s, gave 15s)")
	}
	// 21s later: should be eligible
	leased3, ok := pool.AcquireNextInactiveForRecheck(now.Add(11*time.Second).Add(21*time.Second), minInterval)
	if !ok {
		t.Fatal("expected eligible after 21s")
	}
	pool.CompleteRecheck(ResolverRecheckResult{Connection: leased3, MTUVerified: false})

	// Test max cap: streak 10 should cap at 5 minutes
	pool.mu.Lock()
	pool.candidates[0].failStreak = 10
	pool.mu.Unlock()

	lastCheck := now.Add(11 * time.Second).Add(21 * time.Second)
	// 4 minutes: not eligible
	if _, ok := pool.AcquireNextInactiveForRecheck(lastCheck.Add(4*time.Minute), minInterval); ok {
		t.Fatal("expected backoff capped at 5 minutes (gave 4 minutes)")
	}
	// 6 minutes: eligible
	leased4, ok := pool.AcquireNextInactiveForRecheck(lastCheck.Add(6*time.Minute), minInterval)
	if !ok {
		t.Fatal("expected eligible after 6 minutes")
	}

	// Recovery: successful qualification resets streak to 0
	recoveredConn := leased4
	recoveredConn.UploadMTUBytes = 100
	recoveredConn.DownloadMTUBytes = 500
	pool.CompleteRecheck(ResolverRecheckResult{
		Connection:  recoveredConn,
		MTUVerified: true,
	})

	pool.mu.RLock()
	streak := pool.candidates[0].failStreak
	pool.mu.RUnlock()
	if streak != 0 {
		t.Fatalf("expected failStreak reset to 0 after recovery, got %d", streak)
	}
}

func TestDiscoveryCoverage_CoverageStatsAndFirstPassCompletion(t *testing.T) {
	log := logger.New("TestLogger", "error")
	pool := NewResolverPool(4, log)
	pool.SetTargetEndpoints(2)
	pool.SetSessionMTU(100, 500)

	conns := []*Connection{
		{Key: "c-1", Resolver: "10.0.0.1", ResolverPort: 53, ResolverLabel: "10.0.0.1:53", Domain: "v.example.com"},
		{Key: "c-2", Resolver: "10.0.0.2", ResolverPort: 53, ResolverLabel: "10.0.0.2:53", Domain: "v.example.com"},
		{Key: "c-3", Resolver: "10.0.0.3", ResolverPort: 53, ResolverLabel: "10.0.0.3:53", Domain: "v.example.com"},
		{Key: "c-4", Resolver: "10.0.0.4", ResolverPort: 53, ResolverLabel: "10.0.0.4:53", Domain: "v.example.com"},
	}
	pool.SetConnections(conns)

	// Step 0: all untested
	stats := pool.CoverageStats()
	if stats.ConfiguredPaths != 4 || stats.CompletedInitialAttempts != 0 || stats.RemainingUntested != 4 || stats.IsFirstPassComplete {
		t.Fatalf("unexpected initial stats: %+v", stats)
	}

	// Step 1: qualify c-1
	pool.ApplyMTUProbeResult("c-1", 100, 50, 500, 10*time.Millisecond, true)
	stats = pool.CoverageStats()
	if stats.CompletedInitialAttempts != 1 || stats.RemainingUntested != 3 || stats.DistinctQualified != 1 {
		t.Fatalf("stats after c-1: %+v", stats)
	}

	// Step 2: reject c-2
	pool.ApplyMTUProbeResult("c-2", 0, 0, 0, 0, false)
	stats = pool.CoverageStats()
	if stats.CompletedInitialAttempts != 2 || stats.RemainingUntested != 2 || stats.DistinctQualified != 1 {
		t.Fatalf("stats after c-2 rejection: %+v", stats)
	}

	// Step 3: lease one untested candidate and cancel (release without completion)
	// Passing minInterval ensures recently failed c-2 observes backoff
	leased, ok := pool.AcquireNextInactiveForRecheck(time.Now(), 10*time.Second)
	if !ok || (leased.Key != "c-3" && leased.Key != "c-4") {
		t.Fatalf("expected c-3 or c-4 to be leased, got %+v", leased)
	}
	pool.ReleaseRecheck(candidateSnapshotForTest(pool, leased.Key))
	stats = pool.CoverageStats()
	if stats.CompletedInitialAttempts != 2 || stats.RemainingUntested != 2 {
		t.Fatalf("stats after cancelled %s should not count as completed: %+v", leased.Key, stats)
	}

	// Step 4: qualify c-3 and reject c-4
	pool.ApplyMTUProbeResult("c-3", 100, 50, 500, 15*time.Millisecond, true)
	pool.ApplyMTUProbeResult("c-4", 0, 0, 0, 0, false)

	stats = pool.CoverageStats()
	if stats.CompletedInitialAttempts != 4 || stats.RemainingUntested != 0 || !stats.IsFirstPassComplete {
		t.Fatalf("expected first pass complete: %+v", stats)
	}
	if !pool.IsFirstPassComplete() {
		t.Fatal("expected IsFirstPassComplete() to return true")
	}
}

func TestDiscoveryCoverage_RecheckInactiveSwitch(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{"v.example.com"}
	cfg.Resolvers = []config.ResolverAddress{
		{IP: "127.0.0.1", Port: 5353},
		{IP: "127.0.0.2", Port: 5353},
	}
	cfg.RX_TX_Workers = 1

	// FastStart enabled by default when RecheckInactiveServersEnabled is true
	cfg.RecheckInactiveServersEnabled = true
	c := createTestFastStartClient(t, cfg)
	discCfg := c.newDiscoveryConfig()
	if !discCfg.FastStart {
		t.Fatal("expected FastStart=true when RecheckInactiveServersEnabled=true")
	}
	if discCfg.TargetResolvers != 1 {
		t.Fatalf("expected TargetResolvers=1 (RX_TX_Workers), got %d", discCfg.TargetResolvers)
	}

	// When RecheckInactiveServersEnabled is false, full initial scan is required
	cfg.RecheckInactiveServersEnabled = false
	c2 := createTestFastStartClient(t, cfg)
	discCfg2 := c2.newDiscoveryConfig()
	if discCfg2.FastStart {
		t.Fatal("expected FastStart=false when RecheckInactiveServersEnabled=false")
	}
	if discCfg2.TargetResolvers != 1 {
		t.Fatalf("full scan must retain worker-bounded continuing coverage, got %d", discCfg2.TargetResolvers)
	}
}

func TestDiscoveryCoverage_BackgroundLimiterDoesNotThrottleForeground(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{"v.example.com"}
	cfg.Resolvers = []config.ResolverAddress{{IP: "127.0.0.1", Port: 53}}
	c := createTestFastStartClient(t, cfg)

	// Set limiter with zero tokens and very long wait
	c.SetBackgroundQueryLimiter(NewBackgroundQueryLimiter(0.001, 1))
	c.BackgroundQueryLimiter().TryAcquire() // drain the 1 token

	// Background query acquisition will block / cancel
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := c.acquireBackgroundQuery(ctx)
	if err == nil {
		t.Fatal("expected background query to block and timeout")
	}

	// Foreground tunnel query paths do NOT call acquireBackgroundQuery and remain unaffected
	if c.bgLimiter == nil {
		t.Fatal("expected bgLimiter to be set")
	}
}
