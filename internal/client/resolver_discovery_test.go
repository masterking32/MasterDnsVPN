// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides unit tests for DiscoveryEngine using FakeResolverProber.
// ==============================================================================
package client

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"masterdnsvpn-go/internal/logger"
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

	log := logger.New("TestLogger", "warn")
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

	probedCount := prober.MTUProbedCount()
	if probedCount >= 10 {
		t.Fatalf("expected early exit, but all %d candidates were probed", probedCount)
	}
	if probedCount < 2 {
		t.Fatalf("expected at least 2 candidates probed, got %d", probedCount)
	}
}

func TestDiscoveryEngine_Replenishment_OnBurstFailure(t *testing.T) {
	_, pool, cfg := createTestDiscoverySetup(5)
	cfg.TargetResolvers = 2
	cfg.Parallelism = 2

	prober := NewFakeResolverProber()
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

func TestDiscoveryEngine_ContextCancellationPrompt(t *testing.T) {
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

	if duration > 1*time.Second {
		t.Fatalf("cancellation took %v, exceeded 1s bound", duration)
	}
}

func TestDiscoveryEngine_FullScanWhenFastStartDisabled(t *testing.T) {
	_, pool, cfg := createTestDiscoverySetup(5)
	cfg.FastStart = false
	cfg.TargetResolvers = 2 // Ignored when FastStart = false

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

func TestDiscoveryEngine_ActiveStandbyAllocation(t *testing.T) {
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

	for _, conn := range pool.ActiveResolvers() {
		if conn.StandbyEligible {
			t.Fatalf("active connection %s must not be StandbyEligible", conn.Key)
		}
	}
}

func TestDiscoveryEngine_MultiDomainExclusivity(t *testing.T) {
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

	log := logger.New("TestLogger", "warn")
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

func TestDiscoveryEngine_CapacityBounding(t *testing.T) {
	_, pool, cfg := createTestDiscoverySetup(6)
	cfg.MaxActiveResolvers = 3
	cfg.TargetResolvers = 5

	prober := NewFakeResolverProber()
	engine := NewDiscoveryEngine(cfg, prober, pool, nil)

	ctx := context.Background()
	err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("expected Run() to succeed, got: %v", err)
	}

	if pool.ActiveCount() > 3 {
		t.Fatalf("expected active count <= 3, got: %d", pool.ActiveCount())
	}

	activeMap := make(map[string]bool)
	for _, conn := range pool.ActiveResolvers() {
		activeMap[conn.Key] = true
		if conn.StandbyEligible {
			t.Fatalf("active connection %s cannot be StandbyEligible", conn.Key)
		}
	}
}

func TestDiscoveryEngine_ZeroValidReturnsError(t *testing.T) {
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

func TestDiscoveryEngine_WorkerPanicRecovery(t *testing.T) {
	_, pool, cfg := createTestDiscoverySetup(4)
	cfg.TargetResolvers = 2

	prober := NewFakeResolverProber()
	prober.SetOnProbeMTU(func(conn Connection) {
		if conn.Key == "conn-1" {
			panic("simulated prober panic")
		}
	})

	engine := NewDiscoveryEngine(cfg, prober, pool, nil)
	ctx := context.Background()
	err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("expected Run() to succeed despite panic on conn-1, got: %v", err)
	}

	if pool.ActiveCount() != 2 {
		t.Fatalf("expected 2 active resolvers, got: %d", pool.ActiveCount())
	}

	for _, c := range pool.ActiveResolvers() {
		if c.Key == "conn-1" {
			t.Fatalf("panicking candidate conn-1 must not be active")
		}
	}
}

func TestDiscoveryEngine_MicroBurstDisabled(t *testing.T) {
	_, pool, cfg := createTestDiscoverySetup(3)
	cfg.MicroBurstEnabled = false
	cfg.TargetResolvers = 2

	prober := NewFakeResolverProber()
	engine := NewDiscoveryEngine(cfg, prober, pool, nil)

	ctx := context.Background()
	err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("expected Run() to succeed, got: %v", err)
	}

	if prober.BurstProbedCount() != 0 {
		t.Fatalf("expected 0 burst probes when MicroBurstEnabled is false, got: %d", prober.BurstProbedCount())
	}

	if pool.ActiveCount() != 2 {
		t.Fatalf("expected 2 active resolvers, got: %d", pool.ActiveCount())
	}
}

func TestDiscoveryEngine_PreserveQualifiedStandbyOnOptimize(t *testing.T) {
	// Setup 3 candidates: conn-1, conn-2, conn-3.
	// TargetResolvers = 2, MaxActiveResolvers = 2.
	// All 3 qualify in bursts. conn-1 & conn-2 are active winners, conn-3 is standby.
	// Optimize can promote standby conn-3.
	// FinalizeFastStart must recognize conn-3 as qualified (in qualifiedKeys)
	// and NOT deactivate it as unqualified.
	pool := NewResolverPool(2, nil)
	conn1 := Connection{Key: "conn-1", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", Domain: "example.com", DownloadMTUBytes: 500, UploadMTUBytes: 200}
	conn2 := Connection{Key: "conn-2", Resolver: "2.2.2.2", ResolverPort: 53, ResolverLabel: "2.2.2.2:53", Domain: "example.com", DownloadMTUBytes: 500, UploadMTUBytes: 200}
	conn3 := Connection{Key: "conn-3", Resolver: "3.3.3.3", ResolverPort: 53, ResolverLabel: "3.3.3.3:53", Domain: "example.com", DownloadMTUBytes: 500, UploadMTUBytes: 200}
	pool.SetConnections([]*Connection{&conn1, &conn2, &conn3})
	pool.SetSessionMTU(100, 300)

	cfg := DiscoveryConfig{
		FastStart:             true,
		TargetResolvers:       2,
		Parallelism:           3,
		MaxActiveResolvers:    2,
		MicroBurstEnabled:     true,
		MicroBurstPacketCount: 6,
		MicroBurstParallelism: 3,
		MicroBurstTimeout:     time.Second,
		Domains:               []string{"example.com"},
	}

	prober := NewFakeResolverProber()
	prober.SetBurstResponse("conn-1", BurstProbeResult{SentCount: 6, ReceivedCount: 6, LossRatio: 0, AverageRTT: 20 * time.Millisecond, BurstThroughputKBps: 200, Qualified: true})
	prober.SetBurstResponse("conn-2", BurstProbeResult{SentCount: 6, ReceivedCount: 6, LossRatio: 0, AverageRTT: 25 * time.Millisecond, BurstThroughputKBps: 180, Qualified: true})
	prober.SetBurstResponse("conn-3", BurstProbeResult{SentCount: 6, ReceivedCount: 6, LossRatio: 0, AverageRTT: 15 * time.Millisecond, BurstThroughputKBps: 220, Qualified: true})

	engine := NewDiscoveryEngine(cfg, prober, pool, nil)
	ctx := context.Background()
	if err := engine.Run(ctx, []Connection{conn1, conn2, conn3}); err != nil {
		t.Fatalf("engine.Run() failed: %v", err)
	}

	if pool.ActiveCount() != 2 {
		t.Fatalf("expected 2 active resolvers after FinalizeFastStart, got %d", pool.ActiveCount())
	}
}

func TestDiscoveryEngine_CountAdmittedEndpointsFastStartQuota(t *testing.T) {
	// Endpoint A has 2 domain connections: conn-A1 (d1), conn-A2 (d2).
	// Endpoint B has 1 domain connection: conn-B1 (d1).
	// TargetResolvers = 2 (quota requires 2 unique endpoints), MaxActiveResolvers = 2.
	// If batch 1 probes conn-A1 & conn-A2, both occupy the 2 slots.
	// But that's only ONE unique endpoint (A).
	// Discovery must NOT stop; it must continue to probe conn-B1 in the next batch
	// to satisfy the 2-endpoint quota.
	pool := NewResolverPool(2, nil)
	connA1 := Connection{Key: "A:d1", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", Domain: "d1.com", DownloadMTUBytes: 500, UploadMTUBytes: 200}
	connA2 := Connection{Key: "A:d2", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", Domain: "d2.com", DownloadMTUBytes: 500, UploadMTUBytes: 200}
	connB1 := Connection{Key: "B:d1", Resolver: "2.2.2.2", ResolverPort: 53, ResolverLabel: "2.2.2.2:53", Domain: "d1.com", DownloadMTUBytes: 500, UploadMTUBytes: 200}
	pool.SetConnections([]*Connection{&connA1, &connA2, &connB1})
	pool.SetSessionMTU(100, 300)

	cfg := DiscoveryConfig{
		FastStart:             true,
		TargetResolvers:       2,
		Parallelism:           2,
		MaxActiveResolvers:    2,
		MicroBurstEnabled:     true,
		MicroBurstPacketCount: 6,
		MicroBurstParallelism: 2,
		MicroBurstTimeout:     time.Second,
		Domains:               []string{"d1.com", "d2.com"},
	}

	prober := NewFakeResolverProber()
	prober.SetBurstResponse("A:d1", BurstProbeResult{SentCount: 6, ReceivedCount: 6, LossRatio: 0, AverageRTT: 20 * time.Millisecond, BurstThroughputKBps: 200, Qualified: true})
	prober.SetBurstResponse("A:d2", BurstProbeResult{SentCount: 6, ReceivedCount: 6, LossRatio: 0, AverageRTT: 20 * time.Millisecond, BurstThroughputKBps: 200, Qualified: true})
	prober.SetBurstResponse("B:d1", BurstProbeResult{SentCount: 6, ReceivedCount: 6, LossRatio: 0, AverageRTT: 15 * time.Millisecond, BurstThroughputKBps: 250, Qualified: true})

	engine := NewDiscoveryEngine(cfg, prober, pool, nil)
	ctx := context.Background()
	if err := engine.Run(ctx); err != nil {
		t.Fatalf("engine.Run() failed: %v", err)
	}

	t.Logf("Probed MTU keys: %v", prober.ProbedMTUKeys())
	t.Logf("Probed Burst keys: %v", prober.ProbedBurstKeys())
	bProbed := false
	for _, k := range prober.ProbedBurstKeys() {
		if k == "B:d1" {
			bProbed = true
			break
		}
	}
	if !bProbed {
		t.Fatal("expected candidate B:d1 to be burst-probed because quota of 2 unique endpoints was not met by endpoint A alone")
	}

	endpoints := make(map[string]bool)
	for _, c := range pool.ActiveResolvers() {
		endpoints[c.ResolverLabel] = true
	}
	if len(endpoints) < 2 {
		t.Fatalf("expected 2 unique endpoints in active pool, got %d (%v)", len(endpoints), endpoints)
	}
}

func TestDiscoveryEngine_OnMTUSuccessCallback(t *testing.T) {
	_, pool, cfg := createTestDiscoverySetup(3)
	cfg.TargetResolvers = 2

	var mu sync.Mutex
	var reportedConns []Connection
	cfg.OnMTUSuccess = func(conn Connection) {
		mu.Lock()
		defer mu.Unlock()
		reportedConns = append(reportedConns, conn)
	}

	prober := NewFakeResolverProber()
	prober.SetMTUResponse("conn-1", MTUProbeResult{Success: true, UploadBytes: 200, UploadChars: 250, DownloadBytes: 500, ResolveTime: 5 * time.Millisecond})
	prober.SetMTUResponse("conn-2", MTUProbeResult{Success: false, RejectReason: "rejected"})
	prober.SetMTUResponse("conn-3", MTUProbeResult{Success: true, UploadBytes: 200, UploadChars: 250, DownloadBytes: 500, ResolveTime: 5 * time.Millisecond})

	engine := NewDiscoveryEngine(cfg, prober, pool, nil)
	ctx := context.Background()
	if err := engine.Run(ctx); err != nil {
		t.Fatalf("engine.Run() failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(reportedConns) != 2 {
		t.Fatalf("expected 2 successful MTU connections reported to OnMTUSuccess, got %d", len(reportedConns))
	}
	for _, c := range reportedConns {
		if c.Key == "conn-2" {
			t.Fatal("failed MTU probe conn-2 must not be reported to OnMTUSuccess")
		}
	}
}

func TestDiscoveryEngine_ReserveDistinctEndpointsQuotaWithSlowerCandidate(t *testing.T) {
	// Scenario:
	// Two faster pairings on Endpoint A (A:d1, A:d2).
	// A slower qualified pairing on Endpoint B (B:d1).
	// Additional unresponsive candidates (C:d1 fails MTU, D:d1 fails burst).
	// TargetResolvers = 2, MaxActiveResolvers = 2 (capacity 2).
	// Selection and optimization must honor the unique-endpoint quota within capacity,
	// admitting both A and B, rather than letting A's two faster pairings crowd out B.
	pool := NewResolverPool(2, nil)

	connA1 := Connection{Key: "A:d1", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", Domain: "d1.com", DownloadMTUBytes: 500, UploadMTUBytes: 200}
	connA2 := Connection{Key: "A:d2", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", Domain: "d2.com", DownloadMTUBytes: 500, UploadMTUBytes: 200}
	connB1 := Connection{Key: "B:d1", Resolver: "2.2.2.2", ResolverPort: 53, ResolverLabel: "2.2.2.2:53", Domain: "d1.com", DownloadMTUBytes: 500, UploadMTUBytes: 200}
	connC1 := Connection{Key: "C:d1", Resolver: "3.3.3.3", ResolverPort: 53, ResolverLabel: "3.3.3.3:53", Domain: "d1.com", DownloadMTUBytes: 500, UploadMTUBytes: 200}
	connD1 := Connection{Key: "D:d1", Resolver: "4.4.4.4", ResolverPort: 53, ResolverLabel: "4.4.4.4:53", Domain: "d2.com", DownloadMTUBytes: 500, UploadMTUBytes: 200}

	pool.SetConnections([]*Connection{&connA1, &connA2, &connB1, &connC1, &connD1})
	pool.SetSessionMTU(100, 300)

	cfg := DiscoveryConfig{
		FastStart:             true,
		TargetResolvers:       2,
		Parallelism:           2,
		MaxActiveResolvers:    2,
		MicroBurstEnabled:     true,
		MicroBurstPacketCount: 6,
		MicroBurstParallelism: 2,
		MicroBurstTimeout:     time.Second,
		Domains:               []string{"d1.com", "d2.com"},
	}

	prober := NewFakeResolverProber()
	// Two fast pairings on endpoint A
	prober.SetBurstResponse("A:d1", BurstProbeResult{SentCount: 6, ReceivedCount: 6, LossRatio: 0, AverageRTT: 10 * time.Millisecond, BurstThroughputKBps: 300, Qualified: true})
	prober.SetBurstResponse("A:d2", BurstProbeResult{SentCount: 6, ReceivedCount: 6, LossRatio: 0, AverageRTT: 12 * time.Millisecond, BurstThroughputKBps: 280, Qualified: true})

	// Slower qualified pairing on endpoint B
	prober.SetBurstResponse("B:d1", BurstProbeResult{SentCount: 6, ReceivedCount: 6, LossRatio: 0, AverageRTT: 45 * time.Millisecond, BurstThroughputKBps: 120, Qualified: true})

	// Unresponsive candidates
	prober.SetMTUResponse("C:d1", MTUProbeResult{Success: false, RejectReason: "mtu timeout"})
	prober.SetBurstResponse("D:d1", BurstProbeResult{SentCount: 6, ReceivedCount: 0, LossRatio: 1.0, Qualified: false})

	engine := NewDiscoveryEngine(cfg, prober, pool, nil)
	ctx := context.Background()
	if err := engine.Run(ctx); err != nil {
		t.Fatalf("engine.Run() failed: %v", err)
	}

	active := pool.ActiveResolvers()
	if len(active) != 2 {
		t.Fatalf("expected exactly 2 active resolvers, got %d", len(active))
	}

	activeEndpoints := make(map[string]bool)
	for _, c := range active {
		activeEndpoints[c.ResolverLabel] = true
	}

	if !activeEndpoints["1.1.1.1:53"] {
		t.Fatalf("expected endpoint 1.1.1.1:53 to be active, got: %v", activeEndpoints)
	}
	if !activeEndpoints["2.2.2.2:53"] {
		t.Fatalf("expected endpoint 2.2.2.2:53 to be active, got: %v", activeEndpoints)
	}
	if activeEndpoints["3.3.3.3:53"] || activeEndpoints["4.4.4.4:53"] {
		t.Fatalf("unresponsive endpoints should not be active, got: %v", activeEndpoints)
	}
}
