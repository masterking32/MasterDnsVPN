package client

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestStartupQualificationDomainRetry(t *testing.T) {
	conns, pool, cfg := createTestDiscoverySetup(2)
	conns[1].ResolverLabel = conns[0].ResolverLabel
	conns[1].Resolver = conns[0].Resolver
	conns[1].Domain = "alternate.example.com"
	cfg.Domains = append(cfg.Domains, conns[1].Domain)
	pool.SetConnections(conns)
	cfg.FastStart = true
	cfg.TargetResolvers = 1
	cfg.Parallelism = 1
	prober := NewFakeResolverProber()
	prober.SetBurstResponse(conns[0].Key, BurstProbeResult{SentCount: 6})
	if err := NewDiscoveryEngine(cfg, prober, pool, nil).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if prober.BurstProbedCount() != 2 {
		t.Fatal("alternate pairing was skipped")
	}
}

func TestStartupQualificationPanicProgress(t *testing.T) {
	_, pool, cfg := createTestDiscoverySetup(1)
	cfg.Parallelism = 1
	prober := NewFakeResolverProber()
	prober.SetOnProbeMTU(func(Connection) { panic("probe failure") })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := NewDiscoveryEngine(cfg, prober, pool, nil).Run(ctx)
	if !errors.Is(err, ErrNoValidConnections) || prober.MTUProbedCount() != 1 {
		t.Fatalf("err=%v probes=%d", err, prober.MTUProbedCount())
	}
}

func TestStartupQualificationDefersAdmission(t *testing.T) {
	conns, pool, cfg := createTestDiscoverySetup(2)
	cfg.FastStart = false
	cfg.MaxActiveResolvers = 1
	pool.SetMaxActive(1)
	pool.ApplyMTUProbeResult(conns[0].Key, 200, 250, 500, time.Second, true)
	pool.SeedBurstStats(conns[0].Key, 6, 6, time.Second)
	prober := NewFakeResolverProber()
	prober.SetOnProbeBurst(func(Connection) {
		old, _ := pool.GetConnectionByKey(conns[0].Key)
		candidate, _ := pool.GetConnectionByKey(conns[1].Key)
		if !old.IsValid || candidate.IsValid || candidate.StandbyEligible {
			t.Error("unqualified candidate changed admission")
		}
	})
	prober.SetBurstResponse(conns[1].Key, BurstProbeResult{SentCount: 6})
	if err := NewDiscoveryEngine(cfg, prober, pool, nil).Run(context.Background(), []Connection{*conns[1]}); err != nil {
		t.Fatal(err)
	}
	old, _ := pool.GetConnectionByKey(conns[0].Key)
	if !old.IsValid {
		t.Fatal("qualified resolver displaced by rejected candidate")
	}
}

func TestStartupQualificationZeroScore(t *testing.T) {
	pool, _ := poolTestSetup("failed")
	pool.ApplyMTUProbeResult("failed", 200, 250, 500, time.Second, true)
	pool.SeedBurstStats("failed", 10, 0, time.Second)
	pool.mu.RLock()
	score := pool.calculateConnectionScoreLocked(0)
	pool.mu.RUnlock()
	if score != 0 {
		t.Fatalf("100%% loss score=%v", score)
	}
}

func TestStartupQualificationRefillsVacancy(t *testing.T) {
	pool, _ := poolTestSetup("standby")
	pool.SetMaxActive(1)
	pool.SetConnectionStandbyEligible("standby", true)
	if !pool.Optimize() || pool.ActiveCount() != 1 {
		t.Fatal("qualified standby did not fill vacancy")
	}
}

type startupMTUProber struct {
	*FakeResolverProber
	up, down int
}

func (p *startupMTUProber) ProbeBurst(ctx context.Context, c Connection, n, down, up int, d time.Duration) BurstProbeResult {
	p.up = up
	p.down = down
	return p.FakeResolverProber.ProbeBurst(ctx, c, n, down, up, d)
}
func TestStartupQualificationBoundsBurstMTU(t *testing.T) {
	_, pool, cfg := createTestDiscoverySetup(1)
	pool.SetSessionMTU(400, 1000)
	p := &startupMTUProber{FakeResolverProber: NewFakeResolverProber()}
	_ = NewDiscoveryEngine(cfg, p, pool, nil).Run(context.Background())
	if p.up != 200 || p.down != 500 {
		t.Fatalf("burst MTUs=%d/%d", p.up, p.down)
	}
}
