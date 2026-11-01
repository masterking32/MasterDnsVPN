package client

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Run must select the best burst-qualified candidates, not merely the first
// candidates admitted during MTU discovery. Observe pool membership, not order.
func TestDiscoveryEngine_QualificationSelection(t *testing.T) {
	for _, capacity := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("capacity-%d", capacity), func(t *testing.T) {
			conns, pool, cfg := createTestDiscoverySetup(4)
			cfg.FastStart = false
			cfg.MaxActiveResolvers = capacity
			pool.SetMaxActive(capacity)
			prober := NewFakeResolverProber()
			// Slowest first makes choosing the first candidates insufficient.
			for i, rtt := range []time.Duration{100 * time.Millisecond, 20 * time.Millisecond, 5 * time.Millisecond, time.Millisecond} {
				prober.SetBurstResponse(conns[i].Key, BurstProbeResult{
					Qualified: i != 3, SentCount: 6, ReceivedCount: 6,
					AverageRTT: rtt, BurstThroughputKBps: 1000,
					DownloadMTUBytes: 500,
				})
			}
			if err := NewDiscoveryEngine(cfg, prober, pool, nil).Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			wantCount := capacity
			if capacity == 0 {
				wantCount = 3 // MAX_ACTIVE_RESOLVERS=0 is unlimited.
			}
			if pool.ActiveCount() != wantCount || prober.BurstProbedCount() != 4 {
				t.Fatalf("active=%d burst probes=%d; want %d and 4", pool.ActiveCount(), prober.BurstProbedCount(), wantCount)
			}
			for i, conn := range conns {
				got, _ := pool.GetConnectionByKey(conn.Key)
				wantActive := i < 3 && (capacity == 0 || i >= 3-capacity)
				wantStandby := i < 3 && !wantActive
				if got.IsValid != wantActive || got.StandbyEligible != wantStandby {
					t.Fatalf("%s: active=%v standby=%v; want %v, %v", conn.Key, got.IsValid, got.StandbyEligible, wantActive, wantStandby)
				}
			}
		})
	}
}

func TestDiscoveryEngine_AllBurstRejected(t *testing.T) {
	conns, pool, cfg := createTestDiscoverySetup(3)
	cfg.FastStart = false
	prober := NewFakeResolverProber()
	for _, conn := range conns {
		prober.SetBurstResponse(conn.Key, BurstProbeResult{SentCount: 6, Qualified: false})
	}
	err := NewDiscoveryEngine(cfg, prober, pool, nil).Run(context.Background())
	if !errors.Is(err, ErrNoValidConnections) {
		t.Fatalf("want ErrNoValidConnections, got %v", err)
	}
	for _, conn := range pool.AllConnections() {
		if conn.IsValid || conn.StandbyEligible {
			t.Fatalf("rejected candidate remains eligible: %+v", conn)
		}
	}
}

func TestDiscoveryEngine_QualificationReplacesSaturatedPool(t *testing.T) {
	conns, pool, cfg := createTestDiscoverySetup(6)
	cfg.FastStart = false
	cfg.MaxActiveResolvers = 2
	pool.SetMaxActive(2)
	for _, conn := range conns[:2] {
		pool.SetConnectionMTU(conn.Key, 200, 250, 500)
		pool.SeedBurstStats(conn.Key, 6, 6, time.Second)
		pool.SetConnectionValidity(conn.Key, true)
	}
	prober := NewFakeResolverProber()
	var candidates []Connection
	for i, conn := range conns[2:] {
		candidates = append(candidates, *conn)
		prober.SetBurstResponse(conn.Key, BurstProbeResult{
			Qualified: i != 3, SentCount: 6, ReceivedCount: 6,
			AverageRTT:          time.Duration(i+1) * 10 * time.Millisecond,
			BurstThroughputKBps: 1000, DownloadMTUBytes: 500,
		})
	}
	if err := NewDiscoveryEngine(cfg, prober, pool, nil).Run(context.Background(), candidates); err != nil {
		t.Fatal(err)
	}
	if pool.ActiveCount() != 2 {
		t.Fatalf("want two active resolvers, got %d", pool.ActiveCount())
	}
	for i, conn := range conns {
		got, _ := pool.GetConnectionByKey(conn.Key)
		wantActive := i == 2 || i == 3
		if got.IsValid != wantActive || (got.IsValid && got.StandbyEligible) {
			t.Fatalf("unexpected placement: %+v", got)
		}
		if i >= 4 && got.StandbyEligible != (i == 4) {
			t.Fatalf("qualified overflow must be standby; failed candidate must not: %+v", got)
		}
		if i >= 2 && i <= 4 {
			stats := pool.statsForKey(conn.Key)
			if stats.sent.Load() != 6 || stats.acked.Load() != 6 {
				t.Fatalf("missing burst measurements for %s", conn.Key)
			}
		}
	}
}

// Test at the admission seam: Run's earlier MTU admission could conceal a
// regression that seeds the winner's measurements after attempting promotion.
func TestResolverPool_AdmissionSeedsBeforeDisplacement(t *testing.T) {
	pool, results := poolTestSetup("old-1", "old-2", "winner")
	pool.SetMaxActive(2)
	for _, key := range []string{"old-1", "old-2"} {
		pool.SeedBurstStats(key, 10, 10, 80*time.Millisecond)
		pool.SetConnectionValidity(key, true)
	}
	results[2].BurstResult.AverageRTT = time.Millisecond
	pool.AdmitStartupBatch(results[2:], []Connection{results[2].Connection})
	winner, _ := pool.GetConnectionByKey("winner")
	if !winner.IsValid || winner.StandbyEligible || pool.ActiveCount() != 2 {
		t.Fatalf("winner not admitted into full pool: %+v (active=%d)", winner, pool.ActiveCount())
	}
	stats := pool.statsForKey("winner")
	if stats.sent.Load() != 10 || stats.acked.Load() != 10 {
		t.Fatal("winner measurements not committed")
	}
}
