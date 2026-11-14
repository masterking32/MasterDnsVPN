package client

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"masterdnsvpn-go/internal/config"
)

func TestRankedEndpointsExcludeUnqualified(t *testing.T) {
	pool, _ := poolTestSetup("active", "standby", "rejected", "rechecking", "untested")
	pool.SetConnectionValidity("active", true)
	pool.SetConnectionStandbyEligible("standby", true)
	pool.SeedBurstStats("rejected", 6, 0, 0)
	pool.beginConnectionRecheck("rechecking")
	got := pool.RankedEndpoints(10)
	if len(got) != 2 {
		t.Fatalf("ranked=%v; want only active and qualified standby", got)
	}
}

func TestInitialDiscoveryDoesNotFlushRankings(t *testing.T) {
	const domain = "v.example.com"
	conn, port, _ := startMockMTUDNSListener(t, domain)
	defer conn.Close()
	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{domain}
	cfg.Resolvers = []config.ResolverAddress{{IP: "127.0.0.1", Port: port}}
	cfg.ResolversFilePath = "unused"
	cfg.MinUploadMTU, cfg.MaxUploadMTU = 100, 200
	cfg.MinDownloadMTU, cfg.MaxDownloadMTU = 200, 400
	c := newAcceptanceClient(t, cfg)
	c.rankedWriter.Close()
	var writes atomic.Int32
	c.rankedWriter = newRankedPersistenceWriter(RankedPersistenceConfig{
		Enabled: true, ResolversPath: "unused", CoalesceDelay: time.Hour, MaxDirtyWait: time.Hour,
	}, nil, c.pool.RankedEndpoints, func(string, []config.ResolverAddress) error {
		writes.Add(1)
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.RunInitialMTUTests(ctx); err != nil {
		t.Fatal(err)
	}
	if got := writes.Load(); got != 0 {
		t.Fatalf("discovery forced %d ranking writes instead of returning readiness", got)
	}
	c.Close()
	if got := writes.Load(); got != 1 {
		t.Fatalf("shutdown must flush pending rankings, got %d writes", got)
	}
}

func TestLiveObservationsPersistRankings(t *testing.T) {
	for _, observation := range []string{"success", "timeout", "shutdown"} {
		t.Run(observation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := config.DefaultClientConfig()
				cfg.AutoSaveRankedResolvers = false
				c := New(cfg, nil, nil)
				defer c.Close()
				var mu sync.Mutex
				var saved [][]config.ResolverAddress
				c.rankedWriter = newRankedPersistenceWriter(RankedPersistenceConfig{
					Enabled: true, ResolversPath: "unused", CoalesceDelay: 20 * time.Millisecond,
				}, nil, c.pool.RankedEndpoints, func(_ string, ranked []config.ResolverAddress) error {
					mu.Lock()
					defer mu.Unlock()
					saved = append(saved, append([]config.ResolverAddress(nil), ranked...))
					return nil
				})
				c.balancer.SetConnections([]*Connection{
					{Key: "a", Resolver: "1.1.1.1", ResolverPort: 53},
					{Key: "b", Resolver: "8.8.8.8", ResolverPort: 53},
				})
				c.pool.ApplyMTUProbeResult("a", 100, 160, 400, time.Millisecond, true)
				c.pool.ApplyMTUProbeResult("b", 100, 160, 400, 100*time.Millisecond, true)
				if err := c.rankedWriter.Flush(context.Background()); err != nil {
					t.Fatal(err)
				}
				mu.Lock()
				initialOK := len(saved) == 1 && saved[0][0].IP == "1.1.1.1"
				mu.Unlock()
				if !initialOK {
					t.Fatal("expected initial ranking with a first")
				}

				// Neither observation changes membership; b must still move ahead of a.
				c.balancer.ReportSend("a")
				if observation == "timeout" {
					c.balancer.ReportTimeout("a", time.Now(), time.Second, 2)
				} else {
					c.balancer.ReportSuccess("a", time.Second)
				}
				if c.pool.ActiveCount() != 2 {
					t.Fatal("observation unexpectedly changed membership")
				}
				if observation == "shutdown" {
					c.Close() // Flush the observation before the coalescing timer fires.
				} else {
					time.Sleep(30 * time.Millisecond)
					synctest.Wait()
				}
				mu.Lock()
				updatedOK := len(saved) == 2 && saved[1][0].IP == "8.8.8.8"
				mu.Unlock()
				if !updatedOK {
					t.Fatal("live ranking change was not persisted")
				}
				if observation != "shutdown" {
					// More observations with the same exported order must not rewrite.
					c.balancer.ReportSend("a")
					c.balancer.ReportSuccess("a", time.Second)
					time.Sleep(30 * time.Millisecond)
					synctest.Wait()
					mu.Lock()
					count := len(saved)
					mu.Unlock()
					if count != 2 {
						t.Fatalf("unchanged ranking caused %d total writes, want 2", count)
					}
				}
			})
		})
	}
}
