// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

func poolTestSetup(keys ...string) (*ResolverPool, []QualifiedResolver) {
	p := NewResolverPool(0, nil)
	connections := make([]*Connection, len(keys))
	results := make([]QualifiedResolver, len(keys))
	for i, key := range keys {
		connections[i] = &Connection{
			Key:           key,
			ResolverLabel: key,
			Domain:        "example.com",
			Resolver:      "1.1.1." + strconv.Itoa(i+1),
			ResolverPort:  53,
		}
	}
	p.SetConnections(connections)
	for i, conn := range connections {
		p.SetConnectionMTU(conn.Key, 100, 160, 1000)
		results[i] = QualifiedResolver{
			Connection: *conn,
			BurstResult: BurstProbeResult{
				Qualified:     true,
				SentCount:     10,
				ReceivedCount: 10,
				AverageRTT:    time.Duration(i+1) * 10 * time.Millisecond,
			},
		}
	}
	return p, results
}

func TestResolverPool_AdmissionBatchReplacesSaturatedPool(t *testing.T) {
	p, results := poolTestSetup("old", "winner", "standby", "failed")
	p.SetMaxActive(1)
	p.SetConnectionValidity("old", true)
	// Incumbent releases capacity when losing startup ranking
	p.SeedBurstStats("old", 10, 10, time.Millisecond)
	results[3].BurstResult.Qualified = false
	p.AdmitStartupBatch(results, []Connection{results[1].Connection})

	for _, snapshot := range p.GetStatsSnapshot() {
		key := snapshot.Connection.Key
		if snapshot.IsValid != (key == "winner") {
			t.Fatalf("unexpected active placement for %s: %+v", key, snapshot)
		}
		wantStandby := key == "old" || key == "standby"
		if snapshot.StandbyEligible != wantStandby {
			t.Fatalf("unexpected standby placement for %s: %+v", key, snapshot)
		}
		if key != "failed" && (snapshot.Sent != 10 || snapshot.Acked != 10) {
			t.Fatalf("qualification measurements missing for %s: %+v", key, snapshot)
		}
	}
}

func TestResolverPool_AdmissionBatchPreservesOtherBatches(t *testing.T) {
	p, results := poolTestSetup("earlier", "new")
	p.SetMaxActive(2)
	p.AdmitStartupBatch(results[:1], []Connection{results[0].Connection})
	p.AdmitStartupBatch(results[1:], []Connection{results[1].Connection})
	if p.ActiveCount() != 2 {
		t.Fatal("a later startup batch displaced an earlier qualified resolver")
	}
}

func TestResolverPool_SnapshotsNeverExposeIntermediatePlacement(t *testing.T) {
	p, results := poolTestSetup("first", "second")
	p.SetMaxActive(1)
	p.AdmitStartupBatch(results, []Connection{results[0].Connection})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			p.AdmitStartupBatch(results, []Connection{results[i%2].Connection})
		}
	}()

	for i := 0; i < 1000; i++ {
		active, standby := 0, 0
		for _, snapshot := range p.GetStatsSnapshot() {
			if snapshot.IsValid {
				active++
			}
			if snapshot.StandbyEligible {
				standby++
			}
			if snapshot.IsValid && snapshot.StandbyEligible {
				t.Fatal("resolver is both active and standby")
			}
		}
		if active != 1 || standby != 1 {
			t.Fatalf("partial admission visible: active=%d standby=%d", active, standby)
		}
	}
	wg.Wait()
}

func TestResolverPool_RecheckLifecycle(t *testing.T) {
	for _, scheduled := range []bool{false, true} {
		name := "direct"
		if scheduled {
			name = "scheduled"
		}
		t.Run(name, func(t *testing.T) {
			p, results := poolTestSetup("active", "candidate")
			p.SetMaxActive(1)
			p.AdmitStartupBatch(results, []Connection{results[0].Connection})
			p.SeedBurstStats("active", 10, 5, time.Second)

			var conn Connection
			if scheduled {
				var ok bool
				conn, ok = p.AcquireNextInactiveForRecheck(time.Now(), time.Second)
				if !ok || conn.Key != "candidate" {
					t.Fatal("expected candidate to be selected")
				}
			} else {
				if !p.beginConnectionRecheck("candidate") {
					t.Fatal("candidate missing")
				}
				conn, _ = p.GetConnectionByKey("candidate")
			}
			if p.Optimize() {
				t.Fatal("candidate promoted during network probing")
			}
			conn.DownloadMTUBytes = 1200
			got, ok := p.CompleteRecheck(ResolverRecheckResult{
				Connection:  conn,
				MTUVerified: true,
				Burst:       &results[1].BurstResult,
			})
			if !ok || !got.IsValid || got.StandbyEligible || got.DownloadMTUBytes != 1200 {
				t.Fatalf("recheck was not committed with actual admission: %+v", got)
			}
		})
	}
}

func TestResolverPool_RecheckRejectionAndConservativeStats(t *testing.T) {
	for _, outcome := range []string{"mtu-failure", "burst-failure", "without-burst"} {
		t.Run(outcome, func(t *testing.T) {
			p, results := poolTestSetup("candidate")
			p.AdmitStartupBatch(results, nil)
			p.beginConnectionRecheck("candidate")
			conn, _ := p.GetConnectionByKey("candidate")
			conn.DownloadMTUBytes = 1200
			result := ResolverRecheckResult{Connection: conn, MTUVerified: outcome != "mtu-failure"}
			if outcome == "burst-failure" {
				result.Burst = &BurstProbeResult{Qualified: false}
			}
			got, _ := p.CompleteRecheck(result)
			if got.IsValid != (outcome == "without-burst") || got.StandbyEligible {
				t.Fatalf("unexpected placement: %+v", got)
			}
			wantMTU := 1200
			if outcome == "mtu-failure" {
				wantMTU = 1000
			}
			if got.DownloadMTUBytes != wantMTU {
				t.Fatalf("MTU=%d, want %d", got.DownloadMTUBytes, wantMTU)
			}
			if outcome == "without-burst" {
				snapshot := p.GetStatsSnapshot()[0]
				if snapshot.Sent != 10 || snapshot.Acked != 8 || snapshot.Lost != 0 || snapshot.AverageRTT != 0 {
					t.Fatalf("conservative statistics changed: %+v", snapshot)
				}
			}
		})
	}
}

func TestResolverPool_RecheckPreservesReplacementThreshold(t *testing.T) {
	for _, rtt := range []time.Duration{90 * time.Millisecond, 110 * time.Millisecond} {
		t.Run(rtt.String(), func(t *testing.T) {
			p, results := poolTestSetup("active", "candidate")
			p.SetMaxActive(1)
			results[0].BurstResult.AverageRTT = 100 * time.Millisecond
			results[1].BurstResult.AverageRTT = rtt
			p.AdmitStartupBatch(results, []Connection{results[0].Connection})
			// Neither candidate clears periodic optimization's 25% improvement threshold
			if p.Optimize() {
				t.Fatal("periodic replacement threshold changed")
			}
			p.beginConnectionRecheck("candidate")
			conn, _ := p.GetConnectionByKey("candidate")
			got, ok := p.CompleteRecheck(ResolverRecheckResult{
				Connection:  conn,
				MTUVerified: true,
				Burst:       &results[1].BurstResult,
			})
			// Immediate admission still accepts any strictly better score
			wantActive := rtt < 100*time.Millisecond
			if !ok || got.IsValid != wantActive || got.StandbyEligible == wantActive {
				t.Fatalf("unexpected actual placement for RTT %s: %+v", rtt, got)
			}
			if p.ActiveCount() != 1 {
				t.Fatal("recheck changed pool capacity")
			}
		})
	}
}

func TestResolverPool_CapacityBounding(t *testing.T) {
	p, results := poolTestSetup("c1", "c2", "c3", "c4")
	p.SetMaxActive(2)

	// Admit c1 and c2
	p.AdmitStartupBatch(results[:2], []Connection{results[0].Connection, results[1].Connection})
	if p.ActiveCount() != 2 {
		t.Fatalf("expected 2 active resolvers, got %d", p.ActiveCount())
	}

	// c3 has averageRTT 30ms (worse than c1 10ms, c2 20ms) -> should become Standby
	p.SetConnectionValidity("c3", true)
	if p.ActiveCount() != 2 {
		t.Fatalf("active count changed unexpectedly: %d", p.ActiveCount())
	}
	conn3, _ := p.GetConnectionByKey("c3")
	if conn3.IsValid || !conn3.StandbyEligible {
		t.Fatalf("expected c3 to be standby, got IsValid=%v, StandbyEligible=%v", conn3.IsValid, conn3.StandbyEligible)
	}

	// c4 has averageRTT 5ms (better than c2 20ms) -> should displace c2
	p.SeedBurstStats("c4", 10, 10, 5*time.Millisecond)
	p.SetConnectionValidity("c4", true)
	if p.ActiveCount() != 2 {
		t.Fatalf("expected active count to remain bounded at 2, got %d", p.ActiveCount())
	}
	conn4, _ := p.GetConnectionByKey("c4")
	if !conn4.IsValid || conn4.StandbyEligible {
		t.Fatalf("expected c4 to be active, got IsValid=%v", conn4.IsValid)
	}
	conn2, _ := p.GetConnectionByKey("c2")
	if conn2.IsValid || !conn2.StandbyEligible {
		t.Fatalf("expected displaced c2 to become standby, got IsValid=%v, StandbyEligible=%v", conn2.IsValid, conn2.StandbyEligible)
	}
}

func TestResolverPool_ReleaseRecheck_RestoresStandby(t *testing.T) {
	p, _ := poolTestSetup("cand1", "cand2")
	p.SetConnectionStandbyEligible("cand1", true)

	// Acquire cand1 for recheck
	conn, ok := p.AcquireNextInactiveForRecheck(time.Now(), 0)
	if !ok || conn.Key != "cand1" {
		t.Fatalf("expected to acquire cand1, got %s", conn.Key)
	}
	// While rechecking, standby eligibility is revoked
	if p.IsConnectionStandbyEligible("cand1") {
		t.Fatal("expected standby eligibility to be revoked during recheck")
	}

	// Release recheck with wasStandby = true -> restores standby
	p.ReleaseRecheck("cand1", true)
	if !p.IsConnectionStandbyEligible("cand1") {
		t.Fatal("expected standby eligibility to be restored after release")
	}

	// Now recheck without standby -> release with wasStandby = false
	conn2, ok2 := p.AcquireNextInactiveForRecheck(time.Now(), 0)
	if !ok2 || conn2.Key != "cand2" {
		t.Fatalf("expected to acquire cand2, got %s", conn2.Key)
	}
	p.ReleaseRecheck("cand2", false)
	if p.IsConnectionStandbyEligible("cand2") {
		t.Fatal("expected cand2 to remain inactive without standby")
	}
}

func TestResolverPool_FinalizeFastStart_QuotaAndStandby(t *testing.T) {
	p := NewResolverPool(10, nil)
	connections := []*Connection{
		{Key: "e1-d1", ResolverLabel: "e1", Domain: "d1.com"},
		{Key: "e1-d2", ResolverLabel: "e1", Domain: "d2.com"},
		{Key: "e2-d1", ResolverLabel: "e2", Domain: "d1.com"},
		{Key: "e3-d1", ResolverLabel: "e3", Domain: "d1.com"},
	}
	p.SetConnections(connections)
	for _, c := range connections {
		p.SetConnectionMTU(c.Key, 100, 160, 1000)
		p.SetConnectionValidity(c.Key, true)
	}
	if p.ActiveCount() != 4 {
		t.Fatalf("expected 4 active connections, got %d", p.ActiveCount())
	}

	// Finalize to target of 2 unique endpoints
	p.FinalizeFastStart(nil, 2)

	active := p.ActiveResolvers()
	endpoints := make(map[string]bool)
	for _, c := range active {
		endpoints[c.ResolverLabel] = true
	}
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 unique endpoints, got %d", len(endpoints))
	}

	// Surplus connection should be standby
	e3, _ := p.GetConnectionByKey("e3-d1")
	if e3.IsValid || !e3.StandbyEligible {
		t.Fatalf("expected e3 to be demoted to standby, got IsValid=%v, StandbyEligible=%v", e3.IsValid, e3.StandbyEligible)
	}
}

func TestResolverPool_Optimize_SessionMTUVerification(t *testing.T) {
	p, results := poolTestSetup("active", "standby")
	p.SetMaxActive(1)
	p.SetSessionMTU(100, 1200)

	// Active has low MTU but is active with degraded RTT
	p.SetConnectionMTU("active", 100, 160, 1200)
	p.AdmitStartupBatch(results[:1], []Connection{results[0].Connection})
	p.SeedBurstStats("active", 10, 5, 500*time.Millisecond)

	// Standby has fast RTT (10ms) but DownloadMTU is only 800 < 1200
	p.SetConnectionMTU("standby", 100, 160, 800)
	p.SetConnectionStandbyEligible("standby", true)
	p.SeedBurstStats("standby", 10, 10, 10*time.Millisecond)

	// Optimize should NOT promote standby because 800 < 1200
	if p.Optimize() {
		t.Fatal("Optimize promoted candidate that does not meet session MTU")
	}

	// Now update standby MTU to meet session MTU
	p.SetConnectionMTU("standby", 100, 160, 1300)
	if !p.Optimize() {
		t.Fatal("Optimize should have swapped now that candidate meets session MTU")
	}

	connStandby, _ := p.GetConnectionByKey("standby")
	if !connStandby.IsValid {
		t.Fatal("expected standby to be promoted to active")
	}
}

func TestResolverPool_RankedEndpoints_OrderingAndBoost(t *testing.T) {
	p := NewResolverPool(5, nil)
	connections := []*Connection{
		{Key: "c1", ResolverLabel: "r1", Resolver: "10.0.0.1", ResolverPort: 53, Domain: "d1"},
		{Key: "c2", ResolverLabel: "r1", Resolver: "10.0.0.1", ResolverPort: 53, Domain: "d2"},
		{Key: "c3", ResolverLabel: "r2", Resolver: "10.0.0.2", ResolverPort: 53, Domain: "d1"},
	}
	p.SetConnections(connections)
	p.SetConnectionMTU("c1", 100, 160, 1000)
	p.SetConnectionMTU("c2", 100, 160, 1000)
	p.SetConnectionMTU("c3", 100, 160, 1000)

	p.SeedBurstStats("c1", 10, 10, 50*time.Millisecond)
	p.SeedBurstStats("c2", 10, 10, 20*time.Millisecond)
	p.SeedBurstStats("c3", 10, 10, 10*time.Millisecond)

	// Make c1 active (+1000.0 boost), and qualify the other pairings as standby.
	p.SetConnectionValidity("c1", true)
	p.SetConnectionStandbyEligible("c2", true)
	p.SetConnectionStandbyEligible("c3", true)

	ranked := p.RankedEndpoints(10)
	// c1 and c2 share 10.0.0.1:53 -> should be deduplicated to 1 entry
	if len(ranked) != 2 {
		t.Fatalf("expected 2 unique endpoints, got %d", len(ranked))
	}

	// 10.0.0.1:53 should be first due to active boost on c1
	if ranked[0].IP != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1 to be ranked first due to active boost, got %s", ranked[0].IP)
	}
	if ranked[1].IP != "10.0.0.2" {
		t.Fatalf("expected 10.0.0.2 to be ranked second, got %s", ranked[1].IP)
	}
}

func TestResolverPool_EventDrivenOnPoolChanged(t *testing.T) {
	p, results := poolTestSetup("c1", "c2")
	p.SetMaxActive(1)

	var changeCount int
	var mu sync.Mutex
	p.SetOnPoolChanged(func() {
		mu.Lock()
		changeCount++
		mu.Unlock()
		// Test that callback can safely read RankedEndpoints without deadlocking
		_ = p.RankedEndpoints(5)
	})

	p.AdmitStartupBatch(results[:1], []Connection{results[0].Connection})

	mu.Lock()
	count1 := changeCount
	mu.Unlock()
	if count1 == 0 {
		t.Fatal("expected onPoolChanged to fire on AdmitStartupBatch")
	}

	p.SetConnectionValidity("c2", true)
	mu.Lock()
	count2 := changeCount
	mu.Unlock()
	if count2 <= count1 {
		t.Fatal("expected onPoolChanged to fire on SetConnectionValidity")
	}
}

func TestResolverPool_CandidateFSM_MutualExclusivity(t *testing.T) {
	p, _ := poolTestSetup("c1")

	// 1. Initial StateInactive
	conn, _ := p.GetConnectionByKey("c1")
	if conn.IsValid || conn.StandbyEligible {
		t.Fatalf("initial state violated mutual exclusivity: IsValid=%v, Standby=%v", conn.IsValid, conn.StandbyEligible)
	}

	// 2. StateStandby
	p.SetConnectionStandbyEligible("c1", true)
	conn, _ = p.GetConnectionByKey("c1")
	if conn.IsValid || !conn.StandbyEligible {
		t.Fatalf("standby state violated mutual exclusivity: IsValid=%v, Standby=%v", conn.IsValid, conn.StandbyEligible)
	}

	// 3. StateActive
	p.SetConnectionValidity("c1", true)
	conn, _ = p.GetConnectionByKey("c1")
	if !conn.IsValid || conn.StandbyEligible {
		t.Fatalf("active state violated mutual exclusivity: IsValid=%v, Standby=%v", conn.IsValid, conn.StandbyEligible)
	}

	// Cannot set standby eligible while active
	if p.SetConnectionStandbyEligible("c1", true) {
		t.Fatal("SetConnectionStandbyEligible should fail while active")
	}
	conn, _ = p.GetConnectionByKey("c1")
	if !conn.IsValid || conn.StandbyEligible {
		t.Fatalf("active state violated after invalid standby set: IsValid=%v, Standby=%v", conn.IsValid, conn.StandbyEligible)
	}

	// 4. Back to inactive
	p.SetConnectionValidity("c1", false)
	conn, _ = p.GetConnectionByKey("c1")
	if conn.IsValid || conn.StandbyEligible {
		t.Fatalf("inactive state violated mutual exclusivity: IsValid=%v, Standby=%v", conn.IsValid, conn.StandbyEligible)
	}
}
