package client

import (
	"testing"
	"time"
)

func TestPoolRecoveryRecheckLeaseExclusive(t *testing.T) {
	pool, _ := poolTestSetup("candidate")
	now := time.Now()
	first, ok := pool.AcquireNextInactiveForRecheck(now, 0)
	if !ok {
		t.Fatal("initial lease unavailable")
	}
	if _, ok := pool.AcquireNextInactiveForRecheck(now.Add(time.Hour), 0); ok {
		t.Fatal("in-flight recheck leased twice")
	}
	pool.CompleteRecheck(ResolverRecheckResult{Connection: first})
	if _, ok := pool.AcquireNextInactiveForRecheck(now.Add(2*time.Hour), 0); !ok {
		t.Fatal("completed lease not released")
	}
}

func TestPoolRecoveryRecheckRespectsSessionMTU(t *testing.T) {
	for _, tc := range []struct {
		name     string
		up, down int
	}{
		{"upload-too-small", 99, 1000}, {"download-too-small", 100, 999}, {"missing-mtu", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool, _ := poolTestSetup("candidate")
			pool.SetSessionMTU(100, 1000)
			conn, _ := pool.AcquireNextInactiveForRecheck(time.Now(), 0)
			conn.UploadMTUBytes = tc.up
			conn.DownloadMTUBytes = tc.down
			result, ok := pool.CompleteRecheck(ResolverRecheckResult{Connection: conn, MTUVerified: true, Burst: &BurstProbeResult{Qualified: true, SentCount: 6, ReceivedCount: 6, AverageRTT: time.Millisecond}})
			if !ok || result.IsValid || result.StandbyEligible {
				t.Fatalf("incompatible recheck admitted: %+v", result)
			}
			pool.Optimize()
			if pool.ActiveCount() != 0 {
				t.Fatal("incompatible resolver promoted")
			}
		})
	}
}

func TestPoolRecoveryRefillsOnlyEligibleStandby(t *testing.T) {
	for _, capacity := range []int{0, 1, 2} {
		pool, _ := poolTestSetup("failed", "good", "better", "too-small", "rechecking", "untested")
		pool.SetMaxActive(capacity)
		pool.SetSessionMTU(100, 1000)
		pool.SetConnectionValidity("failed", true)
		for _, key := range []string{"good", "better", "too-small", "rechecking"} {
			pool.SetConnectionStandbyEligible(key, true)
		}
		pool.SeedBurstStats("good", 6, 6, 20*time.Millisecond)
		pool.SeedBurstStats("better", 6, 6, time.Millisecond)
		pool.SetConnectionMTU("too-small", 99, 160, 1000)
		pool.beginConnectionRecheck("rechecking")
		pool.SetConnectionValidity("failed", false)
		if !pool.Optimize() {
			t.Fatal("empty pool not recovered")
		}
		want := capacity
		if want == 0 {
			want = 2
		}
		if pool.ActiveCount() != want {
			t.Fatalf("capacity %d: active=%d want=%d", capacity, pool.ActiveCount(), want)
		}
		best, _ := pool.GetConnectionByKey("better")
		if !best.IsValid {
			t.Fatal("best standby not promoted")
		}
		for _, key := range []string{"failed", "too-small", "rechecking", "untested"} {
			conn, _ := pool.GetConnectionByKey(key)
			if conn.IsValid {
				t.Fatalf("ineligible %s promoted", key)
			}
		}
		if pool.Optimize() {
			t.Fatal("stable pool changed again")
		}
	}
}

func TestPoolRecovery_BurstDisabledPreservesLatencyAndPromotes(t *testing.T) {
	// Tests burst-disabled recovery into a full pool, including a candidate without previous measurements.
	pool, _ := poolTestSetup("slow-active", "fast-untested")
	pool.SetMaxActive(1)
	pool.SetSessionMTU(100, 1000)

	// "slow-active" is active with high latency
	pool.SetConnectionValidity("slow-active", true)
	pool.SetConnectionMTU("slow-active", 150, 200, 1200)
	pool.SeedBurstStats("slow-active", 20, 20, 200*time.Millisecond)

	// "fast-untested" is inactive without previous measurements (MTUResolveTime = 0, no burst stats)
	conn, ok := pool.AcquireNextInactiveForRecheck(time.Now(), 0)
	if !ok || conn.Key != "fast-untested" {
		t.Fatalf("expected fast-untested to be acquired for recheck, got ok=%v conn=%+v", ok, conn)
	}
	if conn.MTUResolveTime != 0 {
		t.Fatalf("expected initially untested candidate to have 0 MTUResolveTime, got %v", conn.MTUResolveTime)
	}

	// Recheck completes with burst disabled (Burst: nil) but fast MTU resolve time (5ms)
	conn.UploadMTUBytes = 150
	conn.DownloadMTUBytes = 1200
	conn.MTUResolveTime = 5 * time.Millisecond

	retConn, ok := pool.CompleteRecheck(ResolverRecheckResult{
		Connection:  conn,
		MTUVerified: true,
		Burst:       nil, // Burst rechecks disabled
	})
	if !ok {
		t.Fatal("CompleteRecheck failed unexpectedly")
	}
	if retConn.MTUResolveTime != 5*time.Millisecond {
		t.Fatalf("expected CompleteRecheck to return committed latency 5ms, got %v", retConn.MTUResolveTime)
	}

	// Check candidate in pool has committed latency
	poolConn, ok := pool.GetConnectionByKey("fast-untested")
	if !ok || poolConn.MTUResolveTime != 5*time.Millisecond {
		t.Fatalf("expected candidate in pool to preserve recovery latency 5ms, got %v", poolConn.MTUResolveTime)
	}

	// CompleteRecheck evaluates pool admission: with latency preserved, fast-untested
	// receives a high score (from 5ms RTT) and immediately displaces slow-active (200ms RTT).
	// Without the fix, MTUResolveTime would be dropped, yielding fallback score 1,
	// and fast-untested would remain on standby despite being faster than active resolvers.
	if !retConn.IsValid {
		t.Fatal("expected CompleteRecheck to promote fast-untested to active pool due to preserved recovery latency")
	}

	active, _ := pool.GetConnectionByKey("fast-untested")
	if !active.IsValid {
		t.Fatal("expected fast-untested to be active in pool")
	}

	demoted, _ := pool.GetConnectionByKey("slow-active")
	if demoted.IsValid || !demoted.StandbyEligible {
		t.Fatalf("expected slow-active to be demoted to standby, got IsValid=%v StandbyEligible=%v",
			demoted.IsValid, demoted.StandbyEligible)
	}

	if pool.ActiveCount() != 1 {
		t.Fatalf("expected exactly 1 active resolver, got %d", pool.ActiveCount())
	}
}

func TestPoolRecovery_NoDiversityChurnForSlowCandidate(t *testing.T) {
	// Verifies that forced diversity override is restricted to startup admission
	// and does NOT run during background recovery.
	// Scenario:
	// Active pool has two pairings of endpoint A: A:d1 (90 KB/s), A:d2 (85 KB/s).
	// An inactive candidate B:d1 (endpoint B) recovers with 1 KB/s (300ms RTT).
	// Background recovery must NOT displace the 85 KB/s pairing for endpoint diversity.
	// Runtime Optimize() must NOT churn active membership.
	pool, _ := poolTestSetup("A:d1", "A:d2", "B:d1")
	pool.SetMaxActive(2)
	pool.SetSessionMTU(100, 1000)

	// A:d1 and A:d2 are active with fast performance
	pool.SetConnectionValidity("A:d1", true)
	pool.SetConnectionMTU("A:d1", 150, 200, 1200)
	pool.SeedBurstStats("A:d1", 20, 20, 10*time.Millisecond)

	pool.SetConnectionValidity("A:d2", true)
	pool.SetConnectionMTU("A:d2", 150, 200, 1200)
	pool.SeedBurstStats("A:d2", 20, 20, 12*time.Millisecond)

	// B:d1 is inactive
	conn, ok := pool.AcquireNextInactiveForRecheck(time.Now(), 0)
	if !ok || conn.Key != "B:d1" {
		t.Fatalf("expected B:d1 to be acquired, got ok=%v conn=%+v", ok, conn)
	}

	// B:d1 recovers with poor latency (300ms)
	conn.UploadMTUBytes = 150
	conn.DownloadMTUBytes = 1200
	conn.MTUResolveTime = 300 * time.Millisecond

	retConn, ok := pool.CompleteRecheck(ResolverRecheckResult{
		Connection:  conn,
		MTUVerified: true,
		Burst:       nil,
	})
	if !ok {
		t.Fatal("CompleteRecheck failed unexpectedly")
	}

	// Must NOT displace the 85 KB/s pairing to force diversity during background recovery
	if retConn.IsValid {
		t.Fatal("slow candidate B:d1 unexpectedly promoted to active pool during background recovery")
	}
	if !retConn.StandbyEligible {
		t.Fatal("candidate B:d1 should be standby eligible")
	}

	// Active pool must still contain A:d1 and A:d2
	active := pool.ActiveResolvers()
	if len(active) != 2 {
		t.Fatalf("expected 2 active resolvers, got %d", len(active))
	}
	activeKeys := make(map[string]bool)
	for _, c := range active {
		activeKeys[c.Key] = true
	}
	if !activeKeys["A:d1"] || !activeKeys["A:d2"] {
		t.Fatalf("expected active pool to remain {A:d1, A:d2}, got: %v", activeKeys)
	}

	// Runtime Optimize() must not demote either active pairing
	swapped := pool.Optimize()
	if swapped {
		t.Fatal("runtime Optimize() unexpectedly swapped candidates")
	}

	// Second recheck cycle on B:d1 to verify no churn across consecutive cycles
	conn2, ok := pool.AcquireNextInactiveForRecheck(time.Now().Add(time.Hour), 0)
	if !ok || conn2.Key != "B:d1" {
		t.Fatalf("expected B:d1 to be re-acquired, got ok=%v conn=%+v", ok, conn2)
	}
	conn2.UploadMTUBytes = 150
	conn2.DownloadMTUBytes = 1200
	conn2.MTUResolveTime = 300 * time.Millisecond

	retConn2, _ := pool.CompleteRecheck(ResolverRecheckResult{
		Connection:  conn2,
		MTUVerified: true,
		Burst:       nil,
	})
	if retConn2.IsValid {
		t.Fatal("slow candidate B:d1 promoted on second recheck cycle")
	}

	if pool.Optimize() {
		t.Fatal("runtime Optimize() swapped candidates on second cycle")
	}

	activeAfter := pool.ActiveResolvers()
	if len(activeAfter) != 2 {
		t.Fatalf("expected 2 active resolvers after second cycle, got %d", len(activeAfter))
	}
}
