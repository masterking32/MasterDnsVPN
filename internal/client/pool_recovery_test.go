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
