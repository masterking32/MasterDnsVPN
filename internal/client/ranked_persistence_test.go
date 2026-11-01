package client

import "testing"

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
