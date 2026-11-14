package client

import (
	"testing"
	"time"

	"masterdnsvpn-go/internal/logger"
)

// TestResolverPool_Policy_UnifiedReplacementMargin verifies that the 1.25x margin
// is strictly enforced on all optional performance replacements.
func TestResolverPool_Policy_UnifiedReplacementMargin(t *testing.T) {
	log := logger.New("TestLogger", "debug")
	pool := NewResolverPool(1, log) // capacity = 1
	pool.SetSessionMTU(1000, 1000)

	conn1 := &Connection{
		Domain:           "d1.example.com",
		Resolver:         "1.1.1.1",
		ResolverPort:     53,
		ResolverLabel:    "1.1.1.1:53",
		Key:              "1.1.1.1:53#d1.example.com",
		DownloadMTUBytes: 1000,
		UploadMTUBytes:   1000,
		MTUResolveTime:   100 * time.Millisecond, // score baseline ~ 8.138
	}
	pool.SetConnections([]*Connection{conn1})
	pool.AcquireCandidateForChecking(conn1.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn1.Key), true, 1000, 1000, 1000, 100*time.Millisecond)

	activeScore := pool.CalculateConnectionScore(conn1.Key)
	if activeScore <= 0 {
		t.Fatalf("expected positive active score, got %v", activeScore)
	}

	// 1. Candidate with score <= 1.25x activeScore must NOT displace active pairing
	// 100ms RTT -> 80ms RTT gives exactly 1.25x latency penalty ratio
	connMarginal := &Connection{
		Domain:           "d2.example.com",
		Resolver:         "8.8.8.8",
		ResolverPort:     53,
		ResolverLabel:    "8.8.8.8:53",
		Key:              "8.8.8.8:53#d2.example.com",
		DownloadMTUBytes: 1000,
		UploadMTUBytes:   1000,
		MTUResolveTime:   85 * time.Millisecond,
	}
	pool.AddConnection(connMarginal)
	pool.AcquireCandidateForChecking(connMarginal.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, connMarginal.Key), true, 1000, 1000, 1000, 85*time.Millisecond)

	stMarginal, _ := pool.CandidateState(connMarginal.Key)
	if stMarginal != StateStandby {
		t.Fatalf("marginal candidate (score <= 1.25x) must land in StateStandby, got %v", stMarginal)
	}
	stActive, _ := pool.CandidateState(conn1.Key)
	if stActive != StateActive {
		t.Fatalf("active candidate must remain StateActive, got %v", stActive)
	}

	// Also verify that Optimize() does not displace it
	pool.Optimize()
	stMarginalAfterOpt, _ := pool.CandidateState(connMarginal.Key)
	if stMarginalAfterOpt != StateStandby {
		t.Fatalf("Optimize must not displace active pairing when margin <= 1.25x")
	}

	// 2. Candidate with score > 1.25x activeScore (>25% improvement) DOES displace active pairing
	connFaster := &Connection{
		Domain:           "d3.example.com",
		Resolver:         "9.9.9.9",
		ResolverPort:     53,
		ResolverLabel:    "9.9.9.9:53",
		Key:              "9.9.9.9:53#d3.example.com",
		DownloadMTUBytes: 1000,
		UploadMTUBytes:   1000,
		MTUResolveTime:   40 * time.Millisecond, // ~2.5x faster
	}
	pool.AddConnection(connFaster)
	pool.AcquireCandidateForChecking(connFaster.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, connFaster.Key), true, 1000, 1000, 1000, 40*time.Millisecond)

	stFaster, _ := pool.CandidateState(connFaster.Key)
	if stFaster != StateActive {
		t.Fatalf("faster candidate (>1.25x score) must be promoted to StateActive, got %v", stFaster)
	}
	st1Demoted, _ := pool.CandidateState(conn1.Key)
	if st1Demoted != StateStandby {
		t.Fatalf("displaced candidate conn1 must become StateStandby, got %v", st1Demoted)
	}
	if got := pool.CoverageStats().OptionalReplacements; got != 1 {
		t.Fatalf("expected one optional performance replacement, got %d", got)
	}
}

// TestResolverPool_Policy_EndpointCoverageRepair verifies that distinct-endpoint coverage
// is maintained as a continuing requirement, taking priority over performance margin.
func TestResolverPool_Policy_EndpointCoverageRepair(t *testing.T) {
	log := logger.New("TestLogger", "debug")
	pool := NewResolverPool(2, log) // capacity = 2, target endpoints = 2
	pool.SetSessionMTU(1000, 1000)
	pool.SetTargetEndpoints(2)

	// Two active paths on the SAME endpoint 1.1.1.1:53 across different domains
	conn1A := &Connection{
		Domain:           "domA.com",
		Resolver:         "1.1.1.1",
		ResolverPort:     53,
		ResolverLabel:    "1.1.1.1:53",
		Key:              "1.1.1.1:53#domA.com",
		DownloadMTUBytes: 1200,
		UploadMTUBytes:   1200,
		MTUResolveTime:   40 * time.Millisecond,
	}
	conn1B := &Connection{
		Domain:           "domB.com",
		Resolver:         "1.1.1.1",
		ResolverPort:     53,
		ResolverLabel:    "1.1.1.1:53",
		Key:              "1.1.1.1:53#domB.com",
		DownloadMTUBytes: 1200,
		UploadMTUBytes:   1200,
		MTUResolveTime:   45 * time.Millisecond,
	}
	pool.SetConnections([]*Connection{conn1A, conn1B})
	pool.AcquireCandidateForChecking(conn1A.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn1A.Key), true, 1200, 1200, 1200, 40*time.Millisecond)
	pool.AcquireCandidateForChecking(conn1B.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn1B.Key), true, 1200, 1200, 1200, 45*time.Millisecond)

	if pool.ActiveCount() != 2 {
		t.Fatalf("expected 2 active paths")
	}

	// Incoming candidate has distinct endpoint 8.8.8.8:53, but slower RTT (70ms vs 45ms)
	// Missing coverage repair must displace duplicate 1.1.1.1 (conn1B) even without 1.25x margin
	conn2 := &Connection{
		Domain:           "domA.com",
		Resolver:         "8.8.8.8",
		ResolverPort:     53,
		ResolverLabel:    "8.8.8.8:53",
		Key:              "8.8.8.8:53#domA.com",
		DownloadMTUBytes: 1200,
		UploadMTUBytes:   1200,
		MTUResolveTime:   70 * time.Millisecond,
	}
	pool.AddConnection(conn2)
	pool.AcquireCandidateForChecking(conn2.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn2.Key), true, 1200, 1200, 1200, 70*time.Millisecond)

	st2, _ := pool.CandidateState(conn2.Key)
	if st2 != StateActive {
		t.Fatalf("unrepresented distinct endpoint conn2 must be promoted to repair coverage, got %v", st2)
	}
	st1BDemoted, _ := pool.CandidateState(conn1B.Key)
	if st1BDemoted != StateStandby {
		t.Fatalf("duplicate endpoint pairing conn1B must be demoted to StateStandby, got %v", st1BDemoted)
	}

	if got := pool.CoverageStats().OptionalReplacements; got != 0 {
		t.Fatalf("coverage repair must not count as optional replacement, got %d", got)
	}

	// 2. Once coverage is satisfied (we now have 1.1.1.1 and 8.8.8.8), a 3rd distinct endpoint
	// that is slower (120ms) is NOT admitted merely because it is distinct
	conn3 := &Connection{
		Domain:           "domA.com",
		Resolver:         "9.9.9.9",
		ResolverPort:     53,
		ResolverLabel:    "9.9.9.9:53",
		Key:              "9.9.9.9:53#domA.com",
		DownloadMTUBytes: 1200,
		UploadMTUBytes:   1200,
		MTUResolveTime:   120 * time.Millisecond,
	}
	pool.AddConnection(conn3)
	pool.AcquireCandidateForChecking(conn3.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn3.Key), true, 1200, 1200, 1200, 1200*time.Millisecond)

	st3, _ := pool.CandidateState(conn3.Key)
	if st3 != StateStandby {
		t.Fatalf("slower candidate conn3 must land in Standby once coverage target is met; got %v", st3)
	}

	// 3. Intra-endpoint performance replacement:
	// A faster candidate on 1.1.1.1:53 (10ms) arrives when target coverage is met (1.1.1.1 + 8.8.8.8).
	// It should displace the slower 1.1.1.1:53 active path (conn1A at 40ms) while preserving coverage.
	conn1C := &Connection{
		Domain:           "domC.com",
		Resolver:         "1.1.1.1",
		ResolverPort:     53,
		ResolverLabel:    "1.1.1.1:53",
		Key:              "1.1.1.1:53#domC.com",
		DownloadMTUBytes: 1200,
		UploadMTUBytes:   1200,
		MTUResolveTime:   10 * time.Millisecond,
	}
	pool.AddConnection(conn1C)
	pool.AcquireCandidateForChecking(conn1C.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn1C.Key), true, 1200, 1200, 1200, 10*time.Millisecond)

	st1C, _ := pool.CandidateState(conn1C.Key)
	if st1C != StateActive {
		t.Fatalf("faster intra-endpoint candidate conn1C must displace slower incumbent conn1A, got %v", st1C)
	}
	st1ADemoted, _ := pool.CandidateState(conn1A.Key)
	if st1ADemoted != StateStandby {
		t.Fatalf("displaced incumbent conn1A must transition to StateStandby, got %v", st1ADemoted)
	}
}

// TestResolverPool_EndpointCoverage_UnlabeledEndpointsFallback verifies that endpoint quota
// counting and coverage repair fall back to formatting Resolver:ResolverPort when ResolverLabel is empty.
func TestResolverPool_EndpointCoverage_UnlabeledEndpointsFallback(t *testing.T) {
	log := logger.New("TestLogger", "debug")
	pool := NewResolverPool(2, log)
	pool.SetTargetEndpoints(2)
	pool.SetSessionMTU(1000, 1000)

	// Two candidates on 1.1.1.1:53 with empty ResolverLabel
	c1 := &Connection{
		Domain:           "d1.com",
		Resolver:         "1.1.1.1",
		ResolverPort:     53,
		ResolverLabel:    "", // intentionally empty
		Key:              "1.1.1.1:53#d1.com",
		DownloadMTUBytes: 1000,
		UploadMTUBytes:   1000,
		MTUResolveTime:   50 * time.Millisecond,
	}
	c2 := &Connection{
		Domain:           "d2.com",
		Resolver:         "1.1.1.1",
		ResolverPort:     53,
		ResolverLabel:    "", // intentionally empty
		Key:              "1.1.1.1:53#d2.com",
		DownloadMTUBytes: 1000,
		UploadMTUBytes:   1000,
		MTUResolveTime:   60 * time.Millisecond,
	}

	pool.SetConnections([]*Connection{c1, c2})
	pool.AcquireCandidateForChecking(c1.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, c1.Key), true, 1000, 1000, 1000, 50*time.Millisecond)
	pool.AcquireCandidateForChecking(c2.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, c2.Key), true, 1000, 1000, 1000, 60*time.Millisecond)

	if pool.ActiveCount() != 2 {
		t.Fatalf("expected 2 active candidates, got %d", pool.ActiveCount())
	}

	// Now introduce candidate on a distinct endpoint (8.8.8.8:53) also with empty ResolverLabel
	c3 := &Connection{
		Domain:           "d1.com",
		Resolver:         "8.8.8.8",
		ResolverPort:     53,
		ResolverLabel:    "", // intentionally empty
		Key:              "8.8.8.8:53#d1.com",
		DownloadMTUBytes: 1000,
		UploadMTUBytes:   1000,
		MTUResolveTime:   70 * time.Millisecond,
	}
	pool.AddConnection(c3)
	pool.AcquireCandidateForChecking(c3.Key)
	// Committing c3 must trigger Endpoint Coverage Repair: c3 on 8.8.8.8:53 should displace
	// the duplicate 1.1.1.1:53 pairing c2 (worst duplicate)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, c3.Key), true, 1000, 1000, 1000, 70*time.Millisecond)

	st3, _ := pool.CandidateState(c3.Key)
	if st3 != StateActive {
		t.Fatalf("expected c3 on distinct endpoint 8.8.8.8 to be promoted via coverage repair, got %v", st3)
	}

	st2, _ := pool.CandidateState(c2.Key)
	if st2 != StateStandby {
		t.Fatalf("expected duplicate c2 on 1.1.1.1 to be demoted to Standby, got %v", st2)
	}
}

// TestResolverPool_Optimize_DisplacesLowestScoringActive verifies that Optimize()
// displaces the lowest-scoring active candidate rather than evicting sequentially.
func TestResolverPool_Optimize_DisplacesLowestScoringActive(t *testing.T) {
	pool := NewResolverPool(2, nil)
	pool.SetSessionMTU(1000, 1000)
	pool.SetTargetEndpoints(2)

	// conn1: endpoint 1.1.1.1:53 (first active, score ~20)
	conn1 := &Connection{
		Domain:           "d1.com",
		Resolver:         "1.1.1.1",
		ResolverPort:     53,
		ResolverLabel:    "1.1.1.1:53",
		Key:              "1.1.1.1:53#d1.com",
		DownloadMTUBytes: 1000,
		UploadMTUBytes:   1000,
		MTUResolveTime:   50 * time.Millisecond,
	}
	// conn2: endpoint 2.2.2.2:53 (second active, score ~20 initially)
	conn2 := &Connection{
		Domain:           "d1.com",
		Resolver:         "2.2.2.2",
		ResolverPort:     53,
		ResolverLabel:    "2.2.2.2:53",
		Key:              "2.2.2.2:53#d1.com",
		DownloadMTUBytes: 1000,
		UploadMTUBytes:   1000,
		MTUResolveTime:   50 * time.Millisecond,
	}
	// conn3: endpoint 3.3.3.3:53 (standby, initially 500ms RTT so it lands in Standby)
	conn3 := &Connection{
		Domain:           "d1.com",
		Resolver:         "3.3.3.3",
		ResolverPort:     53,
		ResolverLabel:    "3.3.3.3:53",
		Key:              "3.3.3.3:53#d1.com",
		DownloadMTUBytes: 1000,
		UploadMTUBytes:   1000,
		MTUResolveTime:   500 * time.Millisecond,
	}

	pool.SetConnections([]*Connection{conn1, conn2, conn3})
	pool.AcquireCandidateForChecking(conn1.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn1.Key), true, 1000, 1000, 1000, 50*time.Millisecond)
	pool.AcquireCandidateForChecking(conn2.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn2.Key), true, 1000, 1000, 1000, 50*time.Millisecond)
	pool.AcquireCandidateForChecking(conn3.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn3.Key), true, 1000, 1000, 1000, 500*time.Millisecond)

	if pool.ActiveCount() != 2 {
		t.Fatalf("expected 2 active paths, got %d", pool.ActiveCount())
	}
	st3Init, _ := pool.CandidateState(conn3.Key)
	if st3Init != StateStandby {
		t.Fatalf("expected conn3 initially in StateStandby, got %v", st3Init)
	}

	// Update stats:
	// conn1: 20ms RTT (better active candidate, score ~46.9)
	// conn2: 22ms RTT (worse active candidate, score ~42.5)
	// conn3: 14ms RTT (fastest, in standby, score ~67.8)
	pool.SeedBurstStats(conn1.Key, 10, 10, 20*time.Millisecond)
	pool.SeedBurstStats(conn2.Key, 10, 10, 22*time.Millisecond)
	pool.SeedBurstStats(conn3.Key, 10, 10, 14*time.Millisecond)

	score1 := pool.CalculateConnectionScore(conn1.Key)
	score2 := pool.CalculateConnectionScore(conn2.Key)
	score3 := pool.CalculateConnectionScore(conn3.Key)

	// Verify precondition:
	// score3 beats score1 (>1.25x) and score2 (>1.25x), but score1 does NOT beat score2 by 1.25x
	if !(score3 > score1*1.25 && score3 > score2*1.25 && score1 > score2 && score1 <= score2*1.25) {
		t.Fatalf("precondition failed: score1=%v, score2=%v, score3=%v", score1, score2, score3)
	}

	// Optimize pool
	swapped := pool.Optimize()
	st1, _ := pool.CandidateState(conn1.Key)
	st2, _ := pool.CandidateState(conn2.Key)
	st3, _ := pool.CandidateState(conn3.Key)
	if !swapped {
		t.Fatalf("expected Optimize() to perform a swap")
	}

	// conn3 should be promoted to StateActive
	if st3 != StateActive {
		t.Fatalf("expected conn3 to be StateActive, got %v", st3)
	}

	// conn1 (better active) must REMAIN StateActive
	if st1 != StateActive {
		t.Fatalf("expected better candidate conn1 to remain StateActive, got %v (was incorrectly displaced!)", st1)
	}

	// conn2 (worse active) must be DEMOTED to StateStandby
	if st2 != StateStandby {
		t.Fatalf("expected worse candidate conn2 to be demoted to StateStandby, got %v", st2)
	}
}
