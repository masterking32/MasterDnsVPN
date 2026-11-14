package client

import (
	"testing"
	"time"

	"masterdnsvpn-go/internal/logger"
)

// TestResolverPool_AuthoritativeLifecycle_FiveStates verifies the 5 authoritative states:
// Untested, Checking, Active, Standby, Rejected, and their exact transition rules.
func TestResolverPool_AuthoritativeLifecycle_FiveStates(t *testing.T) {
	log := logger.New("TestLogger", "debug")
	pool := NewResolverPool(2, log)
	pool.SetSessionMTU(1000, 1000)

	conn1 := &Connection{
		Domain:        "tunnel.example.com",
		Resolver:      "1.1.1.1",
		ResolverPort:  53,
		ResolverLabel: "1.1.1.1:53",
		Key:           "1.1.1.1:53#tunnel.example.com",
	}
	conn2 := &Connection{
		Domain:        "tunnel.example.com",
		Resolver:      "8.8.8.8",
		ResolverPort:  53,
		ResolverLabel: "8.8.8.8:53",
		Key:           "8.8.8.8:53#tunnel.example.com",
	}

	pool.SetConnections([]*Connection{conn1, conn2})

	// 1. Initial state must be Untested
	st1, ok := pool.CandidateState(conn1.Key)
	if !ok || st1 != StateUntested {
		t.Fatalf("expected conn1 to be StateUntested, got %v (ok=%v)", st1, ok)
	}
	c1, _ := pool.GetConnectionByKey(conn1.Key)
	if c1.IsValid || c1.StandbyEligible {
		t.Fatalf("expected Untested candidate to have IsValid=false, StandbyEligible=false; got IsValid=%v StandbyEligible=%v", c1.IsValid, c1.StandbyEligible)
	}

	// 2. Untested candidates cannot appear in RankedEndpoints
	ranked := pool.RankedEndpoints(10)
	if len(ranked) != 0 {
		t.Fatalf("expected empty RankedEndpoints for Untested candidates, got %d", len(ranked))
	}

	// 3. Acquire candidate for checking -> StateChecking
	acquired, ok := pool.AcquireCandidateForChecking(conn1.Key)
	if !ok {
		t.Fatalf("expected AcquireCandidateForChecking to succeed")
	}
	if acquired.Key != conn1.Key {
		t.Fatalf("acquired key mismatch: got %v, want %v", acquired.Key, conn1.Key)
	}
	stChecking, _ := pool.CandidateState(conn1.Key)
	if stChecking != StateChecking {
		t.Fatalf("expected StateChecking, got %v", stChecking)
	}

	// Checking candidates cannot enter RankedEndpoints or be promoted by Optimize
	if len(pool.RankedEndpoints(10)) != 0 {
		t.Fatalf("expected empty RankedEndpoints while in StateChecking")
	}
	pool.Optimize()
	if pool.ActiveCount() != 0 {
		t.Fatalf("Checking candidate must not be promoted by Optimize; ActiveCount=%d", pool.ActiveCount())
	}

	// 4. Cancellation of initial check returns to Untested
	pool.CancelChecking(candidateSnapshotForTest(pool, conn1.Key))
	stCancelled, _ := pool.CandidateState(conn1.Key)
	if stCancelled != StateUntested {
		t.Fatalf("expected cancelled initial check to return to StateUntested, got %v", stCancelled)
	}

	// 5. Check failure leads to StateRejected
	_, ok = pool.AcquireCandidateForChecking(conn1.Key)
	if !ok {
		t.Fatalf("expected to re-acquire conn1 for checking")
	}
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn1.Key), false, 0, 0, 0, 0)
	stRejected, _ := pool.CandidateState(conn1.Key)
	if stRejected != StateRejected {
		t.Fatalf("expected failed check to lead to StateRejected, got %v", stRejected)
	}
	c1Rejected, _ := pool.GetConnectionByKey(conn1.Key)
	if c1Rejected.IsValid || c1Rejected.StandbyEligible {
		t.Fatalf("Rejected candidate must have IsValid=false, StandbyEligible=false")
	}
	if len(pool.RankedEndpoints(10)) != 0 {
		t.Fatalf("Rejected candidate must not enter RankedEndpoints")
	}

	// 6. Rejected candidate can be retried -> moves back to StateChecking
	_, ok = pool.AcquireCandidateForChecking(conn1.Key)
	if !ok {
		t.Fatalf("expected to acquire Rejected candidate for retry")
	}
	stRetry, _ := pool.CandidateState(conn1.Key)
	if stRetry != StateChecking {
		t.Fatalf("expected retry to move to StateChecking, got %v", stRetry)
	}

	// 7. Successful check leads to StateActive (within capacity)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn1.Key), true, 1200, 1200, 1200, 50*time.Millisecond)
	stActive, _ := pool.CandidateState(conn1.Key)
	if stActive != StateActive {
		t.Fatalf("expected successful qualification to lead to StateActive, got %v", stActive)
	}
	c1Active, _ := pool.GetConnectionByKey(conn1.Key)
	if !c1Active.IsValid || c1Active.StandbyEligible {
		t.Fatalf("Active candidate must have IsValid=true, StandbyEligible=false")
	}

	// Active candidate now appears in RankedEndpoints
	rankedActive := pool.RankedEndpoints(10)
	if len(rankedActive) != 1 || rankedActive[0].IP != "1.1.1.1" {
		t.Fatalf("expected RankedEndpoints to contain 1.1.1.1, got %+v", rankedActive)
	}

	// 8. Add second connection and make it Active as well (capacity=2)
	pool.AcquireCandidateForChecking(conn2.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn2.Key), true, 1200, 1200, 1200, 40*time.Millisecond)
	if pool.ActiveCount() != 2 {
		t.Fatalf("expected ActiveCount=2, got %d", pool.ActiveCount())
	}

	// 9. Add third candidate (capacity is 2, so third should become Standby)
	conn3 := &Connection{
		Domain:        "tunnel.example.com",
		Resolver:      "9.9.9.9",
		ResolverPort:  53,
		ResolverLabel: "9.9.9.9:53",
		Key:           "9.9.9.9:53#tunnel.example.com",
	}
	pool.AddConnection(conn3)
	pool.AcquireCandidateForChecking(conn3.Key)
	// conn3 qualifies but has worse latency (100ms vs 40ms/50ms), pool is full -> Standby
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn3.Key), true, 1200, 1200, 1200, 100*time.Millisecond)
	st3, _ := pool.CandidateState(conn3.Key)
	if st3 != StateStandby {
		t.Fatalf("expected conn3 to become StateStandby when pool full, got %v", st3)
	}
	c3Standby, _ := pool.GetConnectionByKey(conn3.Key)
	if c3Standby.IsValid || !c3Standby.StandbyEligible {
		t.Fatalf("Standby candidate must have IsValid=false, StandbyEligible=true")
	}

	// 10. Recheck of Standby candidate -> moves to StateChecking
	acquired3, ok := pool.AcquireCandidateForChecking(conn3.Key)
	if !ok {
		t.Fatalf("expected AcquireCandidateForChecking for standby candidate")
	}
	if acquired3.Key != conn3.Key {
		t.Fatalf("acquired key mismatch")
	}
	// While checking, StandbyEligible is revoked
	c3Checking, _ := pool.GetConnectionByKey(conn3.Key)
	if c3Checking.StandbyEligible {
		t.Fatalf("Standby candidate in StateChecking must have StandbyEligible=false")
	}

	// 11. Cancellation of Standby recheck restores Standby if still session compatible
	pool.CancelChecking(candidateSnapshotForTest(pool, conn3.Key))
	st3Restored, _ := pool.CandidateState(conn3.Key)
	if st3Restored != StateStandby {
		t.Fatalf("expected cancelled standby recheck to restore StateStandby, got %v", st3Restored)
	}

	// 12. If Session MTU changes and candidate is no longer compatible, standby is not restored on cancel
	pool.AcquireCandidateForChecking(conn3.Key)
	pool.SetSessionMTU(1500, 1500) // conn3 has downloadMTU 1200 < 1500
	pool.CancelChecking(candidateSnapshotForTest(pool, conn3.Key))
	st3Incompat, _ := pool.CandidateState(conn3.Key)
	if st3Incompat == StateStandby {
		t.Fatalf("incompatible candidate must not restore StateStandby on cancel; got %v", st3Incompat)
	}
	c3Incompat, _ := pool.GetConnectionByKey(conn3.Key)
	if c3Incompat.StandbyEligible {
		t.Fatalf("incompatible candidate must have StandbyEligible=false")
	}
}

// TestResolverPool_LateCompletion_Ignored verifies that duplicate or late completions
// arriving after cancellation or state changes are safely rejected and cannot overwrite
// newer decisions.
func TestResolverPool_LateCompletion_Ignored(t *testing.T) {
	log := logger.New("TestLogger", "debug")
	pool := NewResolverPool(2, log)
	pool.SetSessionMTU(1000, 1000)

	conn := &Connection{
		Domain:        "tunnel.example.com",
		Resolver:      "1.1.1.1",
		ResolverPort:  53,
		ResolverLabel: "1.1.1.1:53",
		Key:           "1.1.1.1:53#tunnel.example.com",
	}
	pool.SetConnections([]*Connection{conn})

	// Acquire and then cancel
	pool.AcquireCandidateForChecking(conn.Key)
	pool.CancelChecking(candidateSnapshotForTest(pool, conn.Key))

	// Late completion arriving for cancelled candidate must fail
	ok := pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn.Key), true, 1200, 1200, 1200, 50*time.Millisecond)
	if ok {
		t.Fatalf("expected late CommitCandidateOutcome to be rejected")
	}
	st, _ := pool.CandidateState(conn.Key)
	if st != StateUntested {
		t.Fatalf("late completion must not alter Untested state; got %v", st)
	}

	// Late CompleteRecheck
	recheckRes := ResolverRecheckResult{
		Connection:  *conn,
		MTUVerified: true,
	}
	recheckRes.Connection.UploadMTUBytes = 1200
	recheckRes.Connection.DownloadMTUBytes = 1200
	_, okRecheck := pool.CompleteRecheck(recheckRes)
	if okRecheck {
		t.Fatalf("expected late CompleteRecheck to return ok=false")
	}
}

// TestResolverPool_DisplacementAndInvalidation verifies that active paths demoted
// by better candidates become Standby, and active paths that fail become Rejected.
func TestResolverPool_DisplacementAndInvalidation(t *testing.T) {
	log := logger.New("TestLogger", "debug")
	pool := NewResolverPool(1, log) // capacity = 1
	pool.SetSessionMTU(1000, 1000)

	conn1 := &Connection{
		Domain:        "tunnel.example.com",
		Resolver:      "1.1.1.1",
		ResolverPort:  53,
		ResolverLabel: "1.1.1.1:53",
		Key:           "1.1.1.1:53#tunnel.example.com",
	}
	conn2 := &Connection{
		Domain:        "tunnel.example.com",
		Resolver:      "8.8.8.8",
		ResolverPort:  53,
		ResolverLabel: "8.8.8.8:53",
		Key:           "8.8.8.8:53#tunnel.example.com",
	}
	pool.SetConnections([]*Connection{conn1, conn2})

	// Admit conn1 to active
	pool.AcquireCandidateForChecking(conn1.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn1.Key), true, 1200, 1200, 1200, 100*time.Millisecond)
	if pool.ActiveCount() != 1 {
		t.Fatalf("expected 1 active pairing")
	}

	// Admit conn2 which is much faster (20ms vs 100ms) -> displaces conn1
	pool.AcquireCandidateForChecking(conn2.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn2.Key), true, 1200, 1200, 1200, 20*time.Millisecond)

	st1, _ := pool.CandidateState(conn1.Key)
	if st1 != StateStandby {
		t.Fatalf("displaced candidate conn1 must become StateStandby, got %v", st1)
	}
	st2, _ := pool.CandidateState(conn2.Key)
	if st2 != StateActive {
		t.Fatalf("incoming candidate conn2 must become StateActive, got %v", st2)
	}

	// Invalidation of active candidate through failure -> becomes StateRejected
	pool.SetConnectionValidity(conn2.Key, false)
	st2Rejected, _ := pool.CandidateState(conn2.Key)
	if st2Rejected != StateRejected {
		t.Fatalf("invalidated active candidate must become StateRejected, got %v", st2Rejected)
	}

	// Optimization can now promote the qualified Standby conn1 into the vacant active slot
	pool.Optimize()
	st1Promoted, _ := pool.CandidateState(conn1.Key)
	if st1Promoted != StateActive {
		t.Fatalf("standby conn1 must be promoted into vacant active slot, got %v", st1Promoted)
	}
}

// TestResolverPool_FinalizeFastStart_StandbyDerivedViewSessionMTU verifies that
// finalization rejects incompatible paths and never exposes them as Standby.
func TestResolverPool_FinalizeFastStart_StandbyDerivedViewSessionMTU(t *testing.T) {
	pool := NewResolverPool(4, nil)
	pool.SetSessionMTU(1000, 1000)

	conn1 := &Connection{Key: "c1", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", Domain: "d.com", UploadMTUBytes: 1200, DownloadMTUBytes: 1200}
	conn2 := &Connection{Key: "c2", Resolver: "8.8.8.8", ResolverPort: 53, ResolverLabel: "8.8.8.8:53", Domain: "d.com", UploadMTUBytes: 500, DownloadMTUBytes: 500} // Below Session MTU!

	pool.SetConnections([]*Connection{conn1, conn2})
	pool.SetConnectionMTU("c1", 1200, 1200, 1200)
	pool.SetConnectionValidity("c1", true)
	pool.SetConnectionMTU("c2", 500, 500, 500)
	pool.SetConnectionValidity("c2", true)

	// Reconciliation excludes c2 because it cannot carry the Session.
	pool.FinalizeFastStart(nil, 1)

	c2, ok := pool.GetConnectionByKey("c2")
	if !ok {
		t.Fatal("c2 not found")
	}
	st2, _ := pool.CandidateState("c2")
	if st2 != StateRejected {
		t.Fatalf("expected c2 to be StateRejected, got %v", st2)
	}
	// Because c2 (500 MTU) is below Session MTU (1000), StandbyEligible MUST be false!
	if c2.StandbyEligible {
		t.Fatalf("expected StandbyEligible=false for candidate below Session MTU, got true")
	}
}
