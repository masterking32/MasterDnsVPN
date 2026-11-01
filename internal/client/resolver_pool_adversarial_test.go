// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestEmpirical_Adversarial_MutualExclusivityConcurrentStress stress-tests that
// IsValid and StandbyEligible are STRICTLY mutually exclusive under high-frequency
// concurrent operations across all ResolverPool methods.
func TestEmpirical_Adversarial_MutualExclusivityConcurrentStress(t *testing.T) {
	numCandidates := 30
	maxActive := 5
	p := NewResolverPool(maxActive, nil)

	conns := make([]*Connection, numCandidates)
	for i := 0; i < numCandidates; i++ {
		conns[i] = &Connection{
			Key:           fmt.Sprintf("cand-%d", i),
			Resolver:      fmt.Sprintf("10.0.0.%d", (i%10)+1),
			ResolverPort:  53,
			ResolverLabel: fmt.Sprintf("10.0.0.%d:53", (i%10)+1),
			Domain:        fmt.Sprintf("d%d.example.com", i%3),
		}
	}
	p.SetConnections(conns)
	for i := 0; i < numCandidates; i++ {
		p.SetConnectionMTU(fmt.Sprintf("cand-%d", i), 100, 160, 1000)
		p.SeedBurstStats(fmt.Sprintf("cand-%d", i), 10, 10, time.Duration(10+i)*time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var violationCount atomic.Uint64
	var opCount atomic.Uint64
	var wg sync.WaitGroup

	// Writers
	for w := 0; w < 10; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))
			for ctx.Err() == nil {
				key := fmt.Sprintf("cand-%d", r.Intn(numCandidates))
				op := r.Intn(7)
				switch op {
				case 0:
					p.SetConnectionValidity(key, r.Intn(2) == 1)
				case 1:
					p.SetConnectionStandbyEligible(key, r.Intn(2) == 1)
				case 2:
					if conn, ok := p.AcquireNextInactiveForRecheck(time.Now(), 0); ok {
						if r.Intn(2) == 1 {
							p.ReleaseRecheck(conn.Key, r.Intn(2) == 1)
						} else {
							p.CompleteRecheck(ResolverRecheckResult{
								Connection:  conn,
								MTUVerified: r.Intn(2) == 1,
								Burst: &BurstProbeResult{
									Qualified:     r.Intn(2) == 1,
									SentCount:     10,
									ReceivedCount: 10,
									AverageRTT:    time.Duration(r.Intn(100)+1) * time.Millisecond,
								},
							})
						}
					}
				case 3:
					p.Optimize()
				case 4:
					subCount := r.Intn(5) + 1
					selected := make([]Connection, subCount)
					results := make([]QualifiedResolver, subCount)
					for i := 0; i < subCount; i++ {
						k := fmt.Sprintf("cand-%d", r.Intn(numCandidates))
						c, _ := p.GetConnectionByKey(k)
						selected[i] = c
						results[i] = QualifiedResolver{
							Connection: c,
							BurstResult: BurstProbeResult{
								Qualified:     true,
								SentCount:     10,
								ReceivedCount: 10,
								AverageRTT:    time.Duration(r.Intn(50)+5) * time.Millisecond,
							},
						}
					}
					p.AdmitStartupBatch(results, selected)
				case 5:
					p.FinalizeFastStart(nil, maxActive)
				case 6:
					p.SetSessionMTU(r.Intn(200)+50, r.Intn(1000)+500)
				}
				opCount.Add(1)
			}
		}(w)
	}

	// Readers checking mutual exclusivity
	for rd := 0; rd < 6; rd++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				// Check AllConnections
				all := p.AllConnections()
				for _, conn := range all {
					if conn.IsValid && conn.StandbyEligible {
						violationCount.Add(1)
					}
				}

				// Check ActiveResolvers
				active := p.ActiveResolvers()
				for _, conn := range active {
					if !conn.IsValid || conn.StandbyEligible {
						violationCount.Add(1)
					}
				}

				// Check InactiveConnections
				inactive := p.InactiveConnections()
				for _, conn := range inactive {
					if conn.IsValid {
						violationCount.Add(1)
					}
				}

				// Check StatsSnapshot
				snapshots := p.GetStatsSnapshot()
				for _, snap := range snapshots {
					if snap.IsValid && snap.StandbyEligible {
						violationCount.Add(1)
					}
				}

				// Check Capacity Bounding
				if len(active) > maxActive {
					violationCount.Add(1)
				}
			}
		}()
	}

	wg.Wait()

	if v := violationCount.Load(); v > 0 {
		t.Fatalf("FAILED: detected %d mutual exclusivity / capacity bounding violations across %d operations", v, opCount.Load())
	}
	t.Logf("PASSED: %d concurrent operations with zero mutual exclusivity or capacity violations", opCount.Load())
}

// TestEmpirical_Adversarial_OptimizeVsRecheckRace tests that a candidate acquired
// for health recheck CANNOT be promoted by concurrent Optimize() calls, and that
// if recheck fails, it is not promoted.
func TestEmpirical_Adversarial_OptimizeVsRecheckRace(t *testing.T) {
	p := NewResolverPool(1, nil)
	conns := []*Connection{
		{Key: "active-degraded", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", Domain: "d.com"},
		{Key: "standby-fast", Resolver: "1.1.1.2", ResolverPort: 53, ResolverLabel: "1.1.1.2:53", Domain: "d.com"},
	}
	p.SetConnections(conns)
	p.SetConnectionMTU("active-degraded", 100, 160, 1000)
	p.SetConnectionMTU("standby-fast", 100, 160, 1000)

	// active-degraded: score is low (loss 80%, RTT 500ms)
	p.SeedBurstStats("active-degraded", 100, 20, 500*time.Millisecond)
	p.SetConnectionValidity("active-degraded", true)

	// standby-fast: score is very high (loss 0%, RTT 10ms)
	p.SeedBurstStats("standby-fast", 100, 100, 10*time.Millisecond)
	p.SetConnectionStandbyEligible("standby-fast", true)

	// Step 1: Acquire standby-fast for recheck
	leasedConn, ok := p.AcquireNextInactiveForRecheck(time.Now(), 0)
	if !ok || leasedConn.Key != "standby-fast" {
		t.Fatalf("expected to acquire standby-fast, got ok=%v, key=%s", ok, leasedConn.Key)
	}

	// While leased: StandbyEligible MUST be revoked
	if p.IsConnectionStandbyEligible("standby-fast") {
		t.Fatal("standby-fast is still standby eligible during active recheck lease")
	}

	// Concurrently invoke Optimize() 1000 times
	var wg sync.WaitGroup
	var promotedWhileLeased atomic.Bool
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				if p.Optimize() {
					// Check if standby-fast was promoted
					conn, _ := p.GetConnectionByKey("standby-fast")
					if conn.IsValid {
						promotedWhileLeased.Store(true)
					}
				}
			}
		}()
	}
	wg.Wait()

	if promotedWhileLeased.Load() {
		t.Fatal("FAILED: standby-fast was promoted to active pool by Optimize() while in StateRechecking!")
	}

	// Step 2: Complete recheck with failure (MTU failed)
	leasedConn.DownloadMTUBytes = 0
	_, _ = p.CompleteRecheck(ResolverRecheckResult{
		Connection:  leasedConn,
		MTUVerified: false,
	})

	// Optimize() again: MUST NOT swap because candidate failed recheck
	swapped := p.Optimize()
	if swapped {
		t.Fatal("FAILED: Optimize() swapped after failed recheck!")
	}

	active := p.ActiveResolvers()
	if len(active) != 1 || active[0].Key != "active-degraded" {
		t.Fatalf("unexpected active pool state: %+v", active)
	}
	t.Log("PASSED: Candidate in recheck safely isolated from Optimize() race")
}

// TestEmpirical_Adversarial_CapacityBoundingOverflow tests that attempting to admit
// more candidates than maxActive strictly bounds the active pool.
func TestEmpirical_Adversarial_CapacityBoundingOverflow(t *testing.T) {
	maxActive := 3
	totalCandidates := 20
	p := NewResolverPool(maxActive, nil)

	conns := make([]*Connection, totalCandidates)
	for i := 0; i < totalCandidates; i++ {
		conns[i] = &Connection{
			Key:           fmt.Sprintf("node-%d", i),
			Resolver:      fmt.Sprintf("192.168.1.%d", i+1),
			ResolverPort:  53,
			ResolverLabel: fmt.Sprintf("192.168.1.%d:53", i+1),
			Domain:        "example.com",
		}
	}
	p.SetConnections(conns)

	// Step 1: Sequentially activate all candidates
	for i := 0; i < totalCandidates; i++ {
		key := fmt.Sprintf("node-%d", i)
		p.SetConnectionMTU(key, 100, 160, 1000)
		p.SeedBurstStats(key, 10, 10, time.Duration(100-i)*time.Millisecond) // progressively better RTT
		p.SetConnectionValidity(key, true)

		if p.ActiveCount() > maxActive {
			t.Fatalf("ActiveCount exceeded maxActive: got %d, max %d at iteration %d", p.ActiveCount(), maxActive, i)
		}
	}

	if p.ActiveCount() != maxActive {
		t.Fatalf("expected ActiveCount to equal maxActive (%d), got %d", maxActive, p.ActiveCount())
	}

	// Check that displaced candidates are in StateStandby
	activeKeys := make(map[string]bool)
	for _, c := range p.ActiveResolvers() {
		activeKeys[c.Key] = true
	}
	for i := 0; i < totalCandidates; i++ {
		key := fmt.Sprintf("node-%d", i)
		conn, _ := p.GetConnectionByKey(key)
		if activeKeys[key] {
			if !conn.IsValid || conn.StandbyEligible {
				t.Fatalf("active candidate %s had invalid flags: IsValid=%v Standby=%v", key, conn.IsValid, conn.StandbyEligible)
			}
		} else {
			if conn.IsValid || !conn.StandbyEligible {
				t.Fatalf("displaced candidate %s had invalid flags: IsValid=%v Standby=%v", key, conn.IsValid, conn.StandbyEligible)
			}
		}
	}

	// Step 2: Call AdmitStartupBatch with all 20 candidates in 'selected'
	selected := make([]Connection, totalCandidates)
	results := make([]QualifiedResolver, totalCandidates)
	for i := 0; i < totalCandidates; i++ {
		c, _ := p.GetConnectionByKey(fmt.Sprintf("node-%d", i))
		selected[i] = c
		results[i] = QualifiedResolver{
			Connection: c,
			BurstResult: BurstProbeResult{
				Qualified:     true,
				SentCount:     10,
				ReceivedCount: 10,
				AverageRTT:    time.Duration(i+1) * 5 * time.Millisecond,
			},
		}
	}

	p.AdmitStartupBatch(results, selected)

	if p.ActiveCount() > maxActive {
		t.Fatalf("ActiveCount exceeded maxActive after AdmitStartupBatch overflow: got %d, max %d", p.ActiveCount(), maxActive)
	}
	t.Logf("PASSED: Pool strictly bounded at %d active resolvers despite admitting %d candidates", maxActive, totalCandidates)
}

// TestEmpirical_Adversarial_HysteresisThreshold verifies the >1.25x performance improvement
// requirement for degradation swap optimization.
func TestEmpirical_Adversarial_HysteresisThreshold(t *testing.T) {
	p := NewResolverPool(1, nil)
	conns := []*Connection{
		{Key: "active", Resolver: "10.0.0.1", ResolverPort: 53, ResolverLabel: "10.0.0.1:53", Domain: "d.com"},
		{Key: "standby", Resolver: "10.0.0.2", ResolverPort: 53, ResolverLabel: "10.0.0.2:53", Domain: "d.com"},
	}
	p.SetConnections(conns)
	p.SetConnectionMTU("active", 100, 160, 1000)
	p.SetConnectionMTU("standby", 100, 160, 1000)

	// Base metrics: active has RTT 100ms, 0% loss
	p.SeedBurstStats("active", 100, 100, 100*time.Millisecond)
	p.SetConnectionValidity("active", true)

	// Standby initially set to standby
	p.SetConnectionStandbyEligible("standby", true)

	// Sub-test 1: Standby RTT is 90ms (1.11x improvement -> should NOT swap)
	p.SeedBurstStats("standby", 100, 100, 90*time.Millisecond)
	if p.Optimize() {
		t.Fatal("Optimize swapped when improvement was only ~1.11x (< 1.25x)")
	}

	// Sub-test 2: Standby RTT is 85ms (1.17x improvement -> should NOT swap)
	p.SeedBurstStats("standby", 100, 100, 85*time.Millisecond)
	if p.Optimize() {
		t.Fatal("Optimize swapped when improvement was only ~1.17x (< 1.25x)")
	}

	// Sub-test 3: Standby RTT is 83ms (score ratio ~1.2399x < 1.25x -> should NOT swap)
	p.SeedBurstStats("standby", 100, 100, 83*time.Millisecond)
	if p.Optimize() {
		t.Fatal("Optimize swapped when improvement was ~1.2399x (< 1.25x)")
	}

	// Sub-test 4: Standby RTT is 81ms (score ratio ~1.275x > 1.25x -> MUST swap)
	p.SeedBurstStats("standby", 100, 100, 81*time.Millisecond)
	if !p.Optimize() {
		t.Fatal("Optimize failed to swap when improvement was ~1.275x (> 1.25x)")
	}

	// Verify states after swap
	actConn, _ := p.GetConnectionByKey("active")
	stbConn, _ := p.GetConnectionByKey("standby")
	if actConn.IsValid || !actConn.StandbyEligible {
		t.Fatalf("demoted active should be standby, got IsValid=%v Standby=%v", actConn.IsValid, actConn.StandbyEligible)
	}
	if !stbConn.IsValid || stbConn.StandbyEligible {
		t.Fatalf("promoted standby should be active, got IsValid=%v Standby=%v", stbConn.IsValid, stbConn.StandbyEligible)
	}

	t.Log("PASSED: 1.25x hysteresis threshold correctly enforced")
}

// TestEmpirical_Adversarial_SessionMTUComplianceUnderOptimization tests that Optimize()
// strictly checks session MTU requirements before promoting any candidate.
func TestEmpirical_Adversarial_SessionMTUComplianceUnderOptimization(t *testing.T) {
	p := NewResolverPool(1, nil)
	conns := []*Connection{
		{Key: "active", Resolver: "10.0.0.1", ResolverPort: 53, ResolverLabel: "10.0.0.1:53", Domain: "d.com"},
		{Key: "cand-low-upload", Resolver: "10.0.0.2", ResolverPort: 53, ResolverLabel: "10.0.0.2:53", Domain: "d.com"},
		{Key: "cand-low-download", Resolver: "10.0.0.3", ResolverPort: 53, ResolverLabel: "10.0.0.3:53", Domain: "d.com"},
		{Key: "cand-zero-mtu", Resolver: "10.0.0.4", ResolverPort: 53, ResolverLabel: "10.0.0.4:53", Domain: "d.com"},
		{Key: "cand-compliant", Resolver: "10.0.0.5", ResolverPort: 53, ResolverLabel: "10.0.0.5:53", Domain: "d.com"},
	}
	p.SetConnections(conns)

	// Set session MTU: upload 150, download 1200
	p.SetSessionMTU(150, 1200)

	// Active meets MTU, but degraded RTT (500ms)
	p.SetConnectionMTU("active", 150, 200, 1200)
	p.SeedBurstStats("active", 100, 100, 500*time.Millisecond)
	p.SetConnectionValidity("active", true)

	// All challengers have great RTT (10ms -> 50x better)
	p.SeedBurstStats("cand-low-upload", 100, 100, 10*time.Millisecond)
	p.SeedBurstStats("cand-low-download", 100, 100, 10*time.Millisecond)
	p.SeedBurstStats("cand-zero-mtu", 100, 100, 10*time.Millisecond)
	p.SeedBurstStats("cand-compliant", 100, 100, 10*time.Millisecond)

	// cand-low-upload: upload 100 < 150
	p.SetConnectionMTU("cand-low-upload", 100, 160, 1200)
	p.SetConnectionStandbyEligible("cand-low-upload", true)

	// cand-low-download: download 1000 < 1200
	p.SetConnectionMTU("cand-low-download", 150, 200, 1000)
	p.SetConnectionStandbyEligible("cand-low-download", true)

	// cand-zero-mtu: MTU not probed yet (0)
	p.SetConnectionStandbyEligible("cand-zero-mtu", true)

	// Optimize MUST NOT promote any of the non-compliant candidates
	if p.Optimize() {
		t.Fatal("Optimize promoted candidate that failed session MTU requirement!")
	}

	// Now enable compliant candidate (upload 160 >= 150, download 1300 >= 1200)
	p.SetConnectionMTU("cand-compliant", 160, 220, 1300)
	p.SetConnectionStandbyEligible("cand-compliant", true)

	if !p.Optimize() {
		t.Fatal("Optimize failed to promote fully compliant candidate!")
	}

	conn, _ := p.GetConnectionByKey("cand-compliant")
	if !conn.IsValid {
		t.Fatal("cand-compliant was not promoted to active!")
	}
	t.Log("PASSED: Session MTU compliance strictly enforced in pool optimization")
}

// TestEmpirical_Adversarial_PersistenceCallbackDeadlockFreedom tests that SetOnPoolChanged
// never deadlocks when the callback re-enters the pool concurrently with multiple mutating writers.
func TestEmpirical_Adversarial_PersistenceCallbackDeadlockFreedom(t *testing.T) {
	p := NewResolverPool(3, nil)
	conns := make([]*Connection, 10)
	for i := 0; i < 10; i++ {
		conns[i] = &Connection{
			Key:           fmt.Sprintf("cb-node-%d", i),
			Resolver:      fmt.Sprintf("10.0.1.%d", i+1),
			ResolverPort:  53,
			ResolverLabel: fmt.Sprintf("10.0.1.%d:53", i+1),
			Domain:        "d.com",
		}
	}
	p.SetConnections(conns)
	for i := 0; i < 10; i++ {
		p.SetConnectionMTU(fmt.Sprintf("cb-node-%d", i), 100, 160, 1000)
		p.SeedBurstStats(fmt.Sprintf("cb-node-%d", i), 10, 10, time.Duration(10+i)*time.Millisecond)
	}

	var callbackInvocations atomic.Uint64

	// Callback performs re-entrant queries on the pool
	p.SetOnPoolChanged(func() {
		callbackInvocations.Add(1)
		// Re-entrant read calls: must never deadlock
		_ = p.RankedEndpoints(10)
		_ = p.ActiveResolvers()
		_ = p.AllConnections()
		_, _ = p.SessionMTU()
		_ = p.ActiveCount()
		_ = p.TotalCount()
		_, _ = p.GetConnectionByKey("cb-node-0")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var opCount atomic.Uint64

	// Concurrently invoke mutations that trigger onPoolChanged
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id)))
			for ctx.Err() == nil {
				key := fmt.Sprintf("cb-node-%d", r.Intn(10))
				switch r.Intn(4) {
				case 0:
					p.SetConnectionValidity(key, r.Intn(2) == 1)
				case 1:
					p.ApplyMTUProbeResult(key, 120, 180, 1100, 15*time.Millisecond, r.Intn(2) == 1)
				case 2:
					p.Optimize()
				case 3:
					c, _ := p.GetConnectionByKey(key)
					p.CompleteRecheck(ResolverRecheckResult{
						Connection:  c,
						MTUVerified: r.Intn(2) == 1,
						Burst: &BurstProbeResult{
							Qualified:     r.Intn(2) == 1,
							SentCount:     10,
							ReceivedCount: 10,
							AverageRTT:    20 * time.Millisecond,
						},
					})
				}
				opCount.Add(1)
			}
		}(w)
	}

	// Concurrently re-register callback
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			p.SetOnPoolChanged(func() {
				callbackInvocations.Add(1)
				_ = p.RankedEndpoints(5)
				_ = p.ActiveResolvers()
			})
			time.Sleep(5 * time.Millisecond)
		}
	}()

	wg.Wait()

	inv := callbackInvocations.Load()
	ops := opCount.Load()
	if inv == 0 {
		t.Fatal("expected onPoolChanged callbacks to be invoked")
	}
	t.Logf("PASSED: %d operations triggered %d re-entrant callbacks with zero deadlocks", ops, inv)
}

// TestEmpirical_Adversarial_FailedRecheckFSMStateTransition investigates whether
// a failed recheck properly transitions the candidate to StateInactive rather than
// leaking StateRechecking.
func TestEmpirical_Adversarial_FailedRecheckFSMStateTransition(t *testing.T) {
	p := NewResolverPool(2, nil)
	conns := []*Connection{
		{Key: "cand-fsm", Resolver: "10.0.0.1", ResolverPort: 53, ResolverLabel: "10.0.0.1:53", Domain: "d.com"},
	}
	p.SetConnections(conns)
	p.SetConnectionMTU("cand-fsm", 100, 160, 1000)

	// Step 1: Set standby
	p.SetConnectionStandbyEligible("cand-fsm", true)
	candIdx := p.indexByKey["cand-fsm"]
	if p.candidates[candIdx].state != StateStandby {
		t.Fatalf("expected StateStandby, got %s", p.candidates[candIdx].state)
	}

	// Step 2: Acquire for recheck -> StateRechecking
	conn, ok := p.AcquireNextInactiveForRecheck(time.Now(), 0)
	if !ok || conn.Key != "cand-fsm" {
		t.Fatalf("failed to acquire cand-fsm")
	}
	if p.candidates[candIdx].state != StateRechecking {
		t.Fatalf("expected StateRechecking, got %s", p.candidates[candIdx].state)
	}

	// Step 3: Complete recheck with failure (MTU failed)
	_, _ = p.CompleteRecheck(ResolverRecheckResult{
		Connection:  conn,
		MTUVerified: false,
	})

	// Challenge: What is the state now?
	currState := p.candidates[candIdx].state
	t.Logf("State after failed CompleteRecheck: %s", currState)

	// If the state is still StateRechecking, then ReleaseRecheck can be called!
	// If a caller or deferred cleanup calls ReleaseRecheck("cand-fsm", true),
	// does it improperly restore standby eligibility even though recheck failed?
	p.ReleaseRecheck("cand-fsm", true)
	if p.candidates[candIdx].conn.StandbyEligible {
		t.Errorf("BUG DISCOVERED: Failed recheck left candidate in StateRechecking; subsequent ReleaseRecheck revived it into StandbyEligible!")
	}
}

// TestEmpirical_Adversarial_DuplicateKeysInSetConnections verifies behavior when
// duplicate connection keys are passed to SetConnections.
func TestEmpirical_Adversarial_DuplicateKeysInSetConnections(t *testing.T) {
	p := NewResolverPool(2, nil)
	conns := []*Connection{
		{Key: "dup-key", Resolver: "10.0.0.1", ResolverPort: 53, ResolverLabel: "10.0.0.1:53", Domain: "d1.com"},
		{Key: "dup-key", Resolver: "10.0.0.2", ResolverPort: 53, ResolverLabel: "10.0.0.2:53", Domain: "d2.com"},
	}
	p.SetConnections(conns)

	// If indexByKey was overwritten, TotalCount may report 2 while indexByKey has 1 entry
	t.Logf("TotalCount: %d, indexByKey len: %d, inactiveIDs len: %d", p.TotalCount(), len(p.indexByKey), len(p.inactiveIDs))
	if len(p.indexByKey) != p.TotalCount() {
		t.Logf("NOTE: SetConnections silently permits duplicate keys, orphaning candidate at index 0")
	}
}

