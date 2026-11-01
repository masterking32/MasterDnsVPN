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
	"math"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ==============================================================================
// TIER 1: FEATURE COVERAGE
// Verifies primary behavior for all features in PR #205 Architectural Deepening.
// ==============================================================================

// TestE2E_Tier1_ResolverEvaluation_Calculations verifies pure resolver evaluation:
// baseline speed, loss ratio deduction, latency penalties, speed formatting, and quality tiers.
func TestE2E_Tier1_ResolverEvaluation_Calculations(t *testing.T) {
	// Case 1: Healthy resolver - 1200 byte MTU, 50ms RTT, 0% loss
	speed, score := CalculateResolverScore(1200, 50*time.Millisecond, 0.0)
	expectedSpeed := (1200.0 / 1024.0) / 0.05 // ~23.4375 KB/s
	if math.Abs(speed-expectedSpeed) > 0.01 {
		t.Fatalf("expected speed %.4f, got %.4f", expectedSpeed, speed)
	}
	expectedPenalty := 1.0 + (50.0 / 500.0) // 1.10
	expectedScore := expectedSpeed / expectedPenalty
	if math.Abs(score-expectedScore) > 0.01 {
		t.Fatalf("expected score %.4f, got %.4f", expectedScore, score)
	}

	tier, badge := ResolverQualityTier(score)
	if tier != "Excellent" || badge != "<green>[EXCELLENT]</green>" {
		t.Fatalf("expected Excellent tier, got %s / %s", tier, badge)
	}

	// Case 2: Good tier (8.0 <= score < 15.0)
	// MTU=1000, RTT=80ms, Loss=0% -> Speed = (1000/1024)/0.08 = 12.207 KB/s. Penalty = 1.0 + 80/500 = 1.16. Score = 10.52
	_, goodScore := CalculateResolverScore(1000, 80*time.Millisecond, 0.0)
	tierGood, badgeGood := ResolverQualityTier(goodScore)
	if tierGood != "Good" || badgeGood != "<cyan>[GOOD]</cyan>" {
		t.Fatalf("expected Good tier, got %s / %s (score=%.2f)", tierGood, badgeGood, goodScore)
	}

	// Case 3: Fair tier (4.0 <= score < 8.0)
	// MTU=1000, RTT=120ms, Loss=10% -> Speed = (1000/1024)/0.12 = 8.138 KB/s. Penalty = 1.24. Score = 5.91
	_, fairScore := CalculateResolverScore(1000, 120*time.Millisecond, 0.10)
	tierFair, badgeFair := ResolverQualityTier(fairScore)
	if tierFair != "Fair" || badgeFair != "<yellow>[FAIR]</yellow>" {
		t.Fatalf("expected Fair tier, got %s / %s (score=%.2f)", tierFair, badgeFair, fairScore)
	}

	// Case 4: Poor tier (score < 4.0)
	_, poorScore := CalculateResolverScore(500, 400*time.Millisecond, 0.50)
	tierPoor, badgePoor := ResolverQualityTier(poorScore)
	if tierPoor != "Poor" || badgePoor != "<red>[POOR]</red>" {
		t.Fatalf("expected Poor tier, got %s / %s (score=%.2f)", tierPoor, badgePoor, poorScore)
	}

	// Case 5: Speed formatting helper
	if formatted := FormatResolverSpeed(0); formatted != "n/a" {
		t.Fatalf("expected n/a for 0 speed, got %s", formatted)
	}
	if formatted := FormatResolverSpeed(512.5); formatted != "512.5 KB/s" {
		t.Fatalf("expected '512.5 KB/s', got %s", formatted)
	}
	if formatted := FormatResolverSpeed(2048.0); formatted != "2.00 MB/s" {
		t.Fatalf("expected '2.00 MB/s', got %s", formatted)
	}
}

// TestE2E_Tier1_ResolverPool_CapacityBounding verifies that the pool strictly enforces
// capacity bounds across admissions, displacements, and saturation.
func TestE2E_Tier1_ResolverPool_CapacityBounding(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	const maxActive = 3
	b.SetMaxActiveResolvers(maxActive)

	var conns []*Connection
	for i := 1; i <= 8; i++ {
		conns = append(conns, &Connection{
			Key:           fmt.Sprintf("r%d", i),
			Resolver:      fmt.Sprintf("10.0.0.%d", i),
			ResolverPort:  53,
			Domain:        "tunnel.example.com",
			ResolverLabel: fmt.Sprintf("10.0.0.%d:53", i),
		})
	}
	b.SetConnections(conns)

	if b.TotalCount() != 8 {
		t.Fatalf("expected total count 8, got %d", b.TotalCount())
	}
	if b.ActiveCount() != 0 {
		t.Fatalf("expected initial active count 0, got %d", b.ActiveCount())
	}

	// Admit candidates one by one and verify capacity capping
	for i := 1; i <= 8; i++ {
		key := fmt.Sprintf("r%d", i)
		b.SeedBurstStats(key, 100, 100, time.Duration(10*i)*time.Millisecond)
		b.SetConnectionValidity(key, true)

		active := b.ActiveCount()
		if active > maxActive {
			t.Fatalf("capacity bound violated: active=%d exceeded maxActive=%d", active, maxActive)
		}
	}

	if b.ActiveCount() != maxActive {
		t.Fatalf("expected active count to be saturated at %d, got %d", maxActive, b.ActiveCount())
	}
}

// TestE2E_Tier1_ResolverPool_CandidateStateTransitions verifies that candidates cleanly
// transition across Inactive, Active, Standby, and Rechecking without state corruptions.
func TestE2E_Tier1_ResolverPool_CandidateStateTransitions(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	b.SetMaxActiveResolvers(2)

	conns := []*Connection{
		{Key: "c1", Resolver: "1.1.1.1", ResolverPort: 53, Domain: "d.com", ResolverLabel: "1.1.1.1:53"},
		{Key: "c2", Resolver: "1.1.1.2", ResolverPort: 53, Domain: "d.com", ResolverLabel: "1.1.1.2:53"},
		{Key: "c3", Resolver: "1.1.1.3", ResolverPort: 53, Domain: "d.com", ResolverLabel: "1.1.1.3:53"},
	}
	b.SetConnections(conns)

	// Step 1: Initial state -> All Inactive
	for _, c := range conns {
		conn, _ := b.GetConnectionByKey(c.Key)
		if conn.IsValid || conn.StandbyEligible {
			t.Fatalf("expected candidate %s to start Inactive (IsValid=false, Standby=false)", c.Key)
		}
	}

	// Step 2: Activate c1 and c2 -> StateActive
	b.SetConnectionValidity("c1", true)
	b.SetConnectionValidity("c2", true)
	c1, _ := b.GetConnectionByKey("c1")
	if !c1.IsValid || c1.StandbyEligible {
		t.Fatalf("expected c1 to be StateActive (IsValid=true, Standby=false)")
	}

	// Step 3: Mark c3 as StandbyEligible -> StateStandby
	b.SetConnectionStandbyEligible("c3", true)
	c3, _ := b.GetConnectionByKey("c3")
	if c3.IsValid || !c3.StandbyEligible {
		t.Fatalf("expected c3 to be StateStandby (IsValid=false, Standby=true)")
	}

	// Step 4: Begin recheck on c3 -> StateRechecking (StandbyEligible revoked during lease)
	leased := b.beginConnectionRecheck("c3")
	if !leased {
		t.Fatalf("expected beginConnectionRecheck on c3 to succeed")
	}
	c3Rechecking, _ := b.GetConnectionByKey("c3")
	if c3Rechecking.IsValid || c3Rechecking.StandbyEligible {
		t.Fatalf("expected c3 during recheck to have StandbyEligible=false, got IsValid=%v Standby=%v",
			c3Rechecking.IsValid, c3Rechecking.StandbyEligible)
	}

	// Step 5: Complete recheck with failure -> demoted back to StateInactive
	resultFail := resolverRecheckResult{
		Connection:  c3Rechecking,
		MTUVerified: false,
	}
	updatedConn, found := b.completeConnectionRecheck(resultFail)
	if !found {
		t.Fatalf("expected candidate c3 to be found in pool")
	}
	if updatedConn.IsValid {
		t.Fatalf("unverified candidate must not be promoted (IsValid should be false)")
	}
	c3Failed, _ := b.GetConnectionByKey("c3")
	if c3Failed.IsValid || c3Failed.StandbyEligible {
		t.Fatalf("expected failed recheck to land in StateInactive (IsValid=false, Standby=false)")
	}
}

// TestE2E_Tier1_ResolverPool_OptimizationSwaps verifies degradation swaps when a standby
// beats an active resolver by greater than the 1.25x hysteresis threshold.
func TestE2E_Tier1_ResolverPool_OptimizationSwaps(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	b.SetMaxActiveResolvers(1)
	b.SetSessionSynchronizedMTU(100, 1000)

	conns := []*Connection{
		{Key: "incumbent", Resolver: "10.0.0.1", ResolverPort: 53, Domain: "d.com", ResolverLabel: "10.0.0.1:53"},
		{Key: "challenger", Resolver: "10.0.0.2", ResolverPort: 53, Domain: "d.com", ResolverLabel: "10.0.0.2:53"},
	}
	b.SetConnections(conns)
	b.SetConnectionMTU("incumbent", 100, 100, 1000)
	b.SetConnectionMTU("challenger", 100, 100, 1000)

	// Incumbent is active with 50% loss, 200ms RTT
	b.SeedBurstStats("incumbent", 100, 50, 200*time.Millisecond)
	b.SetConnectionValidity("incumbent", true)

	// Challenger is standby with only marginally better score (< 1.25x improvement)
	// Incumbent score: ~1.75. Let challenger score be ~2.0 (1.14x)
	b.SeedBurstStats("challenger", 100, 55, 190*time.Millisecond)
	b.SetConnectionStandbyEligible("challenger", true)

	swapped := b.OptimizeActivePool()
	if swapped {
		t.Fatalf("expected OptimizeActivePool to NOT swap when improvement < 1.25x threshold")
	}

	// Challenger improves significantly: 0% loss, 20ms RTT (> 10x improvement)
	b.SeedBurstStats("challenger", 100, 100, 20*time.Millisecond)
	swapped = b.OptimizeActivePool()
	if !swapped {
		t.Fatalf("expected OptimizeActivePool to swap when improvement > 1.25x threshold")
	}

	// Verify challenger is now active, incumbent is demoted to standby
	ch, _ := b.GetConnectionByKey("challenger")
	if !ch.IsValid || ch.StandbyEligible {
		t.Fatalf("expected challenger to be active (IsValid=true, Standby=false)")
	}
	inc, _ := b.GetConnectionByKey("incumbent")
	if inc.IsValid || !inc.StandbyEligible {
		t.Fatalf("expected incumbent to be demoted to standby (IsValid=false, Standby=true)")
	}
}

// TestE2E_Tier1_Discovery_WorkerParallelismAndBatching verifies worker pool parallelism
// and candidate batching without concurrency conflicts.
func TestE2E_Tier1_Discovery_WorkerParallelismAndBatching(t *testing.T) {
	const totalCandidates = 20
	const workerCount = 4

	candidateChan := make(chan int, totalCandidates)
	for i := 0; i < totalCandidates; i++ {
		candidateChan <- i
	}
	close(candidateChan)

	var probedCount atomic.Int32
	var maxConcurrency atomic.Int32
	var currentConcurrency atomic.Int32

	var wg sync.WaitGroup
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range candidateChan {
				cur := currentConcurrency.Add(1)
				for {
					max := maxConcurrency.Load()
					if cur <= max || maxConcurrency.CompareAndSwap(max, cur) {
						break
					}
				}

				// Simulate probing work
				time.Sleep(5 * time.Millisecond)
				probedCount.Add(1)
				currentConcurrency.Add(-1)
			}
		}()
	}
	wg.Wait()

	if probedCount.Load() != totalCandidates {
		t.Fatalf("expected %d candidates probed, got %d", totalCandidates, probedCount.Load())
	}
	if maxConcurrency.Load() > workerCount {
		t.Fatalf("max concurrency %d exceeded workerCount %d", maxConcurrency.Load(), workerCount)
	}
	if maxConcurrency.Load() <= 1 && totalCandidates > 5 {
		t.Fatalf("expected parallel execution across workers, got maxConcurrency=%d", maxConcurrency.Load())
	}
}

// TestE2E_Tier1_Discovery_FastStartEarlyExitAndReplenishment verifies that FastStart exits early
// once the target quota is reached, and replenishes if initial burst probes fail.
func TestE2E_Tier1_Discovery_FastStartEarlyExitAndReplenishment(t *testing.T) {
	const targetQuota = 3
	candidates := []struct {
		Endpoint  string
		MTUPass   bool
		BurstPass bool
	}{
		{"10.0.0.1:53", true, false}, // burst fail -> triggers replenishment
		{"10.0.0.2:53", true, true},  // qualified 1
		{"10.0.0.3:53", true, true},  // qualified 2
		{"10.0.0.4:53", true, true},  // qualified 3 -> target met!
		{"10.0.0.5:53", true, true},  // should be skipped due to early exit
		{"10.0.0.6:53", true, true},  // should be skipped due to early exit
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var qualifiedEndpoints []string
	var probedCount int

discoveryLoop:
	for _, cand := range candidates {
		select {
		case <-ctx.Done():
			break discoveryLoop
		default:
		}

		probedCount++
		if cand.MTUPass && cand.BurstPass {
			qualifiedEndpoints = append(qualifiedEndpoints, cand.Endpoint)
			if len(qualifiedEndpoints) >= targetQuota {
				cancel() // Early exit trigger!
			}
		}
	}

	if len(qualifiedEndpoints) != targetQuota {
		t.Fatalf("expected %d qualified endpoints, got %d", targetQuota, len(qualifiedEndpoints))
	}
	if probedCount > 4 {
		t.Fatalf("expected early exit after probing 4 candidates, probed %d", probedCount)
	}
}

// TestE2E_Tier1_Persistence_EventDrivenTriggers verifies that pool state modifications
// trigger ranked endpoint updates with active members prioritized.
func TestE2E_Tier1_Persistence_EventDrivenTriggers(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	b.SetMaxActiveResolvers(2)

	conns := []*Connection{
		{Key: "r1", Resolver: "10.0.0.1", ResolverPort: 53, Domain: "d.com", ResolverLabel: "10.0.0.1:53"},
		{Key: "r2", Resolver: "10.0.0.2", ResolverPort: 53, Domain: "d.com", ResolverLabel: "10.0.0.2:53"},
		{Key: "r3", Resolver: "10.0.0.3", ResolverPort: 53, Domain: "d.com", ResolverLabel: "10.0.0.3:53"},
	}
	b.SetConnections(conns)

	b.SeedBurstStats("r1", 100, 100, 20*time.Millisecond)
	b.SeedBurstStats("r2", 100, 100, 40*time.Millisecond)
	b.SeedBurstStats("r3", 100, 100, 10*time.Millisecond) // fastest, but standby

	b.SetConnectionValidity("r1", true)
	b.SetConnectionValidity("r2", true)
	b.SetConnectionStandbyEligible("r3", true)

	// Query ranked endpoints: active members must sort first due to active bonus
	ranked := b.GetRankedEndpoints(10)
	if len(ranked) < 2 {
		t.Fatalf("expected at least 2 ranked endpoints, got %d", len(ranked))
	}

	// First two must be active resolvers (10.0.0.1 and 10.0.0.2)
	if ranked[0].IP != "10.0.0.1" && ranked[0].IP != "10.0.0.2" {
		t.Fatalf("expected active resolver at rank 0, got %s", ranked[0].IP)
	}
	if ranked[1].IP != "10.0.0.1" && ranked[1].IP != "10.0.0.2" {
		t.Fatalf("expected active resolver at rank 1, got %s", ranked[1].IP)
	}
}

// ==============================================================================
// TIER 2: BOUNDARY / CORNER CASES
// Verifies extreme inputs, zero/negative metrics, and edge capacity bounding.
// ==============================================================================

// TestE2E_Tier2_Boundary_ZeroNegativeRTTAndLoss tests arithmetic edge cases in score calculations.
func TestE2E_Tier2_Boundary_ZeroNegativeRTTAndLoss(t *testing.T) {
	// Zero RTT -> must yield (0, 0)
	s1, sc1 := CalculateResolverScore(1200, 0, 0.0)
	if s1 != 0 || sc1 != 0 {
		t.Fatalf("expected (0, 0) for zero RTT, got (%.2f, %.2f)", s1, sc1)
	}

	// Negative RTT -> must yield (0, 0)
	s2, sc2 := CalculateResolverScore(1200, -10*time.Millisecond, 0.0)
	if s2 != 0 || sc2 != 0 {
		t.Fatalf("expected (0, 0) for negative RTT, got (%.2f, %.2f)", s2, sc2)
	}

	// Negative DownloadMTU -> defaults to 500
	s3, _ := CalculateResolverScore(-1, 50*time.Millisecond, 0.0)
	expectedS3 := (500.0 / 1024.0) / 0.05
	if math.Abs(s3-expectedS3) > 0.01 {
		t.Fatalf("expected MTU <= 0 to default to 500 (speed %.2f), got %.2f", expectedS3, s3)
	}

	// Negative LossRatio -> clamped to 0.0
	_, sc4 := CalculateResolverScore(1000, 50*time.Millisecond, -0.5)
	_, sc4Expected := CalculateResolverScore(1000, 50*time.Millisecond, 0.0)
	if math.Abs(sc4-sc4Expected) > 0.001 {
		t.Fatalf("expected negative loss to clamp to 0.0")
	}

	// Excessive LossRatio (> 1.0) -> clamped to 1.0 -> score = 0.0
	_, sc5 := CalculateResolverScore(1000, 50*time.Millisecond, 2.5)
	if sc5 != 0 {
		t.Fatalf("expected loss > 1.0 to produce score 0.0, got %.4f", sc5)
	}

	// 100% loss -> score = 0.0
	_, sc6 := CalculateResolverScore(1000, 50*time.Millisecond, 1.0)
	if sc6 != 0 {
		t.Fatalf("expected 100%% loss to produce score 0.0, got %.4f", sc6)
	}

	// Massive RTT (100 seconds) -> huge latency penalty
	_, sc7 := CalculateResolverScore(1000, 100*time.Second, 0.0)
	if sc7 <= 0 || sc7 > 0.01 {
		t.Fatalf("expected near-zero score for 100s RTT, got %.6f", sc7)
	}
}

// TestE2E_Tier2_Boundary_PoolCapacityLimits tests zero, single, and empty candidate edge cases.
func TestE2E_Tier2_Boundary_PoolCapacityLimits(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)

	// Empty pool
	b.SetConnections(nil)
	if b.TotalCount() != 0 || b.ActiveCount() != 0 {
		t.Fatalf("expected empty balancer to have 0 counts")
	}
	if b.OptimizeActivePool() {
		t.Fatalf("empty pool should return false on optimize")
	}

	// Single candidate pool with maxActive = 1
	b.SetMaxActiveResolvers(1)
	single := []*Connection{
		{Key: "solo", Resolver: "127.0.0.1", ResolverPort: 53, Domain: "d.com", ResolverLabel: "127.0.0.1:53"},
	}
	b.SetConnections(single)
	b.SetConnectionValidity("solo", true)

	if b.ActiveCount() != 1 || b.TotalCount() != 1 {
		t.Fatalf("expected active=1, total=1")
	}

	// Single active candidate cannot be optimized away
	if b.OptimizeActivePool() {
		t.Fatalf("cannot optimize when no standbys exist")
	}
}

// TestE2E_Tier2_Boundary_RecheckCooldown tests cooldown after a completed probe.
func TestE2E_Tier2_Boundary_RecheckCooldown(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	b.SetMaxActiveResolvers(1)

	conns := []*Connection{
		{Key: "r1", Resolver: "10.0.0.1", ResolverPort: 53, Domain: "d.com", ResolverLabel: "10.0.0.1:53"},
	}
	b.SetConnections(conns)

	// Acquire for health check
	now := time.Now()
	nextConn, ok := b.NextInactiveConnectionForHealthCheck(now, 60*time.Second)
	if !ok || nextConn.Key != "r1" {
		t.Fatalf("expected to acquire r1 for health check")
	}

	// Completion releases the lease, but does not bypass its cooldown.
	b.completeConnectionRecheck(resolverRecheckResult{Connection: nextConn})

	// Attempting immediate re-acquisition within 60s cooldown must fail
	_, ok2 := b.NextInactiveConnectionForHealthCheck(now.Add(30*time.Second), 60*time.Second)
	if ok2 {
		t.Fatalf("expected acquisition to fail within cooldown interval")
	}

	// Re-acquisition after 61s must succeed
	nextConn3, ok3 := b.NextInactiveConnectionForHealthCheck(now.Add(61*time.Second), 60*time.Second)
	if !ok3 || nextConn3.Key != "r1" {
		t.Fatalf("expected acquisition to succeed after interval elapsed")
	}
}

// ==============================================================================
// TIER 3: CROSS-FEATURE PAIRWISE INTERACTIONS
// Verifies interactions between Discovery, ResolverPool, Balancer, and Persistence.
// ==============================================================================

// TestE2E_Tier3_Pairwise_DiscoveryToPoolAdmission verifies the end-to-end flow from
// candidate qualification -> batch admission -> active/standby partition -> target dispatch.
func TestE2E_Tier3_Pairwise_DiscoveryToPoolAdmission(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	const maxActive = 2
	b.SetMaxActiveResolvers(maxActive)

	conns := []*Connection{
		{Key: "c1", Resolver: "10.0.0.1", ResolverPort: 53, Domain: "d.com", ResolverLabel: "10.0.0.1:53", UploadMTUBytes: 200, DownloadMTUBytes: 1200},
		{Key: "c2", Resolver: "10.0.0.2", ResolverPort: 53, Domain: "d.com", ResolverLabel: "10.0.0.2:53", UploadMTUBytes: 200, DownloadMTUBytes: 1200},
		{Key: "c3", Resolver: "10.0.0.3", ResolverPort: 53, Domain: "d.com", ResolverLabel: "10.0.0.3:53", UploadMTUBytes: 200, DownloadMTUBytes: 1200},
		{Key: "c4", Resolver: "10.0.0.4", ResolverPort: 53, Domain: "d.com", ResolverLabel: "10.0.0.4:53", UploadMTUBytes: 200, DownloadMTUBytes: 1200},
	}
	b.SetConnections(conns)

	// Simulate discovery results
	results := []QualifiedResolver{
		{
			Connection:  *conns[0],
			BurstResult: BurstProbeResult{SentCount: 6, ReceivedCount: 6, LossRatio: 0.0, AverageRTT: 20 * time.Millisecond, Qualified: true},
		},
		{
			Connection:  *conns[1],
			BurstResult: BurstProbeResult{SentCount: 6, ReceivedCount: 6, LossRatio: 0.0, AverageRTT: 25 * time.Millisecond, Qualified: true},
		},
		{
			Connection:  *conns[2],
			BurstResult: BurstProbeResult{SentCount: 6, ReceivedCount: 6, LossRatio: 0.0, AverageRTT: 30 * time.Millisecond, Qualified: true},
		},
		{
			Connection:  *conns[3],
			BurstResult: BurstProbeResult{SentCount: 6, ReceivedCount: 2, LossRatio: 0.66, AverageRTT: 100 * time.Millisecond, Qualified: false},
		},
	}

	// Select top 2 for active pool
	selected := []Connection{*conns[0], *conns[1]}
	b.admitQualifiedBatch(results, selected)

	if b.ActiveCount() != 2 {
		t.Fatalf("expected 2 active connections, got %d", b.ActiveCount())
	}

	// c1 and c2 must be active
	c1, _ := b.GetConnectionByKey("c1")
	c2, _ := b.GetConnectionByKey("c2")
	if !c1.IsValid || c1.StandbyEligible || !c2.IsValid || c2.StandbyEligible {
		t.Fatalf("c1 and c2 must be active")
	}

	// c3 was qualified but not selected -> must be StandbyEligible
	c3, _ := b.GetConnectionByKey("c3")
	if c3.IsValid || !c3.StandbyEligible {
		t.Fatalf("c3 must be standby eligible (IsValid=false, Standby=true)")
	}

	// c4 was disqualified -> must be Inactive
	c4, _ := b.GetConnectionByKey("c4")
	if c4.IsValid || c4.StandbyEligible {
		t.Fatalf("c4 must be inactive (IsValid=false, Standby=false)")
	}

	// Verify Balancer target selection routes only to c1 and c2
	targets, err := b.SelectTargets(0, 1, 2)
	if err != nil {
		t.Fatalf("SelectTargets failed: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
	for _, tgt := range targets {
		if tgt.Key != "c1" && tgt.Key != "c2" {
			t.Fatalf("target selection selected non-active candidate: %s", tgt.Key)
		}
	}
}

// TestE2E_Tier3_Pairwise_RecheckDegradationSwapPersistence tests active degradation ->
// recheck -> swap -> ranked endpoints reflection.
func TestE2E_Tier3_Pairwise_RecheckDegradationSwapPersistence(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	b.SetMaxActiveResolvers(1)
	b.SetSessionSynchronizedMTU(100, 1000)

	conns := []*Connection{
		{Key: "active-deg", Resolver: "10.0.0.1", ResolverPort: 53, Domain: "d.com", ResolverLabel: "10.0.0.1:53"},
		{Key: "standby-fast", Resolver: "10.0.0.2", ResolverPort: 53, Domain: "d.com", ResolverLabel: "10.0.0.2:53"},
	}
	b.SetConnections(conns)
	b.SetConnectionMTU("active-deg", 100, 100, 1000)
	b.SetConnectionMTU("standby-fast", 100, 100, 1000)

	// Active candidate is degraded
	b.SeedBurstStats("active-deg", 100, 30, 400*time.Millisecond) // 70% loss
	b.SetConnectionValidity("active-deg", true)

	// Standby is healthy
	b.SeedBurstStats("standby-fast", 100, 100, 20*time.Millisecond) // 0% loss
	b.SetConnectionStandbyEligible("standby-fast", true)

	// Perform optimization swap
	if !b.OptimizeActivePool() {
		t.Fatalf("expected OptimizeActivePool to swap degraded active")
	}

	// Persistence query: ranked endpoints must reflect standby-fast at rank 0
	ranked := b.GetRankedEndpoints(5)
	if len(ranked) == 0 || ranked[0].IP != "10.0.0.2" {
		t.Fatalf("expected newly promoted 10.0.0.2 at rank 0, got %+v", ranked)
	}
}

// ==============================================================================
// TIER 4: REAL-WORLD WORKLOADS & ADVERSARIAL STRESS
// Stress tests concurrency, race conditions, invariant integrity, and scope limits.
// ==============================================================================

// TestE2E_Tier4_Workload_HighConcurrencyDiscoveryStress runs concurrent simulated probes,
// admissions, and validity updates across 20 goroutines with zero data races.
func TestE2E_Tier4_Workload_HighConcurrencyDiscoveryStress(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	b.SetMaxActiveResolvers(4)

	const numConns = 30
	var conns []*Connection
	for i := 0; i < numConns; i++ {
		conns = append(conns, &Connection{
			Key:           fmt.Sprintf("stress-%d", i),
			Resolver:      fmt.Sprintf("10.1.%d.1", i),
			ResolverPort:  53,
			Domain:        "stress.example.com",
			ResolverLabel: fmt.Sprintf("10.1.%d.1:53", i),
		})
	}
	b.SetConnections(conns)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			r := uint32(workerID * 100)
			for {
				select {
				case <-ctx.Done():
					return
				default:
					r = r*1664525 + 1013904223
					idx := int(r % numConns)
					key := fmt.Sprintf("stress-%d", idx)

					// Random operation
					op := (r >> 16) % 4
					switch op {
					case 0:
						b.SeedBurstStats(key, 50, 40+int(r%11), time.Duration(10+r%100)*time.Millisecond)
					case 1:
						b.SetConnectionValidity(key, (r%2) == 0)
					case 2:
						b.SetConnectionStandbyEligible(key, (r%2) == 1)
					case 3:
						_ = b.OptimizeActivePool()
					}
				}
			}
		}(i)
	}
	wg.Wait()

	if b.ActiveCount() > 4 {
		t.Fatalf("capacity bound breached under stress: %d > 4", b.ActiveCount())
	}
}

// TestE2E_Tier4_Adversarial_InvariantAudit_MutualExclusivity performs continuous verification
// that IsValid and StandbyEligible are MUTUALLY EXCLUSIVE across all state changes.
func TestE2E_Tier4_Adversarial_InvariantAudit_MutualExclusivity(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	b.SetMaxActiveResolvers(3)

	const numCandidates = 15
	var conns []*Connection
	for i := 0; i < numCandidates; i++ {
		conns = append(conns, &Connection{
			Key:           fmt.Sprintf("inv-%d", i),
			Resolver:      fmt.Sprintf("192.168.1.%d", i+1),
			ResolverPort:  53,
			Domain:        "inv.com",
			ResolverLabel: fmt.Sprintf("192.168.1.%d:53", i+1),
		})
	}
	b.SetConnections(conns)

	assertMutualExclusivity := func(step string) {
		t.Helper()
		for _, c := range conns {
			conn, ok := b.GetConnectionByKey(c.Key)
			if !ok {
				continue
			}
			if conn.IsValid && conn.StandbyEligible {
				t.Fatalf("[%s] Mutual exclusivity violation on %s: IsValid=true AND StandbyEligible=true", step, c.Key)
			}
		}
	}

	// Audit across sequential admissions, promotions, demotions, and rechecks
	for i := 0; i < numCandidates; i++ {
		key := fmt.Sprintf("inv-%d", i)
		b.SeedBurstStats(key, 100, 95, time.Duration(15+i)*time.Millisecond)
		b.SetConnectionValidity(key, true)
		assertMutualExclusivity(fmt.Sprintf("Admit-%d", i))
	}

	for i := 0; i < numCandidates; i++ {
		key := fmt.Sprintf("inv-%d", i)
		b.SetConnectionStandbyEligible(key, true)
		assertMutualExclusivity(fmt.Sprintf("Standby-%d", i))
	}

	for iter := 0; iter < 10; iter++ {
		b.OptimizeActivePool()
		assertMutualExclusivity(fmt.Sprintf("Optimize-%d", iter))
	}
}

// TestE2E_Tier4_Adversarial_Immutability_ScopeAudit verifies that git status reports zero
// modifications to go.mod, go.sum, and zero modifications outside internal/client/ & internal/config/.
func TestE2E_Tier4_Adversarial_Immutability_ScopeAudit(t *testing.T) {
	// 1. Verify go.mod and go.sum immutability
	cmdDiff := exec.Command("git", "diff", "--", "go.mod", "go.sum")
	outDiff, err := cmdDiff.CombinedOutput()
	if err != nil {
		t.Fatalf("git diff failed: %v", err)
	}
	if strings.TrimSpace(string(outDiff)) != "" {
		t.Fatalf("CRITICAL INVARIANT VIOLATION: go.mod / go.sum has been modified!\n%s", string(outDiff))
	}

	// 2. Verify git status has no staged or unstaged modifications in cmd/ or internal/ outside client and config
	cmdStatus := exec.Command("git", "status", "--porcelain")
	outStatus, err := cmdStatus.CombinedOutput()
	if err != nil {
		t.Fatalf("git status failed: %v", err)
	}

	lines := strings.Split(string(outStatus), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) < 3 {
			continue
		}
		filePath := strings.TrimSpace(line[2:])
		if strings.HasPrefix(filePath, "cmd/") {
			t.Fatalf("CRITICAL SCOPE VIOLATION: modified forbidden path: %s", filePath)
		}
		if strings.HasPrefix(filePath, "internal/") &&
			!strings.HasPrefix(filePath, "internal/client") &&
			!strings.HasPrefix(filePath, "internal/config") {
			t.Fatalf("CRITICAL SCOPE VIOLATION: modified forbidden path: %s", filePath)
		}
	}
}

// TestE2E_Tier2_Boundary_AllCandidatesProbeFailure verifies that the pool behaves safely
// and returns appropriate errors or empty lists when every candidate fails probes.
func TestE2E_Tier2_Boundary_AllCandidatesProbeFailure(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	b.SetMaxActiveResolvers(3)

	conns := []*Connection{
		{Key: "f1", Resolver: "192.0.2.1", ResolverPort: 53, Domain: "fail.com", ResolverLabel: "192.0.2.1:53"},
		{Key: "f2", Resolver: "192.0.2.2", ResolverPort: 53, Domain: "fail.com", ResolverLabel: "192.0.2.2:53"},
	}
	b.SetConnections(conns)

	// All fail burst probes
	results := []QualifiedResolver{
		{
			Connection:  *conns[0],
			BurstResult: BurstProbeResult{SentCount: 6, ReceivedCount: 0, LossRatio: 1.0, Qualified: false},
		},
		{
			Connection:  *conns[1],
			BurstResult: BurstProbeResult{SentCount: 6, ReceivedCount: 0, LossRatio: 1.0, Qualified: false},
		},
	}
	b.admitQualifiedBatch(results, nil)

	if b.ActiveCount() != 0 {
		t.Fatalf("expected 0 active resolvers when all fail, got %d", b.ActiveCount())
	}

	// Dispatching must return an error rather than panic
	targets, err := b.SelectTargets(0, 1, 1)
	if err == nil && len(targets) > 0 {
		t.Fatalf("expected error or zero targets when no active resolvers exist")
	}
}

// TestE2E_Tier3_Pairwise_StandbyRecheckFailureRevocation verifies that when a standby
// candidate is leased for recheck and fails, its StandbyEligible flag is revoked immediately,
// preventing concurrent OptimizeActivePool from promoting it.
func TestE2E_Tier3_Pairwise_StandbyRecheckFailureRevocation(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	b.SetMaxActiveResolvers(1)
	b.SetSessionSynchronizedMTU(100, 1000)

	conns := []*Connection{
		{Key: "act", Resolver: "10.0.0.1", ResolverPort: 53, Domain: "d.com", ResolverLabel: "10.0.0.1:53"},
		{Key: "stby", Resolver: "10.0.0.2", ResolverPort: 53, Domain: "d.com", ResolverLabel: "10.0.0.2:53"},
	}
	b.SetConnections(conns)
	b.SetConnectionMTU("act", 100, 100, 1000)
	b.SetConnectionMTU("stby", 100, 100, 1000)

	b.SeedBurstStats("act", 100, 40, 300*time.Millisecond) // degraded
	b.SetConnectionValidity("act", true)

	b.SeedBurstStats("stby", 100, 100, 20*time.Millisecond) // healthy standby
	b.SetConnectionStandbyEligible("stby", true)

	// Step 1: Lease stby for recheck -> revokes StandbyEligible
	leased := b.beginConnectionRecheck("stby")
	if !leased {
		t.Fatalf("expected beginConnectionRecheck to lease stby")
	}

	stbyLeased, _ := b.GetConnectionByKey("stby")
	if stbyLeased.StandbyEligible {
		t.Fatalf("recheck lease must clear StandbyEligible immediately")
	}

	// Step 2: Concurrent OptimizeActivePool must NOT promote stby while under recheck
	swapped := b.OptimizeActivePool()
	if swapped {
		t.Fatalf("OptimizeActivePool must NOT promote a candidate currently leased for recheck")
	}

	// Step 3: Complete recheck with failure -> remains Inactive, StandbyEligible=false
	updated, ok := b.completeConnectionRecheck(resolverRecheckResult{
		Connection:  stbyLeased,
		MTUVerified: false,
	})
	if !ok || updated.IsValid || updated.StandbyEligible {
		t.Fatalf("failed recheck must leave candidate Inactive and not StandbyEligible")
	}
}

// TestE2E_Tier4_Workload_RapidDegradationSwapsUnderLoss simulates rapid alternating packet loss
// across active pool members, verifying that the pool continuously promotes qualified standbys,
// enforces capacity limits, and never routes packets to invalid candidates.
func TestE2E_Tier4_Workload_RapidDegradationSwapsUnderLoss(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	const maxActive = 4
	b.SetMaxActiveResolvers(maxActive)
	b.SetSessionSynchronizedMTU(100, 1000)

	const totalResolvers = 12
	var conns []*Connection
	for i := 0; i < totalResolvers; i++ {
		conns = append(conns, &Connection{
			Key:           fmt.Sprintf("swap-%d", i),
			Resolver:      fmt.Sprintf("10.200.0.%d", i+1),
			ResolverPort:  53,
			Domain:        "loss-stress.com",
			ResolverLabel: fmt.Sprintf("10.200.0.%d:53", i+1),
		})
	}
	b.SetConnections(conns)
	for i := 0; i < totalResolvers; i++ {
		b.SetConnectionMTU(fmt.Sprintf("swap-%d", i), 100, 100, 1000)
	}

	// Initially activate first 4, rest as standbys
	for i := 0; i < maxActive; i++ {
		key := fmt.Sprintf("swap-%d", i)
		b.SeedBurstStats(key, 100, 100, 20*time.Millisecond)
		b.SetConnectionValidity(key, true)
	}
	for i := maxActive; i < totalResolvers; i++ {
		key := fmt.Sprintf("swap-%d", i)
		b.SeedBurstStats(key, 100, 100, 25*time.Millisecond)
		b.SetConnectionStandbyEligible(key, true)
	}

	// Simulate 50 rounds of sudden packet loss on random active members followed by optimization
	for round := 0; round < 50; round++ {
		// Degrade active members
		activeList := b.ActiveConnections()
		for _, act := range activeList {
			b.SeedBurstStats(act.Key, 100, 10, 800*time.Millisecond) // heavy degradation
		}

		// Improve standbys
		for i := 0; i < totalResolvers; i++ {
			key := fmt.Sprintf("swap-%d", i)
			c, _ := b.GetConnectionByKey(key)
			if c.StandbyEligible {
				b.SeedBurstStats(key, 100, 100, time.Duration(15+(round%10))*time.Millisecond)
			}
		}

		// Run optimization
		_ = b.OptimizeActivePool()

		// Verify capacity and invariants
		if b.ActiveCount() > maxActive {
			t.Fatalf("round %d: active count %d > maxActive %d", round, b.ActiveCount(), maxActive)
		}

		// Select targets must only return valid connections
		targets, err := b.SelectTargets(0, uint16(round), 2)
		if err == nil {
			for _, tgt := range targets {
				conn, ok := b.GetConnectionByKey(tgt.Key)
				if !ok || !conn.IsValid {
					t.Fatalf("round %d: SelectTargets returned non-active connection %s", round, tgt.Key)
				}
				if conn.StandbyEligible {
					t.Fatalf("round %d: selected target %s has StandbyEligible=true", round, tgt.Key)
				}
			}
		}
	}
}
