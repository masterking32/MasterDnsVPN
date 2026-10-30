package client

import (
	"fmt"
	"testing"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

func TestBalancerLeastLossFallsBackToRoundRobinWithoutStats(t *testing.T) {
	b := NewBalancer(BalancingLeastLoss, nil)
	connections := []*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
		{Key: "c", IsValid: true},
	}
	b.SetConnections(connections)
	_ = b.SetConnectionValidity("a", true)
	_ = b.SetConnectionValidity("b", true)
	_ = b.SetConnectionValidity("c", true)

	first, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected first connection")
	}
	second, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected second connection")
	}
	third, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected third connection")
	}

	if first.Key != "a" || second.Key != "b" || third.Key != "c" {
		t.Fatalf("expected round-robin a,b,c before stats, got %q,%q,%q", first.Key, second.Key, third.Key)
	}
}

func TestBalancerLowestLatencyUsesRuntimeStats(t *testing.T) {
	b := NewBalancer(BalancingLowestLatency, nil)
	connections := []*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
	}
	b.SetConnections(connections)
	_ = b.SetConnectionValidity("a", true)
	_ = b.SetConnectionValidity("b", true)

	for i := 0; i < 6; i++ {
		b.ReportSend("a")
		b.ReportSuccess("a", 8*time.Millisecond)
		b.ReportSend("b")
		b.ReportSuccess("b", 2*time.Millisecond)
	}

	best, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected best connection")
	}
	if best.Key != "b" {
		t.Fatalf("expected lower-latency resolver b, got %q", best.Key)
	}
}

func TestBalancerHybridPrefersLowerLossWhenLatencyIsClose(t *testing.T) {
	b := NewBalancer(BalancingHybridScore, nil)
	connections := []*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
	}
	b.SetConnections(connections)
	_ = b.SetConnectionValidity("a", true)
	_ = b.SetConnectionValidity("b", true)

	for i := 0; i < 10; i++ {
		b.ReportSend("a")
		b.ReportSuccess("a", 12*time.Millisecond)
		b.ReportSend("b")
		b.ReportSuccess("b", 8*time.Millisecond)
	}
	for i := 0; i < 3; i++ {
		b.ReportSend("a")
		b.ReportTimeout("a", time.Now(), 10*time.Second, 1)
	}

	best, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected best connection")
	}
	if best.Key != "b" {
		t.Fatalf("expected hybrid mode to prefer lower-loss resolver b, got %q", best.Key)
	}
}

func TestBalancerHybridPrefersLowerLatencyWhenLossIsEqual(t *testing.T) {
	b := NewBalancer(BalancingHybridScore, nil)
	connections := []*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
	}
	b.SetConnections(connections)
	_ = b.SetConnectionValidity("a", true)
	_ = b.SetConnectionValidity("b", true)

	for i := 0; i < 6; i++ {
		b.ReportSend("a")
		b.ReportSuccess("a", 12*time.Millisecond)
		b.ReportSend("b")
		b.ReportSuccess("b", 3*time.Millisecond)
	}

	best, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected best connection")
	}
	if best.Key != "b" {
		t.Fatalf("expected hybrid mode to prefer lower-latency resolver b when loss is equal, got %q", best.Key)
	}
}

func TestBalancerHybridFallsBackToRoundRobinWithoutStats(t *testing.T) {
	b := NewBalancer(BalancingHybridScore, nil)
	connections := []*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
		{Key: "c", IsValid: true},
	}
	b.SetConnections(connections)
	_ = b.SetConnectionValidity("a", true)
	_ = b.SetConnectionValidity("b", true)
	_ = b.SetConnectionValidity("c", true)

	first, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected first connection")
	}
	second, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected second connection")
	}
	third, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected third connection")
	}

	if first.Key != "a" || second.Key != "b" || third.Key != "c" {
		t.Fatalf("expected round-robin a,b,c before hybrid stats, got %q,%q,%q", first.Key, second.Key, third.Key)
	}
}

func TestBalancerLossThenLatencyPrefersLowerLossFirst(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	connections := []*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
	}
	b.SetConnections(connections)
	_ = b.SetConnectionValidity("a", true)
	_ = b.SetConnectionValidity("b", true)

	for i := 0; i < 10; i++ {
		b.ReportSend("a")
		b.ReportSuccess("a", 4*time.Millisecond)
		b.ReportSend("b")
		b.ReportSuccess("b", 10*time.Millisecond)
	}
	for i := 0; i < 2; i++ {
		b.ReportSend("a")
		b.ReportTimeout("a", time.Now(), 10*time.Second, 1)
	}

	best, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected best connection")
	}
	if best.Key != "b" {
		t.Fatalf("expected loss-then-latency mode to prefer lower-loss resolver b, got %q", best.Key)
	}
}

func TestBalancerLossThenLatencyUsesLatencyInsideLossTier(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	connections := []*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
	}
	b.SetConnections(connections)
	_ = b.SetConnectionValidity("a", true)
	_ = b.SetConnectionValidity("b", true)

	for i := 0; i < 8; i++ {
		b.ReportSend("a")
		b.ReportSuccess("a", 15*time.Millisecond)
		b.ReportSend("b")
		b.ReportSuccess("b", 4*time.Millisecond)
	}

	best, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected best connection")
	}
	if best.Key != "b" {
		t.Fatalf("expected lower-latency resolver b inside equal-loss tier, got %q", best.Key)
	}
}

func TestBalancerLossThenLatencyRoundRobinsAcrossNearTopCandidates(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	connections := []*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
	}
	b.SetConnections(connections)
	_ = b.SetConnectionValidity("a", true)
	_ = b.SetConnectionValidity("b", true)

	for i := 0; i < 8; i++ {
		b.ReportSend("a")
		b.ReportSuccess("a", 10*time.Millisecond)
		b.ReportSend("b")
		b.ReportSuccess("b", 12*time.Millisecond)
	}

	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		best, ok := b.GetBestConnection()
		if !ok {
			t.Fatal("expected best connection")
		}
		seen[best.Key] = true
	}

	if !seen["a"] || !seen["b"] {
		t.Fatalf("expected round-robin across near-top candidates, seen=%v", seen)
	}
}

func TestBalancerLeastLossTopRandomFallsBackToRoundRobinWithoutStats(t *testing.T) {
	b := NewBalancer(BalancingLeastLossTopRandom, nil)
	connections := []*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
		{Key: "c", IsValid: true},
	}
	b.SetConnections(connections)
	_ = b.SetConnectionValidity("a", true)
	_ = b.SetConnectionValidity("b", true)
	_ = b.SetConnectionValidity("c", true)

	first, _ := b.GetBestConnection()
	second, _ := b.GetBestConnection()
	third, _ := b.GetBestConnection()
	if first.Key != "a" || second.Key != "b" || third.Key != "c" {
		t.Fatalf("expected round-robin a,b,c before loss-top-random stats, got %q,%q,%q", first.Key, second.Key, third.Key)
	}
}

func TestBalancerLeastLossTopRandomUsesTopLossTier(t *testing.T) {
	b := NewBalancer(BalancingLeastLossTopRandom, nil)
	connections := []*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
		{Key: "c", IsValid: true},
		{Key: "d", IsValid: true},
	}
	b.SetConnections(connections)
	for _, key := range []string{"a", "b", "c", "d"} {
		_ = b.SetConnectionValidity(key, true)
	}

	for i := 0; i < 10; i++ {
		for _, key := range []string{"a", "b", "c", "d"} {
			b.ReportSend(key)
			b.ReportSuccess(key, 5*time.Millisecond)
		}
	}
	for i := 0; i < 1; i++ {
		b.ReportSend("c")
		b.ReportTimeout("c", time.Now(), 10*time.Second, 1)
		b.ReportSend("d")
		b.ReportTimeout("d", time.Now(), 10*time.Second, 1)
	}

	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		best, ok := b.GetBestConnection()
		if !ok {
			t.Fatal("expected best connection")
		}
		seen[best.Key] = true
		if best.Key == "c" || best.Key == "d" {
			t.Fatalf("expected picks only from lower-loss top tier, got %q", best.Key)
		}
	}

	if !seen["a"] || !seen["b"] {
		t.Fatalf("expected random selection among top loss tier, seen=%v", seen)
	}
}

func TestBalancerLeastLossTopRoundRobinUsesTopLossTier(t *testing.T) {
	b := NewBalancer(BalancingLeastLossTopRoundRobin, nil)
	connections := []*Connection{
		{Key: "a", IsValid: true},
		{Key: "b", IsValid: true},
		{Key: "c", IsValid: true},
		{Key: "d", IsValid: true},
	}
	b.SetConnections(connections)
	for _, key := range []string{"a", "b", "c", "d"} {
		_ = b.SetConnectionValidity(key, true)
	}

	for i := 0; i < 10; i++ {
		for _, key := range []string{"a", "b", "c", "d"} {
			b.ReportSend(key)
			b.ReportSuccess(key, 5*time.Millisecond)
		}
	}
	for i := 0; i < 1; i++ {
		b.ReportSend("c")
		b.ReportTimeout("c", time.Now(), 10*time.Second, 1)
		b.ReportSend("d")
		b.ReportTimeout("d", time.Now(), 10*time.Second, 1)
	}

	first, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected best connection")
	}
	second, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected best connection")
	}
	if (first.Key != "a" && first.Key != "b") || (second.Key != "a" && second.Key != "b") {
		t.Fatalf("expected picks only from lower-loss top tier, got %q then %q", first.Key, second.Key)
	}
	if first.Key == second.Key {
		t.Fatalf("expected round-robin across top loss tier, got %q then %q", first.Key, second.Key)
	}
}

func TestBalancerStatsHalfLifeAlsoAppliesOnSend(t *testing.T) {
	b := NewBalancer(BalancingLeastLoss, nil)
	connections := []*Connection{
		{Key: "a", IsValid: true},
	}
	b.SetConnections(connections)

	for i := 0; i < connectionStatsHalfLifeThreshold+1; i++ {
		b.ReportSend("a")
	}

	stats := b.statsForKey("a")
	if stats == nil {
		t.Fatal("expected stats for resolver a")
	}

	sent, acked, _, sum, count := stats.snapshot()
	if sent != (connectionStatsHalfLifeThreshold+1)/2 {
		t.Fatalf("expected send-triggered half-life to bound sent, got sent=%d acked=%d sum=%d count=%d", sent, acked, sum, count)
	}
	if acked != 0 || sum != 0 || count != 0 {
		t.Fatalf("expected send-triggered half-life to preserve zero success stats, got acked=%d sum=%d count=%d", acked, sum, count)
	}
}

func TestBalancerStatsHalfLifePreservesRelativeSuccessSignal(t *testing.T) {
	b := NewBalancer(BalancingLeastLoss, nil)
	connections := []*Connection{
		{Key: "a", IsValid: true},
	}
	b.SetConnections(connections)

	for i := 0; i < 800; i++ {
		b.ReportSend("a")
	}
	for i := 0; i < 400; i++ {
		b.ReportSuccess("a", 5*time.Millisecond)
	}
	for i := 0; i < 401; i++ {
		b.ReportSend("a")
	}

	stats := b.statsForKey("a")
	if stats == nil {
		t.Fatal("expected stats for resolver a")
	}

	sent, acked, _, sum, count := stats.snapshot()
	if sent != 700 || acked != 200 || count != 200 {
		t.Fatalf("expected balanced half-life after crossing threshold, got sent=%d acked=%d count=%d", sent, acked, count)
	}
	if sum != uint64(time.Millisecond/time.Microsecond)*5*200 {
		t.Fatalf("expected RTT signal to decay proportionally, got sum=%d", sum)
	}
}

func TestBalancerSetConnectionsCopiesSourceDomain(t *testing.T) {
	b := NewBalancer(BalancingRoundRobinDefault, nil)
	connections := []*Connection{
		{Key: "a", IsValid: true, Domain: "a.example.com"},
	}
	b.SetConnections(connections)

	connections[0].Domain = "mutated.example.com"

	got, ok := b.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected resolver a in balancer snapshot")
	}
	if got.Domain != "a.example.com" {
		t.Fatalf("expected balancer to keep copied domain after source mutation, got %q", got.Domain)
	}
}

func TestBalancerSetConnectionValidityDoesNotPullSourceMutation(t *testing.T) {
	b := NewBalancer(BalancingRoundRobinDefault, nil)
	connections := []*Connection{
		{Key: "a", IsValid: false, UploadMTUBytes: 140, DownloadMTUBytes: 220},
	}
	b.SetConnections(connections)

	connections[0].UploadMTUBytes = 90
	connections[0].DownloadMTUBytes = 180

	if !b.SetConnectionValidity("a", true) {
		t.Fatal("expected SetConnectionValidity to succeed")
	}

	got, ok := b.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected resolver a in snapshot")
	}
	if !got.IsValid {
		t.Fatal("expected resolver a to become valid")
	}
	if got.UploadMTUBytes != 0 || got.DownloadMTUBytes != 0 {
		t.Fatalf("expected balancer state to stay independent from source mutation, got up=%d down=%d", got.UploadMTUBytes, got.DownloadMTUBytes)
	}
}

func TestBalancerSetConnectionMTUUpdatesBalancerOnly(t *testing.T) {
	b := NewBalancer(BalancingRoundRobinDefault, nil)
	connections := []*Connection{
		{Key: "a", IsValid: true, UploadMTUBytes: 120, UploadMTUChars: 180, DownloadMTUBytes: 220},
	}
	b.SetConnections(connections)

	if !b.SetConnectionMTU("a", 90, 135, 180) {
		t.Fatal("expected SetConnectionMTU to succeed")
	}

	if connections[0].UploadMTUBytes != 120 || connections[0].UploadMTUChars != 180 || connections[0].DownloadMTUBytes != 220 {
		t.Fatalf("expected source MTUs to remain unchanged, got up=%d chars=%d down=%d", connections[0].UploadMTUBytes, connections[0].UploadMTUChars, connections[0].DownloadMTUBytes)
	}

	got, ok := b.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected resolver a in snapshot")
	}
	if got.UploadMTUBytes != 90 || got.UploadMTUChars != 135 || got.DownloadMTUBytes != 180 {
		t.Fatalf("expected snapshot MTUs to update, got up=%d chars=%d down=%d", got.UploadMTUBytes, got.UploadMTUChars, got.DownloadMTUBytes)
	}
}

func TestBalancerLossThenLatency_NoProbationStarvation(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	connections := []*Connection{
		{Key: "slow-established", IsValid: true},
		{Key: "fast-new", IsValid: true},
	}
	b.SetConnections(connections)
	_ = b.SetConnectionValidity("slow-established", true)
	_ = b.SetConnectionValidity("fast-new", true)

	// "slow-established" has 10 packets, 0 loss, 600ms latency
	for i := 0; i < 10; i++ {
		b.ReportSend("slow-established")
		b.ReportSuccess("slow-established", 600*time.Millisecond)
	}

	// "fast-new" has 2 packets, 0 loss, 45ms latency (previously trapped under sent < 5 probation)
	for i := 0; i < 2; i++ {
		b.ReportSend("fast-new")
		b.ReportSuccess("fast-new", 45*time.Millisecond)
	}

	best, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected a valid connection")
	}
	if best.Key != "fast-new" {
		t.Fatalf("expected fast newly reactivated resolver to be picked, got %q", best.Key)
	}
}

func TestBalancerLossThenLatency_SeededReactivationExploration(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	connections := []*Connection{
		{Key: "fast-established", IsValid: true},
		{Key: "reactivated-seeded", IsValid: true},
	}
	b.SetConnections(connections)
	_ = b.SetConnectionValidity("fast-established", true)
	_ = b.SetConnectionValidity("reactivated-seeded", true)

	// "fast-established" has 10 packets, 0 loss, 40ms latency
	for i := 0; i < 10; i++ {
		b.ReportSend("fast-established")
		b.ReportSuccess("fast-established", 40*time.Millisecond)
	}

	// "reactivated-seeded" has conservative stats seeded (sent=10, acked=8, lost=0, rttCount=0)
	b.SeedConservativeStats("reactivated-seeded")

	// Verify that the candidate pool includes both resolvers so zero-RTT candidate gets explored
	pool := b.GetUniqueConnections(2)
	if len(pool) != 2 {
		t.Fatalf("expected both resolvers in candidate pool for exploration, got %d", len(pool))
	}

	hasReactivated := false
	for i := 0; i < 50; i++ {
		best, ok := b.GetBestConnection()
		if !ok {
			t.Fatal("expected a valid connection")
		}
		if best.Key == "reactivated-seeded" {
			hasReactivated = true
			break
		}
	}
	if !hasReactivated {
		t.Fatal("expected zero-RTT reactivated resolver to be selected for exploration")
	}

	// Once explored and reporting 20ms RTT, it should consistently win over 40ms established
	b.ReportSend("reactivated-seeded")
	b.ReportSuccess("reactivated-seeded", 20*time.Millisecond)

	best, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected a valid connection")
	}
	if best.Key != "reactivated-seeded" {
		t.Fatalf("expected measured 20ms reactivated resolver to win over 40ms, got %q", best.Key)
	}
}

func TestBalancerSelectTargets_LossThenLatencyExplorationDistribution(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	connections := []*Connection{
		{Key: "fast-established", IsValid: true},
		{Key: "reactivated-seeded", IsValid: true},
	}
	b.SetConnections(connections)
	_ = b.SetConnectionValidity("fast-established", true)
	_ = b.SetConnectionValidity("reactivated-seeded", true)

	// "fast-established" has 10 packets, 0 loss, 40ms latency
	for i := 0; i < 10; i++ {
		b.ReportSend("fast-established")
		b.ReportSuccess("fast-established", 40*time.Millisecond)
	}

	// "reactivated-seeded" has conservative stats seeded (sent=10, acked=8, lost=0, rttCount=0)
	b.SeedConservativeStats("reactivated-seeded")

	counts := make(map[string]int)
	totalCalls := 100
	for i := 0; i < totalCalls; i++ {
		targets, err := b.SelectTargets(uint8(Enums.PACKET_STREAM_DATA), 1, 1)
		if err != nil {
			t.Fatalf("unexpected error selecting targets: %v", err)
		}
		if len(targets) != 1 {
			t.Fatalf("expected 1 target, got %d", len(targets))
		}
		counts[targets[0].Key]++
	}

	if counts["reactivated-seeded"] == 0 {
		t.Fatalf("expected reactivated-seeded to receive calls for zero-RTT exploration via SelectTargets(..., 1), got 0/%d", totalCalls)
	}
	if counts["fast-established"] == 0 {
		t.Fatalf("expected fast-established to receive calls, got 0/%d", totalCalls)
	}

	// Both candidates must receive significant traffic share (>15% each across eligible candidates)
	minRequired := int(float64(totalCalls) * 0.15)
	if counts["reactivated-seeded"] < minRequired || counts["fast-established"] < minRequired {
		t.Fatalf("unbalanced distribution in SelectTargets(..., 1): fast-established=%d, reactivated-seeded=%d (expected each >= %d)",
			counts["fast-established"], counts["reactivated-seeded"], minRequired)
	}
}

func TestBalancerSelectTargets_LossThenLatencyMultipleEligibleCandidatesDistribution(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	connections := []*Connection{
		{Key: "cand-1", IsValid: true},
		{Key: "cand-2", IsValid: true},
		{Key: "cand-3", IsValid: true},
	}
	b.SetConnections(connections)
	for _, c := range connections {
		_ = b.SetConnectionValidity(c.Key, true)
	}

	// cand-1: 0 loss, 40ms latency (best latency)
	for i := 0; i < 10; i++ {
		b.ReportSend("cand-1")
		b.ReportSuccess("cand-1", 40*time.Millisecond)
	}
	// cand-2: 0 loss, 46ms latency (tolerance for 40ms is 40/4=10ms -> cutoff 50ms; 46 <= 50)
	for i := 0; i < 10; i++ {
		b.ReportSend("cand-2")
		b.ReportSuccess("cand-2", 46*time.Millisecond)
	}
	// cand-3: seeded conservative stats (0 loss, 0 RTT, zero-RTT exploration candidate)
	b.SeedConservativeStats("cand-3")

	counts := make(map[string]int)
	totalCalls := 300
	for i := 0; i < totalCalls; i++ {
		targets, err := b.SelectTargets(uint8(Enums.PACKET_STREAM_DATA), 1, 1)
		if err != nil {
			t.Fatalf("unexpected error selecting targets: %v", err)
		}
		if len(targets) != 1 {
			t.Fatalf("expected 1 target, got %d", len(targets))
		}
		counts[targets[0].Key]++
	}

	// Assert balanced distribution (>15% each across all 3 eligible candidates)
	minRequired := int(float64(totalCalls) * 0.15) // 45 calls out of 300 (expected ~100)
	for _, c := range connections {
		if counts[c.Key] < minRequired {
			t.Fatalf("unbalanced distribution for %q in SelectTargets(..., 1): got %d/%d (%.1f%%), expected >= %d (15%%)",
				c.Key, counts[c.Key], totalCalls, float64(counts[c.Key])/float64(totalCalls)*100, minRequired)
		}
	}
}

func TestBalancerSelectTargets_LeastLossTopRandomMultiTargetSubsetSampling(t *testing.T) {
	b := NewBalancer(BalancingLeastLossTopRandom, nil)
	connections := make([]*Connection, 32)
	for i := 0; i < 32; i++ {
		connections[i] = &Connection{Key: fmt.Sprintf("c%d", i+1), IsValid: true}
	}
	b.SetConnections(connections)
	for _, c := range connections {
		_ = b.SetConnectionValidity(c.Key, true)
		for i := 0; i < 10; i++ {
			b.ReportSend(c.Key)
			b.ReportSuccess(c.Key, 20*time.Millisecond)
		}
	}

	// Repeatedly request 2 targets from pool of 4 (top 10% of 32 candidates = 4)
	seenFirst := make(map[string]bool)
	seenPairs := make(map[string]bool)
	for i := 0; i < 100; i++ {
		targets, err := b.SelectTargets(uint8(Enums.PACKET_PING), 0, 2)
		if err != nil || len(targets) != 2 {
			t.Fatalf("expected 2 targets, got %d, err=%v", len(targets), err)
		}
		if targets[0].Key == targets[1].Key {
			t.Fatalf("expected unique targets in sample, got duplicates: %v", targets)
		}
		seenFirst[targets[0].Key] = true
		seenPairs[targets[0].Key+":"+targets[1].Key] = true
	}

	if len(seenFirst) < 2 {
		t.Fatalf("expected random subset sampling to vary first selected target, got %v", seenFirst)
	}
	if len(seenPairs) < 3 {
		t.Fatalf("expected multiple distinct target pairs selected, got %d pairs", len(seenPairs))
	}
}

func TestBalancerLimitConnectionPool_EdgeCases(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)

	// 1. Empty pool returns nil
	if res := b.limitConnectionPoolLocked(nil, 1, poolPickRandom); res != nil {
		t.Fatalf("expected nil for empty pool, got %v", res)
	}

	pool := []Connection{
		{Key: "c1"},
		{Key: "c2"},
		{Key: "c3"},
	}

	// 2. count <= 0 returns nil
	if res := b.limitConnectionPoolLocked(pool, 0, poolPickRandom); res != nil {
		t.Fatalf("expected nil for count=0, got %v", res)
	}
	if res := b.limitConnectionPoolLocked(pool, -1, poolPickRandom); res != nil {
		t.Fatalf("expected nil for count=-1, got %v", res)
	}

	// 3. count >= len(pool) returns pool unmodified
	if res := b.limitConnectionPoolLocked(pool, 3, poolPickRandom); len(res) != 3 {
		t.Fatalf("expected all 3 conns when count=3, got %d", len(res))
	}
	if res := b.limitConnectionPoolLocked(pool, 5, poolPickRandom); len(res) != 3 {
		t.Fatalf("expected all 3 conns when count=5, got %d", len(res))
	}

	// 4. count == 1 limits capacity to 1
	pCopy := append([]Connection(nil), pool...)
	res1 := b.limitConnectionPoolLocked(pCopy, 1, poolPickRandom)
	if len(res1) != 1 || cap(res1) != 1 {
		t.Fatalf("expected len=1 and cap=1 for count=1, got len=%d cap=%d", len(res1), cap(res1))
	}

	// 5. count == 2 limits capacity to 2
	pCopy2 := append([]Connection(nil), pool...)
	res2 := b.limitConnectionPoolLocked(pCopy2, 2, poolPickRandom)
	if len(res2) != 2 || cap(res2) != 2 {
		t.Fatalf("expected len=2 and cap=2 for count=2, got len=%d cap=%d", len(res2), cap(res2))
	}
}


