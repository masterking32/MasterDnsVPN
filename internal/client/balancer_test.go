package client

import (
	"testing"
	"time"
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

