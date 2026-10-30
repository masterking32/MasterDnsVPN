package client

import (
	"context"
	"sync"
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

func TestBalancerMaxActiveResolversEnforced(t *testing.T) {
	b := NewBalancer(BalancingRoundRobinDefault, nil)
	b.SetMaxActiveResolvers(3)

	connections := []*Connection{
		{Key: "c1"}, {Key: "c2"}, {Key: "c3"}, {Key: "c4"}, {Key: "c5"},
	}
	b.SetConnections(connections)

	for _, c := range connections {
		b.SetConnectionValidity(c.Key, true)
	}

	if b.ActiveCount() != 3 {
		t.Fatalf("expected ActiveCount to be strictly bounded to 3, got=%d", b.ActiveCount())
	}
	if b.TotalCount() != 5 {
		t.Fatalf("expected TotalCount=5, got=%d", b.TotalCount())
	}
}

func TestBalancerDynamicPromotionDemotion(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	b.SetMaxActiveResolvers(2)

	connections := []*Connection{
		{Key: "slow1", DownloadMTUBytes: 1000, UploadMTUBytes: 100},
		{Key: "slow2", DownloadMTUBytes: 1000, UploadMTUBytes: 100},
		{Key: "fast1", DownloadMTUBytes: 1000, UploadMTUBytes: 100},
	}
	b.SetConnections(connections)

	// Activate slow1 (500ms) and slow2 (600ms)
	b.SeedBurstStats("slow1", 4, 4, 500*time.Millisecond)
	b.SetConnectionValidity("slow1", true)

	b.SeedBurstStats("slow2", 4, 4, 600*time.Millisecond)
	b.SetConnectionValidity("slow2", true)

	if b.ActiveCount() != 2 {
		t.Fatalf("expected 2 active resolvers initially, got=%d", b.ActiveCount())
	}

	// Now activate fast1 (45ms) - should displace slow2
	b.SeedBurstStats("fast1", 4, 4, 45*time.Millisecond)
	b.SetConnectionValidity("fast1", true)

	if b.ActiveCount() != 2 {
		t.Fatalf("expected ActiveCount to stay strictly 2, got=%d", b.ActiveCount())
	}

	fast1Conn, ok := b.GetConnectionByKey("fast1")
	if !ok || !fast1Conn.IsValid {
		t.Fatal("expected fast1 to be promoted to active")
	}

	slow2Conn, ok := b.GetConnectionByKey("slow2")
	if !ok || slow2Conn.IsValid {
		t.Fatal("expected slow2 to be demoted to standby (IsValid=false)")
	}

	slow1Conn, ok := b.GetConnectionByKey("slow1")
	if !ok || !slow1Conn.IsValid {
		t.Fatal("expected slow1 to remain active")
	}
}

func TestBalancerOptimizeActivePool(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	b.SetMaxActiveResolvers(2)

	connections := []*Connection{
		{Key: "a"},
		{Key: "b"},
		{Key: "standby1"},
	}
	b.SetConnections(connections)
	b.SetConnectionMTU("a", 100, 150, 1000)
	b.SetConnectionMTU("b", 100, 150, 1000)
	b.SetConnectionMTU("standby1", 100, 150, 1000)

	// Activate a and b with good initial latencies
	b.SeedBurstStats("a", 10, 10, 30*time.Millisecond)
	b.SetConnectionValidity("a", true)

	b.SeedBurstStats("b", 10, 10, 35*time.Millisecond)
	b.SetConnectionValidity("b", true)

	// Standby resolver has verified MTU and 55ms RTT (scores lower than a and b, so stays in standby)
	b.SeedBurstStats("standby1", 4, 4, 55*time.Millisecond)
	b.SetConnectionValidity("standby1", true)

	standbyConn, _ := b.GetConnectionByKey("standby1")
	if standbyConn.IsValid {
		t.Fatal("expected standby1 to start in standby pool")
	}

	// Simulate heavy degradation on "a": RTT spikes to 800ms with 30% loss
	b.SeedBurstStats("a", 20, 14, 800*time.Millisecond)

	// Run optimization
	swapped := b.OptimizeActivePool()
	if !swapped {
		t.Fatal("expected OptimizeActivePool to swap degraded active resolver")
	}

	// Verify standby1 is now active and "a" is now standby
	standbyConnAfter, _ := b.GetConnectionByKey("standby1")
	if !standbyConnAfter.IsValid {
		t.Fatal("expected standby1 to be promoted to active")
	}

	aConnAfter, _ := b.GetConnectionByKey("a")
	if aConnAfter.IsValid {
		t.Fatal("expected degraded resolver a to be demoted to standby")
	}

	if b.ActiveCount() != 2 {
		t.Fatalf("expected ActiveCount to remain strictly 2, got=%d", b.ActiveCount())
	}
}

func TestBalancerGetRankedEndpoints(t *testing.T) {
	b := NewBalancer(BalancingLowestLatency, nil)
	b.SetMaxActiveResolvers(2)

	connections := []*Connection{
		{Key: "1.1.1.1|53|domain.com", Resolver: "1.1.1.1", ResolverPort: 53, Domain: "domain.com", UploadMTUBytes: 120, DownloadMTUBytes: 1500},
		{Key: "8.8.8.8|53|domain.com", Resolver: "8.8.8.8", ResolverPort: 53, Domain: "domain.com", UploadMTUBytes: 120, DownloadMTUBytes: 1500},
		{Key: "9.9.9.9|53|domain.com", Resolver: "9.9.9.9", ResolverPort: 53, Domain: "domain.com", UploadMTUBytes: 120, DownloadMTUBytes: 1500},
		{Key: "1.1.1.1|53|domain2.com", Resolver: "1.1.1.1", ResolverPort: 53, Domain: "domain2.com", UploadMTUBytes: 120, DownloadMTUBytes: 1500},
	}
	b.SetConnections(connections)

	// 1.1.1.1: fast 15ms
	b.SeedBurstStats("1.1.1.1|53|domain.com", 20, 20, 15*time.Millisecond)
	b.SetConnectionValidity("1.1.1.1|53|domain.com", true)

	// 8.8.8.8: medium 30ms
	b.SeedBurstStats("8.8.8.8|53|domain.com", 20, 20, 30*time.Millisecond)
	b.SetConnectionValidity("8.8.8.8|53|domain.com", true)

	// 9.9.9.9: slow 120ms
	b.SeedBurstStats("9.9.9.9|53|domain.com", 20, 20, 120*time.Millisecond)
	b.SetConnectionValidity("9.9.9.9|53|domain.com", true)

	ranked := b.GetRankedEndpoints(10)
	if len(ranked) != 3 {
		t.Fatalf("expected 3 unique endpoints, got %d", len(ranked))
	}

	// First should be 1.1.1.1 (lowest RTT/highest score)
	if ranked[0].IP != "1.1.1.1" {
		t.Errorf("expected 1st ranked resolver to be 1.1.1.1, got %s", ranked[0].IP)
	}
	// Second should be 8.8.8.8
	if ranked[1].IP != "8.8.8.8" {
		t.Errorf("expected 2nd ranked resolver to be 8.8.8.8, got %s", ranked[1].IP)
	}
	// Third should be 9.9.9.9
	if ranked[2].IP != "9.9.9.9" {
		t.Errorf("expected 3rd ranked resolver to be 9.9.9.9, got %s", ranked[2].IP)
	}

	// Test maxCount clamp
	limited := b.GetRankedEndpoints(2)
	if len(limited) != 2 {
		t.Fatalf("expected 2 endpoints when limited, got %d", len(limited))
	}
}

func TestResolverStatsSnapshotDataRace(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	connections := []*Connection{
		{Key: "r1", IsValid: true},
		{Key: "r2", IsValid: true},
		{Key: "r3", IsValid: true},
	}
	b.SetConnections(connections)
	b.SetConnectionValidity("r1", true)
	b.SetConnectionValidity("r2", true)
	b.SetConnectionValidity("r3", true)

	for i := uint16(1); i <= 10; i++ {
		b.EnsureStream(i)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup

	// Goroutine 1: Continuous SelectTargets mutating PreferredResolverKey on streams
	wg.Add(1)
	go func() {
		defer wg.Done()
		var streamID uint16 = 1
		for ctx.Err() == nil {
			packetType := uint8(Enums.PACKET_STREAM_DATA)
			if streamID%2 == 0 {
				packetType = uint8(Enums.PACKET_STREAM_RESEND)
			}
			_, _ = b.SelectTargets(packetType, streamID, 2)
			streamID = (streamID % 10) + 1
		}
	}()

	// Goroutine 2: Continuous GetStatsSnapshot reading PreferredResolverKey
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			snaps := b.GetStatsSnapshot()
			if len(snaps) != 3 {
				t.Errorf("expected 3 snapshots, got %d", len(snaps))
				return
			}
		}
	}()

	// Goroutine 3: Continuous SnapshotResolverStats reading PreferredResolverKey
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			_ = b.SnapshotResolverStats()
		}
	}()

	// Goroutine 4: Clear references periodically
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			b.mu.Lock()
			b.clearPreferredResolverReferencesLocked("r1")
			b.mu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}
	}()

	wg.Wait()
}

func TestBalancerOptimizeActivePool_StandbyEligibility(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	b.SetMaxActiveResolvers(2)

	connections := []*Connection{
		{Key: "active-1", Resolver: "1.1.1.1", ResolverPort: 53, Domain: "d1.example.com", ResolverLabel: "1.1.1.1:53"},
		{Key: "active-2", Resolver: "8.8.8.8", ResolverPort: 53, Domain: "d1.example.com", ResolverLabel: "8.8.8.8:53"},
		{Key: "disabled-res", Resolver: "9.9.9.9", ResolverPort: 53, Domain: "d1.example.com", ResolverLabel: "9.9.9.9:53"},
		{Key: "standby-res", Resolver: "1.0.0.1", ResolverPort: 53, Domain: "d1.example.com", ResolverLabel: "1.0.0.1:53"},
	}
	b.SetConnections(connections)

	// Set valid MTU for all 4 resolvers
	b.SetConnectionMTU("active-1", 100, 150, 1000)
	b.SetConnectionMTU("active-2", 100, 150, 1000)
	b.SetConnectionMTU("disabled-res", 100, 150, 1000)
	b.SetConnectionMTU("standby-res", 100, 150, 1000)

	// Activate active-1 and active-2
	b.SeedBurstStats("active-1", 10, 10, 30*time.Millisecond)
	b.SetConnectionValidity("active-1", true)

	b.SeedBurstStats("active-2", 10, 10, 35*time.Millisecond)
	b.SetConnectionValidity("active-2", true)

	if b.ActiveCount() != 2 {
		t.Fatalf("expected 2 active connections, got=%d", b.ActiveCount())
	}

	// 1. Configure disabled-res: high score (fast 15ms RTT, 0% loss), but explicitly invalidated
	b.SeedBurstStats("disabled-res", 10, 10, 15*time.Millisecond)
	b.SetConnectionValidity("disabled-res", false)

	connDisabled, ok := b.GetConnectionByKey("disabled-res")
	if !ok {
		t.Fatal("disabled-res not found in balancer")
	}
	if connDisabled.IsValid {
		t.Fatal("expected disabled-res IsValid to be false")
	}
	if connDisabled.StandbyEligible {
		t.Fatal("expected disabled-res StandbyEligible to be false after invalidation")
	}

	// Degrade active-1 severely (800ms latency, 40% packet loss)
	b.SeedBurstStats("active-1", 20, 12, 800*time.Millisecond)

	// Attempt optimization. With disabled-res ineligible, no swap should occur!
	swapped := b.OptimizeActivePool()
	if swapped {
		t.Fatal("expected OptimizeActivePool NOT to swap disabled-res into active pool")
	}

	connDisabledAfter, _ := b.GetConnectionByKey("disabled-res")
	if connDisabledAfter.IsValid {
		t.Fatal("disabled-res was promoted despite StandbyEligible == false")
	}

	// 2. Now introduce standby-res: marked standby eligible
	b.SeedBurstStats("standby-res", 10, 10, 25*time.Millisecond)
	b.SetConnectionStandbyEligible("standby-res", true)

	connStandby, ok := b.GetConnectionByKey("standby-res")
	if !ok || connStandby.IsValid || !connStandby.StandbyEligible {
		t.Fatalf("expected standby-res to be inactive and StandbyEligible == true, got valid=%v eligible=%v",
			connStandby.IsValid, connStandby.StandbyEligible)
	}

	// Now run optimization: standby-res should be promoted, active-1 demoted
	swapped = b.OptimizeActivePool()
	if !swapped {
		t.Fatal("expected OptimizeActivePool to swap degraded active-1 with qualified standby-res")
	}

	// Verify standby-res is active and no longer standby
	connStandbyAfter, _ := b.GetConnectionByKey("standby-res")
	if !connStandbyAfter.IsValid {
		t.Fatal("expected standby-res to be promoted (IsValid == true)")
	}
	if connStandbyAfter.StandbyEligible {
		t.Fatal("expected promoted resolver to have StandbyEligible == false")
	}

	// Verify active-1 was demoted and marked standby eligible
	connActive1After, _ := b.GetConnectionByKey("active-1")
	if connActive1After.IsValid {
		t.Fatal("expected active-1 to be demoted (IsValid == false)")
	}
	if !connActive1After.StandbyEligible {
		t.Fatal("expected demoted resolver to become StandbyEligible == true")
	}

	// Verify active count remains 2
	if b.ActiveCount() != 2 {
		t.Fatalf("expected active count to remain strictly 2, got=%d", b.ActiveCount())
	}
}

func TestBalancerOptimizeActivePool_SessionMTUVerification(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	b.SetMaxActiveResolvers(2)

	// Active session synchronized MTU: Upload 150, Download 1000
	b.SetSessionSynchronizedMTU(150, 1000)

	connections := []*Connection{
		{Key: "active-1", Resolver: "1.1.1.1", ResolverPort: 53, Domain: "d.com", ResolverLabel: "1.1.1.1:53"},
		{Key: "active-2", Resolver: "8.8.8.8", ResolverPort: 53, Domain: "d.com", ResolverLabel: "8.8.8.8:53"},
		{Key: "standby-low-up", Resolver: "9.9.9.9", ResolverPort: 53, Domain: "d.com", ResolverLabel: "9.9.9.9:53"},
		{Key: "standby-low-down", Resolver: "1.0.0.1", ResolverPort: 53, Domain: "d.com", ResolverLabel: "1.0.0.1:53"},
		{Key: "standby-sufficient", Resolver: "8.8.4.4", ResolverPort: 53, Domain: "d.com", ResolverLabel: "8.8.4.4:53"},
	}
	b.SetConnections(connections)

	// Active connections meet session MTU
	b.SetConnectionMTU("active-1", 150, 150, 1000)
	b.SetConnectionMTU("active-2", 150, 150, 1000)

	// Standby with low upload MTU (120 < 150), but excellent latency (12ms)
	b.SetConnectionMTU("standby-low-up", 120, 120, 1200)

	// Standby with low download MTU (800 < 1000), but excellent latency (15ms)
	b.SetConnectionMTU("standby-low-down", 160, 160, 800)

	// Standby with sufficient MTU (150/1000), good latency (25ms)
	b.SetConnectionMTU("standby-sufficient", 150, 150, 1000)

	// Activate active-1 and active-2
	b.SeedBurstStats("active-1", 10, 10, 30*time.Millisecond)
	b.SetConnectionValidity("active-1", true)
	b.SeedBurstStats("active-2", 10, 10, 35*time.Millisecond)
	b.SetConnectionValidity("active-2", true)

	// Seed stats and mark all standbys eligible
	b.SeedBurstStats("standby-low-up", 10, 10, 12*time.Millisecond)
	b.SetConnectionStandbyEligible("standby-low-up", true)

	b.SeedBurstStats("standby-low-down", 10, 10, 15*time.Millisecond)
	b.SetConnectionStandbyEligible("standby-low-down", true)

	b.SeedBurstStats("standby-sufficient", 10, 10, 25*time.Millisecond)
	b.SetConnectionStandbyEligible("standby-sufficient", true)

	// Degrade active-1 (900ms latency, 50% loss)
	b.SeedBurstStats("active-1", 20, 10, 900*time.Millisecond)

	// Optimize pool
	swapped := b.OptimizeActivePool()
	if !swapped {
		t.Fatal("expected OptimizeActivePool to swap degraded active-1 with standby-sufficient")
	}

	// Verify that standby-low-up was NOT promoted despite 12ms RTT
	connLowUp, _ := b.GetConnectionByKey("standby-low-up")
	if connLowUp.IsValid {
		t.Fatal("standby-low-up was erroneously promoted despite UploadMTU (120) < syncedUploadMTU (150)")
	}

	// Verify that standby-low-down was NOT promoted despite 15ms RTT
	connLowDown, _ := b.GetConnectionByKey("standby-low-down")
	if connLowDown.IsValid {
		t.Fatal("standby-low-down was erroneously promoted despite DownloadMTU (800) < syncedDownloadMTU (1000)")
	}

	// Verify that standby-sufficient was the one promoted
	connSufficient, _ := b.GetConnectionByKey("standby-sufficient")
	if !connSufficient.IsValid {
		t.Fatal("expected standby-sufficient to be promoted")
	}

	// Verify active-1 was demoted
	connActive1, _ := b.GetConnectionByKey("active-1")
	if connActive1.IsValid {
		t.Fatal("expected active-1 to be demoted")
	}

	if b.ActiveCount() != 2 {
		t.Fatalf("expected active count to remain 2, got=%d", b.ActiveCount())
	}
}
