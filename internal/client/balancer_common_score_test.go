package client

import (
	"fmt"
	"math"
	"testing"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

func TestBalancerCommonScore_NormalizesUniqueConnectionCount(t *testing.T) {
	b := NewBalancer(BalancingCommonScore, nil)
	b.SetConnections([]*Connection{{Key: "a", ResolverLabel: "A", Domain: "one.example"}})
	b.SetConnectionValidity("a", true)
	for _, count := range []int{-1, 0, 1, 2} {
		if got := b.GetUniqueConnections(count); len(got) != 1 || got[0].Key != "a" {
			t.Fatalf("GetUniqueConnections(%d) = %+v, want one Active Path", count, got)
		}
	}
}

func TestTieredStrategiesFillDuplicationAcrossEndpoints(t *testing.T) {
	for _, strategy := range []int{BalancingLossThenLatency, BalancingLeastLossTopRandom, BalancingLeastLossTopRoundRobin} {
		t.Run(fmt.Sprint(strategy), func(t *testing.T) {
			b := NewBalancer(strategy, nil)
			b.SetConnections([]*Connection{
				{Key: "a1", ResolverLabel: "A", Domain: "one.example"},
				{Key: "a2", ResolverLabel: "A", Domain: "two.example"},
				{Key: "b", ResolverLabel: "B", Domain: "one.example"},
				{Key: "c", ResolverLabel: "C", Domain: "one.example"},
			})
			for i, key := range []string{"a1", "a2", "b", "c"} {
				b.SetConnectionValidity(key, true)
				b.SeedBurstStats(key, 100, 100-max(0, i-1)*10, time.Duration(i+1)*time.Millisecond)
			}
			// Both members of the initial preferred tier share A. Additional
			// copies must consider the remaining Active endpoints B and C.
			for _, count := range []int{1, 2, 3, 4} {
				for _, packet := range []struct {
					kind   uint8
					stream uint16
				}{
					{Enums.PACKET_PING, 0}, {Enums.PACKET_STREAM_SYN, 77},
				} {
					targets, err := b.SelectTargets(packet.kind, packet.stream, count)
					if err != nil {
						t.Fatal(err)
					}
					if len(targets) != min(count, 3) {
						t.Fatalf("packet %d requested %d copies: got %d targets: %+v", packet.kind, count, len(targets), targets)
					}
					seen := make(map[EndpointKey]bool)
					for _, target := range targets {
						if seen[target.EndpointKey()] {
							t.Fatalf("duplicate endpoint in %+v", targets)
						}
						seen[target.EndpointKey()] = true
					}
					if targets[0].EndpointKey() != "A" {
						t.Fatalf("preferred tier bypassed: %+v", targets)
					}
				}
			}
			if targets := b.GetUniqueConnections(3); len(targets) != 3 {
				t.Fatalf("GetUniqueConnections returned %d, want 3", len(targets))
			}
		})
	}
}

// TestBalancerDefaultCommonScore_FavorsHigherScore verifies that BalancingCommonScore
// selects the connection with the higher common evaluation score.
func TestBalancerDefaultCommonScore_FavorsHigherScore(t *testing.T) {
	pool := NewResolverPool(10, nil)
	b := NewBalancer(BalancingCommonScore, nil, pool)

	conns := []*Connection{
		{Key: "slow", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", Domain: "d.com"},
		{Key: "fast", Resolver: "8.8.8.8", ResolverPort: 53, ResolverLabel: "8.8.8.8:53", Domain: "d.com"},
	}
	b.SetConnections(conns)
	b.ApplyMTUProbeResult("slow", 200, 100, 1200, 200*time.Millisecond, true)
	b.ApplyMTUProbeResult("fast", 200, 100, 1200, 30*time.Millisecond, true)

	// fast has much lower RTT, so higher composite score
	scoreSlow := pool.CalculateConnectionScore("slow")
	scoreFast := pool.CalculateConnectionScore("fast")
	if scoreFast <= scoreSlow {
		t.Fatalf("expected fast score (%f) > slow score (%f)", scoreFast, scoreSlow)
	}

	best, ok := b.GetBestConnection()
	if !ok {
		t.Fatal("expected best connection")
	}
	if best.Key != "fast" {
		t.Fatalf("expected common score to pick 'fast', got %q", best.Key)
	}

	targets, err := b.SelectTargets(uint8(Enums.PACKET_PING), 0, 1)
	if err != nil {
		t.Fatalf("SelectTargets failed: %v", err)
	}
	if len(targets) != 1 || targets[0].Key != "fast" {
		t.Fatalf("expected SelectTargets to return 'fast', got %v", targets)
	}
}

// TestBalancerCommonScore_DeterministicTieRotation verifies that when candidates have
// equal common scores, selections rotate deterministically across calls rather than
// sticking to insertion order.
func TestBalancerCommonScore_DeterministicTieRotation(t *testing.T) {
	pool := NewResolverPool(10, nil)
	b := NewBalancer(BalancingCommonScore, nil, pool)

	conns := []*Connection{
		{Key: "tie-a", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", Domain: "d.com"},
		{Key: "tie-b", Resolver: "8.8.8.8", ResolverPort: 53, ResolverLabel: "8.8.8.8:53", Domain: "d.com"},
	}
	b.SetConnections(conns)
	b.ApplyMTUProbeResult("tie-a", 200, 100, 1200, 50*time.Millisecond, true)
	b.ApplyMTUProbeResult("tie-b", 200, 100, 1200, 50*time.Millisecond, true)

	scoreA := pool.CalculateConnectionScore("tie-a")
	scoreB := pool.CalculateConnectionScore("tie-b")
	if math.Abs(scoreA-scoreB) > 1e-6 {
		t.Fatalf("expected identical scores, got A=%f, B=%f", scoreA, scoreB)
	}

	counts := make(map[string]int)
	lastSelected := ""
	for i := 0; i < 20; i++ {
		targets, err := b.SelectTargets(uint8(Enums.PACKET_PING), 0, 1)
		if err != nil {
			t.Fatalf("iteration %d: SelectTargets failed: %v", i, err)
		}
		if len(targets) != 1 {
			t.Fatalf("iteration %d: expected 1 target, got %d", i, len(targets))
		}
		current := targets[0].Key
		if current == lastSelected {
			t.Fatalf("iteration %d: expected alternation between tied candidates, got repeated %q", i, current)
		}
		lastSelected = current
		counts[current]++
	}

	if counts["tie-a"] != 10 || counts["tie-b"] != 10 {
		t.Fatalf("expected exactly 10/10 split between tied candidates, got A=%d, B=%d", counts["tie-a"], counts["tie-b"])
	}
}

// TestBalancerCommonScore_StreamPreferencePreserved verifies that ranking does not
// bypass a deliberate per-Stream preferred pairing until failover rules require reselection.
func TestBalancerCommonScore_StreamPreferencePreserved(t *testing.T) {
	pool := NewResolverPool(10, nil)
	b := NewBalancer(BalancingCommonScore, nil, pool)
	b.SetStreamFailoverConfig(3, 500*time.Millisecond)

	conns := []*Connection{
		{Key: "r1", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", Domain: "d.com"},
		{Key: "r2", Resolver: "8.8.8.8", ResolverPort: 53, ResolverLabel: "8.8.8.8:53", Domain: "d.com"},
	}
	b.SetConnections(conns)
	b.ApplyMTUProbeResult("r1", 200, 100, 1200, 50*time.Millisecond, true)
	b.ApplyMTUProbeResult("r2", 200, 100, 1200, 50*time.Millisecond, true)

	streamID := uint16(42)
	b.EnsureStream(streamID)

	// Send initial stream data packet to establish preferred pairing with duplication=2
	targets1, err := b.SelectTargets(uint8(Enums.PACKET_STREAM_DATA), streamID, 2)
	if err != nil {
		t.Fatalf("SelectTargets 1 failed: %v", err)
	}
	if len(targets1) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets1))
	}
	primary := targets1[0].Key

	// Now introduce an observation that makes the secondary candidate technically higher scoring
	pool.SeedBurstStats(targets1[1].Key, 50, 50, 10*time.Millisecond)

	// Send subsequent stream data packets: preferred pairing MUST stay sticky
	for i := 0; i < 5; i++ {
		targets, err := b.SelectTargets(uint8(Enums.PACKET_STREAM_DATA), streamID, 2)
		if err != nil {
			t.Fatalf("subsequent SelectTargets %d failed: %v", i, err)
		}
		if targets[0].Key != primary {
			t.Fatalf("iteration %d: preferred pairing changed from %q to %q before failover", i, primary, targets[0].Key)
		}
	}
}

// TestBalancerCommonScore_FailoverReselection verifies that when stream resend streaks
// exceed the threshold, failover switches to the best alternate.
func TestBalancerCommonScore_FailoverReselection(t *testing.T) {
	pool := NewResolverPool(10, nil)
	b := NewBalancer(BalancingCommonScore, nil, pool)
	b.SetStreamFailoverConfig(2, 10*time.Millisecond)

	conns := []*Connection{
		{Key: "primary", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", Domain: "d.com"},
		{Key: "backup", Resolver: "8.8.8.8", ResolverPort: 53, ResolverLabel: "8.8.8.8:53", Domain: "d.com"},
	}
	b.SetConnections(conns)
	b.ApplyMTUProbeResult("primary", 200, 100, 1200, 30*time.Millisecond, true)
	b.ApplyMTUProbeResult("backup", 200, 100, 1200, 40*time.Millisecond, true)

	streamID := uint16(77)
	b.EnsureStream(streamID)

	// First packet establishes primary
	t1, err := b.SelectTargets(uint8(Enums.PACKET_STREAM_DATA), streamID, 2)
	if err != nil || len(t1) < 1 || t1[0].Key != "primary" {
		t.Fatalf("expected initial preferred 'primary', got %v (err=%v)", t1, err)
	}

	// Resend 1 (streak = 1, threshold = 2) -> still primary
	time.Sleep(15 * time.Millisecond)
	t2, err := b.SelectTargets(uint8(Enums.PACKET_STREAM_RESEND), streamID, 2)
	if err != nil || len(t2) < 1 || t2[0].Key != "primary" {
		t.Fatalf("expected resend 1 to stay on 'primary', got %v", t2)
	}

	// Resend 2 (streak = 2 >= threshold) -> failover triggered to backup
	time.Sleep(15 * time.Millisecond)
	t3, err := b.SelectTargets(uint8(Enums.PACKET_STREAM_RESEND), streamID, 2)
	if err != nil || len(t3) < 1 || t3[0].Key != "backup" {
		t.Fatalf("expected resend 2 to failover to 'backup', got %v", t3)
	}
}

// TestBalancerCommonScore_DuplicationDistinctEndpoints verifies that when multiple domains
// are configured on the same endpoint, duplicated routes select candidates across distinct endpoints.
func TestBalancerCommonScore_DuplicationDistinctEndpoints(t *testing.T) {
	pool := NewResolverPool(10, nil)
	b := NewBalancer(BalancingCommonScore, nil, pool)

	conns := []*Connection{
		{Key: "ep1-d1", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", Domain: "domain1.com"},
		{Key: "ep1-d2", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", Domain: "domain2.com"},
		{Key: "ep2-d1", Resolver: "8.8.8.8", ResolverPort: 53, ResolverLabel: "8.8.8.8:53", Domain: "domain1.com"},
		{Key: "ep2-d2", Resolver: "8.8.8.8", ResolverPort: 53, ResolverLabel: "8.8.8.8:53", Domain: "domain2.com"},
	}
	b.SetConnections(conns)
	b.ApplyMTUProbeResult("ep1-d1", 200, 100, 1200, 30*time.Millisecond, true)
	b.ApplyMTUProbeResult("ep1-d2", 200, 100, 1200, 32*time.Millisecond, true)
	b.ApplyMTUProbeResult("ep2-d1", 200, 100, 1200, 60*time.Millisecond, true)
	b.ApplyMTUProbeResult("ep2-d2", 200, 100, 1200, 62*time.Millisecond, true)

	// Request duplication count 2: must pick one from ep1 and one from ep2
	targets, err := b.SelectTargets(uint8(Enums.PACKET_PING), 0, 2)
	if err != nil {
		t.Fatalf("SelectTargets failed: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 distinct routes, got %d", len(targets))
	}

	ep1 := connectionEndpointKey(targets[0])
	ep2 := connectionEndpointKey(targets[1])
	if ep1 == ep2 {
		t.Fatalf("expected duplicated routes on distinct endpoints, but both share %q (%s, %s)", ep1, targets[0].Key, targets[1].Key)
	}
}

// TestBalancerCommonScore_InsufficientDistinctEndpoints verifies that when there are not
// enough distinct endpoints to satisfy the requested duplication count, only the distinct
// endpoints are returned (domains on the same endpoint are not treated as independent routes).
func TestBalancerCommonScore_InsufficientDistinctEndpoints(t *testing.T) {
	pool := NewResolverPool(10, nil)
	b := NewBalancer(BalancingCommonScore, nil, pool)

	conns := []*Connection{
		{Key: "ep1-d1", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", Domain: "domain1.com"},
		{Key: "ep1-d2", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", Domain: "domain2.com"},
	}
	b.SetConnections(conns)
	b.ApplyMTUProbeResult("ep1-d1", 200, 100, 1200, 30*time.Millisecond, true)
	b.ApplyMTUProbeResult("ep1-d2", 200, 100, 1200, 35*time.Millisecond, true)

	// Requested duplication = 2, but only 1 distinct endpoint exists!
	targets, err := b.SelectTargets(uint8(Enums.PACKET_PING), 0, 2)
	if err != nil {
		t.Fatalf("SelectTargets failed: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 route because only 1 distinct endpoint exists, got %d: %v", len(targets), targets)
	}
	if targets[0].Key != "ep1-d1" {
		t.Fatalf("expected higher scoring domain 'ep1-d1' to be selected, got %q", targets[0].Key)
	}
}

// TestBalancerExplicitStrategies_DocumentedBehaviorPreserved verifies that explicit
// strategies retain their documented selection policies.
func TestBalancerExplicitStrategies_DocumentedBehaviorPreserved(t *testing.T) {
	// Round-Robin
	bRR := NewBalancer(BalancingRoundRobin, nil)
	connsRR := []*Connection{
		{Key: "r1", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", IsValid: true},
		{Key: "r2", Resolver: "8.8.8.8", ResolverPort: 53, ResolverLabel: "8.8.8.8:53", IsValid: true},
	}
	bRR.SetConnections(connsRR)
	bRR.SetConnectionValidity("r1", true)
	bRR.SetConnectionValidity("r2", true)

	c1, _ := bRR.GetBestConnection()
	c2, _ := bRR.GetBestConnection()
	if c1.Key == c2.Key {
		t.Fatalf("expected RoundRobin to rotate, got same key %q", c1.Key)
	}

	// Lowest Latency
	bLL := NewBalancer(BalancingLowestLatency, nil)
	connsLL := []*Connection{
		{Key: "fast", Resolver: "1.1.1.1", ResolverPort: 53, ResolverLabel: "1.1.1.1:53", IsValid: true},
		{Key: "slow", Resolver: "8.8.8.8", ResolverPort: 53, ResolverLabel: "8.8.8.8:53", IsValid: true},
	}
	bLL.SetConnections(connsLL)
	bLL.SetConnectionValidity("fast", true)
	bLL.SetConnectionValidity("slow", true)

	for i := 0; i < 5; i++ {
		bLL.ReportSend("fast")
		bLL.ReportSuccess("fast", 20*time.Millisecond)
		bLL.ReportSend("slow")
		bLL.ReportSuccess("slow", 100*time.Millisecond)
	}
	bestLL, ok := bLL.GetBestConnection()
	if !ok || bestLL.Key != "fast" {
		t.Fatalf("expected LowestLatency to pick 'fast', got %v", bestLL.Key)
	}
}
