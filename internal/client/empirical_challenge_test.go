package client

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
)

// TestEmpirical_ProbeConnectionMTU_Cancellation tests probe cancellation across
// varying cancellation delays against non-responsive mock UDP blackhole listeners.
// It verifies:
// 1. Immediate return (< 300ms) for all delay values (10ms, 25ms, 50ms, 100ms, pre-canceled).
// 2. Zero goroutine leaks across iterations.
// 3. Proper rejection reason (mtuRejectUpload).
func TestEmpirical_ProbeConnectionMTU_Cancellation(t *testing.T) {
	// Create a non-responsive mock UDP blackhole listener that reads packets but drops them.
	blackholeConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP for blackhole: %v", err)
	}
	defer blackholeConn.Close()
	blackholePort := blackholeConn.LocalAddr().(*net.UDPAddr).Port

	// Discard any incoming packets in the blackhole
	stopBlackhole := make(chan struct{})
	defer close(stopBlackhole)
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-stopBlackhole:
				return
			default:
				_ = blackholeConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				_, _, _ = blackholeConn.ReadFromUDP(buf)
			}
		}
	}()

	cfg := config.DefaultClientConfig()
	domain := "v.example.com"
	cfg.Domains = []string{domain}
	cfg.Resolvers = []config.ResolverAddress{{IP: "127.0.0.1", Port: blackholePort}}
	cfg.MTUTestTimeout = 3.0 // 3 seconds timeout if cancellation fails!
	cfg.MTUTestRetries = 2

	client := createTestFastStartClient(t, cfg)
	conn := Connection{
		Domain:        domain,
		Resolver:      "127.0.0.1",
		ResolverPort:  blackholePort,
		ResolverLabel: fmt.Sprintf("127.0.0.1:%d", blackholePort),
		Key:           "blackhole-empirical",
	}

	delays := []time.Duration{
		0,                   // Pre-canceled
		10 * time.Millisecond,
		25 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		150 * time.Millisecond,
	}

	// Warm up runtime and stabilize goroutines
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	const iterationsPerDelay = 5

	for _, delay := range delays {
		for iter := 0; iter < iterationsPerDelay; iter++ {
			t.Run(fmt.Sprintf("Delay_%v_Iter_%d", delay, iter), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				if delay == 0 {
					cancel()
				} else {
					time.AfterFunc(delay, cancel)
				}
				defer cancel()

				start := time.Now()
				_, reason := client.probeConnectionMTU(ctx, conn, 200)
				duration := time.Since(start)

				if reason != mtuRejectUpload {
					t.Fatalf("expected probe rejection mtuRejectUpload on cancellation, got=%v", reason)
				}

				// Must complete well within 300ms (and significantly faster than 3s timeout)
				maxAllowed := delay + 200*time.Millisecond
				if maxAllowed > 300*time.Millisecond {
					maxAllowed = 300 * time.Millisecond
				}
				if duration >= maxAllowed {
					t.Fatalf("probe took %v, exceeded max allowed %v (cancellation was not immediate)", duration, maxAllowed)
				}
			})
		}
	}

	// Verify zero goroutine leaks: wait a short stabilization period for any context.AfterFunc callbacks to finish
	var finalGoroutines int
	for i := 0; i < 10; i++ {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
		finalGoroutines = runtime.NumGoroutine()
		if finalGoroutines <= initialGoroutines {
			break
		}
	}

	if finalGoroutines > initialGoroutines {
		t.Fatalf("goroutine leak detected: started with %d, ended with %d (leaked %d)",
			initialGoroutines, finalGoroutines, finalGoroutines-initialGoroutines)
	}
}

// TestEmpirical_OptimizeActivePool_DegradedAndPartialMTU tests:
// 1. Multiple degraded active resolvers simultaneously.
// 2. Inactive standbys with partial MTU compliance (e.g. low upload, low download, unprobed, invalid).
// 3. Ensuring only qualified standbys meeting all constraints are promoted.
// 4. Verifying pool sizes and states are consistent.
func TestEmpirical_OptimizeActivePool_DegradedAndPartialMTU(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	b.SetMaxActiveResolvers(4)

	// Set session synchronized MTU: Upload 150, Download 1000
	b.SetSessionSynchronizedMTU(150, 1000)

	connections := []*Connection{
		// 4 Active resolvers
		{Key: "act-healthy", Resolver: "1.1.1.1", ResolverPort: 53, Domain: "d.com", ResolverLabel: "1.1.1.1:53"},
		{Key: "act-degraded-1", Resolver: "1.1.1.2", ResolverPort: 53, Domain: "d.com", ResolverLabel: "1.1.1.2:53"},
		{Key: "act-degraded-2", Resolver: "1.1.1.3", ResolverPort: 53, Domain: "d.com", ResolverLabel: "1.1.1.3:53"},
		{Key: "act-degraded-3", Resolver: "1.1.1.4", ResolverPort: 53, Domain: "d.com", ResolverLabel: "1.1.1.4:53"},

		// 6 Standby / Inactive resolvers
		{Key: "inact-disabled", Resolver: "2.2.2.1", ResolverPort: 53, Domain: "d.com", ResolverLabel: "2.2.2.1:53"},
		{Key: "stby-low-upload", Resolver: "2.2.2.2", ResolverPort: 53, Domain: "d.com", ResolverLabel: "2.2.2.2:53"},
		{Key: "stby-low-download", Resolver: "2.2.2.3", ResolverPort: 53, Domain: "d.com", ResolverLabel: "2.2.2.3:53"},
		{Key: "stby-zero-mtu", Resolver: "2.2.2.4", ResolverPort: 53, Domain: "d.com", ResolverLabel: "2.2.2.4:53"},
		{Key: "stby-qualified-1", Resolver: "2.2.2.5", ResolverPort: 53, Domain: "d.com", ResolverLabel: "2.2.2.5:53"},
		{Key: "stby-qualified-2", Resolver: "2.2.2.6", ResolverPort: 53, Domain: "d.com", ResolverLabel: "2.2.2.6:53"},
	}
	b.SetConnections(connections)

	// Set MTU values
	b.SetConnectionMTU("act-healthy", 150, 150, 1000)
	b.SetConnectionMTU("act-degraded-1", 150, 150, 1000)
	b.SetConnectionMTU("act-degraded-2", 150, 150, 1000)
	b.SetConnectionMTU("act-degraded-3", 150, 150, 1000)

	b.SetConnectionMTU("inact-disabled", 200, 200, 1200)  // Meets MTU, but will have StandbyEligible=false
	b.SetConnectionMTU("stby-low-upload", 120, 120, 1200) // Upload 120 < 150
	b.SetConnectionMTU("stby-low-download", 160, 160, 800) // Download 800 < 1000
	b.SetConnectionMTU("stby-zero-mtu", 0, 0, 0)          // Zero MTU
	b.SetConnectionMTU("stby-qualified-1", 150, 150, 1000) // Meets MTU
	b.SetConnectionMTU("stby-qualified-2", 180, 180, 1100) // Meets MTU

	// Activate the 4 active connections
	b.SeedBurstStats("act-healthy", 100, 100, 20*time.Millisecond) // RTT 20ms, 0% loss -> High score
	b.SetConnectionValidity("act-healthy", true)

	b.SeedBurstStats("act-degraded-1", 100, 40, 600*time.Millisecond) // 60% loss, 600ms RTT
	b.SetConnectionValidity("act-degraded-1", true)

	b.SeedBurstStats("act-degraded-2", 100, 20, 900*time.Millisecond) // 80% loss, 900ms RTT -> Worst
	b.SetConnectionValidity("act-degraded-2", true)

	b.SeedBurstStats("act-degraded-3", 100, 30, 800*time.Millisecond) // 70% loss, 800ms RTT
	b.SetConnectionValidity("act-degraded-3", true)

	if b.ActiveCount() != 4 {
		t.Fatalf("expected 4 active connections, got=%d", b.ActiveCount())
	}

	// Configure standbys
	// inact-disabled: fast latency (10ms), but explicitly marked StandbyEligible=false
	b.SeedBurstStats("inact-disabled", 100, 100, 10*time.Millisecond)
	b.SetConnectionStandbyEligible("inact-disabled", false)

	// stby-low-upload: fast latency (12ms), StandbyEligible=true
	b.SeedBurstStats("stby-low-upload", 100, 100, 12*time.Millisecond)
	b.SetConnectionStandbyEligible("stby-low-upload", true)

	// stby-low-download: fast latency (14ms), StandbyEligible=true
	b.SeedBurstStats("stby-low-download", 100, 100, 14*time.Millisecond)
	b.SetConnectionStandbyEligible("stby-low-download", true)

	// stby-zero-mtu: fast latency (15ms), StandbyEligible=true
	b.SeedBurstStats("stby-zero-mtu", 100, 100, 15*time.Millisecond)
	b.SetConnectionStandbyEligible("stby-zero-mtu", true)

	// stby-qualified-1: good latency (25ms), 0% loss, StandbyEligible=true
	b.SeedBurstStats("stby-qualified-1", 100, 100, 25*time.Millisecond)
	b.SetConnectionStandbyEligible("stby-qualified-1", true)

	// stby-qualified-2: good latency (30ms), 0% loss, StandbyEligible=true
	b.SeedBurstStats("stby-qualified-2", 100, 100, 30*time.Millisecond)
	b.SetConnectionStandbyEligible("stby-qualified-2", true)

	// Run OptimizeActivePool
	swapped := b.OptimizeActivePool()
	if !swapped {
		t.Fatalf("expected OptimizeActivePool to succeed and swap degraded resolvers")
	}

	// Active count must remain strictly 4
	if b.ActiveCount() != 4 {
		t.Fatalf("expected active count to remain 4, got=%d", b.ActiveCount())
	}

	// Verify that ineligible standbys were NOT promoted
	for _, ineligibleKey := range []string{"inact-disabled", "stby-low-upload", "stby-low-download", "stby-zero-mtu"} {
		conn, ok := b.GetConnectionByKey(ineligibleKey)
		if !ok {
			t.Fatalf("connection %s not found", ineligibleKey)
		}
		if conn.IsValid {
			t.Fatalf("ineligible connection %s was erroneously promoted to active", ineligibleKey)
		}
	}

	// Verify that BOTH qualified standbys WERE promoted
	for _, qualifiedKey := range []string{"stby-qualified-1", "stby-qualified-2"} {
		conn, ok := b.GetConnectionByKey(qualifiedKey)
		if !ok {
			t.Fatalf("connection %s not found", qualifiedKey)
		}
		if !conn.IsValid {
			t.Fatalf("qualified standby %s was NOT promoted", qualifiedKey)
		}
		if conn.StandbyEligible {
			t.Fatalf("promoted connection %s should have StandbyEligible=false", qualifiedKey)
		}
	}

	// Healthy active must still be active
	actHealthy, _ := b.GetConnectionByKey("act-healthy")
	if !actHealthy.IsValid {
		t.Fatalf("act-healthy was demoted unexpectedly")
	}

	// The two worst degraded resolvers (act-degraded-2 and act-degraded-3, or act-degraded-1)
	// should have been demoted and marked StandbyEligible=true
	demotedCount := 0
	for _, key := range []string{"act-degraded-1", "act-degraded-2", "act-degraded-3"} {
		conn, _ := b.GetConnectionByKey(key)
		if !conn.IsValid {
			demotedCount++
			if !conn.StandbyEligible {
				t.Fatalf("demoted connection %s must have StandbyEligible=true", key)
			}
		}
	}
	if demotedCount != 2 {
		t.Fatalf("expected exactly 2 degraded connections to be demoted, got %d", demotedCount)
	}
}

// TestEmpirical_RapidValidityFlipsStress stress-tests Balancer under rapid, concurrent
// validity flips, standby toggles, synchronized MTU modifications, and pool optimizations
// across multiple goroutines, verifying no data races, no deadlocks, and invariant preservation.
func TestEmpirical_RapidValidityFlipsStress(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	const maxActive = 4
	b.SetMaxActiveResolvers(maxActive)
	b.SetSessionSynchronizedMTU(150, 1000)

	const numResolvers = 10
	var connections []*Connection
	for i := 0; i < numResolvers; i++ {
		key := fmt.Sprintf("res-%d", i)
		connections = append(connections, &Connection{
			Key:           key,
			Resolver:      fmt.Sprintf("10.0.0.%d", i+1),
			ResolverPort:  53,
			Domain:        "d.com",
			ResolverLabel: fmt.Sprintf("10.0.0.%d:53", i+1),
		})
	}
	b.SetConnections(connections)

	// Set baseline MTU for all resolvers
	for i := 0; i < numResolvers; i++ {
		key := fmt.Sprintf("res-%d", i)
		b.SetConnectionMTU(key, 150+i*10, 150+i*10, 1000+i*50)
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var opCount atomic.Int64

	// Worker group 1: Validity flapping
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			i := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
					key := fmt.Sprintf("res-%d", (workerID+i)%numResolvers)
					valid := (i % 2) == 0
					b.SetConnectionValidity(key, valid)
					opCount.Add(1)
					i++
				}
			}
		}(w)
	}

	// Worker group 2: Standby eligibility toggling
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			i := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
					key := fmt.Sprintf("res-%d", (workerID+i)%numResolvers)
					eligible := (i % 2) == 1
					b.SetConnectionStandbyEligible(key, eligible)
					opCount.Add(1)
					i++
				}
			}
		}(w)
	}

	// Worker group 3: Burst stats and latency updates
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			i := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
					key := fmt.Sprintf("res-%d", (workerID+i)%numResolvers)
					sent := int(50 + (i % 50))
					acked := int(20 + (i % 30))
					rtt := time.Duration(10+(i%100)) * time.Millisecond
					b.SeedBurstStats(key, sent, acked, rtt)
					opCount.Add(1)
					i++
				}
			}
		}(w)
	}

	// Worker group 4: Session synchronized MTU changes
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			i := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
					up := 100 + (i%5)*20
					down := 800 + (i%5)*100
					b.SetSessionSynchronizedMTU(up, down)
					opCount.Add(1)
					i++
				}
			}
		}(w)
	}

	// Worker group 5: Active pool optimization and querying
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					_ = b.OptimizeActivePool()
					_ = b.ActiveConnections()
					_ = b.GetStatsSnapshot()
					_, _ = b.SelectTargets(6, 1, 1)
					opCount.Add(1)
				}
			}
		}()
	}

	wg.Wait()

	t.Logf("Completed %d concurrent operations with zero deadlocks or race conditions", opCount.Load())

	// Verify invariants after stress run
	activeCount := b.ActiveCount()
	if activeCount > maxActive {
		t.Fatalf("active count %d exceeds maxActiveResolvers %d", activeCount, maxActive)
	}

	activeConns := b.ActiveConnections()
	if len(activeConns) != activeCount {
		t.Fatalf("ActiveConnections length %d does not match ActiveCount %d", len(activeConns), activeCount)
	}

	seenKeys := make(map[string]bool)
	for _, c := range activeConns {
		if !c.IsValid {
			t.Fatalf("active connection %s has IsValid=false", c.Key)
		}
		if c.StandbyEligible {
			t.Fatalf("active connection %s has StandbyEligible=true", c.Key)
		}
		if seenKeys[c.Key] {
			t.Fatalf("duplicate active connection key: %s", c.Key)
		}
		seenKeys[c.Key] = true
	}
}

// TestEmpirical_MicroBurst_ActivePoolFullPromotion tests whether micro-burst qualification
// properly promotes qualified candidate resolvers when the active pool is already full of
// lower-performing active resolvers.
// Because calculateConnectionScoreLocked evaluates the candidate's score when SetConnectionValidity
// is called, calling SetConnectionValidity BEFORE SeedBurstStats evaluates unseeded stats (score 1.0),
// causing the superior candidate to be placed in the standby pool instead of active pool!
func TestEmpirical_MicroBurst_ActivePoolFullPromotion(t *testing.T) {
	domain := "v.example.com"
	conn0, port0, _ := startMockSelectivelyDroppingMTUDNSListener(t, domain, -1)
	defer conn0.Close()
	conn1, port1, _ := startMockSelectivelyDroppingMTUDNSListener(t, domain, -1)
	defer conn1.Close()

	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{domain}
	cfg.Resolvers = []config.ResolverAddress{
		{IP: "127.0.0.1", Port: port0},
		{IP: "127.0.0.1", Port: port1},
	}
	cfg.MicroBurstTestEnabled = true
	cfg.MicroBurstPacketCount = 6
	cfg.MaxActiveResolvers = 2

	client := createTestFastStartClient(t, cfg)
	balancer := client.balancer
	balancer.SetMaxActiveResolvers(2)

	// Pre-populate balancer with 2 older active resolvers with moderate score (RTT 80ms)
	oldConns := []*Connection{
		{Key: "old-1", Resolver: "8.8.8.8", ResolverPort: 53, Domain: domain, ResolverLabel: "8.8.8.8:53"},
		{Key: "old-2", Resolver: "8.8.4.4", ResolverPort: 53, Domain: domain, ResolverLabel: "8.8.4.4:53"},
		{Key: "new-burst-super", Resolver: "127.0.0.1", ResolverPort: port0, Domain: domain, ResolverLabel: fmt.Sprintf("127.0.0.1:%d", port0)},
	}
	balancer.SetConnections(oldConns)
	balancer.SetConnectionMTU("old-1", 150, 150, 1000)
	balancer.SetConnectionMTU("old-2", 150, 150, 1000)
	balancer.SetConnectionMTU("new-burst-super", 150, 150, 1000)

	// Seed old-1 and old-2 with moderate scores (80ms RTT, 0% loss -> score around 12)
	balancer.SeedBurstStats("old-1", 10, 10, 80*time.Millisecond)
	balancer.SetConnectionValidity("old-1", true)

	balancer.SeedBurstStats("old-2", 10, 10, 80*time.Millisecond)
	balancer.SetConnectionValidity("old-2", true)

	if balancer.ActiveCount() != 2 {
		t.Fatalf("expected 2 active connections initially, got %d", balancer.ActiveCount())
	}

	// Now run micro-burst qualification on new-burst-super (which has ~0-5ms RTT against localhost)
	candidateConn := Connection{
		Key:           "new-burst-super",
		Resolver:      "127.0.0.1",
		ResolverPort:  port0,
		Domain:        domain,
		ResolverLabel: fmt.Sprintf("127.0.0.1:%d", port0),
	}

	qualified, _ := client.runMicroBurstQualification(context.Background(), []Connection{candidateConn})
	if len(qualified) == 0 {
		t.Fatalf("expected new-burst-super to qualify in micro-burst")
	}

	// Verify if new-burst-super was promoted into active pool
	cSuper, ok := balancer.GetConnectionByKey("new-burst-super")
	if !ok {
		t.Fatal("new-burst-super not found in balancer")
	}

	if !cSuper.IsValid {
		t.Fatalf("BUG CONFIRMED: new-burst-super qualified in micro-burst (top ranked) but was NOT promoted to active (IsValid=false, StandbyEligible=%v) because SetConnectionValidity was called before SeedBurstStats!",
			cSuper.StandbyEligible)
	}
}

// TestEmpirical_ActiveStandbyMutualExclusivity isolates Bug 2:
// Balancer allows SetConnectionStandbyEligible(key, true) to succeed on an ACTIVE connection,
// putting the connection into a contradictory state where IsValid=true and StandbyEligible=true.
func TestEmpirical_ActiveStandbyMutualExclusivity(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	b.SetMaxActiveResolvers(2)

	connections := []*Connection{
		{Key: "res-1", Resolver: "1.1.1.1", ResolverPort: 53, Domain: "d.com", ResolverLabel: "1.1.1.1:53"},
	}
	b.SetConnections(connections)
	b.SetConnectionValidity("res-1", true)

	// res-1 is active
	conn, ok := b.GetConnectionByKey("res-1")
	if !ok || !conn.IsValid {
		t.Fatal("expected res-1 to be active")
	}

	// Calling SetConnectionStandbyEligible on an active connection should not succeed / corrupt state
	ret := b.SetConnectionStandbyEligible("res-1", true)

	connAfter, _ := b.GetConnectionByKey("res-1")
	if connAfter.IsValid && connAfter.StandbyEligible {
		t.Fatalf("BUG CONFIRMED: active connection res-1 was marked StandbyEligible=true! Active connections must not be standby eligible (SetConnectionStandbyEligible returned %v)", ret)
	}
}
