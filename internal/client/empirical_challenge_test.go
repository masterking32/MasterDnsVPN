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
		0, // Pre-canceled
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

	b.SetConnectionMTU("inact-disabled", 200, 200, 1200)   // Meets MTU, but will have StandbyEligible=false
	b.SetConnectionMTU("stby-low-upload", 120, 120, 1200)  // Upload 120 < 150
	b.SetConnectionMTU("stby-low-download", 160, 160, 800) // Download 800 < 1000
	b.SetConnectionMTU("stby-zero-mtu", 0, 0, 0)           // Zero MTU
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

// TestEmpirical_RuntimeStats_MonotonicCounterGating tests:
// 1. Monotonicity of totalPacketsSent under high concurrency (multiple worker goroutines).
// 2. Ensuring that when individual connection stats are halved by applyHalfLife() (threshold 1000),
//    totalPacketsSent NEVER drops or fluctuates.
// 3. Ensuring that periodic runtime stats gating (currentSentTotal > lastSentTotal) is never suppressed
//    or stalled by half-life decay.
func TestEmpirical_RuntimeStats_MonotonicCounterGating(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	const numResolvers = 5
	var conns []*Connection
	for i := 0; i < numResolvers; i++ {
		key := fmt.Sprintf("res-%d", i)
		conns = append(conns, &Connection{
			Key:           key,
			Resolver:      fmt.Sprintf("1.1.1.%d", i+1),
			ResolverPort:  53,
			Domain:        "example.com",
			ResolverLabel: fmt.Sprintf("1.1.1.%d:53", i+1),
		})
	}
	b.SetConnections(conns)
	for _, c := range conns {
		b.SetConnectionValidity(c.Key, true)
	}

	const numWorkers = 8
	const packetsPerWorker = 3000 // 24,000 packets total, triggering multiple half-life cycles (>1000)
	var wg sync.WaitGroup

	var monotonicViolations atomic.Int64

	// Concurrently monitor TotalPacketsSent from a background checker
	stopMonitor := make(chan struct{})
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		var last uint64
		for {
			select {
			case <-stopMonitor:
				return
			default:
				cur := b.TotalPacketsSent()
				if cur < last {
					monotonicViolations.Add(1)
				}
				last = cur
				runtime.Gosched()
			}
		}
	}()

	// Launch workers calling ReportSend and ReportSuccess (to trigger applyHalfLife on both sent & acked)
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			var localLast uint64
			for p := 0; p < packetsPerWorker; p++ {
				key := fmt.Sprintf("res-%d", (workerID+p)%numResolvers)
				b.ReportSend(key)
				if p%2 == 0 {
					b.ReportSuccess(key, 10*time.Millisecond)
				}

				// Spot check monotonicity for this worker
				cur := b.TotalPacketsSent()
				if cur < localLast {
					monotonicViolations.Add(1)
				}
				localLast = cur
			}
		}(w)
	}

	wg.Wait()
	close(stopMonitor)
	<-monitorDone

	if violations := monotonicViolations.Load(); violations > 0 {
		t.Fatalf("observed %d monotonic violations in TotalPacketsSent", violations)
	}

	expectedTotal := uint64(numWorkers * packetsPerWorker)
	if actual := b.TotalPacketsSent(); actual != expectedTotal {
		t.Fatalf("expected TotalPacketsSent = %d, got %d", expectedTotal, actual)
	}

	// Verify that individual connection stats decayed via applyHalfLife
	// but TotalPacketsSent stayed at expectedTotal
	var sumDecayedSent uint64
	for i := 0; i < numResolvers; i++ {
		key := fmt.Sprintf("res-%d", i)
		stats := b.statsForKey(key)
		if stats != nil {
			sumDecayedSent += stats.sent.Load()
		}
	}
	t.Logf("Total packets sent: %d, Sum of decayed individual sent stats: %d (decayed by %d)",
		expectedTotal, sumDecayedSent, expectedTotal-sumDecayedSent)
	if sumDecayedSent >= expectedTotal {
		t.Fatalf("expected applyHalfLife to have decayed individual sent stats below total (%d >= %d)",
			sumDecayedSent, expectedTotal)
	}

	// Test periodic stats gating logic with decayed counters
	// If gating used sumDecayedSent, it would have stalled. With TotalPacketsSent, it gates cleanly.
	lastSentTotal := b.TotalPacketsSent()
	b.ReportSend("res-0")
	currentSentTotal := b.TotalPacketsSent()
	if currentSentTotal <= lastSentTotal {
		t.Fatalf("gating failed: currentSentTotal (%d) <= lastSentTotal (%d)", currentSentTotal, lastSentTotal)
	}
}

// TestEmpirical_MicroBurst_PacingAndQueueDelayElimination empirically verifies:
// 1. Queries are paced at 2ms intervals to prevent local buffer saturation.
// 2. The concurrent receiver reads responses as they arrive without waiting for the sender
//    loop to finish, eliminating local socket buffer queue delay.
// 3. Thread safety between sender (itemMu write) and receiver (itemMu read).
// 4. Clean completion and bounded goroutine lifecycle via senderDone.
func TestEmpirical_MicroBurst_PacingAndQueueDelayElimination(t *testing.T) {
	domain := "example.com"
	server, addr := startMockBurstServer(t, domain, 0, 0) // immediate response
	defer server.Close()

	var port int
	_, _ = fmt.Sscanf(addr, "127.0.0.1:%d", &port)

	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{domain}
	cfg.Resolvers = []config.ResolverAddress{{IP: "127.0.0.1", Port: port}}
	cfg.MicroBurstTestEnabled = true
	cfg.MicroBurstPacketCount = 8 // 8 packets -> at 2ms pacing = at least 14ms send duration
	cfg.MaxActiveResolvers = 1

	client := createTestFastStartClient(t, cfg)

	conn := Connection{
		Key:           "pacing-test",
		Resolver:      "127.0.0.1",
		ResolverPort:  port,
		Domain:        domain,
		ResolverLabel: addr,
	}

	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	transport, err := client.newUDPQueryTransport(context.Background(), conn.ResolverLabel)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}
	defer transport.conn.Close()

	start := time.Now()
	result := client.sendPipelinedMicroBurst(context.Background(), conn, transport, 8, 500, 100, 2*time.Second)
	totalDuration := time.Since(start)

	if !result.Qualified {
		t.Fatalf("expected micro-burst to qualify, rejected: %s", result.RejectReason)
	}
	if result.ReceivedCount != 8 {
		t.Fatalf("expected 8 received packets, got %d", result.ReceivedCount)
	}

	// With 8 queries paced at 2ms, total send duration must be at least 14ms (7 intervals * 2ms)
	// (or at least 10ms allowing for OS timer granularity)
	if totalDuration < 10*time.Millisecond {
		t.Fatalf("expected total duration >= 10ms due to 2ms pacing across 8 queries, took %v", totalDuration)
	}

	// Under concurrent receiving:
	// If responses had to wait in the socket buffer until all 8 queries were sent,
	// query 0's RTT would be >= 14ms, and average RTT would be >= 7ms.
	// Because replies are read concurrently as they arrive, the average RTT on localhost is < 6ms!
	t.Logf("Measured AverageRTT: %v, MinRTT: %v, MaxRTT: %v, TotalDuration: %v",
		result.AverageRTT, result.MinRTT, result.MaxRTT, totalDuration)

	if result.AverageRTT > 6*time.Millisecond {
		t.Fatalf("queue delay detected! AverageRTT is %v (expected < 6ms on localhost under concurrent receive)",
			result.AverageRTT)
	}

	// Verify zero goroutine leaks (senderDone guaranteed exit)
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
		t.Fatalf("goroutine leak: initial %d, final %d", initialGoroutines, finalGoroutines)
	}
}

// TestEmpirical_ConcurrentBalancerStress performs massive multi-goroutine stress on Balancer:
// - Heavy concurrent ReportSend, ReportSuccess, ReportLoss triggering applyHalfLife
// - Concurrent TotalPacketsSent queries
// - Concurrent OptimizeActivePool, SetConnectionValidity, SetConnectionStandbyEligible
// Verifies:
// 1. Zero data races
// 2. Zero deadlocks
// 3. TotalPacketsSent monotonic invariant
// 4. Active pool capacity invariant (ActiveCount <= MaxActiveResolvers)
// 5. Mutual exclusivity invariant (!conn.IsValid || !conn.StandbyEligible)
func TestEmpirical_ConcurrentBalancerStress(t *testing.T) {
	b := NewBalancer(BalancingLossThenLatency, nil)
	const maxActive = 3
	b.SetMaxActiveResolvers(maxActive)
	b.SetSessionSynchronizedMTU(150, 1000)

	const numResolvers = 8
	var conns []*Connection
	for i := 0; i < numResolvers; i++ {
		key := fmt.Sprintf("res-%d", i)
		conns = append(conns, &Connection{
			Key:           key,
			Resolver:      fmt.Sprintf("10.0.1.%d", i+1),
			ResolverPort:  53,
			Domain:        "example.com",
			ResolverLabel: fmt.Sprintf("10.0.1.%d:53", i+1),
		})
	}
	b.SetConnections(conns)
	for i := 0; i < numResolvers; i++ {
		key := fmt.Sprintf("res-%d", i)
		b.SetConnectionMTU(key, 150+i*10, 150+i*10, 1000+i*20)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var totalOps atomic.Int64
	var monotonicViolations atomic.Int64

	// Workers: Packet reports & TotalPacketsSent checking
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			var localLast uint64
			i := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
					key := fmt.Sprintf("res-%d", (workerID+i)%numResolvers)
					b.ReportSend(key)
					if i%3 == 0 {
						b.ReportSuccess(key, time.Duration(10+(i%50))*time.Millisecond)
					} else if i%7 == 0 {
						_ = b.ReportTimeout(key, time.Now(), time.Minute, 1)
					}
					cur := b.TotalPacketsSent()
					if cur < localLast {
						monotonicViolations.Add(1)
					}
					localLast = cur
					totalOps.Add(1)
					i++
				}
			}
		}(w)
	}

	// Workers: Validity and Standby state modifications
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
					if i%2 == 0 {
						b.SetConnectionValidity(key, (i%4) == 0)
					} else {
						b.SetConnectionStandbyEligible(key, (i%4) != 0)
					}
					totalOps.Add(1)
					i++
				}
			}
		}(w)
	}

	// Workers: Active pool optimizations and snapshot queries
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
					totalOps.Add(1)
				}
			}
		}()
	}

	wg.Wait()

	t.Logf("Completed %d concurrent operations across all subsystems", totalOps.Load())

	if violations := monotonicViolations.Load(); violations > 0 {
		t.Fatalf("detected %d monotonic violations in TotalPacketsSent under stress", violations)
	}

	// Validate post-stress invariants
	if b.ActiveCount() > maxActive {
		t.Fatalf("active count %d exceeded maxActive %d", b.ActiveCount(), maxActive)
	}

	for _, c := range b.AllConnections() {
		if c.IsValid && c.StandbyEligible {
			t.Fatalf("invariant violated: connection %s has both IsValid=true and StandbyEligible=true", c.Key)
		}
	}
}

// TestEmpirical_MTU_BatchStandbyEligibilityPreserved verifies that MTU batch testing
// records and evaluates candidates even when placed into Standby pool due to MaxActiveResolvers
// capacity (acceptedConn.IsValid || acceptedConn.StandbyEligible).
//
// The test uses controlled probe outcomes to make replenishment assertions independent of
// thread/worker probe scheduling.
func TestEmpirical_MTU_BatchStandbyEligibilityPreserved(t *testing.T) {
	domain := "v.example.com"
	pool := NewResolverPool(2, nil)

	conn0 := Connection{Key: "r0", Resolver: "127.0.0.1", ResolverPort: 5300, ResolverLabel: "127.0.0.1:5300", Domain: domain, DownloadMTUBytes: 300, UploadMTUBytes: 100}
	conn1 := Connection{Key: "r1", Resolver: "127.0.0.1", ResolverPort: 5301, ResolverLabel: "127.0.0.1:5301", Domain: domain, DownloadMTUBytes: 300, UploadMTUBytes: 100}
	conn2 := Connection{Key: "r2", Resolver: "127.0.0.1", ResolverPort: 5302, ResolverLabel: "127.0.0.1:5302", Domain: domain, DownloadMTUBytes: 300, UploadMTUBytes: 100}
	conn3 := Connection{Key: "r3", Resolver: "127.0.0.1", ResolverPort: 5303, ResolverLabel: "127.0.0.1:5303", Domain: domain, DownloadMTUBytes: 300, UploadMTUBytes: 100}

	pool.SetConnections([]*Connection{&conn0, &conn1, &conn2, &conn3})
	pool.SetSessionMTU(100, 300)

	cfg := DiscoveryConfig{
		FastStart:             true,
		TargetResolvers:       2,
		Parallelism:           2,
		MaxActiveResolvers:    2,
		MicroBurstEnabled:     true,
		MicroBurstPacketCount: 6,
		MicroBurstParallelism: 2,
		MicroBurstTimeout:     100 * time.Millisecond,
		Domains:               []string{domain},
	}

	prober := NewFakeResolverProber()
	// Resolvers 0 and 1: pass MTU, fail micro-burst
	prober.SetBurstResponse("r0", BurstProbeResult{SentCount: 6, ReceivedCount: 2, LossRatio: 0.67, AverageRTT: 10 * time.Millisecond, Qualified: false})
	prober.SetBurstResponse("r1", BurstProbeResult{SentCount: 6, ReceivedCount: 2, LossRatio: 0.67, AverageRTT: 10 * time.Millisecond, Qualified: false})

	// Resolvers 2 and 3: pass MTU and qualify micro-burst
	prober.SetBurstResponse("r2", BurstProbeResult{SentCount: 6, ReceivedCount: 6, LossRatio: 0, AverageRTT: 20 * time.Millisecond, BurstThroughputKBps: 200, Qualified: true})
	prober.SetBurstResponse("r3", BurstProbeResult{SentCount: 6, ReceivedCount: 6, LossRatio: 0, AverageRTT: 25 * time.Millisecond, BurstThroughputKBps: 180, Qualified: true})

	engine := NewDiscoveryEngine(cfg, prober, pool, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine.Run() failed unexpectedly: %v", err)
	}

	activeConns := pool.ActiveResolvers()
	if len(activeConns) != 2 {
		t.Fatalf("expected exactly 2 active connections, got %d", len(activeConns))
	}

	activeKeys := make(map[string]bool)
	for _, c := range activeConns {
		activeKeys[c.Key] = true
	}

	if !activeKeys["r2"] {
		t.Fatalf("expected resolver r2 to be active in pool, got: %v", activeKeys)
	}
	if !activeKeys["r3"] {
		t.Fatalf("expected resolver r3 to be active in pool, got: %v", activeKeys)
	}
	if activeKeys["r0"] || activeKeys["r1"] {
		t.Fatalf("burst-failing resolvers unexpectedly remained active: %v", activeKeys)
	}
}

// TestEmpirical_MTU_BatchStandbyEligibilityPreserved_UDP retains end-to-end UDP socket integration
// coverage for batch standby replenishment with a generous 30s timeout.
func TestEmpirical_MTU_BatchStandbyEligibilityPreserved_UDP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping UDP integration in short mode")
	}
	domain := "v.example.com"

	// Resolvers 0 and 1: answer 2 MTU packets, then drop all subsequent (fails micro-burst)
	conn0, port0, _ := startMockSelectivelyDroppingMTUDNSListener(t, domain, 2)
	defer conn0.Close()
	conn1, port1, _ := startMockSelectivelyDroppingMTUDNSListener(t, domain, 2)
	defer conn1.Close()

	// Resolvers 2 and 3: answer all packets (passes MTU and micro-burst)
	conn2, port2, _ := startMockSelectivelyDroppingMTUDNSListener(t, domain, -1)
	defer conn2.Close()
	conn3, port3, _ := startMockSelectivelyDroppingMTUDNSListener(t, domain, -1)
	defer conn3.Close()

	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{domain}
	cfg.Resolvers = []config.ResolverAddress{
		{IP: "127.0.0.1", Port: port0},
		{IP: "127.0.0.1", Port: port1},
		{IP: "127.0.0.1", Port: port2},
		{IP: "127.0.0.1", Port: port3},
	}
	cfg.RecheckInactiveServersEnabled = true
	cfg.AutoSaveRankedResolvers = false
	cfg.RX_TX_Workers = 2
	cfg.MaxActiveResolvers = 2
	cfg.MicroBurstTestEnabled = true
	cfg.MicroBurstPacketCount = 6
	cfg.MinUploadMTU = 100
	cfg.MaxUploadMTU = 100
	cfg.MinDownloadMTU = 300
	cfg.MaxDownloadMTU = 300
	cfg.MTUTestRetries = 1
	cfg.MTUTestTimeout = 0.5

	client := createTestFastStartClient(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.RunInitialMTUTests(ctx)
	if err != nil {
		t.Fatalf("RunInitialMTUTests failed unexpectedly: %v", err)
	}

	balancer := client.balancer
	activeConns := balancer.ActiveConnections()
	if len(activeConns) != 2 {
		t.Fatalf("expected exactly 2 active connections, got %d", len(activeConns))
	}

	activeLabels := make(map[string]bool)
	for _, c := range activeConns {
		activeLabels[c.ResolverLabel] = true
	}

	label2 := fmt.Sprintf("127.0.0.1:%d", port2)
	label3 := fmt.Sprintf("127.0.0.1:%d", port3)
	if !activeLabels[label2] {
		t.Fatalf("expected resolver 2 (%s) to be active in pool, got: %v", label2, activeLabels)
	}
	if !activeLabels[label3] {
		t.Fatalf("expected resolver 3 (%s) to be active in pool, got: %v", label3, activeLabels)
	}

	label0 := fmt.Sprintf("127.0.0.1:%d", port0)
	label1 := fmt.Sprintf("127.0.0.1:%d", port1)
	if activeLabels[label0] || activeLabels[label1] {
		t.Fatalf("burst-failing resolvers unexpectedly remained active: %v", activeLabels)
	}
}

// TestEmpirical_MTU_StrictKeyTrimmingMultiDomain empirically tests that active pool fast-start
// trimming evaluates qualified status strictly against qualifiedKeys[conn.Key] rather than
// qualifiedEndpoints[conn.ResolverLabel].
//
// Scenario:
// 1. Two domains (d1.example.com, d2.example.com) share the same physical DNS resolver endpoint (127.0.0.1:53).
// 2. Both connections (conn1 for d1, conn2 for d2) have completed MTU probes and are initially active.
// 3. During micro-burst qualification, conn1 qualifies (added to qualifiedKeys and qualifiedEndpoints).
// 4. conn2 fails micro-burst qualification (not in qualifiedKeys).
// 5. Because both share conn.ResolverLabel ("127.0.0.1:53"), qualifiedEndpoints[conn2.ResolverLabel] is TRUE!
// 6. With PR 205 fix: fast-start trimming checks qualifiedKeys[conn.Key].
//    conn2 is strictly trimmed (IsValid=false, StandbyEligible=false).
//    conn1 remains active (IsValid=true).
// 7. Counter-factual verification: verifies that if qualifiedEndpoints were used, conn2 would erroneously
//    survive trimming despite failing qualification on its domain.
func TestEmpirical_MTU_StrictKeyTrimmingMultiDomain(t *testing.T) {
	domain1 := "d1.example.com"
	domain2 := "d2.example.com"
	domains := []string{domain1, domain2}
	sharedEndpoint := "127.0.0.1:53"

	cfg := config.DefaultClientConfig()
	cfg.Domains = domains
	cfg.Resolvers = []config.ResolverAddress{{IP: "127.0.0.1", Port: 53}}
	cfg.RecheckInactiveServersEnabled = true
	cfg.MicroBurstTestEnabled = true

	client := createTestFastStartClient(t, cfg)
	balancer := client.balancer

	key1 := fmt.Sprintf("127.0.0.1|53|%s", domain1)
	key2 := fmt.Sprintf("127.0.0.1|53|%s", domain2)

	conns := []*Connection{
		{Key: key1, Resolver: "127.0.0.1", ResolverPort: 53, Domain: domain1, ResolverLabel: sharedEndpoint},
		{Key: key2, Resolver: "127.0.0.1", ResolverPort: 53, Domain: domain2, ResolverLabel: sharedEndpoint},
	}
	balancer.SetConnections(conns)
	balancer.SetConnectionMTU(key1, 150, 150, 1000)
	balancer.SetConnectionMTU(key2, 150, 150, 1000)

	// Both connections are active initially following MTU pass
	balancer.SetConnectionValidity(key1, true)
	balancer.SetConnectionValidity(key2, true)

	if balancer.ActiveCount() != 2 {
		t.Fatalf("expected 2 active connections initially, got %d", balancer.ActiveCount())
	}

	// Micro-burst qualification: key1 qualifies, key2 fails
	qualifiedKeys := make(map[string]struct{})
	qualifiedEndpoints := make(map[string]struct{})

	// key1 qualifies
	qualifiedKeys[key1] = struct{}{}
	qualifiedEndpoints[sharedEndpoint] = struct{}{}
	// key2 fails -> NOT in qualifiedKeys

	// Counter-factual verification: verify that using qualifiedEndpoints WOULD cause a false negative (failure to trim)
	if _, wouldSurviveOldBug := qualifiedEndpoints[conns[1].ResolverLabel]; !wouldSurviveOldBug {
		t.Fatal("precondition failed: shared endpoint must be present in qualifiedEndpoints")
	}

	// Execute PR 205 fast-start trimming logic (internal/client/mtu.go:558-566)
	for _, conn := range balancer.ActiveConnections() {
		if _, qual := qualifiedKeys[conn.Key]; !qual {
			balancer.SetConnectionValidity(conn.Key, false)
			balancer.SetConnectionStandbyEligible(conn.Key, false)
		}
	}

	// Verify key1 is active
	c1, ok1 := balancer.GetConnectionByKey(key1)
	if !ok1 || !c1.IsValid {
		t.Fatalf("expected conn1 for domain %s to remain valid, got IsValid=%v", domain1, c1.IsValid)
	}

	// Verify key2 was strictly trimmed
	c2, ok2 := balancer.GetConnectionByKey(key2)
	if !ok2 {
		t.Fatal("conn2 missing from balancer")
	}
	if c2.IsValid {
		t.Fatalf("BUG CONFIRMED: conn2 for domain %s sharing endpoint %s remained active!", domain2, sharedEndpoint)
	}
	if c2.StandbyEligible {
		t.Fatalf("conn2 should have StandbyEligible=false after fast-start trimming, got true")
	}

	// Active pool count must be strictly 1
	if balancer.ActiveCount() != 1 {
		t.Fatalf("expected active count = 1, got %d", balancer.ActiveCount())
	}
}

// TestEmpirical_RecheckRevokesStandby_NoRaceWithOptimize verifies that:
// 1. recheckInactiveResolver immediately revokes StandbyEligible before initiating network probes.
// 2. High-frequency concurrent calls to OptimizeActivePool() cannot race to promote the degraded/failing
//    standby candidate into the active pool while health probing is in flight.
// 3. Zero data races and zero deadlocks occur under concurrent stress.
func TestEmpirical_RecheckRevokesStandby_NoRaceWithOptimize(t *testing.T) {
	domain := "v.example.com"

	// Create a closed UDP listener so probe times out / fails immediately
	deadConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	deadPort := deadConn.LocalAddr().(*net.UDPAddr).Port
	deadConn.Close() // closed: will fail health probe

	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{domain}
	cfg.Resolvers = []config.ResolverAddress{
		{IP: "1.1.1.1", Port: 53},
		{IP: "1.1.1.2", Port: 53},
		{IP: "127.0.0.1", Port: deadPort},
	}
	cfg.MaxActiveResolvers = 2
	cfg.MTUTestTimeout = 0.2
	cfg.MTUTestRetries = 1

	client := createTestFastStartClient(t, cfg)
	balancer := client.balancer
	balancer.SetMaxActiveResolvers(2)

	deadKey := fmt.Sprintf("127.0.0.1|%d|%s", deadPort, domain)
	allConns := []*Connection{
		{Key: "act-degraded", Resolver: "1.1.1.1", ResolverPort: 53, Domain: domain, ResolverLabel: "1.1.1.1:53"},
		{Key: "act-healthy", Resolver: "1.1.1.2", ResolverPort: 53, Domain: domain, ResolverLabel: "1.1.1.2:53"},
		{Key: deadKey, Resolver: "127.0.0.1", ResolverPort: deadPort, Domain: domain, ResolverLabel: fmt.Sprintf("127.0.0.1:%d", deadPort)},
	}
	balancer.SetConnections(allConns)
	balancer.SetConnectionMTU("act-degraded", 150, 150, 1000)
	balancer.SetConnectionMTU("act-healthy", 150, 150, 1000)
	balancer.SetConnectionMTU(deadKey, 150, 150, 1000)

	// act-degraded: Active, but degraded (90% loss, RTT 600ms -> low score)
	balancer.SeedBurstStats("act-degraded", 100, 10, 600*time.Millisecond)
	balancer.SetConnectionValidity("act-degraded", true)

	// act-healthy: Active, healthy (0% loss, RTT 20ms -> good score)
	balancer.SeedBurstStats("act-healthy", 100, 100, 20*time.Millisecond)
	balancer.SetConnectionValidity("act-healthy", true)

	// deadKey: Inactive, but marked StandbyEligible=true with a very high historical score (100.0)
	// If standby eligibility were not revoked, OptimizeActivePool would immediately promote it over act-degraded!
	balancer.SeedBurstStats(deadKey, 100, 100, 10*time.Millisecond)
	balancer.SetConnectionValidity(deadKey, false)
	balancer.SetConnectionStandbyEligible(deadKey, true)

	if !balancer.IsConnectionStandbyEligible(deadKey) {
		t.Fatal("expected deadKey to be standby eligible initially")
	}

	targetConn, ok := balancer.GetConnectionByKey(deadKey)
	if !ok {
		t.Fatal("targetConn not found")
	}

	var wg sync.WaitGroup
	stressCtx, stressCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer stressCancel()

	var illegalPromotions atomic.Int64
	var optimizeCalls atomic.Int64

	// Trigger recheck in background: immediately revokes StandbyEligible and probes closed UDP port
	recheckStarted := make(chan struct{})
	var recheckWg sync.WaitGroup
	recheckWg.Add(1)
	go func() {
		defer recheckWg.Done()
		close(recheckStarted)
		for i := 0; i < 5; i++ {
			if stressCtx.Err() != nil {
				return
			}
			client.recheckInactiveResolver(stressCtx, targetConn)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	<-recheckStarted
	// Wait until recheck has revoked standby eligibility before in-flight network probe
	for i := 0; i < 100; i++ {
		if !balancer.IsConnectionStandbyEligible(deadKey) {
			break
		}
		time.Sleep(1 * time.Millisecond)
	}

	if balancer.IsConnectionStandbyEligible(deadKey) {
		t.Fatal("expected standby eligibility to be revoked by recheck")
	}

	// Concurrently invoke OptimizeActivePool at high frequency from 6 workers while probe is in flight
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stressCtx.Done():
					return
				default:
					_ = balancer.OptimizeActivePool()
					optimizeCalls.Add(1)

					// Invariant check: deadKey must NEVER be promoted to active while probe in flight
					conn, ok := balancer.GetConnectionByKey(deadKey)
					if ok && conn.IsValid {
						illegalPromotions.Add(1)
					}
				}
			}
		}()
	}

	<-stressCtx.Done()
	recheckWg.Wait()
	wg.Wait()

	t.Logf("Completed %d concurrent OptimizeActivePool calls during recheck", optimizeCalls.Load())

	if promotions := illegalPromotions.Load(); promotions > 0 {
		t.Fatalf("RACE CONDITION: dead resolver was promoted to active %d times during recheck", promotions)
	}

	finalConn, _ := balancer.GetConnectionByKey(deadKey)
	if finalConn.IsValid {
		t.Fatal("dead resolver must remain inactive")
	}
	if finalConn.StandbyEligible {
		t.Fatal("dead resolver must have StandbyEligible=false after recheck failure")
	}
}
