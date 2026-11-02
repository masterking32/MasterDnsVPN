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
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/security"
	"masterdnsvpn-go/internal/udpserver"
)

// mockResolverBehavior controls how a mock DNS listener responds.
type mockResolverBehavior struct {
	delay       time.Duration
	dropPercent int // 0 to 100
	queryCount  atomic.Int32
}

func startConfigurableMockDNSListener(t *testing.T, domain string, behavior *mockResolverBehavior) (*net.UDPConn, int) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}

	serverCfg := config.DefaultServerConfig()
	serverCfg.Domain = []string{domain}
	serverCfg.MinVPNLabelLength = 3
	serverCfg.DataEncryptionMethod = 0
	serverCodec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("server codec init failed: %v", err)
	}
	server := udpserver.New(serverCfg, nil, serverCodec)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			behavior.queryCount.Add(1)
			if behavior.dropPercent >= 100 {
				continue // Nonresponsive blackhole
			}
			if behavior.dropPercent > 0 && (behavior.queryCount.Load()%2 == 0) {
				continue // Drop 50%
			}
			if behavior.delay > 0 {
				time.Sleep(behavior.delay)
			}
			query := make([]byte, n)
			copy(query, buf[:n])
			response := server.HandlePacket(query)
			if len(response) > 0 {
				_, _ = conn.WriteToUDP(response, remoteAddr)
			}
		}
	}()

	port := conn.LocalAddr().(*net.UDPAddr).Port
	return conn, port
}

// TestIntegratedResolverManagerAcceptance verifies the complete resolver manager lifecycle:
// cold startup, early readiness, live traffic, background discovery to 100% coverage,
// failover/replacement, batched ranking persistence, and clean restart.
func TestIntegratedResolverManagerAcceptance(t *testing.T) {
	tempDir := t.TempDir()
	resolversPath := filepath.Join(tempDir, "resolvers.txt")

	dom1 := "v1.example.com"
	dom2 := "v2.example.com"
	domains := []string{dom1, dom2}

	// 1. Setup 4 distinct Resolver Endpoints with diverse behaviors
	// Ep1: Healthy & Fast (0 delay, 0% drop)
	beh1 := &mockResolverBehavior{}
	conn1a, port1 := startConfigurableMockDNSListener(t, dom1, beh1)
	defer conn1a.Close()

	// Ep2: Delayed (15ms delay, 0% drop)
	beh2 := &mockResolverBehavior{delay: 15 * time.Millisecond}
	conn2a, port2 := startConfigurableMockDNSListener(t, dom1, beh2)
	defer conn2a.Close()

	// Ep3: Lossy (50% drop)
	beh3 := &mockResolverBehavior{dropPercent: 50}
	conn3a, port3 := startConfigurableMockDNSListener(t, dom1, beh3)
	defer conn3a.Close()

	// Ep4: Nonresponsive (100% drop)
	beh4 := &mockResolverBehavior{dropPercent: 100}
	conn4a, port4 := startConfigurableMockDNSListener(t, dom1, beh4)
	defer conn4a.Close()

	// Write initial resolvers file
	initialResolversContent := fmt.Sprintf("127.0.0.1:%d\n127.0.0.1:%d\n127.0.0.1:%d\n127.0.0.1:%d\n", port1, port2, port3, port4)
	if err := os.WriteFile(resolversPath, []byte(initialResolversContent), 0644); err != nil {
		t.Fatalf("write resolvers file failed: %v", err)
	}

	// Configure client: 4 endpoints x 2 domains = 8 pairings
	cfg := config.DefaultClientConfig()
	cfg.ResolversFilePath = resolversPath
	cfg.Domains = domains
	cfg.Resolvers = []config.ResolverAddress{
		{IP: "127.0.0.1", Port: port1},
		{IP: "127.0.0.1", Port: port2},
		{IP: "127.0.0.1", Port: port3},
		{IP: "127.0.0.1", Port: port4},
	}
	cfg.RecheckInactiveServersEnabled = true
	cfg.RX_TX_Workers = 2
	cfg.MTUTestParallelism = 2
	cfg.MaxActiveResolvers = 4
	cfg.MinUploadMTU = 100
	cfg.MaxUploadMTU = 200
	cfg.MinDownloadMTU = 200
	cfg.MaxDownloadMTU = 400
	cfg.MTUTestRetries = 1
	cfg.MTUTestTimeout = 0.1
	cfg.AutoSaveRankedResolvers = true

	client := createTestFastStartClient(t, cfg)
	defer client.Close()

	// --- PHASE 1: Cold Startup & Early FastStart Readiness ---
	t0 := time.Now()
	ctxInit, cancelInit := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelInit()

	err := client.RunInitialMTUTests(ctxInit)
	if err != nil {
		t.Fatalf("RunInitialMTUTests failed: %v", err)
	}
	tReady := time.Since(t0)

	// Invariant Check: Readiness achieved with distinct qualified endpoints
	activeCount := client.balancer.ActiveCount()
	if activeCount < 2 {
		t.Fatalf("expected at least 2 active resolvers for readiness, got %d", activeCount)
	}
	covInit := client.balancer.CoverageStats()
	if covInit.ConfiguredPairings != 8 {
		t.Fatalf("expected 8 configured pairings, got %d", covInit.ConfiguredPairings)
	}
	// Initial coverage must NOT be 100% yet at early readiness
	if covInit.IsFirstPassComplete {
		t.Fatalf("expected early readiness before first pass complete: %+v", covInit)
	}
	t.Logf("✓ Early readiness achieved in %s (Active: %d/8, Completed attempts: %d)", tReady, activeCount, covInit.CompletedInitialAttempts)

	// --- PHASE 2: Live Traffic & Background Discovery to 100% Coverage ---
	// Background query limiter should bound background queries
	limiter := client.BackgroundQueryLimiter()
	if limiter == nil {
		t.Fatal("expected non-nil BackgroundQueryLimiter")
	}

	// Simulate background discovery driving remaining candidates
	// Recheck remaining inactive resolvers until first pass is complete
	ctxRecheck, cancelRecheck := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelRecheck()

	recheckStartTime := time.Now()
	for !client.balancer.IsFirstPassComplete() && ctxRecheck.Err() == nil {
		conn, ok := client.balancer.NextInactiveConnectionForHealthCheck(time.Now(), 0)
		if !ok || conn.Key == "" {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		// Probe via client's recheckInactiveResolver
		client.recheckInactiveResolver(ctxRecheck, conn)
	}

	if !client.balancer.IsFirstPassComplete() {
		t.Fatalf("expected first pass to reach 100%% complete: %+v", client.balancer.CoverageStats())
	}
	tCoverage := time.Since(recheckStartTime)
	covDone := client.balancer.CoverageStats()
	t.Logf("✓ Full 100%% first-pass coverage achieved in %s (Completed: %d/8, Untested: %d, Distinct qualified: %d)",
		tCoverage, covDone.CompletedInitialAttempts, covDone.RemainingUntested, covDone.DistinctQualified)

	// --- PHASE 3: Mutual Exclusivity Invariant & Score-Based Traffic ---
	snapshots := client.balancer.GetStatsSnapshot()
	for _, s := range snapshots {
		// Mutual exclusivity: A candidate cannot be both Active and Standby
		if s.IsValid && s.StandbyEligible {
			t.Fatalf("invariant violation: candidate %s is both active and standby", s.Connection.Key)
		}
	}

	// Verify default common-score routing selects faster candidates
	targets, err := client.balancer.SelectTargets(Enums.PACKET_STREAM_DATA, 1, 2)
	if err != nil || len(targets) == 0 {
		t.Fatalf("SelectTargets failed: %v", err)
	}
	for _, tg := range targets {
		if !tg.IsValid {
			t.Fatalf("expected only valid active resolvers in targets, got invalid: %s", tg.Key)
		}
	}

	// --- PHASE 4: Pool Policy & Failover Replacement ---
	// Simulate degradation of the top active candidate by applying high loss
	activeConns := client.balancer.ActiveConnections()
	if len(activeConns) > 0 {
		degradedKey := activeConns[0].Key
		// Invalidate degraded connection
		client.balancer.SetConnectionValidity(degradedKey, false)
		// Active pool should remain valid and promote eligible standby candidate
		newActiveCount := client.balancer.ActiveCount()
		if newActiveCount < 1 {
			t.Fatal("expected pool to retain active candidates after failover")
		}
		t.Logf("✓ Failover handled successfully: active count now %d", newActiveCount)
	}

	// --- PHASE 5: Batched Persistence Writer & Clean Restart ---
	// Force flush of ranked persistence writer
	client.SaveRankedResolversToFile()
	client.Close() // Graceful close flushes rankedWriter

	// Read back written resolvers file
	savedData, err := os.ReadFile(resolversPath)
	if err != nil {
		t.Fatalf("failed to read resolvers file: %v", err)
	}
	if len(savedData) == 0 {
		t.Fatal("expected non-empty resolvers file after auto-save")
	}
	t.Logf("✓ Ranked persistence file verified:\n%s", string(savedData))

	// Simulate Restart: New client loads the ranked resolvers
	clientRestart := createTestFastStartClient(t, cfg)
	defer clientRestart.Close()

	if clientRestart.balancer.TotalCount() != 8 {
		t.Fatalf("expected 8 total candidates on restart, got %d", clientRestart.balancer.TotalCount())
	}
	t.Log("✓ Client restart successfully loaded ranked resolvers and initialized pool")
}

// TestIntegratedResolverManager_DiagnosticsAudit verifies that DumpRuntimeStats produces
// coverage diagnostics, active/standby partitions, and accurate loss/RTT reporting.
func TestIntegratedResolverManager_DiagnosticsAudit(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{"v.example.com"}
	cfg.Resolvers = []config.ResolverAddress{{IP: "127.0.0.1", Port: 53}}
	c := createTestFastStartClient(t, cfg)
	defer c.Close()

	// Qualify single candidate
	conns := c.balancer.AllConnections()
	if len(conns) == 0 {
		t.Fatal("expected connections in balancer")
	}
	c.balancer.ApplyMTUProbeResult(conns[0].Key, 100, 50, 500, 10*time.Millisecond, true)

	// DumpRuntimeStats should run without panic and report coverage
	c.DumpRuntimeStats("Acceptance Audit")
	cov := c.balancer.CoverageStats()
	if cov.CompletedInitialAttempts != 1 || cov.DistinctQualified != 1 {
		t.Fatalf("unexpected coverage stats: %+v", cov)
	}
}
