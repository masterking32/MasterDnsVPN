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
	"sync/atomic"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/security"
	"masterdnsvpn-go/internal/udpserver"
)

func startMockMTUDNSListener(t *testing.T, domain string) (*net.UDPConn, int, *atomic.Int32) {
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

	var queryCount atomic.Int32
	go func() {
		buf := make([]byte, 4096)
		for {
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			queryCount.Add(1)
			query := make([]byte, n)
			copy(query, buf[:n])
			response := server.HandlePacket(query)
			if len(response) > 0 {
				_, _ = conn.WriteToUDP(response, remoteAddr)
			}
		}
	}()

	port := conn.LocalAddr().(*net.UDPAddr).Port
	return conn, port, &queryCount
}

func createTestFastStartClient(t *testing.T, cfg config.ClientConfig) *Client {
	t.Helper()
	cfg.AutoSaveRankedResolvers = false
	codec, err := security.NewCodec(cfg.DataEncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		t.Fatalf("client codec init failed: %v", err)
	}
	client := New(cfg, nil, codec)
	if err := client.BuildConnectionMap(); err != nil {
		t.Fatalf("BuildConnectionMap failed: %v", err)
	}
	return client
}

func TestRunInitialMTUTests_FastStartExitsEarly(t *testing.T) {
	domain := "v.example.com"

	// Start 10 mock resolver listeners
	conns := make([]*net.UDPConn, 10)
	resolvers := make([]config.ResolverAddress, 10)
	for i := 0; i < 10; i++ {
		conn, port, _ := startMockMTUDNSListener(t, domain)
		conns[i] = conn
		resolvers[i] = config.ResolverAddress{IP: "127.0.0.1", Port: port}
		defer conn.Close()
	}

	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{domain}
	cfg.Resolvers = resolvers
	cfg.RecheckInactiveServersEnabled = true
	cfg.RX_TX_Workers = 2
	cfg.MTUTestParallelism = 2
	cfg.MinUploadMTU = 100
	cfg.MaxUploadMTU = 200
	cfg.MinDownloadMTU = 200
	cfg.MaxDownloadMTU = 400
	cfg.MTUTestRetries = 1
	cfg.MTUTestTimeout = 1.0

	client := createTestFastStartClient(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.RunInitialMTUTests(ctx)
	if err != nil {
		t.Fatalf("RunInitialMTUTests failed: %v", err)
	}

	activeCount := client.balancer.ActiveCount()
	if activeCount < 2 || activeCount >= 10 {
		t.Fatalf("expected early exit with partial active resolvers (>=2 and <10), got=%d", activeCount)
	}

	totalCount := client.balancer.TotalCount()
	if totalCount != 10 {
		t.Fatalf("expected total 10 connections in balancer, got=%d", totalCount)
	}
}

func TestRunInitialMTUTests_FullScanWhenRecheckDisabled(t *testing.T) {
	domain := "v.example.com"

	// Start 4 mock resolver listeners
	conns := make([]*net.UDPConn, 4)
	resolvers := make([]config.ResolverAddress, 4)
	for i := 0; i < 4; i++ {
		conn, port, _ := startMockMTUDNSListener(t, domain)
		conns[i] = conn
		resolvers[i] = config.ResolverAddress{IP: "127.0.0.1", Port: port}
		defer conn.Close()
	}

	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{domain}
	cfg.Resolvers = resolvers
	cfg.RecheckInactiveServersEnabled = false // Disabled: must scan all
	cfg.RX_TX_Workers = 2
	cfg.MTUTestParallelism = 2
	cfg.MinUploadMTU = 100
	cfg.MaxUploadMTU = 200
	cfg.MinDownloadMTU = 200
	cfg.MaxDownloadMTU = 400
	cfg.MTUTestRetries = 1
	cfg.MTUTestTimeout = 1.0

	client := createTestFastStartClient(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.RunInitialMTUTests(ctx)
	if err != nil {
		t.Fatalf("RunInitialMTUTests failed: %v", err)
	}

	activeCount := client.balancer.ActiveCount()
	if activeCount != 4 {
		t.Fatalf("expected all 4 active resolvers when recheck is disabled, got=%d", activeCount)
	}
}

func TestRunInitialMTUTests_FallbackWhenFewerResolversWork(t *testing.T) {
	domain := "v.example.com"

	// 1 working mock resolver + 2 dead ports
	conn, port, _ := startMockMTUDNSListener(t, domain)
	defer conn.Close()

	resolvers := []config.ResolverAddress{
		{IP: "127.0.0.1", Port: port},
		{IP: "127.0.0.1", Port: 59998}, // dead port
		{IP: "127.0.0.1", Port: 59999}, // dead port
	}

	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{domain}
	cfg.Resolvers = resolvers
	cfg.RecheckInactiveServersEnabled = true
	cfg.RX_TX_Workers = 3 // Targets 3, but only 1 will respond
	cfg.MTUTestParallelism = 2
	cfg.MinUploadMTU = 100
	cfg.MaxUploadMTU = 200
	cfg.MinDownloadMTU = 200
	cfg.MaxDownloadMTU = 400
	cfg.MTUTestRetries = 1
	cfg.MTUTestTimeout = 0.1

	client := createTestFastStartClient(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.RunInitialMTUTests(ctx)
	if err != nil {
		t.Fatalf("RunInitialMTUTests should succeed with remaining working resolver, failed: %v", err)
	}

	activeCount := client.balancer.ActiveCount()
	if activeCount != 1 {
		t.Fatalf("expected 1 active resolver, got=%d", activeCount)
	}
}

func startMockMultiDomainMTUDNSListener(t *testing.T, domains []string) (*net.UDPConn, int, *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}

	serverCfg := config.DefaultServerConfig()
	serverCfg.Domain = domains
	serverCfg.MinVPNLabelLength = 3
	serverCfg.DataEncryptionMethod = 0
	serverCodec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("server codec init failed: %v", err)
	}
	server := udpserver.New(serverCfg, nil, serverCodec)

	var queryCount atomic.Int32
	go func() {
		buf := make([]byte, 4096)
		for {
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			queryCount.Add(1)
			query := make([]byte, n)
			copy(query, buf[:n])
			response := server.HandlePacket(query)
			if len(response) > 0 {
				_, _ = conn.WriteToUDP(response, remoteAddr)
			}
		}
	}()

	port := conn.LocalAddr().(*net.UDPAddr).Port
	return conn, port, &queryCount
}

func TestFastStartEarlyExit(t *testing.T) {
	domain := "v.example.com"
	const totalResolvers = 8

	// Start 8 mock resolvers
	resolvers := make([]config.ResolverAddress, totalResolvers)
	for i := 0; i < totalResolvers; i++ {
		conn, port, _ := startMockMTUDNSListener(t, domain)
		resolvers[i] = config.ResolverAddress{IP: "127.0.0.1", Port: port}
		defer conn.Close()
	}

	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{domain}
	cfg.Resolvers = resolvers
	cfg.RecheckInactiveServersEnabled = true
	cfg.RX_TX_Workers = 1      // target is 1 valid resolver
	cfg.MTUTestParallelism = 4 // configured parallelism is 4
	cfg.MinUploadMTU = 100
	cfg.MaxUploadMTU = 200
	cfg.MinDownloadMTU = 200
	cfg.MaxDownloadMTU = 400
	cfg.MTUTestRetries = 1
	cfg.MTUTestTimeout = 1.0

	client := createTestFastStartClient(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.RunInitialMTUTests(ctx)
	if err != nil {
		t.Fatalf("RunInitialMTUTests failed: %v", err)
	}

	activeCount := client.balancer.ActiveCount()
	if activeCount < 1 || activeCount >= totalResolvers {
		t.Fatalf("expected early exit with partial active resolvers (>=1 and <%d), got=%d", totalResolvers, activeCount)
	}
	if client.balancer.TotalCount() != totalResolvers {
		t.Fatalf("expected total %d connections, got=%d", totalResolvers, client.balancer.TotalCount())
	}
}

func TestFastStartUniqueResolvers(t *testing.T) {
	domains := []string{"d1.example.com", "d2.example.com", "d3.example.com"}

	// Start 2 working mock resolvers supporting all domains
	conn1, port1, _ := startMockMultiDomainMTUDNSListener(t, domains)
	defer conn1.Close()
	conn2, port2, _ := startMockMultiDomainMTUDNSListener(t, domains)
	defer conn2.Close()

	resolvers := []config.ResolverAddress{
		{IP: "127.0.0.1", Port: port1},
		{IP: "127.0.0.1", Port: port2},
	}

	cfg := config.DefaultClientConfig()
	cfg.Domains = domains
	cfg.Resolvers = resolvers
	cfg.RecheckInactiveServersEnabled = true
	cfg.RX_TX_Workers = 2 // requires 2 UNIQUE resolvers
	cfg.MTUTestParallelism = 4
	cfg.MinUploadMTU = 100
	cfg.MaxUploadMTU = 200
	cfg.MinDownloadMTU = 200
	cfg.MaxDownloadMTU = 400
	cfg.MTUTestRetries = 1
	cfg.MTUTestTimeout = 1.0

	client := createTestFastStartClient(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.RunInitialMTUTests(ctx)
	if err != nil {
		t.Fatalf("RunInitialMTUTests failed: %v", err)
	}

	// Verify that BOTH unique resolver endpoints are active in balancer
	activeConns := client.balancer.ActiveConnections()
	activeEndpoints := make(map[string]bool)
	for _, conn := range activeConns {
		activeEndpoints[conn.ResolverLabel] = true
	}

	if len(activeEndpoints) < 2 {
		t.Fatalf("expected at least 2 unique resolvers active in balancer, got=%d (activeEndpoints=%+v)", len(activeEndpoints), activeEndpoints)
	}
}

func TestProbeConnectionMTU_ContextCancellation(t *testing.T) {
	blackholeConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer blackholeConn.Close()
	blackholePort := blackholeConn.LocalAddr().(*net.UDPAddr).Port

	cfg := config.DefaultClientConfig()
	domain := "v.example.com"
	cfg.Domains = []string{domain}
	cfg.Resolvers = []config.ResolverAddress{{IP: "127.0.0.1", Port: blackholePort}}
	cfg.MTUTestTimeout = 3.0 // 3 seconds timeout
	cfg.MTUTestRetries = 1

	client := createTestFastStartClient(t, cfg)

	conn := Connection{
		Domain:        domain,
		Resolver:      "127.0.0.1",
		ResolverPort:  blackholePort,
		ResolverLabel: fmt.Sprintf("127.0.0.1:%d", blackholePort),
		Key:           "blackhole",
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(40*time.Millisecond, cancel)

	start := time.Now()
	_, reason := client.probeConnectionMTU(ctx, conn, 200)
	duration := time.Since(start)

	if reason != mtuRejectUpload {
		t.Fatalf("expected probe to reject with mtuRejectUpload on cancellation, got=%v", reason)
	}

	if duration >= 500*time.Millisecond {
		t.Fatalf("probeConnectionMTU blocked for %v (>= 500ms); in-flight socket read was not cancelled immediately on context cancellation", duration)
	}
}

func startMockSelectivelyDroppingMTUDNSListener(t *testing.T, domain string, maxResponsesBeforeDrop int) (*net.UDPConn, int, *atomic.Int32) {
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

	var queryCount atomic.Int32
	go func() {
		buf := make([]byte, 4096)
		for {
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			count := queryCount.Add(1)
			if maxResponsesBeforeDrop >= 0 && int(count) > maxResponsesBeforeDrop {
				// Drop packet: simulate loss / failure during micro-burst
				continue
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
	return conn, port, &queryCount
}

func TestRunInitialMTUTests_BurstRetryScanning(t *testing.T) {
	domain := "v.example.com"

	// 4 mock resolvers:
	// Resolvers 0 & 1 will answer initial MTU probes (2 queries), but drop burst queries
	conn0, port0, _ := startMockSelectivelyDroppingMTUDNSListener(t, domain, 2)
	defer conn0.Close()
	conn1, port1, _ := startMockSelectivelyDroppingMTUDNSListener(t, domain, 2)
	defer conn1.Close()

	// Resolvers 2 & 3 are healthy and answer all MTU and burst queries
	conn2, port2, _ := startMockSelectivelyDroppingMTUDNSListener(t, domain, -1)
	defer conn2.Close()
	conn3, port3, _ := startMockSelectivelyDroppingMTUDNSListener(t, domain, -1)
	defer conn3.Close()

	resolvers := []config.ResolverAddress{
		{IP: "127.0.0.1", Port: port0},
		{IP: "127.0.0.1", Port: port1},
		{IP: "127.0.0.1", Port: port2},
		{IP: "127.0.0.1", Port: port3},
	}

	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{domain}
	cfg.Resolvers = resolvers
	cfg.RecheckInactiveServersEnabled = true // FastStart mode
	cfg.MicroBurstTestEnabled = true         // Micro-burst qualification enabled
	cfg.MicroBurstPacketCount = 6
	cfg.RX_TX_Workers = 2 // Target is 2 burst-qualified resolvers
	cfg.MTUTestParallelism = 2
	cfg.MinUploadMTU = 100
	cfg.MaxUploadMTU = 100 // Single query upload MTU probe
	cfg.MinDownloadMTU = 300
	cfg.MaxDownloadMTU = 300 // Single query download MTU probe
	cfg.MTUTestRetries = 1
	cfg.MTUTestTimeout = 0.5

	client := createTestFastStartClient(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.RunInitialMTUTests(ctx)
	if err != nil {
		t.Fatalf("RunInitialMTUTests failed despite healthy unscanned candidates available: %v", err)
	}

	activeCount := client.balancer.ActiveCount()
	if activeCount != 2 {
		t.Fatalf("expected 2 active resolvers after burst retry scanning, got=%d", activeCount)
	}

	// Verify that the active resolvers in balancer are indeed Resolvers 2 & 3 (port2 and port3)
	activeConns := client.balancer.ActiveConnections()
	labelMap := make(map[string]bool)
	for _, c := range activeConns {
		labelMap[c.ResolverLabel] = true
	}

	expectedLabel2 := fmt.Sprintf("127.0.0.1:%d", port2)
	expectedLabel3 := fmt.Sprintf("127.0.0.1:%d", port3)
	if !labelMap[expectedLabel2] || !labelMap[expectedLabel3] {
		t.Fatalf("expected healthy resolvers %s and %s to be active, got active set: %+v",
			expectedLabel2, expectedLabel3, labelMap)
	}
}

func TestAdversarial_RunInitialMTUTests_Replenishment_2InitialBurstFailures(t *testing.T) {
	t.Parallel()
	domain := "v.example.com"

	// 5 mock resolvers:
	// Resolvers 0 & 1 pass MTU (2 queries) but drop micro-burst packets
	conn0, port0, _ := startMockSelectivelyDroppingMTUDNSListener(t, domain, 2)
	defer conn0.Close()
	conn1, port1, _ := startMockSelectivelyDroppingMTUDNSListener(t, domain, 2)
	defer conn1.Close()

	// Resolvers 2, 3, 4 are healthy and answer all queries
	conn2, port2, _ := startMockSelectivelyDroppingMTUDNSListener(t, domain, -1)
	defer conn2.Close()
	conn3, port3, _ := startMockSelectivelyDroppingMTUDNSListener(t, domain, -1)
	defer conn3.Close()
	conn4, port4, _ := startMockSelectivelyDroppingMTUDNSListener(t, domain, -1)
	defer conn4.Close()

	resolvers := []config.ResolverAddress{
		{IP: "127.0.0.1", Port: port0},
		{IP: "127.0.0.1", Port: port1},
		{IP: "127.0.0.1", Port: port2},
		{IP: "127.0.0.1", Port: port3},
		{IP: "127.0.0.1", Port: port4},
	}

	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{domain}
	cfg.Resolvers = resolvers
	cfg.RecheckInactiveServersEnabled = true
	cfg.MicroBurstTestEnabled = true
	cfg.MicroBurstPacketCount = 6
	cfg.RX_TX_Workers = 2 // targetValidResolvers = 2
	cfg.MTUTestParallelism = 2
	cfg.MinUploadMTU = 100
	cfg.MaxUploadMTU = 100
	cfg.MinDownloadMTU = 300
	cfg.MaxDownloadMTU = 300
	cfg.MTUTestRetries = 1
	cfg.MTUTestTimeout = 0.5

	client := createTestFastStartClient(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := client.RunInitialMTUTests(ctx)
	if err != nil {
		t.Fatalf("RunInitialMTUTests failed: %v", err)
	}

	activeCount := client.balancer.ActiveCount()
	if activeCount != 2 {
		t.Fatalf("expected 2 active resolvers, got=%d", activeCount)
	}

	activeConns := client.balancer.ActiveConnections()
	labelMap := make(map[string]bool)
	for _, c := range activeConns {
		labelMap[c.ResolverLabel] = true
		if c.StandbyEligible {
			t.Fatalf("active connection %s must not be standby eligible", c.Key)
		}
	}

	badLabel0 := fmt.Sprintf("127.0.0.1:%d", port0)
	badLabel1 := fmt.Sprintf("127.0.0.1:%d", port1)
	if labelMap[badLabel0] || labelMap[badLabel1] {
		t.Fatalf("failing resolvers %s or %s were promoted to active", badLabel0, badLabel1)
	}
}

func TestAdversarial_RunInitialMTUTests_ContextCancellationPrompt(t *testing.T) {
	blackholeConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer blackholeConn.Close()
	blackholePort := blackholeConn.LocalAddr().(*net.UDPAddr).Port

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
	cfg.RecheckInactiveServersEnabled = true
	cfg.MicroBurstTestEnabled = true
	cfg.MTUTestTimeout = 3.0
	cfg.MTUTestRetries = 1

	client := createTestFastStartClient(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	start := time.Now()
	_ = client.RunInitialMTUTests(ctx)
	duration := time.Since(start)

	if duration >= 2*time.Second {
		t.Fatalf("RunInitialMTUTests took %v to return after context cancellation (expected < 2s)", duration)
	}
}

func TestRecheckInactiveResolver_RevokesStandbyEligibilityOnFailure(t *testing.T) {
	domain := "v.example.com"
	conn, port, _ := startMockMTUDNSListener(t, domain)
	// Immediately close the mock listener so any probe will fail
	conn.Close()

	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{domain}
	cfg.Resolvers = []config.ResolverAddress{{IP: "127.0.0.1", Port: port}}
	cfg.MTUTestTimeout = 0.2
	cfg.MTUTestRetries = 1

	client := createTestFastStartClient(t, cfg)
	conns := client.balancer.AllConnections()
	if len(conns) == 0 {
		t.Fatal("expected at least 1 connection")
	}

	targetConn := conns[0]
	// Explicitly mark standby eligible while inactive
	client.balancer.SetConnectionValidity(targetConn.Key, false)
	client.balancer.SetConnectionStandbyEligible(targetConn.Key, true)
	if !client.balancer.IsConnectionStandbyEligible(targetConn.Key) {
		t.Fatal("expected targetConn to be standby eligible initially")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client.recheckInactiveResolver(ctx, targetConn)

	if client.balancer.IsConnectionStandbyEligible(targetConn.Key) {
		t.Fatal("expected standby eligibility to be revoked after failed health probe")
	}
	connAfter, ok := client.balancer.GetConnectionByKey(targetConn.Key)
	if !ok || connAfter.IsValid {
		t.Fatal("expected failed resolver to remain inactive")
	}
}
