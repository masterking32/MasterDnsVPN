// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
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
	cfg.MinUploadMTU = 100
	cfg.MaxUploadMTU = 200
	cfg.MinDownloadMTU = 200
	cfg.MaxDownloadMTU = 400
	cfg.MTUTestRetries = 1
	cfg.MTUTestTimeout = 1.0

	client := createTestFastStartClient(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
