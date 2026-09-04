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

func TestCalculateBurstScore(t *testing.T) {
	// Unqualified result must return 0
	unqualified := BurstProbeResult{
		Qualified:     false,
		ReceivedCount: 0,
	}
	if score := calculateBurstScore(unqualified); score != 0 {
		t.Fatalf("expected 0 score for unqualified, got %v", score)
	}

	// Fast server (200 KB/s, 0% loss, 20ms RTT)
	fastResult := BurstProbeResult{
		Qualified:      true,
		SentCount:      6,
		ReceivedCount:  6,
		LossRatio:      0.0,
		ThroughputKBps: 200.0,
		AverageRTT:     20 * time.Millisecond,
	}
	fastScore := calculateBurstScore(fastResult)

	// Slower server (50 KB/s, 0% loss, 100ms RTT)
	slowResult := BurstProbeResult{
		Qualified:      true,
		SentCount:      6,
		ReceivedCount:  6,
		LossRatio:      0.0,
		ThroughputKBps: 50.0,
		AverageRTT:     100 * time.Millisecond,
	}
	slowScore := calculateBurstScore(slowResult)

	// Lossy server (200 KB/s, 16.7% loss, 20ms RTT)
	lossyResult := BurstProbeResult{
		Qualified:      true,
		SentCount:      6,
		ReceivedCount:  5,
		LossRatio:      1.0 / 6.0,
		ThroughputKBps: 200.0,
		AverageRTT:     20 * time.Millisecond,
	}
	lossyScore := calculateBurstScore(lossyResult)

	if fastScore <= slowScore {
		t.Fatalf("expected fastScore (%v) > slowScore (%v)", fastScore, slowScore)
	}
	if fastScore <= lossyScore {
		t.Fatalf("expected fastScore (%v) > lossyScore (%v)", fastScore, lossyScore)
	}
}

func startMockBurstServer(t *testing.T, domain string, dropAfter int, delayPerPacket time.Duration) (*net.UDPConn, string) {
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
			if dropAfter > 0 && int(count) > dropAfter {
				// Simulate rate limit drop
				continue
			}

			if delayPerPacket > 0 {
				time.Sleep(delayPerPacket)
			}

			query := make([]byte, n)
			copy(query, buf[:n])
			response := server.HandlePacket(query)
			if len(response) > 0 {
				_, _ = conn.WriteToUDP(response, remoteAddr)
			}
		}
	}()

	addr := fmt.Sprintf("127.0.0.1:%d", conn.LocalAddr().(*net.UDPAddr).Port)
	return conn, addr
}

func TestSendPipelinedMicroBurstSuccess(t *testing.T) {
	mockConn, addr := startMockBurstServer(t, "example.com", 0, 0)
	defer mockConn.Close()

	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{"example.com"}
	cfg.DataEncryptionMethod = 0
	cfg.MaxBurstLossRatio = 0.20
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("security.NewCodec failed: %v", err)
	}
	c := New(cfg, nil, codec)

	conn := Connection{
		Domain:        "example.com",
		Resolver:      "127.0.0.1",
		ResolverLabel: addr,
		Key:           "127.0.0.1|53|example.com",
	}

	transport, err := newUDPQueryTransport(addr)
	if err != nil {
		t.Fatalf("newUDPQueryTransport failed: %v", err)
	}
	defer transport.conn.Close()

	result := c.sendPipelinedMicroBurst(
		context.Background(),
		conn,
		transport,
		6,
		500,
		100,
		2*time.Second,
	)

	if !result.Qualified {
		t.Fatalf("expected micro-burst to qualify, got rejected: %s", result.RejectReason)
	}
	if result.SentCount != 6 {
		t.Fatalf("expected 6 sent, got %d", result.SentCount)
	}
	if result.ReceivedCount != 6 {
		t.Fatalf("expected 6 received, got %d", result.ReceivedCount)
	}
	if result.LossRatio != 0.0 {
		t.Fatalf("expected 0 loss, got %v", result.LossRatio)
	}
	if result.ThroughputKBps <= 0 {
		t.Fatalf("expected positive throughput, got %v", result.ThroughputKBps)
	}
}

func TestSendPipelinedMicroBurstDetectsRateLimiting(t *testing.T) {
	// Drops after 2 queries, so only 2 of 6 arrive
	mockConn, addr := startMockBurstServer(t, "example.com", 2, 0)
	defer mockConn.Close()

	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{"example.com"}
	cfg.DataEncryptionMethod = 0
	cfg.MaxBurstLossRatio = 0.20
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("security.NewCodec failed: %v", err)
	}
	c := New(cfg, nil, codec)

	conn := Connection{
		Domain:        "example.com",
		Resolver:      "127.0.0.1",
		ResolverLabel: addr,
		Key:           "127.0.0.1|53|example.com",
	}

	transport, err := newUDPQueryTransport(addr)
	if err != nil {
		t.Fatalf("newUDPQueryTransport failed: %v", err)
	}
	defer transport.conn.Close()

	result := c.sendPipelinedMicroBurst(
		context.Background(),
		conn,
		transport,
		6,
		500,
		100,
		500*time.Millisecond,
	)

	if result.Qualified {
		t.Fatal("expected micro-burst to fail due to rate limiting drop")
	}
	if result.ReceivedCount != 2 {
		t.Fatalf("expected 2 received, got %d", result.ReceivedCount)
	}
	if result.LossRatio < 0.5 {
		t.Fatalf("expected >=50%% loss ratio, got %v", result.LossRatio)
	}
}

func TestRunMicroBurstQualificationRankingAndSelection(t *testing.T) {
	server1, addr1 := startMockBurstServer(t, "example.com", 0, 0) // fast
	defer server1.Close()
	server2, addr2 := startMockBurstServer(t, "example.com", 0, 10*time.Millisecond) // slower
	defer server2.Close()
	server3, addr3 := startMockBurstServer(t, "example.com", 1, 0) // drops after 1
	defer server3.Close()

	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{"example.com"}
	cfg.DataEncryptionMethod = 0
	cfg.MaxActiveResolvers = 2
	cfg.MicroBurstPacketCount = 4
	cfg.MicroBurstParallelism = 4
	cfg.MaxBurstLossRatio = 0.20

	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("security.NewCodec failed: %v", err)
	}
	c := New(cfg, nil, codec)
	c.syncedDownloadMTU = 400
	c.syncedUploadMTU = 100

	conns := []Connection{
		{
			Domain:        "example.com",
			Resolver:      "127.0.0.1",
			ResolverLabel: addr1,
			Key:           "r1|53|example.com",
		},
		{
			Domain:        "example.com",
			Resolver:      "127.0.0.1",
			ResolverLabel: addr2,
			Key:           "r2|53|example.com",
		},
		{
			Domain:        "example.com",
			Resolver:      "127.0.0.1",
			ResolverLabel: addr3,
			Key:           "r3|53|example.com",
		},
	}

	ptrs := make([]*Connection, len(conns))
	for i := range conns {
		ptrs[i] = &conns[i]
	}
	c.balancer.SetConnections(ptrs)

	activeConns, ranked := c.runMicroBurstQualification(context.Background(), conns)

	if len(activeConns) != 2 {
		t.Fatalf("expected 2 active connections, got %d", len(activeConns))
	}
	if len(ranked) != 3 {
		t.Fatalf("expected 3 ranked results, got %d", len(ranked))
	}

	// Server 3 (lossy) should be ranked last and unqualified
	if ranked[2].Connection.Key != "r3|53|example.com" {
		t.Fatalf("expected lossy server r3 to be ranked last, got %s", ranked[2].Connection.Key)
	}
	if ranked[2].BurstResult.Qualified {
		t.Fatal("expected server r3 to be unqualified")
	}

	// Server 1 should be ranked #1 ahead of Server 2 (which has 10ms artificial delay per packet)
	if ranked[0].Connection.Key != "r1|53|example.com" {
		t.Fatalf("expected server r1 to be ranked #1, got %s", ranked[0].Connection.Key)
	}

	// Verify Balancer active count
	if c.balancer.ActiveCount() != 2 {
		t.Fatalf("expected balancer active count 2, got %d", c.balancer.ActiveCount())
	}
}
