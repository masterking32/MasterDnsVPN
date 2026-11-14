// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"encoding/binary"
	"fmt"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
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

	// Burst throughput comparison with identical RTT and loss
	fastBurstResult := BurstProbeResult{
		Qualified:           true,
		SentCount:           6,
		ReceivedCount:       6,
		LossRatio:           0.0,
		BurstThroughputKBps: 500.0,
		AverageRTT:          30 * time.Millisecond,
	}
	slowBurstResult := BurstProbeResult{
		Qualified:           true,
		SentCount:           6,
		ReceivedCount:       6,
		LossRatio:           0.0,
		BurstThroughputKBps: 50.0,
		AverageRTT:          30 * time.Millisecond,
	}
	if calculateBurstScore(fastBurstResult) <= calculateBurstScore(slowBurstResult) {
		t.Fatalf("expected higher burst throughput to yield higher score")
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
	cfg.AutoSaveRankedResolvers = false
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

	transport, err := c.newUDPQueryTransport(context.Background(), addr)
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

// A receiver deadline can interrupt the paced sender even when no background
// token was needed. Partial samples must not qualify the configured burst.
func TestSendPipelinedMicroBurstRejectsPartialTrain(t *testing.T) {
	for _, background := range []bool{false, true} {
		t.Run(fmt.Sprintf("background=%t", background), func(t *testing.T) {
			mockConn, addr := startMockBurstServer(t, "example.com", 0, 0)
			defer mockConn.Close()
			cfg := config.DefaultClientConfig()
			cfg.Domains = []string{"example.com"}
			cfg.DataEncryptionMethod = 0
			cfg.AutoSaveRankedResolvers = false
			// Isolate completeness from the loss threshold: any received sample
			// would qualify without the full-train guard.
			cfg.MaxBurstLossRatio = 1
			codec, err := security.NewCodec(0, "")
			if err != nil {
				t.Fatal(err)
			}
			c := New(cfg, nil, codec)
			defer c.Close()
			conn := Connection{Domain: "example.com", ResolverLabel: addr, Key: addr + "#example.com"}
			transport, err := c.newUDPQueryTransport(context.Background(), addr)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.conn.Close()
			var limiter *BackgroundQueryLimiter
			if background {
				limiter = NewBackgroundQueryLimiter(10000, 32)
			}
			// Sending 32 queries with 2 ms spacing requires at least 62 ms.
			result := c.sendPipelinedMicroBurst(context.Background(), conn, transport, 32, 500, 100, 20*time.Millisecond, limiter)
			if result.SentCount >= 32 || result.ReceivedCount == 0 {
				t.Fatalf("expected responses from a partial train: %+v", result)
			}
			if result.Qualified || result.RateLimited || result.Incomplete {
				t.Fatalf("partial unthrottled train must be rejected, not retried as a budget interruption: %+v", result)
			}
			if result.RejectReason != "burst interrupted before all queries were sent" {
				t.Fatalf("unexpected rejection reason: %s", result.RejectReason)
			}
		})
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
	cfg.AutoSaveRankedResolvers = false
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

	transport, err := c.newUDPQueryTransport(context.Background(), addr)
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

func TestDiscoveryEngine_UDPQualificationRankingAndSelection(t *testing.T) {
	// Exercise the production qualification implementation with real UDP probes.
	// Keep MTU discovery outside this fixture: its drop counter measures burst queries.
	newEngine := func(c *Client) *DiscoveryEngine {
		c.pool.SetOnPoolChanged(nil)
		c.pool.SetSessionMTU(c.syncedUploadMTU, c.syncedDownloadMTU)
		return NewDiscoveryEngine(DiscoveryConfig{
			MicroBurstParallelism: c.cfg.MicroBurstParallelism,
			MicroBurstPacketCount: c.cfg.MicroBurstPacketCount,
			MicroBurstTimeout:     250 * time.Millisecond,
			MaxActiveResolvers:    c.cfg.MaxActiveResolvers,
		}, NewUDPResolverProber(c), c.pool, nil)
	}
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
	cfg.AutoSaveRankedResolvers = false
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

	ranked := newEngine(c).runMicroBurstQualification(context.Background(), checkingCandidatesForTest(c.pool, conns, c.syncedUploadMTU, c.syncedDownloadMTU))

	activeConns := c.pool.ActiveResolvers()
	if len(activeConns) != 2 {
		t.Fatalf("expected 2 active connections, got %d", len(activeConns))
	}
	if len(ranked) != 3 {
		t.Fatalf("expected 3 ranked results, got %d", len(ranked))
	}

	activeKeys := make(map[string]bool, len(activeConns))
	for _, conn := range activeConns {
		activeKeys[conn.Key] = true
	}
	if !activeKeys[conns[0].Key] || !activeKeys[conns[1].Key] {
		t.Fatalf("expected healthy servers r1 and r2 in the active pool, got %+v", activeConns)
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

	// One lost response out of six is allowed at 20%, but not at zero loss.
	// Fresh listeners ensure previous bursts cannot exhaust the drop counter.
	t.Run("LossThreshold", func(t *testing.T) {
		for _, maxLoss := range []float64{0.20, 0.0} {
			t.Run(fmt.Sprintf("max-loss-%.2f", maxLoss), func(t *testing.T) {
				server, addr := startMockBurstServer(t, "example.com", 5, 0)
				defer server.Close()
				lossCfg := cfg
				lossCfg.MaxBurstLossRatio = maxLoss
				lossCfg.MinBurstThroughputKBps = 0
				lossCfg.MicroBurstPacketCount = 6
				client := New(lossCfg, nil, codec)
				client.syncedDownloadMTU, client.syncedUploadMTU = 400, 100
				candidate := Connection{Key: "partial-loss", Domain: "example.com", ResolverLabel: addr}
				client.balancer.SetConnections([]*Connection{&candidate})
				ranked := newEngine(client).runMicroBurstQualification(context.Background(), checkingCandidatesForTest(client.pool, []Connection{candidate}, client.syncedUploadMTU, client.syncedDownloadMTU))
				if len(ranked) != 1 || ranked[0].BurstResult.ReceivedCount != 5 {
					t.Fatalf("expected exactly five of six responses: %+v", ranked)
				}
				active := client.pool.ActiveResolvers()
				wantQualified := maxLoss > 0
				if ranked[0].BurstResult.Qualified != wantQualified || (len(active) == 1) != wantQualified {
					t.Fatalf("loss threshold %.2f: result=%+v active=%d", maxLoss, ranked[0].BurstResult, len(active))
				}
			})
		}
	})

	// Subtest 2: Fallback Elimination when zero candidates qualify
	t.Run("FallbackEliminationOnZeroQualified", func(t *testing.T) {
		cfgStrict := cfg
		// Set impossibly high min throughput requirement so none qualify
		cfgStrict.MinBurstThroughputKBps = 100000.0
		cStrict := New(cfgStrict, nil, codec)
		cStrict.syncedDownloadMTU = 400
		cStrict.syncedUploadMTU = 100
		cStrict.balancer.SetConnections(ptrs)

		newEngine(cStrict).runMicroBurstQualification(context.Background(), checkingCandidatesForTest(cStrict.pool, conns, cStrict.syncedUploadMTU, cStrict.syncedDownloadMTU))
		activeStrict := cStrict.pool.ActiveResolvers()
		if len(activeStrict) != 0 {
			t.Fatalf("expected 0 active connections when none qualify, got %d", len(activeStrict))
		}
	})
}

func TestSendPipelinedMicroBurstDeterministicTimestampPairing(t *testing.T) {
	// Start mock UDP server that echoes packets
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer serverConn.Close()

	addr := serverConn.LocalAddr().String()
	serverCfg := config.DefaultServerConfig()
	serverCfg.Domain = []string{"example.com"}
	serverCodec, _ := security.NewCodec(0, "")
	server := udpserver.New(serverCfg, nil, serverCodec)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, remoteAddr, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			query := make([]byte, n)
			copy(query, buf[:n])
			response := server.HandlePacket(query)
			if len(response) > 0 {
				_, _ = serverConn.WriteToUDP(response, remoteAddr)
			}
		}
	}()

	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{"example.com"}
	cfg.AutoSaveRankedResolvers = false
	codec, _ := security.NewCodec(0, "")
	c := New(cfg, nil, codec)

	conn := Connection{
		Domain:        "example.com",
		Resolver:      "127.0.0.1",
		ResolverLabel: addr,
		Key:           "127.0.0.1|53|example.com",
	}

	transport, err := c.newUDPQueryTransport(context.Background(), addr)
	if err != nil {
		t.Fatalf("newUDPQueryTransport failed: %v", err)
	}
	defer transport.conn.Close()

	// 8 packets spaced across 14ms (2ms sleep * 7).
	// Under deterministic pairing, MinRTT and MaxRTT reflect actual RTT rather than inflated drift.
	result := c.sendPipelinedMicroBurst(
		context.Background(),
		conn,
		transport,
		8,
		500,
		100,
		2*time.Second,
	)

	if !result.Qualified {
		t.Fatalf("expected micro-burst to qualify, got rejected: %s", result.RejectReason)
	}
	if result.ReceivedCount != 8 {
		t.Fatalf("expected 8 received, got %d", result.ReceivedCount)
	}
	if result.AverageRTT <= 0 {
		t.Fatalf("expected valid positive AverageRTT, got %v", result.AverageRTT)
	}
	if result.BurstThroughputKBps <= 0 {
		t.Fatalf("expected positive BurstThroughputKBps, got %v", result.BurstThroughputKBps)
	}
}

func TestStartupQualificationRejectsMalformedBurst(t *testing.T) {
	for _, mode := range []string{"short", "wrong-declared-size"} {
		t.Run(mode, func(t *testing.T) {
			serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			defer serverConn.Close()
			codec, _ := security.NewCodec(0, "")
			serverCfg := config.DefaultServerConfig()
			serverCfg.Domain = []string{"example.com"}
			serverCfg.DataEncryptionMethod = 0
			server := udpserver.New(serverCfg, nil, codec)
			go func() {
				buf := make([]byte, 4096)
				for {
					n, remote, err := serverConn.ReadFromUDP(buf)
					if err != nil {
						return
					}
					response := server.HandlePacket(buf[:n])
					packet, err := DnsParser.ExtractVPNResponse(response, false)
					if err != nil {
						continue
					}
					if mode == "short" {
						packet.Payload = packet.Payload[:4]
					} else {
						binary.BigEndian.PutUint16(packet.Payload[4:6], 499)
					}
					response, err = DnsParser.BuildVPNResponsePacket(buf[:n], "example.com", packet, false)
					if err == nil {
						_, _ = serverConn.WriteToUDP(response, remote)
					}
				}
			}()
			cfg := config.DefaultClientConfig()
			cfg.DataEncryptionMethod = 0
			cfg.AutoSaveRankedResolvers = false
			c := New(cfg, nil, codec)
			transport, err := c.newUDPQueryTransport(context.Background(), serverConn.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer transport.conn.Close()
			result := c.sendPipelinedMicroBurst(context.Background(), Connection{Domain: "example.com"}, transport, 2, 500, 100, 100*time.Millisecond)
			if result.Qualified || result.ReceivedCount != 0 || result.TotalBytesRx != 0 {
				t.Fatalf("malformed replies counted: %+v", result)
			}
		})
	}
}
