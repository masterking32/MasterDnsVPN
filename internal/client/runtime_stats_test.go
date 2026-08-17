// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
)

func TestGetStatsSnapshotAndDump(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{"example.com"}
	cfg.DataEncryptionMethod = 0
	cfg.RuntimeStatsIntervalSeconds = 60.0

	log := logger.New("TestLogger", "DEBUG")
	c := New(cfg, log, nil)

	conns := []Connection{
		{
			Domain:        "example.com",
			Resolver:      "1.1.1.1",
			ResolverLabel: "1.1.1.1:53",
			Key:           "1.1.1.1|53|example.com",
			IsValid:       true,
		},
		{
			Domain:        "example.com",
			Resolver:      "8.8.8.8",
			ResolverLabel: "8.8.8.8:53",
			Key:           "8.8.8.8|53|example.com",
			IsValid:       true,
		},
		{
			Domain:        "example.com",
			Resolver:      "9.9.9.9",
			ResolverLabel: "9.9.9.9:53",
			Key:           "9.9.9.9|53|example.com",
			IsValid:       false,
		},
	}

	ptrs := make([]*Connection, len(conns))
	for i := range conns {
		ptrs[i] = &conns[i]
	}
	c.balancer.SetConnections(ptrs)
	c.balancer.SetConnectionValidity("1.1.1.1|53|example.com", true)
	c.balancer.SetConnectionValidity("8.8.8.8|53|example.com", true)

	// Seed stats
	c.balancer.SeedBurstStats("1.1.1.1|53|example.com", 100, 99, 18*time.Millisecond)
	c.balancer.SeedBurstStats("8.8.8.8|53|example.com", 50, 48, 25*time.Millisecond)
	c.balancer.SeedBurstStats("9.9.9.9|53|example.com", 20, 15, 40*time.Millisecond)

	snapshots := c.balancer.GetStatsSnapshot()
	if len(snapshots) != 3 {
		t.Fatalf("expected 3 snapshots, got %d", len(snapshots))
	}

	// Verify snapshot values for resolver 1
	var snap1 *ResolverStatsSnapshot
	for i := range snapshots {
		if snapshots[i].Connection.Key == "1.1.1.1|53|example.com" {
			snap1 = &snapshots[i]
			break
		}
	}
	if snap1 == nil {
		t.Fatal("expected snapshot for 1.1.1.1")
	}
	if snap1.Sent != 100 || snap1.Acked != 99 || snap1.Lost != 1 {
		t.Fatalf("unexpected stats for snap1: sent=%d acked=%d lost=%d", snap1.Sent, snap1.Acked, snap1.Lost)
	}
	if snap1.AverageRTT < 17*time.Millisecond || snap1.AverageRTT > 19*time.Millisecond {
		t.Fatalf("unexpected avg RTT for snap1: %v", snap1.AverageRTT)
	}
	if !snap1.IsValid {
		t.Fatal("expected snap1 to be valid")
	}

	// Dump stats table to verify no panic
	c.DumpRuntimeStats("Test")

	// Verify calculateTotalSentPackets
	totalSent := c.calculateTotalSentPackets()
	if totalSent != 170 { // 100 + 50 + 20
		t.Fatalf("expected 170 total sent, got %d", totalSent)
	}
}

func TestLogResolverReactivatedFormatting(t *testing.T) {
	cfg := config.DefaultClientConfig()
	log := logger.New("TestLogger", "DEBUG")
	c := New(cfg, log, nil)

	conn := Connection{
		Domain:           "example.com",
		Resolver:         "1.1.1.3",
		ResolverLabel:    "1.1.1.3:53",
		Key:              "1.1.1.3|53|example.com",
		UploadMTUBytes:   120,
		DownloadMTUBytes: 1000,
	}

	burstResult := &BurstProbeResult{
		SentCount:       6,
		ReceivedCount:   6,
		LossRatio:       0.0,
		ThroughputKBps:  195.4,
		AverageRTT:      24 * time.Millisecond,
		Qualified:       true,
	}

	// Test with burstResult
	c.logResolverReactivated(conn, 22*time.Millisecond, burstResult, 6, 350)

	// Test without burstResult
	c.logResolverReactivated(conn, 20*time.Millisecond, nil, 6, 350)
}

func TestRuntimeStatsLoopTerminatesOnContextDone(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.RuntimeStatsIntervalSeconds = 0.05 // 50ms for fast test

	c := New(cfg, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		c.runRuntimeStatsLoop(ctx)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Succeeded
	case <-time.After(1 * time.Second):
		t.Fatal("runRuntimeStatsLoop did not terminate within deadline")
	}
}
