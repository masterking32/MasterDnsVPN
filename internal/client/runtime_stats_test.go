// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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
	cfg.AutoSaveRankedResolvers = false

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

	// Verify TotalPacketsSent monotonic tracking
	if c.balancer.TotalPacketsSent() != 0 {
		t.Fatalf("expected 0 initial TotalPacketsSent, got %d", c.balancer.TotalPacketsSent())
	}
	c.balancer.ReportSend("1.1.1.1|53|example.com")
	c.balancer.ReportSend("8.8.8.8|53|example.com")
	if c.balancer.TotalPacketsSent() != 2 {
		t.Fatalf("expected 2 TotalPacketsSent, got %d", c.balancer.TotalPacketsSent())
	}
}

func TestDumpRuntimeStats_FilterStandbyEligibility(t *testing.T) {
	// Tests active, standby, failed, and rechecking candidates.
	// Only StandbyEligible candidates should enter the STANDBY diagnostics table.
	// Disabled/failed resolvers with historical traffic must NOT appear as STANDBY.
	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{"example.com"}
	cfg.AutoSaveRankedResolvers = false

	output, err := os.CreateTemp(t.TempDir(), "dump_stats")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()

	original := os.Stdout
	os.Stdout = output
	log := logger.New("stats-eligibility-test", "INFO")
	os.Stdout = original

	c := New(cfg, log, nil)

	conns := []Connection{
		{Domain: "example.com", Resolver: "10.0.0.1", ResolverPort: 53, ResolverLabel: "10.0.0.1:53", Key: "active-conn", IsValid: true},
		{Domain: "example.com", Resolver: "10.0.0.2", ResolverPort: 53, ResolverLabel: "10.0.0.2:53", Key: "standby-conn", IsValid: false},
		{Domain: "example.com", Resolver: "10.0.0.3", ResolverPort: 53, ResolverLabel: "10.0.0.3:53", Key: "failed-conn", IsValid: false},
		{Domain: "example.com", Resolver: "10.0.0.4", ResolverPort: 53, ResolverLabel: "10.0.0.4:53", Key: "recheck-conn", IsValid: false},
	}
	ptrs := make([]*Connection, len(conns))
	for i := range conns {
		ptrs[i] = &conns[i]
	}
	c.balancer.SetConnections(ptrs)

	// Set validity & eligibility
	c.balancer.SetConnectionValidity("active-conn", true)
	c.balancer.SetConnectionStandbyEligible("standby-conn", true)
	c.balancer.SetConnectionStandbyEligible("failed-conn", false)
	c.balancer.beginConnectionRecheck("recheck-conn")

	// Historical traffic on all resolvers
	c.balancer.SeedBurstStats("active-conn", 100, 100, 10*time.Millisecond)
	c.balancer.SeedBurstStats("standby-conn", 40, 40, 15*time.Millisecond)
	c.balancer.SeedBurstStats("failed-conn", 80, 20, 80*time.Millisecond)
	c.balancer.SeedBurstStats("recheck-conn", 30, 30, 25*time.Millisecond)

	snapshots := c.balancer.GetStatsSnapshot()
	if len(snapshots) != 4 {
		t.Fatalf("expected 4 snapshots, got %d", len(snapshots))
	}
	for _, s := range snapshots {
		switch s.Connection.Key {
		case "active-conn":
			if !s.IsValid || s.StandbyEligible {
				t.Fatalf("unexpected state for active-conn: valid=%v standby=%v", s.IsValid, s.StandbyEligible)
			}
		case "standby-conn":
			if s.IsValid || !s.StandbyEligible {
				t.Fatalf("unexpected state for standby-conn: valid=%v standby=%v", s.IsValid, s.StandbyEligible)
			}
		case "failed-conn":
			if s.IsValid || s.StandbyEligible {
				t.Fatalf("unexpected state for failed-conn: valid=%v standby=%v", s.IsValid, s.StandbyEligible)
			}
		case "recheck-conn":
			if s.IsValid || s.StandbyEligible {
				t.Fatalf("unexpected state for recheck-conn: valid=%v standby=%v", s.IsValid, s.StandbyEligible)
			}
		}
	}

	os.Stdout = output
	c.DumpRuntimeStats("EligibilityCheck")
	os.Stdout = original

	data, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	outputStr := string(data)

	// 10.0.0.1:53 should appear as ACTIVE
	if !strings.Contains(outputStr, "10.0.0.1:53") || !strings.Contains(outputStr, "ACTIVE") {
		t.Fatalf("expected active resolver 10.0.0.1:53 in active table, got:\n%s", outputStr)
	}

	// 10.0.0.2:53 should appear as STANDBY
	if !strings.Contains(outputStr, "10.0.0.2:53") || !strings.Contains(outputStr, "STANDBY") {
		t.Fatalf("expected eligible standby resolver 10.0.0.2:53 in standby table, got:\n%s", outputStr)
	}

	// 10.0.0.3:53 (failed) has historical traffic, but should NOT appear as STANDBY
	if strings.Contains(outputStr, "10.0.0.3:53") {
		t.Fatalf("failed resolver 10.0.0.3:53 unexpectedly appeared in standby table:\n%s", outputStr)
	}

	// 10.0.0.4:53 (rechecking) has historical traffic, but should NOT appear as STANDBY
	if strings.Contains(outputStr, "10.0.0.4:53") {
		t.Fatalf("rechecking resolver 10.0.0.4:53 unexpectedly appeared in standby table:\n%s", outputStr)
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
		SentCount:      6,
		ReceivedCount:  6,
		LossRatio:      0.0,
		ThroughputKBps: 195.4,
		AverageRTT:     24 * time.Millisecond,
		Qualified:      true,
	}

	// Test with burstResult
	c.logResolverReactivated(conn, 22*time.Millisecond, burstResult, 6, 350)

	// Test without burstResult
	c.logResolverReactivated(conn, 20*time.Millisecond, nil, 6, 350)
}

func TestRuntimeStatsLoopTerminatesOnContextDone(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.RuntimeStatsIntervalSeconds = 60.0

	c := New(cfg, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		c.runRuntimeStatsLoop(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// Succeeded
	case <-time.After(1 * time.Second):
		t.Fatal("runRuntimeStatsLoop did not terminate within deadline")
	}
}

func TestClientSaveRankedResolversToFile(t *testing.T) {
	dir := t.TempDir()
	resolversPath := filepath.Join(dir, "client_resolvers.txt")
	_ = os.WriteFile(resolversPath, []byte("# User custom\n10.0.0.1\n1.1.1.1\n8.8.8.8\n"), 0o644)

	cfg := config.DefaultClientConfig()
	cfg.ResolversFilePath = resolversPath
	cfg.AutoSaveRankedResolvers = true
	cfg.MaxActiveResolvers = 2

	c := New(cfg, nil, nil)
	conns := []*Connection{
		{Key: "1.1.1.1|53|example.com", Resolver: "1.1.1.1", ResolverPort: 53, Domain: "example.com", UploadMTUBytes: 120, DownloadMTUBytes: 1500},
		{Key: "8.8.8.8|53|example.com", Resolver: "8.8.8.8", ResolverPort: 53, Domain: "example.com", UploadMTUBytes: 120, DownloadMTUBytes: 1500},
	}
	c.balancer.SetConnections(conns)
	c.balancer.SeedBurstStats("1.1.1.1|53|example.com", 20, 20, 15*time.Millisecond)
	c.balancer.SetConnectionValidity("1.1.1.1|53|example.com", true)
	c.balancer.SeedBurstStats("8.8.8.8|53|example.com", 20, 20, 30*time.Millisecond)
	c.balancer.SetConnectionValidity("8.8.8.8|53|example.com", true)

	c.SaveRankedResolversToFile()

	data, err := os.ReadFile(resolversPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	content := string(data)
	if len(content) == 0 {
		t.Fatal("expected content in resolvers file")
	}

	// Verify header marker and preserved user line
	if !strings.Contains(content, config.AutoRankedHeaderMarker) {
		t.Fatalf("unexpected content, missing header marker: %s", content)
	}

	loaded, _, err := config.LoadClientResolvers(resolversPath)
	if err != nil {
		t.Fatalf("LoadClientResolvers failed: %v", err)
	}

	if len(loaded) < 2 {
		t.Fatalf("expected at least 2 loaded resolvers, got %d", len(loaded))
	}
	if loaded[0].IP != "1.1.1.1" {
		t.Errorf("expected 1.1.1.1 to be top ranked, got %s", loaded[0].IP)
	}
	if loaded[1].IP != "8.8.8.8" {
		t.Errorf("expected 8.8.8.8 to be second, got %s", loaded[1].IP)
	}
}

func TestRuntimeStatsLoopDisabled(t *testing.T) {
	cfg := config.DefaultClientConfig()
	cfg.RuntimeStatsIntervalSeconds = 0
	c := New(cfg, nil, nil)
	done := make(chan struct{})
	go func() {
		c.runRuntimeStatsLoop(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("disabled statistics loop did not exit")
	}
}
