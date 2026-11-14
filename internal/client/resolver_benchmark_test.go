// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"bufio"
	"context"
	"flag"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/security"
)

var (
	benchResolversFile = flag.String("resolvers", "", "Path to resolvers list for real-network benchmark")
	benchDomain        = flag.String("domain", "", "Tunnel domain for real-network benchmark")
)

// TestBenchmark_RealNetwork_FastStart implements the opt-in real-network benchmark
// documented in docs/resolver-manager.md. When the -resolvers and -domain flags
// (or MDNS_BENCHMARK_RESOLVERS/MDNS_BENCHMARK_DOMAIN env vars) are provided, it profiles:
//   - T_ready: Time elapsed until Session initialization begins (MinReady met)
//   - T_coverage: Time elapsed until 100% of configured pairings receive qualification
// This probe-only benchmark does not measure foreground application throughput.
func TestBenchmark_RealNetwork_FastStart(t *testing.T) {
	resolversPath := *benchResolversFile
	domain := *benchDomain

	if resolversPath == "" {
		resolversPath = os.Getenv("MDNS_BENCHMARK_RESOLVERS")
	}
	if domain == "" {
		domain = os.Getenv("MDNS_BENCHMARK_DOMAIN")
	}

	if resolversPath == "" || domain == "" {
		t.Skip("skipping real-network benchmark: provide -args -resolvers=<file> -domain=<domain> or MDNS_BENCHMARK_RESOLVERS/MDNS_BENCHMARK_DOMAIN env vars")
	}

	file, err := os.Open(resolversPath)
	if err != nil {
		t.Fatalf("failed to open resolvers file %q: %v", resolversPath, err)
	}
	defer file.Close()

	var resolvers []config.ResolverAddress
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host, portStr, err := net.SplitHostPort(line)
		port := 53
		if err == nil {
			if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
				port = p
			}
		} else {
			host = line
		}
		resolvers = append(resolvers, config.ResolverAddress{IP: host, Port: port})
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("failed scanning resolvers file: %v", err)
	}
	if len(resolvers) == 0 {
		t.Fatalf("resolvers file %q contained zero valid entries", resolversPath)
	}

	t.Logf("Running real-network benchmark with %d resolvers against domain %q", len(resolvers), domain)

	cfg := config.DefaultClientConfig()
	cfg.Domains = []string{domain}
	cfg.Resolvers = resolvers
	cfg.RecheckInactiveServersEnabled = true
	cfg.RX_TX_Workers = 2
	cfg.MTUTestParallelism = 4
	cfg.AutoSaveRankedResolvers = false

	codec, err := security.NewCodec(cfg.DataEncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		t.Fatalf("client codec init failed: %v", err)
	}
	client := New(cfg, nil, codec)
	defer client.Close()
	if err := client.BuildConnectionMap(); err != nil {
		t.Fatalf("BuildConnectionMap failed: %v", err)
	}

	// Profile Phase 1: Fast Start (T_ready)
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = client.RunInitialMTUTests(ctx)
	tReady := time.Since(start)
	if err != nil {
		t.Fatalf("RunInitialMTUTests failed: %v", err)
	}

	// Profile Phase 2: Full Coverage (T_coverage)
	pool := client.balancer.Pool()
	coverageStart := time.Now()
	coverageCtx, coverageCancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer coverageCancel()
	healthDone := make(chan struct{})
	go func() { defer close(healthDone); client.runResolverHealthLoop(coverageCtx) }()
	defer func() { coverageCancel(); <-healthDone }()

	for !pool.IsFirstPassComplete() && coverageCtx.Err() == nil {
		time.Sleep(100 * time.Millisecond)
	}
	tCoverage := time.Since(coverageStart)
	if !pool.IsFirstPassComplete() {
		t.Fatal("background initial coverage did not complete before deadline")
	}

	stats := pool.CoverageStats()
	t.Logf("=== Real-Network Benchmark Results ===")
	t.Logf("T_ready:           %v (Active paths: %d)", tReady, pool.ActiveCount())
	t.Logf("T_coverage:        %v (First pass complete: %v)", tCoverage, stats.IsFirstPassComplete)
	t.Logf("Total Configured:  %d", stats.ConfiguredPaths)
	t.Logf("Initial Completed: %d", stats.CompletedInitialAttempts)
	t.Logf("Remaining Untested:%d", stats.RemainingUntested)
	t.Logf("Distinct Qualified:%d", stats.DistinctQualified)
}
