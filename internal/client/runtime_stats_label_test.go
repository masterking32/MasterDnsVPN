package client

import (
	"os"
	"strings"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
)

func TestRuntimeStatsLabelsSeededSamples(t *testing.T) {
	output, err := os.CreateTemp(t.TempDir(), "stats")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	original := os.Stdout
	os.Stdout = output
	log := logger.New("stats-test", "info")
	os.Stdout = original
	cfg := config.DefaultClientConfig()
	cfg.AutoSaveRankedResolvers = false
	c := New(cfg, log, nil)
	c.balancer.SetConnections([]*Connection{{Key: "resolver", Resolver: "127.0.0.1", ResolverPort: 53, Domain: "example.com"}})
	c.balancer.SeedBurstStats("resolver", 10, 8, 10*time.Millisecond)
	c.balancer.SetConnectionValidity("resolver", true)
	if c.balancer.TotalPacketsSent() != 0 {
		t.Fatal("fixture unexpectedly sent tunnel packets")
	}
	c.DumpRuntimeStats("Test")
	data, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "Total Tunnel Traffic") {
		t.Fatal("seeded samples presented as lifetime traffic")
	}
	if !strings.Contains(text, "Resolver Samples (include probes; decay over time): Sent 10") {
		t.Fatalf("missing sample explanation: %s", text)
	}
}
