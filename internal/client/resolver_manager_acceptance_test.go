// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/dnsparser"
	"masterdnsvpn-go/internal/domainmatcher"
	"masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	"masterdnsvpn-go/internal/udpserver"
	"masterdnsvpn-go/internal/vpnproto"
)

// A local recursive Resolver proxy forwards to one real authoritative Server.
// Endpoints share Session state while exercising different network behavior.
type acceptanceResolver struct {
	queries    atomic.Int64
	mu         sync.Mutex
	probeTimes []time.Time
	conn       *net.UDPConn
	done       chan struct{}
}

func startAcceptanceResolver(t *testing.T, server string, delay time.Duration, dropEvery int, domains []string) *acceptanceResolver {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	target, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := net.DialUDP("udp4", nil, target)
	if err != nil {
		t.Fatal(err)
	}
	r := &acceptanceResolver{conn: conn, done: make(chan struct{})}
	matcher := domainmatcher.New(domains, 3)
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(r.done)
		query, reply := make([]byte, 4096), make([]byte, 4096)
		for {
			n, peer, err := conn.ReadFromUDP(query)
			if err != nil {
				return
			}
			receivedAt := time.Now()
			count := r.queries.Add(1)
			if parsed, err := dnsparser.ParseDNSRequestLite(query[:n]); err == nil {
				decision := matcher.Match(parsed)
				if decision.Action == domainmatcher.ActionProcess {
					packet, err := vpnproto.ParseInflatedFromLabels(decision.Labels, codec)
					if err == nil && (packet.PacketType == enums.PACKET_MTU_UP_REQ || packet.PacketType == enums.PACKET_MTU_DOWN_REQ) {
						r.mu.Lock()
						r.probeTimes = append(r.probeTimes, receivedAt)
						r.mu.Unlock()
					}
				}
			}
			if dropEvery > 0 && count%int64(dropEvery) == 0 {
				continue
			}
			if delay > 0 {
				time.Sleep(delay)
			}
			upstream.SetDeadline(time.Now().Add(300 * time.Millisecond))
			if _, err := upstream.Write(query[:n]); err != nil {
				continue
			}
			n, err = upstream.Read(reply)
			if err == nil {
				conn.WriteToUDP(reply[:n], peer)
			}
		}
	}()
	t.Cleanup(func() { conn.Close(); upstream.Close(); <-r.done })
	return r
}

func newAcceptanceClient(t *testing.T, cfg config.ClientConfig) *Client {
	t.Helper()
	codec, err := security.NewCodec(cfg.DataEncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	c := New(cfg, logger.New("acceptance-client", "error"), codec)
	t.Cleanup(c.Close)
	if err := c.BuildConnectionMap(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIntegratedResolverManagerAcceptance(t *testing.T) {
	// Real TCP destination; its bytes must traverse the Client, DNS tunnel and Server.
	destination, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	destinationDone := make(chan struct{})
	go func() {
		defer close(destinationDone)
		for {
			conn, err := destination.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	defer func() { destination.Close(); <-destinationDone }()
	// Reserve a loopback UDP port for the real Server runtime.
	reservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.LocalAddr().(*net.UDPAddr).Port
	reservation.Close()
	domains := []string{"v1.example.com", "v2.example.com"}
	serverCfg := config.DefaultServerConfig()
	serverCfg.UDPHost, serverCfg.UDPPort = "127.0.0.1", port
	serverCfg.UDPReaders, serverCfg.DNSRequestWorkers = 1, 2
	serverCfg.ProtocolType, serverCfg.ForwardIP = "TCP", "127.0.0.1"
	serverCfg.ForwardPort = destination.Addr().(*net.TCPAddr).Port
	serverCfg.Domain, serverCfg.DataEncryptionMethod = domains, 0
	serverCfg.MinVPNLabelLength = 3
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatal(err)
	}
	server := udpserver.New(serverCfg, logger.New("acceptance-server", "error"), codec)
	serverCtx, stopServer := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(serverCtx) }()
	defer func() {
		stopServer()
		if err := <-serverDone; err != nil && !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	}()

	serverAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	resolvers := []*acceptanceResolver{
		startAcceptanceResolver(t, serverAddr, 0, 0, domains),
		startAcceptanceResolver(t, serverAddr, time.Millisecond, 0, domains),
		startAcceptanceResolver(t, serverAddr, 0, 2, domains),
		startAcceptanceResolver(t, serverAddr, 0, 1, domains),
	}
	cfg := config.DefaultClientConfig()
	cfg.ProtocolType, cfg.ListenIP, cfg.ListenPort = "TCP", "127.0.0.1", 0
	cfg.DataEncryptionMethod = 0
	cfg.Domains = domains
	cfg.Resolvers = nil
	var lines strings.Builder
	for _, r := range resolvers {
		port := r.conn.LocalAddr().(*net.UDPAddr).Port
		cfg.Resolvers = append(cfg.Resolvers, config.ResolverAddress{IP: "127.0.0.1", Port: port})
		fmt.Fprintf(&lines, "127.0.0.1:%d\n", port)
	}
	cfg.ResolversFilePath = filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(cfg.ResolversFilePath, []byte(lines.String()), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.AutoSaveRankedResolvers, cfg.RecheckInactiveServersEnabled = true, true
	cfg.RX_TX_Workers, cfg.MTUTestParallelism, cfg.MaxActiveResolvers = 2, 1, 4
	cfg.MinUploadMTU, cfg.MaxUploadMTU = 100, 200
	cfg.MinDownloadMTU, cfg.MaxDownloadMTU = 200, 400
	cfg.MTUTestRetries, cfg.MTUTestTimeout = 2, 0.3
	cfg.AutoDisableTimeoutWindowSeconds = 30
	c := newAcceptanceClient(t, cfg)
	// Count successful production file replacements, not notifications or snapshots.
	c.rankedWriter.Close()
	var rankingWrites atomic.Int64
	c.rankedWriter = newRankedPersistenceWriter(c.rankedWriter.cfg, c.log, c.pool.RankedEndpoints,
		func(path string, ranked []config.ResolverAddress) error {
			if err := config.UpdateResolversFileWithRanked(path, ranked); err != nil {
				return err
			}
			rankingWrites.Add(1)
			return nil
		})
	const backgroundQPS, backgroundBurst = 15, 15
	c.SetBackgroundQueryLimiter(NewBackgroundQueryLimiter(backgroundQPS, backgroundBurst))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	if err := c.RunInitialMTUTests(ctx); err != nil {
		t.Fatal(err)
	}
	ready := time.Since(start)
	if c.pool.IsFirstPassComplete() {
		t.Fatal("readiness waited for full coverage")
	}
	if err := c.InitializeSession(2); err != nil {
		t.Fatal(err)
	}
	if err := c.StartAsyncRuntime(ctx); err != nil {
		t.Fatal(err)
	}
	c.InitVirtualStream0()
	if c.pingManager != nil {
		c.pingManager.Start(ctx)
	}
	defer c.StopAsyncRuntime()
	healthCtx, stopHealth := context.WithCancel(ctx)
	healthDone := make(chan struct{})
	backgroundStart := time.Now()
	replacementsBefore := c.pool.CoverageStats().OptionalReplacements
	go func() { defer close(healthDone); c.runResolverHealthLoop(healthCtx) }()
	defer func() { stopHealth(); <-healthDone }()

	app, err := net.DialTimeout("tcp4", c.tcpListener.listeners[0].Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	app.SetDeadline(time.Now().Add(15 * time.Second))
	payload := bytes.Repeat([]byte("resolver-lifecycle-"), 32)
	reply := make([]byte, len(payload))
	transferred, exchanges := 0, 0
	trafficStart := time.Now()
	var totalLatency time.Duration
	for {
		before := time.Now()
		if _, err := app.Write(payload); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(app, reply); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(reply, payload) {
			t.Fatal("tunneled destination bytes differ")
		}
		transferred += len(payload)
		exchanges++
		totalLatency += time.Since(before)
		if c.pool.ActiveCount() > cfg.MaxActiveResolvers {
			t.Fatal("active capacity exceeded during traffic")
		}
		if c.pool.IsFirstPassComplete() {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("initial coverage stalled during real traffic")
		}
	}
	coverage := time.Since(start)
	t.Logf("local evidence: readiness=%s coverage=%s echoed_bytes=%d round_trips=%d measured_payload_KiBps=%.2f mean_round_trip=%s", ready, coverage, transferred, exchanges, float64(transferred)/1024/time.Since(trafficStart).Seconds(), totalLatency/time.Duration(exchanges))
	if coverage <= ready {
		t.Fatal("coverage must follow readiness")
	}
	stopHealth()
	<-healthDone
	backgroundEnd := time.Now()
	c.StopAsyncRuntime()
	c.Close()
	var backgroundQueries []time.Time
	for _, r := range resolvers {
		r.mu.Lock()
		for _, at := range r.probeTimes {
			if !at.Before(backgroundStart) && !at.After(backgroundEnd) {
				backgroundQueries = append(backgroundQueries, at)
			}
		}
		r.mu.Unlock()
	}
	sort.Slice(backgroundQueries, func(i, j int) bool { return backgroundQueries[i].Before(backgroundQueries[j]) })
	if len(backgroundQueries) == 0 {
		t.Fatal("initial coverage must send background qualification queries during traffic")
	}
	for i, at := range backgroundQueries {
		// On loopback, arrivals cannot precede their budgeted query starts.
		if allowed := float64(backgroundBurst) + backgroundQPS*at.Sub(backgroundStart).Seconds(); float64(i+1) > allowed {
			t.Fatalf("background query budget exceeded: received=%d allowed=%.2f", i+1, allowed)
		}
	}
	replacements := c.pool.CoverageStats().OptionalReplacements - replacementsBefore
	if rankingWrites.Load() == 0 {
		t.Fatal("expected at least one completed ranking-file write")
	}
	bgDuration := backgroundEnd.Sub(backgroundStart).Seconds()
	bgVolume := len(backgroundQueries)
	bgRate := 0.0
	if bgDuration > 0 {
		bgRate = float64(bgVolume) / bgDuration
	}
	fgThroughput := float64(transferred) / 1024 / time.Since(trafficStart).Seconds()
	fgLatency := totalLatency / time.Duration(exchanges)
	t.Logf("lifecycle acceptance metrics: readiness_time=%s initial_coverage_time=%s foreground_throughput=%.2f_KiBps foreground_latency=%s background_query_volume=%d background_query_rate=%.2f_qps optional_replacement_count=%d ranking_file_write_count=%d",
		ready, coverage, fgThroughput, fgLatency, bgVolume, bgRate, replacements, rankingWrites.Load())
	t.Logf("local evidence: background_queries=%d background_queries_per_second=%.2f budget_QPS=%d burst=%d optional_replacements=%d ranking_file_writes=%d", len(backgroundQueries), bgRate, backgroundQPS, backgroundBurst, replacements, rankingWrites.Load())
	saved, err := os.ReadFile(cfg.ResolversFilePath)
	if err != nil || !strings.Contains(string(saved), "AUTO-RANKED") {
		t.Fatalf("ranked ordering not saved: %v\n%s", err, saved)
	}
	// Load the actual persisted hints and prove they authorize no live candidates.
	cfg.Resolvers, _, err = config.LoadClientResolvers(cfg.ResolversFilePath)
	if err != nil {
		t.Fatal(err)
	}
	restarted := newAcceptanceClient(t, cfg)
	if restarted.pool.ActiveCount() != 0 || restarted.pool.CoverageStats().CompletedInitialAttempts != 0 {
		t.Fatal("saved hints bypassed fresh qualification")
	}
	queriesBefore := resolvers[0].queries.Load() + resolvers[1].queries.Load()
	if err := restarted.RunInitialMTUTests(ctx); err != nil {
		t.Fatal(err)
	}
	if restarted.pool.ActiveCount() == 0 || resolvers[0].queries.Load()+resolvers[1].queries.Load() <= queriesBefore {
		t.Fatal("restart did not perform network qualification")
	}
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
