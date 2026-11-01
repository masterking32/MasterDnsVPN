package client

import (
	"bytes"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"masterdnsvpn-go/internal/compression"
	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func TestNextSessionInitAttemptUsesBalancerSnapshotConnection(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "a", "b")
	connections := []*Connection{
		{Key: "a", Domain: "a.example.com", Resolver: "127.0.0.1", ResolverPort: 5300, ResolverLabel: "127.0.0.1:0"},
		{Key: "b", Domain: "b.example.com", Resolver: "127.0.0.1", ResolverPort: 5301, ResolverLabel: "127.0.0.1:1"},
	}
	c.balancer.SetConnections(connections)
	for _, conn := range connections {
		c.balancer.SetConnectionMTU(conn.Key, 120, 180, 220)
		c.balancer.SetConnectionValidity(conn.Key, true)
	}

	originalDomain := connections[0].Domain
	connections[0].Domain = "mutated.example.com"

	conn, _, _, err := c.nextSessionInitAttempt()
	if err != nil {
		t.Fatalf("nextSessionInitAttempt returned error: %v", err)
	}

	if conn.Domain != originalDomain {
		t.Fatalf("expected session init to use balancer snapshot domain %q, got %q", originalDomain, conn.Domain)
	}
}

func TestApplySessionInitPacketAppliesServerClientPolicy(t *testing.T) {
	cfg := config.ClientConfig{
		PacketDuplicationCount:        9,
		SetupPacketDuplicationCount:   12,
		MaxUploadMTU:                  220,
		MaxDownloadMTU:                6000,
		RX_TX_Workers:                 12,
		PingAggressiveIntervalSeconds: 0.01,
		MaxPacketsPerBatch:            20,
		ARQWindowSize:                 9000,
		ARQDataNackMaxGap:             256,
		CompressionMinSize:            10,
		ARQInitialRTOSeconds:          0.01,
		ARQMaxRTOSeconds:              5.0,
		ARQControlInitialRTOSeconds:   0.01,
		ARQControlMaxRTOSeconds:       5.0,
	}

	c := buildTestClientWithResolvers(cfg, "a")
	c.syncedUploadMTU = 200
	c.syncedDownloadMTU = 5000

	verifyCode := [4]byte{1, 2, 3, 4}
	initPayload := make([]byte, sessionInitPayloadSize)
	initPayload[0] = 1

	var payload [VpnProto.SessionAcceptPayloadSize]byte
	payload[0] = 7
	payload[1] = 9
	payload[2] = compression.PackPair(compression.TypeOff, compression.TypeOff)
	copy(payload[3:7], verifyCode[:])
	policy := VpnProto.EncodeSessionAcceptClientPolicy(VpnProto.SessionAcceptClientPolicy{
		MaxPacketDuplicationCount: 5,
		MaxSetupDuplicationCount:  6,
		MaxUploadMTU:              150,
		MaxDownloadMTU:            4000,
		MaxRxTxWorkers:            4,
		MinPingAggressiveInterval: 0.05,
		MaxPacketsPerBatch:        10,
		MaxARQWindowSize:          8000,
		MaxARQDataNackMaxGap:      128,
		MinCompressionMinSize:     120,
		MinARQInitialRTOSeconds:   0.05,
	})
	copy(payload[VpnProto.SessionAcceptBasePayloadSize:], policy[:])

	err := c.applySessionInitPacket(VpnProto.Packet{
		PacketType: Enums.PACKET_SESSION_ACCEPT,
		Payload:    payload[:],
	}, initPayload, verifyCode)
	if err != nil {
		t.Fatalf("applySessionInitPacket returned error: %v", err)
	}

	if !c.sessionReady {
		t.Fatal("expected session to become ready")
	}
	if c.sessionID != 7 || c.sessionCookie != 9 {
		t.Fatalf("unexpected session identity: id=%d cookie=%d", c.sessionID, c.sessionCookie)
	}
	if c.cfg.PacketDuplicationCount != 5 {
		t.Fatalf("unexpected packet duplication clamp: got=%d want=%d", c.cfg.PacketDuplicationCount, 5)
	}
	if c.cfg.SetupPacketDuplicationCount != 6 {
		t.Fatalf("unexpected setup duplication clamp: got=%d want=%d", c.cfg.SetupPacketDuplicationCount, 6)
	}
	if c.cfg.MaxUploadMTU != 150 {
		t.Fatalf("unexpected upload mtu clamp: got=%d want=%d", c.cfg.MaxUploadMTU, 150)
	}
	if c.cfg.MaxDownloadMTU != 4000 {
		t.Fatalf("unexpected download mtu clamp: got=%d want=%d", c.cfg.MaxDownloadMTU, 4000)
	}
	if c.cfg.RX_TX_Workers != 4 || c.tunnelRX_TX_Workers != 4 {
		t.Fatalf("unexpected worker clamp: cfg=%d runtime=%d", c.cfg.RX_TX_Workers, c.tunnelRX_TX_Workers)
	}
	if c.cfg.TunnelProcessWorkers != 5 || c.tunnelProcessWorkers != 5 {
		t.Fatalf("unexpected process worker sync: cfg=%d runtime=%d", c.cfg.TunnelProcessWorkers, c.tunnelProcessWorkers)
	}
	if c.cfg.PingAggressiveIntervalSeconds < 0.049 || c.cfg.PingAggressiveIntervalSeconds > 0.051 {
		t.Fatalf("unexpected ping min clamp: got=%f", c.cfg.PingAggressiveIntervalSeconds)
	}
	if c.cfg.MaxPacketsPerBatch != 10 {
		t.Fatalf("unexpected packets per batch clamp: got=%d want=%d", c.cfg.MaxPacketsPerBatch, 10)
	}
	if c.cfg.ARQWindowSize != 8000 {
		t.Fatalf("unexpected arq window clamp: got=%d want=%d", c.cfg.ARQWindowSize, 8000)
	}
	if c.cfg.ARQDataNackMaxGap != 128 {
		t.Fatalf("unexpected arq data nack clamp: got=%d want=%d", c.cfg.ARQDataNackMaxGap, 128)
	}
	if c.cfg.CompressionMinSize != 120 {
		t.Fatalf("unexpected compression min size clamp: got=%d want=%d", c.cfg.CompressionMinSize, 120)
	}
	if c.cfg.ARQInitialRTOSeconds < 0.049 || c.cfg.ARQInitialRTOSeconds > 0.051 {
		t.Fatalf("unexpected arq initial rto clamp: got=%f", c.cfg.ARQInitialRTOSeconds)
	}
	if c.syncedUploadMTU != 150 || c.syncedDownloadMTU != 4000 {
		t.Fatalf("unexpected synced mtu clamp: up=%d down=%d", c.syncedUploadMTU, c.syncedDownloadMTU)
	}
	if c.safeUploadMTU <= 0 {
		t.Fatalf("expected safe upload mtu to be recomputed, got=%d", c.safeUploadMTU)
	}
	if c.maxPackedBlocks <= 0 {
		t.Fatalf("expected max packed blocks to be recomputed, got=%d", c.maxPackedBlocks)
	}
	if cap(c.plannerQueue) != 96 {
		t.Fatalf("unexpected planner queue capacity: got=%d want=%d", cap(c.plannerQueue), 96)
	}
	if cap(c.encodedTXChannel) != 96 {
		t.Fatalf("unexpected writer queue capacity: got=%d want=%d", cap(c.encodedTXChannel), 96)
	}
	if cap(c.rxChannel) != c.cfg.EffectiveRXChannelSize() {
		t.Fatalf("unexpected rx channel capacity: got=%d want=%d", cap(c.rxChannel), c.cfg.EffectiveRXChannelSize())
	}
	if c.orphanQueue == nil || c.orphanQueue.FastSize() != 0 {
		t.Fatal("expected orphan queue to be rebuilt cleanly")
	}
	if c.dnsResponses == nil {
		t.Fatal("expected dns response fragment store to be rebuilt")
	}
	if !bytes.Equal(payload[3:7], verifyCode[:]) {
		t.Fatal("verify code should remain in legacy position")
	}
}

func TestApplySessionInitPacketAcceptsLegacySessionAcceptPayload(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "a")
	verifyCode := [4]byte{4, 3, 2, 1}
	initPayload := make([]byte, sessionInitPayloadSize)

	payload := make([]byte, VpnProto.SessionAcceptBasePayloadSize)
	payload[0] = 3
	payload[1] = 5
	payload[2] = compression.PackPair(compression.TypeOff, compression.TypeOff)
	copy(payload[3:7], verifyCode[:])

	err := c.applySessionInitPacket(VpnProto.Packet{
		PacketType: Enums.PACKET_SESSION_ACCEPT,
		Payload:    payload,
	}, initPayload, verifyCode)
	if err != nil {
		t.Fatalf("legacy session accept should still work, got error: %v", err)
	}
	if !c.sessionReady {
		t.Fatal("expected legacy session accept to mark session ready")
	}
}

func TestApplySessionInitPacketPreservesHigherTunnelProcessWorkers(t *testing.T) {
	cfg := config.ClientConfig{
		PacketDuplicationCount:        8,
		SetupPacketDuplicationCount:   9,
		MaxUploadMTU:                  220,
		MaxDownloadMTU:                6000,
		RX_TX_Workers:                 16,
		TunnelProcessWorkers:          200,
		PingAggressiveIntervalSeconds: 0.02,
		MaxPacketsPerBatch:            30,
		ARQWindowSize:                 12000,
		ARQDataNackMaxGap:             300,
		CompressionMinSize:            40,
		ARQInitialRTOSeconds:          0.02,
		ARQControlInitialRTOSeconds:   0.02,
		ARQMaxRTOSeconds:              5.0,
		ARQControlMaxRTOSeconds:       3.0,
	}
	c := buildTestClientWithResolvers(cfg, "a")
	c.tunnelRX_TX_Workers = 16
	c.tunnelProcessWorkers = 200

	verifyCode := [4]byte{1, 2, 3, 4}
	var payload [VpnProto.SessionAcceptPayloadSize]byte
	payload[0] = 9
	payload[1] = 8
	payload[2] = compression.PackPair(compression.TypeOff, compression.TypeOff)
	copy(payload[3:7], verifyCode[:])

	policy := VpnProto.EncodeSessionAcceptClientPolicy(VpnProto.SessionAcceptClientPolicy{
		MaxPacketDuplicationCount: 5,
		MaxSetupDuplicationCount:  6,
		MaxUploadMTU:              150,
		MaxDownloadMTU:            4000,
		MaxRxTxWorkers:            4,
		MinPingAggressiveInterval: 0.05,
		MaxPacketsPerBatch:        10,
		MaxARQWindowSize:          8000,
		MaxARQDataNackMaxGap:      128,
		MinCompressionMinSize:     120,
		MinARQInitialRTOSeconds:   0.05,
	})
	copy(payload[VpnProto.SessionAcceptBasePayloadSize:], policy[:])

	packet := VpnProto.Packet{
		PacketType: Enums.PACKET_SESSION_ACCEPT,
		Payload:    payload[:],
	}

	initPayload := make([]byte, sessionInitPayloadSize)
	initPayload[0] = 1

	if err := c.applySessionInitPacket(packet, initPayload, verifyCode); err != nil {
		t.Fatalf("applySessionInitPacket returned error: %v", err)
	}

	if c.cfg.RX_TX_Workers != 4 || c.tunnelRX_TX_Workers != 4 {
		t.Fatalf("unexpected worker clamp: cfg=%d runtime=%d", c.cfg.RX_TX_Workers, c.tunnelRX_TX_Workers)
	}
	if c.cfg.TunnelProcessWorkers != 200 || c.tunnelProcessWorkers != 200 {
		t.Fatalf("higher process workers should be preserved: cfg=%d runtime=%d", c.cfg.TunnelProcessWorkers, c.tunnelProcessWorkers)
	}
}

func sessionInitTestConfig() config.ClientConfig {
	return config.ClientConfig{
		MaxUploadMTU:   150,
		MaxDownloadMTU: 400,
		MTUTestRetries: 2,
		MTUTestTimeout: 1,
	}
}

// listenTestResolver opens a loopback UDP socket for a test to answer from,
// and returns it with a connection that sends to it.
func listenTestResolver(t *testing.T, key string) (*net.UDPConn, *Connection) {
	t.Helper()

	resolver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP resolver failed: %v", err)
	}
	t.Cleanup(func() { _ = resolver.Close() })

	addr := resolver.LocalAddr().(*net.UDPAddr)
	return resolver, &Connection{
		Key:           key,
		Domain:        key + ".example.com",
		Resolver:      addr.IP.String(),
		ResolverPort:  addr.Port,
		ResolverLabel: addr.String(),
	}
}

// newSessionInitTestClient returns a client whose only valid connection sends
// to a loopback resolver socket, and that socket. The inactive connections are
// added to the balancer as well.
func newSessionInitTestClient(t *testing.T, cfg config.ClientConfig, inactive ...*Connection) (*Client, *net.UDPConn) {
	t.Helper()

	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	resolver, conn := listenTestResolver(t, "a")
	c := New(cfg, nil, codec)
	c.balancer.SetConnections(append([]*Connection{conn}, inactive...))
	c.balancer.SetConnectionMTU(conn.Key, 130, 210, 400)
	c.balancer.SetConnectionValidity(conn.Key, true)
	c.syncedUploadMTU = 130
	c.syncedDownloadMTU = 400
	return c, resolver
}

func sessionAcceptTestPayload(verifyCode [4]byte) []byte {
	return VpnProto.EncodeSessionAcceptPayload(VpnProto.SessionAcceptPayload{
		SessionID:       7,
		SessionCookie:   9,
		CompressionPair: compression.PackPair(compression.TypeOff, compression.TypeOff),
		VerifyCode:      verifyCode,
		ClientPolicy: VpnProto.SessionAcceptClientPolicy{
			MaxUploadMTU:   120,
			MaxDownloadMTU: 4000,
		},
		HasClientPolicySync: true,
	})
}

// answerSessionInitQueries answers every query the resolver socket receives
// with a SESSION_ACCEPT for verifyCode, as the server answers each SESSION_INIT
// query that initializeSessionRequest races. It returns the number of queries
// answered so far.
func answerSessionInitQueries(resolver *net.UDPConn, verifyCode [4]byte, base64Reply bool) *atomic.Int32 {
	payload := sessionAcceptTestPayload(verifyCode)
	answered := &atomic.Int32{}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := resolver.ReadFromUDP(buf)
			if err != nil {
				return
			}
			query := append([]byte(nil), buf[:n]...)
			parsed, err := DnsParser.ParsePacket(query)
			if err != nil || len(parsed.Questions) == 0 {
				continue
			}
			response, err := DnsParser.BuildVPNResponsePacket(query, parsed.Questions[0].Name, VpnProto.Packet{
				PacketType: Enums.PACKET_SESSION_ACCEPT,
				Payload:    payload,
			}, base64Reply)
			if err != nil {
				continue
			}
			if _, err := resolver.WriteToUDP(response, addr); err == nil {
				answered.Add(1)
			}
		}
	}()
	return answered
}

func TestInitializeSessionRequestAfterResetReadsRequestedReplyMode(t *testing.T) {
	cfg := sessionInitTestConfig()
	cfg.BaseEncodeData = true
	c, resolver := newSessionInitTestClient(t, cfg)

	// A session reset sets the session's reply mode back to raw.
	c.resetSessionState(true)

	_, initPayload, verifyCode, err := c.nextSessionInitAttempt()
	if err != nil {
		t.Fatalf("nextSessionInitAttempt returned error: %v", err)
	}
	if initPayload[0] != mtuProbeBase64Reply {
		t.Fatalf("expected session init to ask for base64 replies, got mode=%d", initPayload[0])
	}
	answerSessionInitQueries(resolver, verifyCode, true)

	if err := c.initializeSessionRequest(); err != nil {
		t.Fatalf("initializeSessionRequest returned error: %v", err)
	}
	if !c.SessionReady() || c.responseMode != mtuProbeBase64Reply {
		t.Fatalf("unexpected session state: ready=%v mode=%d", c.SessionReady(), c.responseMode)
	}
}

// initializeSessionRequest races three identical SESSION_INIT queries and
// applies the first answer while the other racers still read theirs. Run with
// -race. The race detector keeps only a few recent accesses per memory word,
// so several clients start a session at once for a regression to be reported
// on every run.
func TestInitializeSessionRequestRacersDoNotRaceWithAppliedAnswer(t *testing.T) {
	const clients = 48
	sessions := make([]*Client, 0, clients)
	answered := make([]*atomic.Int32, 0, clients)
	for range clients {
		c, resolver := newSessionInitTestClient(t, sessionInitTestConfig())
		// Build the init payload first so the resolver can answer its verify code.
		_, _, verifyCode, err := c.nextSessionInitAttempt()
		if err != nil {
			t.Fatalf("nextSessionInitAttempt returned error: %v", err)
		}
		sessions = append(sessions, c)
		answered = append(answered, answerSessionInitQueries(resolver, verifyCode, false))
	}

	var wg sync.WaitGroup
	for _, c := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.initializeSessionRequest(); err != nil {
				t.Errorf("initializeSessionRequest returned error: %v", err)
			}
		}()
	}
	wg.Wait()

	// The other racers go on reading their answers after the first is applied.
	waitForResolverHealthCondition(t, 3*time.Second, func() bool {
		for _, count := range answered {
			if count.Load() < 3 {
				return false
			}
		}
		return true
	}, "expected every racing session init query to be answered")
	time.Sleep(50 * time.Millisecond)
}

// A session init racer that starts after the first answer was applied finds
// the resolver pools closed by the client policy sync and sizes a new pool
// from c.cfg, while the sync is still writing c.cfg: an upload MTU under 100
// turns upload compression off there. Run with -race.
func TestLateSessionInitRacerDoesNotRaceWithClientPolicySync(t *testing.T) {
	c, resolver := newSessionInitTestClient(t, sessionInitTestConfig())
	c.syncedUploadMTU = 90

	conn, initPayload, verifyCode, err := c.nextSessionInitAttempt()
	if err != nil {
		t.Fatalf("nextSessionInitAttempt returned error: %v", err)
	}
	answerSessionInitQueries(resolver, verifyCode, false)
	query, err := c.buildSessionQuery(conn.Domain, Enums.PACKET_SESSION_INIT, initPayload)
	if err != nil {
		t.Fatalf("buildSessionQuery returned error: %v", err)
	}

	// The racers that went first left a pool for the resolver.
	udpConn, err := c.getUDPConn(context.Background(), conn.ResolverLabel)
	if err != nil {
		t.Fatalf("getUDPConn returned error: %v", err)
	}
	c.putUDPConn(conn.ResolverLabel, udpConn)
	poolOpen := func() bool {
		c.resolverConnsMu.Lock()
		defer c.resolverConnsMu.Unlock()
		_, ok := c.resolverConns[conn.ResolverLabel]
		return ok
	}

	racerDone := make(chan struct{})
	go func() {
		defer close(racerDone)
		deadline := time.Now().Add(2 * time.Second)
		for poolOpen() {
			if time.Now().After(deadline) {
				t.Error("expected the client policy sync to close the resolver pools")
				return
			}
			time.Sleep(time.Millisecond)
		}
		if _, err := c.exchangeDNSOverConnection(conn, query, false, c.mtuTestTimeout*3); err != nil {
			t.Errorf("late racer exchange returned error: %v", err)
		}
	}()

	err = c.applySessionInitPacket(VpnProto.Packet{
		PacketType: Enums.PACKET_SESSION_ACCEPT,
		Payload:    sessionAcceptTestPayload(verifyCode),
	}, initPayload, verifyCode)
	<-racerDone
	if err != nil {
		t.Fatalf("applySessionInitPacket returned error: %v", err)
	}
	if c.cfg.UploadCompressionType != int(compression.TypeOff) {
		t.Fatalf("expected upload compression off below 100 bytes, got=%d", c.cfg.UploadCompressionType)
	}
}

// Run starts the resolver health loop before it initializes the session, and
// each session init applies the server's client policy, which lowers the
// synced MTUs under initStateMu while the loop rechecks inactive resolvers
// with them. Run with -race.
func TestResolverHealthRecheckDoesNotRaceWithSessionPolicySync(t *testing.T) {
	cfg := sessionInitTestConfig()
	cfg.RecheckInactiveServersEnabled = true
	// An inactive resolver that answers every probe without a tunnel answer,
	// so each recheck attempt fails.
	resolver, inactive := listenTestResolver(t, "b")
	c, _ := newSessionInitTestClient(t, cfg, inactive)

	probes := make(chan struct{}, 2)
	applied := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for answered := 0; ; answered++ {
			n, addr, err := resolver.ReadFromUDP(buf)
			if err != nil {
				return
			}
			select {
			case probes <- struct{}{}:
			default:
			}
			if answered == 0 {
				// Answer the first probe once the policy is applied, so the
				// recheck's next attempt reads the synced MTUs after that.
				select {
				case <-applied:
				case <-time.After(5 * time.Second):
				}
			}
			response, err := DnsParser.BuildEmptyNoErrorResponse(buf[:n])
			if err != nil {
				continue
			}
			_, _ = resolver.WriteToUDP(response, addr)
		}
	}()
	waitForProbe := func(which string) {
		t.Helper()
		select {
		case <-probes:
		case <-time.After(5 * time.Second):
			t.Fatalf("expected the health loop to send its %s recheck probe", which)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		c.runResolverHealthLoop(ctx)
	}()
	defer func() {
		cancel()
		<-loopDone
	}()

	waitForProbe("first")
	_, initPayload, verifyCode, err := c.nextSessionInitAttempt()
	if err != nil {
		t.Fatalf("nextSessionInitAttempt returned error: %v", err)
	}
	err = c.applySessionInitPacket(VpnProto.Packet{
		PacketType: Enums.PACKET_SESSION_ACCEPT,
		Payload:    sessionAcceptTestPayload(verifyCode),
	}, initPayload, verifyCode)
	close(applied)
	if err != nil {
		t.Fatalf("applySessionInitPacket returned error: %v", err)
	}
	waitForProbe("second")
	if c.syncedUploadMTU != 120 {
		t.Fatalf("expected the client policy to lower the synced upload mtu to 120, got=%d", c.syncedUploadMTU)
	}
}
