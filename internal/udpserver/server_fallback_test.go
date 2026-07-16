package udpserver

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
)

const fallbackIntegrationTimeout = 2 * time.Second

func TestFallbackTargetsListener(t *testing.T) {
	tests := []struct {
		name     string
		listener *net.UDPAddr
		target   *net.UDPAddr
		want     bool
	}{
		{
			name:     "exact listener",
			listener: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53},
			target:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53},
			want:     true,
		},
		{
			name:     "wildcard covers loopback",
			listener: &net.UDPAddr{IP: net.IPv4zero, Port: 53},
			target:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53},
			want:     true,
		},
		{
			name:     "unspecified target reaches specific listener",
			listener: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53},
			target:   &net.UDPAddr{IP: net.IPv4zero, Port: 53},
			want:     true,
		},
		{
			name:     "different port",
			listener: &net.UDPAddr{IP: net.IPv4zero, Port: 53},
			target:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353},
		},
		{
			name:     "specific listener does not cover other address",
			listener: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53},
			target:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53},
		},
		{
			name:     "IPv4 wildcard does not cover IPv6",
			listener: &net.UDPAddr{IP: net.IPv4zero, Port: 53},
			target:   &net.UDPAddr{IP: net.IPv6loopback, Port: 53},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fallbackTargetsListener(tt.listener, tt.target); got != tt.want {
				t.Fatalf("fallbackTargetsListener()=%t want=%t", got, tt.want)
			}
		})
	}
}

func TestNewFallbackServerUsesFullUDPPacketBuffer(t *testing.T) {
	server := New(config.ServerConfig{
		FallbackAddress: "127.0.0.1:5353",
		MaxPacketSize:   512,
	}, nil, nil)
	buffer := server.packetPool.Get().([]byte)
	if len(buffer) != udpFallbackMaxUDPPacketSize {
		t.Fatalf("unexpected fallback packet buffer: got=%d want=%d", len(buffer), udpFallbackMaxUDPPacketSize)
	}
}

type fallbackIntegrationEcho struct {
	conn     *net.UDPConn
	received chan []byte
	done     chan struct{}
}

func startFallbackIntegrationEcho(t *testing.T) *fallbackIntegrationEcho {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP fallback echo failed: %v", err)
	}

	echo := &fallbackIntegrationEcho{
		conn:     conn,
		received: make(chan []byte, 32),
		done:     make(chan struct{}),
	}
	go func() {
		defer close(echo.done)
		buffer := make([]byte, 65535)
		for {
			n, peer, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}

			packet := append([]byte(nil), buffer[:n]...)
			echo.received <- packet
			if _, err := conn.WriteToUDP(packet, peer); err != nil {
				return
			}
		}
	}()

	return echo
}

func (e *fallbackIntegrationEcho) Close(t *testing.T) {
	t.Helper()

	_ = e.conn.Close()
	select {
	case <-e.done:
	case <-time.After(fallbackIntegrationTimeout):
		t.Error("fallback echo goroutine did not stop")
	}
}

func startFallbackIntegrationRuntime(t *testing.T, server *Server, workerConn *net.UDPConn, readerConn *net.UDPConn) {
	t.Helper()
	if server.packetPool.New == nil {
		server.packetPool.New = func() any {
			return make([]byte, udpFallbackMaxUDPPacketSize)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	requests := make(chan request, 4)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		server.dnsWorker(ctx, workerConn, requests, 1)
	}()
	readerDone := make(chan error, 1)
	go func() {
		readerDone <- server.readLoop(ctx, readerConn, requests, 1)
	}()

	t.Cleanup(func() {
		cancel()
		_ = readerConn.Close()
		select {
		case err := <-readerDone:
			if err != nil {
				t.Errorf("fallback integration reader failed: %v", err)
			}
		case <-time.After(fallbackIntegrationTimeout):
			t.Error("fallback integration reader did not stop")
		}
		close(requests)
		select {
		case <-workerDone:
		case <-time.After(fallbackIntegrationTimeout):
			t.Error("DNS worker did not stop")
		}
	})
}

func enqueueFallbackIntegrationDatagram(
	t *testing.T,
	client *net.UDPConn,
	listener *net.UDPConn,
	packet []byte,
) {
	t.Helper()

	if _, err := client.WriteToUDP(packet, listener.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send test datagram failed: %v", err)
	}
}

func readFallbackIntegrationReply(t *testing.T, client *net.UDPConn) ([]byte, *net.UDPAddr) {
	t.Helper()

	if err := client.SetReadDeadline(time.Now().Add(fallbackIntegrationTimeout)); err != nil {
		t.Fatalf("SetReadDeadline client failed: %v", err)
	}
	buffer := make([]byte, 65535)
	n, peer, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("read test reply failed: %v", err)
	}
	return append([]byte(nil), buffer[:n]...), peer
}

func fallbackIntegrationSameUDPAddr(left *net.UDPAddr, right *net.UDPAddr) bool {
	return left != nil && right != nil &&
		left.Port == right.Port && left.Zone == right.Zone && left.IP.Equal(right.IP)
}

func TestDNSWorkerFallbackRoundTripKeepsOtherDNSPeerLocal(t *testing.T) {
	echo := startFallbackIntegrationEcho(t)
	t.Cleanup(func() { echo.Close(t) })

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP DNS listener failed: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	primaryListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP primary DNS listener failed: %v", err)
	}
	t.Cleanup(func() { _ = primaryListener.Close() })

	server := &Server{
		log:           logger.New("Fallback Integration Test", "ERROR"),
		domainMatcher: domainMatcher.New([]string{"vpn.example.com"}, 3),
	}
	server.fallback = newUDPFallbackManager(echo.conn.LocalAddr().(*net.UDPAddr), server.log)
	t.Cleanup(server.fallback.Close)
	// The worker default is deliberately different from the request listener,
	// mirroring the reuseport path where each request carries its ingress socket.
	startFallbackIntegrationRuntime(t, server, primaryListener, listener)

	fallbackClient, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP fallback client failed: %v", err)
	}
	t.Cleanup(func() { _ = fallbackClient.Close() })

	rawPacket := []byte("not a DNS packet")
	enqueueFallbackIntegrationDatagram(t, fallbackClient, listener, rawPacket)
	reply, replyPeer := readFallbackIntegrationReply(t, fallbackClient)
	if !bytes.Equal(reply, rawPacket) {
		t.Fatalf("unexpected fallback reply: got=%q want=%q", reply, rawPacket)
	}
	if !fallbackIntegrationSameUDPAddr(replyPeer, listener.LocalAddr().(*net.UDPAddr)) {
		t.Fatalf("fallback reply did not come from DNS listener: got=%v want=%v", replyPeer, listener.LocalAddr())
	}
	select {
	case forwarded := <-echo.received:
		if !bytes.Equal(forwarded, rawPacket) {
			t.Fatalf("unexpected packet at fallback endpoint: got=%q want=%q", forwarded, rawPacket)
		}
	case <-time.After(fallbackIntegrationTimeout):
		t.Fatal("fallback endpoint did not receive raw packet")
	}

	dnsClient, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP DNS client failed: %v", err)
	}
	t.Cleanup(func() { _ = dnsClient.Close() })
	if fallbackIntegrationSameUDPAddr(fallbackClient.LocalAddr().(*net.UDPAddr), dnsClient.LocalAddr().(*net.UDPAddr)) {
		t.Fatal("fallback and DNS clients unexpectedly share a source address")
	}

	dnsQuery := buildTestDNSQuery(0x7171, "outside.example", Enums.DNS_RECORD_TYPE_A)
	enqueueFallbackIntegrationDatagram(t, dnsClient, listener, dnsQuery)
	dnsReply, dnsReplyPeer := readFallbackIntegrationReply(t, dnsClient)
	if !fallbackIntegrationSameUDPAddr(dnsReplyPeer, listener.LocalAddr().(*net.UDPAddr)) {
		t.Fatalf("DNS reply did not come from DNS listener: got=%v want=%v", dnsReplyPeer, listener.LocalAddr())
	}
	if len(dnsReply) < 12 {
		t.Fatalf("DNS reply too short: %d", len(dnsReply))
	}
	if got := binary.BigEndian.Uint16(dnsReply[2:4]) & 0x000F; got != Enums.DNSR_CODE_NAME_ERROR {
		t.Fatalf("unexpected DNS rcode: got=%d want=%d", got, Enums.DNSR_CODE_NAME_ERROR)
	}
	select {
	case forwarded := <-echo.received:
		t.Fatalf("fallback endpoint received DNS packet from separate source: %x", forwarded)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestDNSWorkerFallbackCompleteResponseUsesDNSStreak(t *testing.T) {
	echo := startFallbackIntegrationEcho(t)
	t.Cleanup(func() { echo.Close(t) })

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP DNS listener failed: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	server := &Server{log: logger.New("Fallback DNS Response Test", "ERROR")}
	server.fallback = newUDPFallbackManager(echo.conn.LocalAddr().(*net.UDPAddr), server.log)
	t.Cleanup(server.fallback.Close)
	startFallbackIntegrationRuntime(t, server, listener, listener)

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP fallback client failed: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	response := buildTestDNSQuery(0x7272, "example.org", Enums.DNS_RECORD_TYPE_A)
	response[2] |= 0x80
	enqueueFallbackIntegrationDatagram(t, client, listener, response)

	nonDNS := buildTestDNSQuery(0x7373, "example.org", Enums.DNS_RECORD_TYPE_A)
	binary.BigEndian.PutUint16(nonDNS[4:6], 2)
	for range udpFallbackNonDNSStreakLimit - 1 {
		enqueueFallbackIntegrationDatagram(t, client, listener, nonDNS)
	}
	if err := client.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline client failed: %v", err)
	}
	buffer := make([]byte, 64)
	if _, _, err := client.ReadFromUDP(buffer); err == nil {
		t.Fatal("DNS response or pre-threshold non-DNS packet unexpectedly reached fallback")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("pre-threshold read failed unexpectedly: %v", err)
	}
	select {
	case forwarded := <-echo.received:
		t.Fatalf("fallback endpoint received pre-threshold packet: %x", forwarded)
	default:
	}

	enqueueFallbackIntegrationDatagram(t, client, listener, nonDNS)
	if reply, _ := readFallbackIntegrationReply(t, client); !bytes.Equal(reply, nonDNS) {
		t.Fatalf("unexpected threshold fallback reply: got=%x want=%x", reply, nonDNS)
	}
	select {
	case forwarded := <-echo.received:
		if !bytes.Equal(forwarded, nonDNS) {
			t.Fatalf("unexpected threshold packet at fallback endpoint: got=%x want=%x", forwarded, nonDNS)
		}
	case <-time.After(fallbackIntegrationTimeout):
		t.Fatal("fallback endpoint did not receive threshold packet")
	}
}

func TestDNSWorkerDropsQueuedReplyAfterFallbackTransition(t *testing.T) {
	upstream := newUDPFallbackTestUpstream(t, false)
	listener := newUDPFallbackTestConn(t)
	client := newUDPFallbackTestConn(t)
	server := &Server{
		log:           logger.New("Fallback Stale DNS Test", "ERROR"),
		domainMatcher: domainMatcher.New([]string{"vpn.example.com"}, 3),
	}
	server.packetPool.New = func() any {
		return make([]byte, udpFallbackMaxUDPPacketSize)
	}
	server.fallback = newUDPFallbackManager(udpFallbackTestAddr(t, upstream.conn), server.log)
	t.Cleanup(server.fallback.Close)

	ctx, cancel := context.WithCancel(context.Background())
	requests := make(chan request, 1)
	readerDone := make(chan error, 1)
	go func() {
		readerDone <- server.readLoop(ctx, listener, requests, 1)
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case err := <-readerDone:
			if err != nil {
				t.Errorf("fallback reader failed: %v", err)
			}
		case <-time.After(fallbackIntegrationTimeout):
			t.Error("fallback reader did not stop")
		}
	})

	query := buildTestDNSQuery(0x7676, "outside.example", Enums.DNS_RECORD_TYPE_A)
	enqueueFallbackIntegrationDatagram(t, client, listener, query)
	var queued request
	select {
	case queued = <-requests:
	case <-time.After(fallbackIntegrationTimeout):
		t.Fatal("DNS request was not queued")
	}
	if queued.fallbackEpoch == nil {
		t.Fatal("queued DNS request has no routing epoch")
	}

	nonDNS := buildTestDNSQuery(0x7777, "example.org", Enums.DNS_RECORD_TYPE_A)
	binary.BigEndian.PutUint16(nonDNS[4:6], 2)
	for range udpFallbackNonDNSStreakLimit {
		enqueueFallbackIntegrationDatagram(t, client, listener, nonDNS)
	}
	if got := receiveUDPFallbackTestPacket(t, upstream).payload; !bytes.Equal(got, nonDNS) {
		t.Fatalf("unexpected threshold fallback packet: got=%x want=%x", got, nonDNS)
	}

	workerRequests := make(chan request, 1)
	workerRequests <- queued
	close(workerRequests)
	server.dnsWorker(context.Background(), listener, workerRequests, 1)

	if err := client.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline client failed: %v", err)
	}
	buffer := make([]byte, 65535)
	if _, _, err := client.ReadFromUDP(buffer); err == nil {
		t.Fatal("stale DNS reply reached the active fallback flow")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("stale-reply read failed unexpectedly: %v", err)
	}
}

func TestDNSWorkerFallbackForwardsNonDNSDatagrams(t *testing.T) {
	emptyQuestion := make([]byte, 12)
	binary.BigEndian.PutUint16(emptyQuestion[0:2], 0x7272)
	binary.BigEndian.PutUint16(emptyQuestion[2:4], 0x0100)

	incompleteQuestions := buildTestDNSQuery(0x7373, "example.org", Enums.DNS_RECORD_TYPE_A)
	binary.BigEndian.PutUint16(incompleteQuestions[4:6], 2)

	for _, tt := range []struct {
		name   string
		packet []byte
	}{
		{name: "empty question", packet: emptyQuestion},
		{name: "incomplete declared questions", packet: incompleteQuestions},
	} {
		t.Run(tt.name, func(t *testing.T) {
			echo := startFallbackIntegrationEcho(t)
			t.Cleanup(func() { echo.Close(t) })

			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatalf("ListenUDP DNS listener failed: %v", err)
			}
			t.Cleanup(func() { _ = listener.Close() })

			server := &Server{log: logger.New("Fallback Non-DNS Test", "ERROR")}
			server.fallback = newUDPFallbackManager(echo.conn.LocalAddr().(*net.UDPAddr), server.log)
			t.Cleanup(server.fallback.Close)
			startFallbackIntegrationRuntime(t, server, listener, listener)

			client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatalf("ListenUDP fallback client failed: %v", err)
			}
			t.Cleanup(func() { _ = client.Close() })

			enqueueFallbackIntegrationDatagram(t, client, listener, tt.packet)

			if reply, _ := readFallbackIntegrationReply(t, client); !bytes.Equal(reply, tt.packet) {
				t.Fatalf("unexpected fallback reply: got=%x want=%x", reply, tt.packet)
			}
			select {
			case forwarded := <-echo.received:
				if !bytes.Equal(forwarded, tt.packet) {
					t.Fatalf("unexpected packet at fallback endpoint: got=%x want=%x", forwarded, tt.packet)
				}
			case <-time.After(fallbackIntegrationTimeout):
				t.Fatal("fallback endpoint did not receive datagram")
			}
		})
	}
}

func TestDNSWorkerWithoutFallbackSilentlyDropsNonDNS(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP DNS listener failed: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	server := &Server{
		log: logger.New("Fallback Disabled Test", "ERROR"),
	}
	startFallbackIntegrationRuntime(t, server, listener, listener)

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP client failed: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	enqueueFallbackIntegrationDatagram(t, client, listener, []byte("not DNS"))
	if err := client.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline client failed: %v", err)
	}
	buffer := make([]byte, 64)
	if _, _, err := client.ReadFromUDP(buffer); err == nil {
		t.Fatal("non-DNS packet unexpectedly received a reply with fallback disabled")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read with fallback disabled failed unexpectedly: %v", err)
	}
}
