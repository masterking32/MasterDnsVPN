package udpserver

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

type udpFallbackTestPacket struct {
	payload []byte
	peer    *net.UDPAddr
}

type udpFallbackBlockingConn struct {
	writeStarted chan struct{}
	closed       chan struct{}
	startOnce    sync.Once
	closeOnce    sync.Once
}

func newUDPFallbackBlockingConn() *udpFallbackBlockingConn {
	return &udpFallbackBlockingConn{
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (c *udpFallbackBlockingConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *udpFallbackBlockingConn) Write(packet []byte) (int, error) {
	c.startOnce.Do(func() { close(c.writeStarted) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *udpFallbackBlockingConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *udpFallbackBlockingConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *udpFallbackBlockingConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *udpFallbackBlockingConn) SetDeadline(time.Time) error      { return nil }
func (c *udpFallbackBlockingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *udpFallbackBlockingConn) SetWriteDeadline(time.Time) error { return nil }

type udpFallbackControlledReplyWriter struct {
	label   string
	started chan struct{}
	release <-chan struct{}
	events  chan<- string
}

func (w *udpFallbackControlledReplyWriter) WriteToUDP(
	packet []byte,
	peer *net.UDPAddr,
) (int, error) {
	close(w.started)
	if w.release != nil {
		<-w.release
	}
	if w.events != nil {
		w.events <- w.label
	}
	return len(packet), nil
}

type udpFallbackTestUpstream struct {
	conn    *net.UDPConn
	packets chan udpFallbackTestPacket
	done    chan struct{}
}

func newUDPFallbackTestConn(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func newUDPFallbackTestUpstream(t *testing.T, echo bool) *udpFallbackTestUpstream {
	t.Helper()
	upstream := &udpFallbackTestUpstream{
		conn:    newUDPFallbackTestConn(t),
		packets: make(chan udpFallbackTestPacket, 32),
		done:    make(chan struct{}),
	}
	go func() {
		defer close(upstream.done)
		buffer := make([]byte, udpFallbackMaxUDPPacketSize)
		for {
			size, peer, err := upstream.conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			payload := append([]byte(nil), buffer[:size]...)
			upstream.packets <- udpFallbackTestPacket{payload: payload, peer: cloneUDPAddr(peer)}
			if echo {
				_, _ = upstream.conn.WriteToUDP(payload, peer)
			}
		}
	}()
	t.Cleanup(func() {
		_ = upstream.conn.Close()
		waitUDPFallbackTestDone(t, upstream.done, "upstream")
	})
	return upstream
}

func udpFallbackTestAddr(t *testing.T, conn *net.UDPConn) *net.UDPAddr {
	t.Helper()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected UDP address type %T", conn.LocalAddr())
	}
	return cloneUDPAddr(addr)
}

func receiveUDPFallbackTestPacket(t *testing.T, upstream *udpFallbackTestUpstream) udpFallbackTestPacket {
	t.Helper()
	select {
	case packet := <-upstream.packets:
		return packet
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for fallback upstream packet")
		return udpFallbackTestPacket{}
	}
}

func receiveUDPFallbackClientPacket(t *testing.T, conn *net.UDPConn) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set UDP read deadline: %v", err)
	}
	buffer := make([]byte, udpFallbackMaxUDPPacketSize)
	size, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("read fallback client packet: %v", err)
	}
	return append([]byte(nil), buffer[:size]...)
}

func waitUDPFallbackTestDone(t *testing.T, done <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s goroutine did not stop", name)
	}
}

func TestUDPFallbackForwardsBidirectionallyAndKeepsPeersDistinct(t *testing.T) {
	upstream := newUDPFallbackTestUpstream(t, true)
	listener := newUDPFallbackTestConn(t)
	clientOne := newUDPFallbackTestConn(t)
	clientTwo := newUDPFallbackTestConn(t)
	manager := newUDPFallbackManager(udpFallbackTestAddr(t, upstream.conn), nil)
	t.Cleanup(manager.Close)
	peerOne := udpFallbackTestAddr(t, clientOne)
	peerTwo := udpFallbackTestAddr(t, clientTwo)

	manager.RouteNonDNS([]byte("first"), peerOne, listener)
	first := receiveUDPFallbackTestPacket(t, upstream)
	if got := string(receiveUDPFallbackClientPacket(t, clientOne)); got != "first" {
		t.Fatalf("unexpected first reply %q", got)
	}
	if !manager.ForwardIfActive([]byte("sticky"), peerOne, listener) {
		t.Fatal("expected sticky fallback fast path")
	}
	receiveUDPFallbackTestPacket(t, upstream)
	if got := string(receiveUDPFallbackClientPacket(t, clientOne)); got != "sticky" {
		t.Fatalf("unexpected sticky reply %q", got)
	}

	manager.RouteNonDNS([]byte("second peer"), peerTwo, listener)
	second := receiveUDPFallbackTestPacket(t, upstream)
	if first.peer.String() == second.peer.String() {
		t.Fatalf("distinct peers shared fallback source %s", first.peer)
	}
	if got := string(receiveUDPFallbackClientPacket(t, clientTwo)); got != "second peer" {
		t.Fatalf("unexpected second-peer reply %q", got)
	}
	if routeDNS, _ := manager.RouteDNS([]byte("parsed DNS race"), peerOne, listener); routeDNS {
		t.Fatal("active fallback peer returned to DNS processing")
	}
	if got := string(receiveUDPFallbackTestPacket(t, upstream).payload); got != "parsed DNS race" {
		t.Fatalf("unexpected raced DNS forwarding %q", got)
	}
}

func TestUDPFallbackDNSStreakThresholdAndReset(t *testing.T) {
	upstream := newUDPFallbackTestUpstream(t, false)
	listener := newUDPFallbackTestConn(t)
	client := newUDPFallbackTestConn(t)
	manager := newUDPFallbackManager(udpFallbackTestAddr(t, upstream.conn), nil)
	t.Cleanup(manager.Close)
	peer := udpFallbackTestAddr(t, client)
	key := makeUDPFallbackPeerKey(peer)

	if routeDNS, _ := manager.RouteDNS([]byte("DNS"), peer, listener); !routeDNS {
		t.Fatal("new DNS peer should remain DNS")
	}
	for range 8 {
		manager.RouteNonDNS([]byte("stray"), peer, listener)
	}
	if routeDNS, _ := manager.RouteDNS([]byte("reset"), peer, listener); !routeDNS {
		t.Fatal("DNS should reset the non-DNS streak")
	}
	for range udpFallbackNonDNSStreakLimit - 1 {
		manager.RouteNonDNS([]byte("stray"), peer, listener)
	}
	manager.mu.Lock()
	state := manager.peers[key]
	sessionExists := state != nil && state.session != nil
	manager.mu.Unlock()
	if state == nil ||
		state.mode != udpFallbackRouteDNS ||
		state.nonDNSStreak != udpFallbackNonDNSStreakLimit-1 ||
		sessionExists {
		t.Fatalf("unexpected pre-threshold state: state=%+v session=%t", state, sessionExists)
	}

	manager.RouteNonDNS([]byte("switch"), peer, listener)
	if got := string(receiveUDPFallbackTestPacket(t, upstream).payload); got != "switch" {
		t.Fatalf("unexpected threshold packet %q", got)
	}
}

func TestUDPFallbackAdmittedDNSWritePrecedesFallbackReply(t *testing.T) {
	manager := newUDPFallbackManager(nil, nil)
	t.Cleanup(manager.Close)
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5300}
	key := makeUDPFallbackPeerKey(peer)
	processDNS, dnsEpoch := manager.RouteDNS([]byte("DNS"), peer, nil)
	if !processDNS || dnsEpoch == nil {
		t.Fatal("new DNS peer did not receive a routing epoch")
	}

	releaseDNS := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseDNS) }) })
	events := make(chan string, 2)
	dnsWriter := &udpFallbackControlledReplyWriter{
		label:   "DNS",
		started: make(chan struct{}),
		release: releaseDNS,
		events:  events,
	}
	dnsDone := make(chan error, 1)
	go func() {
		dnsDone <- dnsEpoch.writeIfActive(dnsWriter, []byte("DNS reply"), peer)
	}()
	select {
	case <-dnsWriter.started:
	case <-time.After(time.Second):
		t.Fatal("DNS write was not admitted")
	}

	for range udpFallbackNonDNSStreakLimit - 1 {
		manager.RouteNonDNS([]byte("non-DNS"), peer, nil)
	}
	transitionDone := make(chan struct{})
	go func() {
		manager.RouteNonDNS([]byte("non-DNS"), peer, nil)
		close(transitionDone)
	}()
	select {
	case <-transitionDone:
	case <-time.After(time.Second):
		t.Fatal("fallback transition waited for the admitted DNS write")
	}
	manager.mu.Lock()
	state := manager.peers[key]
	manager.mu.Unlock()
	if state == nil || state.mode != udpFallbackRouteFallback {
		t.Fatalf("peer did not transition to fallback: %+v", state)
	}
	fallbackEpoch := state.epoch
	if fallbackEpoch.barrier != dnsEpoch.barrier {
		t.Fatal("route transition replaced the peer write barrier")
	}

	otherPeer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 5300}
	processDNS, otherEpoch := manager.RouteDNS([]byte("other DNS"), otherPeer, nil)
	if !processDNS || otherEpoch == nil {
		t.Fatal("unrelated DNS peer did not receive a routing epoch")
	}
	otherWriter := &udpFallbackControlledReplyWriter{started: make(chan struct{})}
	otherDone := make(chan error, 1)
	go func() {
		otherDone <- otherEpoch.writeIfActive(otherWriter, []byte("other reply"), otherPeer)
	}()
	select {
	case err := <-otherDone:
		if err != nil {
			t.Fatalf("unrelated DNS write failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("admitted DNS write blocked an unrelated peer")
	}

	fallbackWriter := &udpFallbackControlledReplyWriter{
		label:   "fallback",
		started: make(chan struct{}),
		events:  events,
	}
	fallbackAttempted := make(chan struct{})
	fallbackDone := make(chan error, 1)
	go func() {
		close(fallbackAttempted)
		fallbackDone <- fallbackEpoch.writeIfActive(fallbackWriter, []byte("fallback reply"), peer)
	}()
	<-fallbackAttempted
	select {
	case <-fallbackWriter.started:
		t.Fatal("fallback reply overtook the admitted DNS write")
	case <-time.After(100 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(releaseDNS) })
	for _, want := range []string{"DNS", "fallback"} {
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("unexpected completed client write: got=%s want=%s", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %s client write", want)
		}
	}
	for _, write := range []struct {
		name string
		done <-chan error
	}{
		{"DNS", dnsDone},
		{"fallback", fallbackDone},
	} {
		select {
		case err := <-write.done:
			if err != nil {
				t.Fatalf("%s write failed: %v", write.name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %s writer", write.name)
		}
	}
}

func TestUDPFallbackCleanupRetainsBusyWriteBarrier(t *testing.T) {
	manager := newUDPFallbackManager(nil, nil)
	t.Cleanup(manager.Close)
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5300}
	key := makeUDPFallbackPeerKey(peer)
	processDNS, epoch := manager.RouteDNS([]byte("DNS"), peer, nil)
	if !processDNS || epoch == nil {
		t.Fatal("new DNS peer did not receive a routing epoch")
	}

	epoch.barrier.mu.Lock()
	var unlockOnce sync.Once
	t.Cleanup(func() { unlockOnce.Do(epoch.barrier.mu.Unlock) })
	manager.mu.Lock()
	manager.peers[key].lastSeen = time.Now().Add(-udpFallbackIdleTimeout - time.Second)
	manager.mu.Unlock()
	manager.cleanup(time.Now())

	manager.mu.Lock()
	_, peerExists := manager.peers[key]
	retainedBarrier := manager.barriers[key]
	manager.mu.Unlock()
	if peerExists {
		t.Fatal("cleanup retained expired peer state")
	}
	if retainedBarrier != epoch.barrier {
		t.Fatal("cleanup discarded a busy peer write barrier")
	}

	processDNS, nextEpoch := manager.RouteDNS([]byte("new DNS"), peer, nil)
	if !processDNS || nextEpoch == nil {
		t.Fatal("expired peer did not receive a new routing epoch")
	}
	if nextEpoch.barrier != epoch.barrier {
		t.Fatal("peer recreation replaced its busy write barrier")
	}

	unlockOnce.Do(epoch.barrier.mu.Unlock)
	manager.mu.Lock()
	manager.peers[key].lastSeen = time.Now().Add(-udpFallbackIdleTimeout - time.Second)
	manager.mu.Unlock()
	manager.cleanup(time.Now())
	manager.mu.Lock()
	_, peerExists = manager.peers[key]
	_, barrierExists := manager.barriers[key]
	manager.mu.Unlock()
	if peerExists || barrierExists {
		t.Fatal("cleanup retained an idle expired peer write barrier")
	}
}

func TestUDPFallbackRetainedNonDNSRefreshesIdleTimeout(t *testing.T) {
	upstream := newUDPFallbackTestUpstream(t, false)
	listener := newUDPFallbackTestConn(t)
	client := newUDPFallbackTestConn(t)
	manager := newUDPFallbackManager(udpFallbackTestAddr(t, upstream.conn), nil)
	t.Cleanup(manager.Close)
	peer := udpFallbackTestAddr(t, client)
	key := makeUDPFallbackPeerKey(peer)

	if routeDNS, _ := manager.RouteDNS([]byte("DNS"), peer, listener); !routeDNS {
		t.Fatal("new DNS peer should remain DNS")
	}
	staleLastSeen := time.Now().Add(-udpFallbackIdleTimeout / 2)
	manager.mu.Lock()
	state := manager.peers[key]
	state.lastSeen = staleLastSeen
	manager.mu.Unlock()

	beforeRoute := time.Now()
	manager.RouteNonDNS([]byte("retained"), peer, listener)
	manager.mu.Lock()
	state = manager.peers[key]
	exists := state != nil
	sessionExists := state != nil && state.session != nil
	manager.mu.Unlock()
	if !exists || state.mode != udpFallbackRouteDNS || sessionExists {
		t.Fatalf("retained non-DNS packet changed routing: dns=%t fallback=%t", exists, sessionExists)
	}
	if state.nonDNSStreak != 1 {
		t.Fatalf("unexpected non-DNS streak: got=%d want=1", state.nonDNSStreak)
	}
	if state.lastSeen.Before(beforeRoute) {
		t.Fatalf("retained non-DNS packet did not refresh activity: got=%v before=%v", state.lastSeen, beforeRoute)
	}

	manager.cleanup(staleLastSeen.Add(udpFallbackIdleTimeout + time.Second))
	manager.mu.Lock()
	_, exists = manager.peers[key]
	manager.mu.Unlock()
	if !exists {
		t.Fatal("cleanup expired a DNS peer that remained active via non-DNS traffic")
	}
}

func TestUDPFallbackBackpressuredUpstreamDoesNotBlockIngressOrClose(t *testing.T) {
	manager := newUDPFallbackManager(nil, nil)
	t.Cleanup(manager.Close)
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5300}
	key := makeUDPFallbackPeerKey(peer)
	conn := newUDPFallbackBlockingConn()
	session := &udpFallbackSession{
		conn:      conn,
		peerLabel: peer.String(),
		sendCh:    make(chan []byte, udpFallbackSendQueueSize),
		closed:    make(chan struct{}),
		done:      make(chan struct{}),
	}
	state := &udpFallbackPeerState{
		mode:     udpFallbackRouteFallback,
		epoch:    newUDPFallbackRouteEpoch(nil),
		lastSeen: time.Now(),
		peer:     cloneUDPAddr(peer),
		session:  session,
	}
	manager.mu.Lock()
	manager.peers[key] = state
	manager.sessionWG.Add(1)
	go manager.forwardPackets(session)
	manager.mu.Unlock()

	firstForwardDone := make(chan bool, 1)
	go func() {
		firstForwardDone <- manager.ForwardIfActive([]byte("blocked"), peer, nil)
	}()
	select {
	case <-conn.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("fallback writer did not reach the upstream write")
	}
	select {
	case handled := <-firstForwardDone:
		if !handled {
			t.Fatal("fallback peer was not forwarded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fallback dispatch waited for the upstream write")
	}

	for range cap(session.sendCh) {
		if !manager.ForwardIfActive([]byte("queued"), peer, nil) {
			t.Fatal("fallback peer lost sticky classification while its writer was blocked")
		}
	}
	forwardDone := make(chan bool, 1)
	go func() {
		forwardDone <- manager.ForwardIfActive([]byte("drop"), peer, nil)
	}()
	select {
	case handled := <-forwardDone:
		if !handled {
			t.Fatal("full fallback queue lost sticky classification")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("full fallback queue blocked ingress")
	}

	otherPeer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 5300}
	if processDNS, _ := manager.RouteDNS([]byte("DNS"), otherPeer, nil); !processDNS {
		t.Fatal("backpressured fallback peer blocked unrelated DNS routing")
	}

	closeDone := make(chan struct{})
	go func() {
		manager.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("manager Close did not cancel the blocked fallback write")
	}
}

func TestUDPFallbackExpiredDNSPeerForwardsNextNonDNS(t *testing.T) {
	upstream := newUDPFallbackTestUpstream(t, false)
	listener := newUDPFallbackTestConn(t)
	client := newUDPFallbackTestConn(t)
	manager := newUDPFallbackManager(udpFallbackTestAddr(t, upstream.conn), nil)
	t.Cleanup(manager.Close)
	peer := udpFallbackTestAddr(t, client)
	key := makeUDPFallbackPeerKey(peer)

	if routeDNS, _ := manager.RouteDNS([]byte("DNS"), peer, listener); !routeDNS {
		t.Fatal("new DNS peer should remain DNS")
	}
	manager.mu.Lock()
	state := manager.peers[key]
	state.lastSeen = time.Now().Add(-udpFallbackIdleTimeout - time.Second)
	manager.mu.Unlock()

	manager.RouteNonDNS([]byte("after idle gap"), peer, listener)
	if got := string(receiveUDPFallbackTestPacket(t, upstream).payload); got != "after idle gap" {
		t.Fatalf("unexpected packet after DNS peer expiry: got=%q", got)
	}
}

func TestUDPFallbackInitialDialFailureKeepsFallbackRoute(t *testing.T) {
	upstream := newUDPFallbackTestUpstream(t, false)
	listener := newUDPFallbackTestConn(t)
	client := newUDPFallbackTestConn(t)
	manager := newUDPFallbackManager(udpFallbackTestAddr(t, upstream.conn), nil)
	t.Cleanup(manager.Close)
	peer := udpFallbackTestAddr(t, client)
	key := makeUDPFallbackPeerKey(peer)

	realDialUDP := manager.dialUDP
	dialAttempts := 0
	manager.dialUDP = func(network string, localAddr, remoteAddr *net.UDPAddr) (*net.UDPConn, error) {
		dialAttempts++
		if dialAttempts == 1 {
			return nil, errors.New("forced initial dial failure")
		}
		return realDialUDP(network, localAddr, remoteAddr)
	}

	manager.RouteNonDNS([]byte("dropped while dialing"), peer, listener)
	manager.mu.Lock()
	state := manager.peers[key]
	manager.mu.Unlock()
	if state == nil || state.mode != udpFallbackRouteFallback || state.session != nil {
		t.Fatalf("dial failure lost fallback routing state: %+v", state)
	}

	dnsPacket := buildTestDNSQuery(0x7474, "example.org", Enums.DNS_RECORD_TYPE_A)
	if routeDNS, _ := manager.RouteDNS(dnsPacket, peer, listener); routeDNS {
		t.Fatal("DNS-shaped retry escaped fallback after initial dial failure")
	}
	if got := receiveUDPFallbackTestPacket(t, upstream).payload; !bytes.Equal(got, dnsPacket) {
		t.Fatalf("unexpected recovered fallback packet: got=%x want=%x", got, dnsPacket)
	}
	if dialAttempts != 2 {
		t.Fatalf("unexpected dial attempts: got=%d want=2", dialAttempts)
	}
}

func TestUDPFallbackRedialFailureKeepsFallbackRoute(t *testing.T) {
	upstream := newUDPFallbackTestUpstream(t, false)
	listener := newUDPFallbackTestConn(t)
	client := newUDPFallbackTestConn(t)
	manager := newUDPFallbackManager(udpFallbackTestAddr(t, upstream.conn), nil)
	t.Cleanup(manager.Close)
	peer := udpFallbackTestAddr(t, client)
	key := makeUDPFallbackPeerKey(peer)

	realDialUDP := manager.dialUDP
	dialAttempts := 0
	manager.dialUDP = func(network string, localAddr, remoteAddr *net.UDPAddr) (*net.UDPConn, error) {
		dialAttempts++
		if dialAttempts == 2 {
			return nil, errors.New("forced redial failure")
		}
		return realDialUDP(network, localAddr, remoteAddr)
	}

	manager.RouteNonDNS([]byte("activate"), peer, listener)
	receiveUDPFallbackTestPacket(t, upstream)
	manager.mu.Lock()
	oldSession := manager.peers[key].session
	manager.mu.Unlock()
	oldSession.close()
	waitUDPFallbackTestDone(t, oldSession.done, "closed reply loop")

	if !manager.ForwardIfActive([]byte("dropped while redialing"), peer, listener) {
		t.Fatal("redial failure lost active fallback classification")
	}
	manager.mu.Lock()
	state := manager.peers[key]
	manager.mu.Unlock()
	if state == nil || state.mode != udpFallbackRouteFallback || state.session != nil {
		t.Fatalf("redial failure lost fallback routing state: %+v", state)
	}

	dnsPacket := buildTestDNSQuery(0x7575, "example.org", Enums.DNS_RECORD_TYPE_A)
	if routeDNS, _ := manager.RouteDNS(dnsPacket, peer, listener); routeDNS {
		t.Fatal("DNS-shaped retry escaped fallback after redial failure")
	}
	if got := receiveUDPFallbackTestPacket(t, upstream).payload; !bytes.Equal(got, dnsPacket) {
		t.Fatalf("unexpected packet after successful redial: got=%x want=%x", got, dnsPacket)
	}
	if dialAttempts != 3 {
		t.Fatalf("unexpected dial attempts: got=%d want=3", dialAttempts)
	}
}

func TestUDPFallbackExpiryRecreationAndClose(t *testing.T) {
	upstream := newUDPFallbackTestUpstream(t, false)
	listener := newUDPFallbackTestConn(t)
	client := newUDPFallbackTestConn(t)
	manager := newUDPFallbackManager(udpFallbackTestAddr(t, upstream.conn), nil)
	peer := udpFallbackTestAddr(t, client)
	key := makeUDPFallbackPeerKey(peer)

	manager.RouteNonDNS([]byte("activate"), peer, listener)
	receiveUDPFallbackTestPacket(t, upstream)
	manager.mu.Lock()
	expiredState := manager.peers[key]
	expiredState.lastSeen = time.Now().Add(-udpFallbackIdleTimeout - time.Second)
	manager.mu.Unlock()
	if manager.ForwardIfActive([]byte("expired"), peer, listener) {
		t.Fatal("expired session consumed the fast-path packet")
	}
	if routeDNS, _ := manager.RouteDNS([]byte("DNS after expiry"), peer, listener); !routeDNS {
		t.Fatal("DNS should resume after fallback expiry")
	}

	manager.mu.Lock()
	dnsState := manager.peers[key]
	dnsState.lastSeen = time.Now().Add(-udpFallbackIdleTimeout - time.Second)
	manager.mu.Unlock()
	manager.cleanup(time.Now())
	manager.RouteNonDNS([]byte("reactivate"), peer, listener)
	receiveUDPFallbackTestPacket(t, upstream)
	manager.mu.Lock()
	oldSession := manager.peers[key].session
	manager.mu.Unlock()
	oldSession.close()
	waitUDPFallbackTestDone(t, oldSession.done, "closed reply loop")

	if !manager.ForwardIfActive([]byte("recreated"), peer, listener) {
		t.Fatal("dead reply loop lost active fallback classification")
	}
	receiveUDPFallbackTestPacket(t, upstream)
	manager.mu.Lock()
	newSession := manager.peers[key].session
	manager.mu.Unlock()
	if newSession == oldSession {
		t.Fatal("dead fallback session was not recreated")
	}

	closeDone := make(chan struct{})
	go func() {
		manager.Close()
		close(closeDone)
	}()
	waitUDPFallbackTestDone(t, closeDone, "manager Close")
	waitUDPFallbackTestDone(t, newSession.done, "active reply loop")
	select {
	case <-manager.cleanupDone:
	default:
		t.Fatal("cleanup loop remained active after Close")
	}
	manager.Close()
}
