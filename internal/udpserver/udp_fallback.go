// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/logger"
)

const (
	udpFallbackIdleTimeout       = 180 * time.Second
	udpFallbackCleanupInterval   = 30 * time.Second
	udpFallbackNonDNSStreakLimit = 16
	udpFallbackMaxUDPPacketSize  = 65535
	udpFallbackSendQueueSize     = 16
)

type udpFallbackPeerKey struct {
	ip   string
	port int
	zone string
}

type udpFallbackRouteMode uint8

const (
	udpFallbackRouteDNS udpFallbackRouteMode = iota
	udpFallbackRouteFallback
)

type udpFallbackReplyWriter interface {
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
}

// udpFallbackWriteBarrier serializes client-bound writes for one peer across
// route epochs. A blocked peer never holds the manager lock or ingress reader.
type udpFallbackWriteBarrier struct {
	mu sync.Mutex
}

// udpFallbackRouteEpoch is a validity token for work queued during one routing
// period. Successive epochs for the same peer share a write barrier.
type udpFallbackRouteEpoch struct {
	active  atomic.Bool
	barrier *udpFallbackWriteBarrier
}

func newUDPFallbackRouteEpoch(barrier *udpFallbackWriteBarrier) *udpFallbackRouteEpoch {
	if barrier == nil {
		barrier = &udpFallbackWriteBarrier{}
	}
	epoch := &udpFallbackRouteEpoch{barrier: barrier}
	epoch.active.Store(true)
	return epoch
}

func (e *udpFallbackRouteEpoch) invalidate() {
	if e != nil {
		e.active.Store(false)
	}
}

func (e *udpFallbackRouteEpoch) writeIfActive(
	conn udpFallbackReplyWriter,
	packet []byte,
	peer *net.UDPAddr,
) error {
	if e == nil {
		return nil
	}
	e.barrier.mu.Lock()
	defer e.barrier.mu.Unlock()
	if !e.active.Load() {
		return nil
	}
	_, err := conn.WriteToUDP(packet, peer)
	return err
}

type udpFallbackPeerState struct {
	mode         udpFallbackRouteMode
	epoch        *udpFallbackRouteEpoch
	lastSeen     time.Time
	nonDNSStreak int
	peer         *net.UDPAddr
	listener     *net.UDPConn
	session      *udpFallbackSession
}

type udpFallbackSession struct {
	conn      net.Conn
	peerLabel string
	sendCh    chan []byte
	closed    chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func (s *udpFallbackSession) close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		if s.closed != nil {
			close(s.closed)
		}
		if s.conn != nil {
			_ = s.conn.Close()
		}
	})
}

type udpFallbackManager struct {
	target *net.UDPAddr
	log    *logger.Logger

	mu          sync.Mutex
	peers       map[udpFallbackPeerKey]*udpFallbackPeerState
	barriers    map[udpFallbackPeerKey]*udpFallbackWriteBarrier
	dialUDP     func(string, *net.UDPAddr, *net.UDPAddr) (*net.UDPConn, error)
	closed      bool
	stopCh      chan struct{}
	cleanupDone chan struct{}
	sessionWG   sync.WaitGroup
	closeOnce   sync.Once
}

func newUDPFallbackManager(target *net.UDPAddr, log *logger.Logger) *udpFallbackManager {
	manager := &udpFallbackManager{
		target:      cloneUDPAddr(target),
		log:         log,
		peers:       make(map[udpFallbackPeerKey]*udpFallbackPeerState),
		barriers:    make(map[udpFallbackPeerKey]*udpFallbackWriteBarrier),
		dialUDP:     net.DialUDP,
		stopCh:      make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}

	if target != nil {
		manager.log.Infof("Non-DNS UDP packets will be forwarded to %s", target)
	}
	go manager.cleanupLoop()
	return manager
}

func (m *udpFallbackManager) Close() {
	if m == nil {
		return
	}

	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		close(m.stopCh)
		sessions := make([]*udpFallbackSession, 0, len(m.peers))
		for _, state := range m.peers {
			state.epoch.invalidate()
			if state.session != nil {
				sessions = append(sessions, state.session)
				state.session = nil
			}
		}
		m.peers = nil
		m.barriers = nil
		m.mu.Unlock()

		for _, session := range sessions {
			session.close()
		}

		<-m.cleanupDone
		m.sessionWG.Wait()
	})
}

func (m *udpFallbackManager) ForwardIfActive(
	packet []byte,
	peer *net.UDPAddr,
	listener *net.UDPConn,
) bool {
	if m == nil || peer == nil {
		return false
	}

	key := makeUDPFallbackPeerKey(peer)
	now := time.Now()

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return false
	}
	state := m.peerStateLocked(key, now)
	session, handled := m.fallbackSessionLocked(key, state, peer, listener, now)
	m.mu.Unlock()

	if !handled {
		return false
	}
	m.forwardPacket(session, packet, peer)
	return true
}

func (m *udpFallbackManager) RouteDNS(
	packet []byte,
	peer *net.UDPAddr,
	listener *net.UDPConn,
) (bool, *udpFallbackRouteEpoch) {
	if m == nil || peer == nil {
		return true, nil
	}

	key := makeUDPFallbackPeerKey(peer)
	now := time.Now()

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return true, nil
	}
	state := m.peerStateLocked(key, now)
	session, handled := m.fallbackSessionLocked(key, state, peer, listener, now)
	if handled {
		m.mu.Unlock()
		m.forwardPacket(session, packet, peer)
		return false, nil
	}

	if state == nil {
		state = &udpFallbackPeerState{
			mode:     udpFallbackRouteDNS,
			epoch:    newUDPFallbackRouteEpoch(m.routeBarrierLocked(key)),
			lastSeen: now,
			peer:     cloneUDPAddr(peer),
			listener: listener,
		}
		m.peers[key] = state
	} else {
		state.lastSeen = now
		state.nonDNSStreak = 0
		state.peer = cloneUDPAddr(peer)
		state.listener = listener
	}
	epoch := state.epoch
	m.mu.Unlock()
	return true, epoch
}

func (m *udpFallbackManager) RouteNonDNS(
	packet []byte,
	peer *net.UDPAddr,
	listener *net.UDPConn,
) {
	if m == nil || peer == nil {
		return
	}

	key := makeUDPFallbackPeerKey(peer)
	now := time.Now()

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}

	state := m.peerStateLocked(key, now)
	session, handled := m.fallbackSessionLocked(key, state, peer, listener, now)
	if handled {
		m.mu.Unlock()
		m.forwardPacket(session, packet, peer)
		return
	}

	if state != nil {
		state.nonDNSStreak++
		state.lastSeen = now
		if state.nonDNSStreak < udpFallbackNonDNSStreakLimit {
			m.mu.Unlock()
			return
		}
		state.epoch.invalidate()
		session = m.activateFallbackLocked(key, peer, listener, now)
		m.mu.Unlock()
		m.forwardPacket(session, packet, peer)
		return
	}

	session = m.activateFallbackLocked(key, peer, listener, now)
	m.mu.Unlock()

	m.forwardPacket(session, packet, peer)
}

func (m *udpFallbackManager) peerStateLocked(
	key udpFallbackPeerKey,
	now time.Time,
) *udpFallbackPeerState {
	state := m.peers[key]
	if state == nil {
		return nil
	}
	if now.Sub(state.lastSeen) <= udpFallbackIdleTimeout {
		return state
	}

	state.epoch.invalidate()
	if state.session != nil {
		state.session.close()
		state.session = nil
	}
	if state.mode == udpFallbackRouteFallback {
		m.log.Debugf("Expired UDP fallback session for %s", state.peer)
	}
	delete(m.peers, key)
	return nil
}

func (m *udpFallbackManager) fallbackSessionLocked(
	key udpFallbackPeerKey,
	state *udpFallbackPeerState,
	peer *net.UDPAddr,
	listener *net.UDPConn,
	now time.Time,
) (*udpFallbackSession, bool) {
	if state == nil {
		return nil, false
	}
	switch state.mode {
	case udpFallbackRouteFallback:
		return m.prepareFallbackLocked(key, state, peer, listener, now), true
	default:
		return nil, false
	}
}

func (m *udpFallbackManager) activateFallbackLocked(
	key udpFallbackPeerKey,
	peer *net.UDPAddr,
	listener *net.UDPConn,
	now time.Time,
) *udpFallbackSession {
	state := &udpFallbackPeerState{
		mode:     udpFallbackRouteFallback,
		epoch:    newUDPFallbackRouteEpoch(m.routeBarrierLocked(key)),
		lastSeen: now,
		peer:     cloneUDPAddr(peer),
		listener: listener,
	}
	m.peers[key] = state
	return m.createSessionLocked(key, state)
}

func (m *udpFallbackManager) routeBarrierLocked(
	key udpFallbackPeerKey,
) *udpFallbackWriteBarrier {
	barrier := m.barriers[key]
	if barrier == nil {
		barrier = &udpFallbackWriteBarrier{}
		m.barriers[key] = barrier
	}
	return barrier
}

func (m *udpFallbackManager) prepareFallbackLocked(
	key udpFallbackPeerKey,
	state *udpFallbackPeerState,
	peer *net.UDPAddr,
	listener *net.UDPConn,
	now time.Time,
) *udpFallbackSession {
	state.lastSeen = now
	state.peer = cloneUDPAddr(peer)
	state.listener = listener

	if state.session != nil {
		select {
		case <-state.session.done:
			state.session.close()
			state.session = nil
			m.log.Debugf("UDP fallback reply loop ended for %s; recreating session", peer)
		default:
			return state.session
		}
	}

	return m.createSessionLocked(key, state)
}

func (m *udpFallbackManager) createSessionLocked(
	key udpFallbackPeerKey,
	state *udpFallbackPeerState,
) *udpFallbackSession {
	peer := state.peer
	if m.target == nil || len(m.target.IP) == 0 {
		m.log.Warnf("Unable to create UDP fallback session for %s: fallback target is not resolved", peer)
		return nil
	}

	network := "udp6"
	localAddr := &net.UDPAddr{IP: net.IPv6unspecified}
	if m.target.IP.To4() != nil {
		network = "udp4"
		localAddr = &net.UDPAddr{IP: net.IPv4zero}
	}

	conn, err := m.dialUDP(network, localAddr, m.target)
	if err != nil {
		m.log.Warnf("Unable to create UDP fallback session for %s: %v", peer, err)
		return nil
	}

	session := &udpFallbackSession{
		conn:      conn,
		peerLabel: peer.String(),
		sendCh:    make(chan []byte, udpFallbackSendQueueSize),
		closed:    make(chan struct{}),
		done:      make(chan struct{}),
	}
	state.session = session
	m.sessionWG.Add(2)
	go m.forwardPackets(session)
	go m.forwardReplies(key, state.epoch, session)
	m.log.Debugf("Created UDP fallback session for %s", peer)
	return session
}

func (m *udpFallbackManager) forwardPacket(
	session *udpFallbackSession,
	packet []byte,
	peer *net.UDPAddr,
) {
	if session == nil {
		return
	}
	select {
	case <-session.closed:
		return
	default:
	}
	if len(session.sendCh) == cap(session.sendCh) {
		m.log.Debugf("Dropped UDP fallback packet for %s: send queue is full", peer)
		return
	}

	queued := append([]byte(nil), packet...)
	select {
	case session.sendCh <- queued:
	case <-session.closed:
	default:
		m.log.Debugf("Dropped UDP fallback packet for %s: send queue is full", peer)
	}
}

func (m *udpFallbackManager) forwardPackets(session *udpFallbackSession) {
	defer m.sessionWG.Done()

	for {
		select {
		case <-session.closed:
			return
		default:
		}
		select {
		case packet := <-session.sendCh:
			if _, err := session.conn.Write(packet); err != nil && !errors.Is(err, net.ErrClosed) {
				m.log.Warnf("UDP fallback write failed for %s via %s: %v", session.peerLabel, m.target, err)
			}
		case <-session.closed:
			return
		}
	}
}

func (m *udpFallbackManager) forwardReplies(
	key udpFallbackPeerKey,
	epoch *udpFallbackRouteEpoch,
	session *udpFallbackSession,
) {
	defer m.sessionWG.Done()
	defer close(session.done)
	defer session.close()

	buffer := make([]byte, udpFallbackMaxUDPPacketSize)
	for {
		size, err := session.conn.Read(buffer)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				m.log.Warnf("UDP fallback reply read failed for %s: %v", session.peerLabel, err)
			}
			return
		}

		now := time.Now()
		m.mu.Lock()
		state := m.peers[key]
		if m.closed ||
			state == nil ||
			state.mode != udpFallbackRouteFallback ||
			state.epoch != epoch ||
			state.session != session {
			m.mu.Unlock()
			continue
		}
		state.lastSeen = now
		listener := state.listener
		peer := cloneUDPAddr(state.peer)
		m.mu.Unlock()

		if listener == nil || peer == nil {
			continue
		}
		err = epoch.writeIfActive(listener, buffer[:size], peer)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			m.log.Warnf("UDP fallback reply write failed for %s: %v", peer, err)
		}
	}
}

func (m *udpFallbackManager) cleanupLoop() {
	ticker := time.NewTicker(udpFallbackCleanupInterval)
	defer ticker.Stop()
	defer close(m.cleanupDone)

	for {
		select {
		case <-m.stopCh:
			return
		case now := <-ticker.C:
			m.cleanup(now)
		}
	}
}

func (m *udpFallbackManager) cleanup(now time.Time) {
	if m == nil {
		return
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}

	expired := make([]*udpFallbackSession, 0)
	for key, state := range m.peers {
		if now.Sub(state.lastSeen) <= udpFallbackIdleTimeout {
			continue
		}

		state.epoch.invalidate()
		if state.session != nil {
			expired = append(expired, state.session)
			state.session = nil
		}
		delete(m.peers, key)
	}
	// A new epoch must reuse the barrier while an admitted write from the old
	// epoch still owns it. Idle barriers can be discarded immediately.
	for key, barrier := range m.barriers {
		if _, active := m.peers[key]; active || !barrier.mu.TryLock() {
			continue
		}
		barrier.mu.Unlock()
		delete(m.barriers, key)
	}
	m.mu.Unlock()

	for _, session := range expired {
		session.close()
	}
}

func makeUDPFallbackPeerKey(peer *net.UDPAddr) udpFallbackPeerKey {
	if peer == nil {
		return udpFallbackPeerKey{}
	}
	return udpFallbackPeerKey{
		ip:   peer.IP.String(),
		port: peer.Port,
		zone: peer.Zone,
	}
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	clone := *addr
	clone.IP = append(net.IP(nil), addr.IP...)
	return &clone
}
