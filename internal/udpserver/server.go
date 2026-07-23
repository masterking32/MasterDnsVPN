// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"container/heap"
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/config"
	dnsCache "masterdnsvpn-go/internal/dnscache"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	fragmentStore "masterdnsvpn-go/internal/fragmentstore"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	mtuProbeModeRaw     = 0
	mtuProbeModeBase64  = 1
	mtuProbeCodeLength  = 4
	mtuProbeMetaLength  = mtuProbeCodeLength + 2
	mtuProbeUpMinSize   = 1 + mtuProbeCodeLength
	mtuProbeDownMinSize = mtuProbeUpMinSize + 2
	mtuProbeMinDownSize = VpnProto.SessionAcceptPayloadSize
	mtuProbeMaxDownSize = 4096
)

var preSessionPacketTypes = buildPreSessionPacketTypes()

type Server struct {
	cfg                      config.ServerConfig
	log                      *logger.Logger
	codec                    *security.Codec
	domainMatcher            *domainMatcher.Matcher
	sessions                 *sessionStore
	deferredDNSSession       *deferredSessionProcessor
	deferredConnectSession   *deferredSessionProcessor
	invalidCookieTracker     *invalidCookieTracker
	dnsCache                 *dnsCache.Store
	dnsResolveInflight       *dnsResolveInflightManager
	dnsUpstreamServers       []string
	dnsUpstreamBufferPool    sync.Pool
	dnsFragments             *fragmentStore.Store[dnsFragmentKey]
	socks5Fragments          *fragmentStore.Store[socks5FragmentKey]
	dnsFragmentTimeout       time.Duration
	resolveDNSQueryFn        func([]byte) ([]byte, error)
	dialStreamUpstreamFn     func(string, string, time.Duration) (net.Conn, error)
	uploadCompressionMask    uint8
	downloadCompressionMask  uint8
	dropLogIntervalNanos     int64
	invalidCookieWindow      time.Duration
	invalidCookieWindowNanos int64
	invalidCookieThreshold   int
	socksConnectTimeout      time.Duration
	useExternalSOCKS5        bool
	externalSOCKS5Address    string
	externalSOCKS5Auth       bool
	externalSOCKS5User       []byte
	externalSOCKS5Pass       []byte
	streamOutboundTTL        time.Duration
	streamOutboundMaxRetry   int
	mtuProbePayloadPool      sync.Pool
	packetPool               sync.Pool
	deferredInflightMu       sync.Mutex
	deferredInflight         map[uint64]struct{}
	deferredInflightIndex    map[uint8]map[uint16]map[uint64]struct{}
	immediateConnectedLog    throttledLogState
	invalidSessionDropLog    throttledLogState
	droppedPackets           atomic.Uint64
	lastDropLogUnix          atomic.Int64
	deferredDroppedPackets   atomic.Uint64
	lastDeferredDropLogUnix  atomic.Int64
	pongNonce                atomic.Uint32
	invalidDropMode          atomic.Uint32
	fallback                 *udpFallbackManager
}

type request struct {
	buf           []byte
	size          int
	addr          *net.UDPAddr
	conn          *net.UDPConn
	parsed        DnsParser.LitePacket
	parseErr      error
	hasParsedDNS  bool
	fallbackEpoch *udpFallbackRouteEpoch
}

type postSessionValidation struct {
	record   *sessionRuntimeView
	response []byte
	ok       bool
}

func New(cfg config.ServerConfig, log *logger.Logger, codec *security.Codec) *Server {
	invalidCookieWindow := cfg.InvalidCookieWindow()
	if invalidCookieWindow <= 0 {
		invalidCookieWindow = 2 * time.Second
	}
	dnsFragmentTimeout := cfg.DNSFragmentAssemblyTimeout()
	if dnsFragmentTimeout <= 0 {
		dnsFragmentTimeout = 5 * time.Minute
	}
	dropLogInterval := cfg.DropLogInterval()
	if dropLogInterval <= 0 {
		dropLogInterval = 2 * time.Second
	}
	socksConnectTimeout := cfg.SOCKSConnectTimeout()
	if socksConnectTimeout <= 0 {
		socksConnectTimeout = 8 * time.Second
	}
	dnsDeferredWorkers, connectDeferredWorkers, dnsDeferredQueue, connectDeferredQueue := splitDeferredSessionPools(cfg.EffectiveDeferredSessionWorkers(), cfg.EffectiveDeferredSessionQueueLimit())
	sessions := newSessionStore(cfg.EffectiveSessionOrphanQueueInitialCap(), cfg.EffectiveStreamQueueInitialCapacity(), cfg.SessionInitReuseTTL(), cfg.RecentlyClosedStreamTTL(), cfg.RecentlyClosedStreamCap)
	sessions.maxActiveSessions = cfg.MaxAllowedClientActiveSessions
	sessions.maxActiveStreams = cfg.MaxAllowedClientActiveStreams
	packetBufferSize := cfg.MaxPacketSize
	if cfg.FallbackAddress != "" && packetBufferSize < udpFallbackMaxUDPPacketSize {
		packetBufferSize = udpFallbackMaxUDPPacketSize
	}
	return &Server{
		cfg:                    cfg,
		log:                    log,
		codec:                  codec,
		domainMatcher:          domainMatcher.New(cfg.Domain, cfg.MinVPNLabelLength),
		sessions:               sessions,
		deferredDNSSession:     newDeferredSessionProcessor(dnsDeferredWorkers, dnsDeferredQueue, log),
		deferredConnectSession: newDeferredSessionProcessor(connectDeferredWorkers, connectDeferredQueue, log),
		invalidCookieTracker:   newInvalidCookieTracker(),
		dnsCache: dnsCache.New(
			cfg.EffectiveDNSCacheMaxRecords(),
			time.Duration(cfg.DNSCacheTTLSeconds*float64(time.Second)),
			dnsFragmentTimeout,
		),
		dnsResolveInflight: newDNSResolveInflightManager(dnsFragmentTimeout),
		dnsUpstreamServers: append([]string(nil), cfg.DNSUpstreamServers...),
		dnsFragments:       fragmentStore.New[dnsFragmentKey](cfg.EffectiveDNSFragmentStoreCapacity()),
		socks5Fragments:    fragmentStore.New[socks5FragmentKey](cfg.EffectiveSOCKS5FragmentStoreCapacity()),
		dnsFragmentTimeout: dnsFragmentTimeout,
		dnsUpstreamBufferPool: sync.Pool{
			New: func() any {
				return make([]byte, 65535)
			},
		},
		dialStreamUpstreamFn: func(network string, address string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(network, address, timeout)
		},
		uploadCompressionMask:    buildCompressionMask(cfg.SupportedUploadCompressionTypes),
		downloadCompressionMask:  buildCompressionMask(cfg.SupportedDownloadCompressionTypes),
		dropLogIntervalNanos:     dropLogInterval.Nanoseconds(),
		invalidCookieWindow:      invalidCookieWindow,
		invalidCookieWindowNanos: invalidCookieWindow.Nanoseconds(),
		invalidCookieThreshold:   cfg.InvalidCookieErrorThreshold,
		socksConnectTimeout:      socksConnectTimeout,
		useExternalSOCKS5:        cfg.UseExternalSOCKS5,
		externalSOCKS5Address:    net.JoinHostPort(cfg.ForwardIP, strconv.Itoa(cfg.ForwardPort)),
		externalSOCKS5Auth:       cfg.SOCKS5Auth,
		externalSOCKS5User:       []byte(cfg.SOCKS5User),
		externalSOCKS5Pass:       []byte(cfg.SOCKS5Pass),
		mtuProbePayloadPool: sync.Pool{
			New: func() any {
				return make([]byte, mtuProbeMaxDownSize)
			},
		},
		deferredInflight:      make(map[uint64]struct{}, 128),
		deferredInflightIndex: make(map[uint8]map[uint16]map[uint64]struct{}, 64),
		packetPool: sync.Pool{
			New: func() any {
				return make([]byte, packetBufferSize)
			},
		},
	}
}

type throttledLogState struct {
	mu   sync.Mutex
	last map[string]int64
	heap throttledLogHeap
}

type throttledLogEntry struct {
	key  string
	seen int64
}

type throttledLogHeap []throttledLogEntry

func (h throttledLogHeap) Len() int { return len(h) }

func (h throttledLogHeap) Less(i, j int) bool {
	return h[i].seen < h[j].seen
}

func (h throttledLogHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *throttledLogHeap) Push(x any) {
	*h = append(*h, x.(throttledLogEntry))
}

func (h *throttledLogHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

const (
	throttledLogSoftCap = 1024
	throttledLogHardCap = 1536
)

func (s *throttledLogState) allow(key string, now time.Time, interval time.Duration) bool {
	if s == nil {
		return true
	}
	if interval <= 0 {
		interval = time.Second
	}

	nowUnixNano := now.UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.last == nil {
		s.last = make(map[string]int64, 64)
	}

	last := s.last[key]

	if last != 0 && nowUnixNano-last < interval.Nanoseconds() {
		return false
	}

	s.last[key] = nowUnixNano
	heap.Push(&s.heap, throttledLogEntry{key: key, seen: nowUnixNano})

	if len(s.last) > 0 {
		s.pruneLocked(nowUnixNano, interval)
	}

	return true
}

func (s *throttledLogState) pruneLocked(nowUnixNano int64, interval time.Duration) {
	if s == nil || len(s.last) == 0 {
		return
	}

	cutoff := nowUnixNano - interval.Nanoseconds()
	for len(s.heap) > 0 {
		entry := s.heap[0]
		last, ok := s.last[entry.key]
		if !ok || last != entry.seen {
			heap.Pop(&s.heap)
			continue
		}
		if entry.seen > cutoff && len(s.last) <= throttledLogHardCap {
			break
		}
		delete(s.last, entry.key)
		heap.Pop(&s.heap)
	}

	for len(s.last) > throttledLogSoftCap && len(s.heap) > 0 {
		entry := heap.Pop(&s.heap).(throttledLogEntry)
		last, ok := s.last[entry.key]
		if !ok || last != entry.seen {
			continue
		}
		delete(s.last, entry.key)
	}
}

func splitDeferredSessionPools(totalWorkers int, totalQueue int) (dnsWorkers int, connectWorkers int, dnsQueue int, connectQueue int) {
	if totalWorkers <= 0 {
		totalWorkers = 1
	}
	if totalQueue <= 0 {
		totalQueue = 256
	}

	// DNS queries use a dedicated lightweight pool so connect-heavy work keeps
	// the full user-configured deferred capacity.
	dnsWorkers = 1
	connectWorkers = totalWorkers

	connectQueue = totalQueue
	dnsQueue = min(max(totalQueue/4, 64), 256)

	return dnsWorkers, connectWorkers, dnsQueue, connectQueue
}

func (s *Server) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var fallbackAddr *net.UDPAddr
	if s.cfg.FallbackAddress != "" {
		resolved, err := net.ResolveUDPAddr("udp", s.cfg.FallbackAddress)
		if err != nil {
			return fmt.Errorf("resolve fallback address %q: %w", s.cfg.FallbackAddress, err)
		}
		if resolved.IP.IsUnspecified() {
			return fmt.Errorf("fallback address %q resolves to an unspecified address", s.cfg.FallbackAddress)
		}
		fallbackAddr = resolved
	}

	readerCount := s.cfg.EffectiveUDPReaders()
	var fallback *udpFallbackManager
	if fallbackAddr != nil {
		// Fallback classification is stateful and order-sensitive per source.
		readerCount = 1
	}
	conns, err := s.openUDPListeners(readerCount)
	if err != nil {
		return err
	}
	var closeListenersOnce sync.Once
	closeListeners := func() {
		closeListenersOnce.Do(func() {
			for _, conn := range conns {
				_ = conn.Close()
			}
		})
	}
	defer closeListeners()

	if fallbackAddr != nil {
		for _, conn := range conns {
			localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
			if !ok {
				continue
			}
			targetsListener, err := fallbackTargetsListener(localAddr, fallbackAddr)
			if err != nil {
				return fmt.Errorf("validate fallback address %s against UDP listener %s: %w", fallbackAddr, localAddr, err)
			}
			if targetsListener {
				return fmt.Errorf("fallback address %s resolves to the UDP listener and would loop", fallbackAddr)
			}
		}

		fallback = newUDPFallbackManager(fallbackAddr, s.log)
		s.fallback = fallback
		defer func() {
			closeListeners()
			fallback.Close()
			s.fallback = nil
		}()
	}

	s.log.Infof(
		"\U0001F4E1 <green>UDP Listener Ready, Addr: <cyan>%s</cyan>, Readers: <cyan>%d</cyan>, Workers: <cyan>%d</cyan>, Queue: <cyan>%d</cyan>, Sockets: <cyan>%d</cyan></green>",
		s.cfg.Address(),
		readerCount,
		s.cfg.EffectiveDNSRequestWorkers(),
		s.cfg.EffectiveMaxConcurrentRequests(),
		len(conns),
	)

	reqCh := make(chan request, s.cfg.EffectiveMaxConcurrentRequests())
	var workerWG sync.WaitGroup
	cleanupDone := make(chan struct{})

	go func() {
		defer close(cleanupDone)
		s.sessionCleanupLoop(runCtx)
	}()

	s.deferredDNSSession.Start(runCtx)
	s.deferredConnectSession.Start(runCtx)
	s.startDNSWorkers(runCtx, conns[0], reqCh, &workerWG)

	go func() {
		<-runCtx.Done()
		closeListeners()
		if fallback != nil {
			fallback.Close()
		}
	}()

	readErrCh := make(chan error, max(1, len(conns)))
	var readerWG sync.WaitGroup
	s.startReaders(runCtx, conns, readerCount, reqCh, readErrCh, &readerWG)

	readerWG.Wait()
	// A UDP reply can be waiting for send-buffer space. Close the listener
	// before waiting for workers or fallback reply loops so teardown unblocks it.
	closeListeners()
	close(reqCh)
	workerWG.Wait()
	cancel()
	<-cleanupDone

	if ctx.Err() != nil {
		return ctx.Err()
	}

	select {
	case err := <-readErrCh:
		return err
	default:
		return nil
	}
}

func fallbackTargetsListener(listener *net.UDPAddr, target *net.UDPAddr) (bool, error) {
	if listener == nil || target == nil || listener.Port != target.Port {
		return false, nil
	}
	if target.IP.IsUnspecified() {
		return true, nil
	}
	if listener.IP.Equal(target.IP) && listener.Zone == target.Zone {
		return true, nil
	}
	if !listener.IP.IsUnspecified() {
		return false, nil
	}
	if listener.IP.To4() != nil && target.IP.To4() == nil {
		return false, nil
	}
	if target.IP.IsLoopback() {
		return true, nil
	}

	interfaceAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, fmt.Errorf("enumerate local interface addresses: %w", err)
	}
	for _, addr := range interfaceAddrs {
		var ip net.IP
		switch value := addr.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		}
		if ip != nil && ip.Equal(target.IP) {
			return true, nil
		}
	}
	return false, nil
}
