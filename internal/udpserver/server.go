// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/arq"
	"masterdnsvpn-go/internal/compression"
	"masterdnsvpn-go/internal/config"
	dnsCache "masterdnsvpn-go/internal/dnscache"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/fragmentstore"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	SocksProto "masterdnsvpn-go/internal/socksproto"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	mtuProbeModeRaw     = 0
	mtuProbeModeBase64  = 1
	mtuProbeCodeLength  = 4
	mtuProbeMetaLength  = mtuProbeCodeLength + 2
	mtuProbeUpMinSize   = 1 + mtuProbeCodeLength
	mtuProbeDownMinSize = mtuProbeUpMinSize + 2
	mtuProbeMinDownSize = 30
	mtuProbeMaxDownSize = 4096
	sessionAcceptSize   = 7
)

var preSessionPacketTypes = buildPreSessionPacketTypes()

type Server struct {
	cfg                      config.ServerConfig
	log                      *logger.Logger
	codec                    *security.Codec
	domainMatcher            *domainMatcher.Matcher
	sessions                 *sessionStore
	deferredSession          *deferredSessionProcessor
	invalidCookieTracker     *invalidCookieTracker
	dnsCache                 *dnsCache.Store
	dnsResolveInflight       *dnsResolveInflightManager
	dnsUpstreamServers       []string
	dnsUpstreamBufferPool    sync.Pool
	dnsFragments             *fragmentstore.Store[dnsFragmentKey]
	socks5Fragments          *fragmentstore.Store[socks5FragmentKey]
	streamDataFragments      *fragmentstore.Store[streamDataFragmentKey]
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
	mtuProbeFillPattern      [256]byte
	packetPool               sync.Pool
	droppedPackets           atomic.Uint64
	lastDropLogUnix          atomic.Int64
	pongNonce                atomic.Uint32
	invalidDropMode          atomic.Uint32
	arqWindowSize            int
}

type request struct {
	buf  []byte
	size int
	addr *net.UDPAddr
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
	return &Server{
		cfg:                  cfg,
		arqWindowSize:        cfg.ARQWindowSize,
		log:                  log,
		codec:                codec,
		domainMatcher:        domainMatcher.New(cfg.Domain, cfg.MinVPNLabelLength),
		sessions:             newSessionStore(),
		deferredSession:      newDeferredSessionProcessor(cfg.DeferredSessionWorkers, cfg.DeferredSessionQueueLimit, log),
		invalidCookieTracker: newInvalidCookieTracker(),
		dnsCache: dnsCache.New(
			cfg.DNSCacheMaxRecords,
			time.Duration(cfg.DNSCacheTTLSeconds*float64(time.Second)),
			dnsFragmentTimeout,
		),
		dnsResolveInflight:  newDNSResolveInflightManager(dnsFragmentTimeout),
		dnsUpstreamServers:  append([]string(nil), cfg.DNSUpstreamServers...),
		dnsFragments:        fragmentstore.New[dnsFragmentKey](32),
		socks5Fragments:     fragmentstore.New[socks5FragmentKey](32),
		streamDataFragments: fragmentstore.New[streamDataFragmentKey](128),
		dnsFragmentTimeout:  dnsFragmentTimeout,
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
		mtuProbeFillPattern: buildMTUProbeFillPattern(),
		packetPool: sync.Pool{
			New: func() any {
				return make([]byte, cfg.MaxPacketSize)
			},
		},
	}
}

func (s *Server) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(s.cfg.UDPHost),
		Port: s.cfg.UDPPort,
	})

	if err != nil {
		return err
	}

	defer conn.Close()

	if err := conn.SetReadBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("\U0001F4E1 <yellow>UDP Read Buffer Setup Failed, <cyan>%v</cyan></yellow>", err)
	}

	if err := conn.SetWriteBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("\U0001F4E1 <yellow>UDP Write Buffer Setup Failed, <cyan>%v</cyan></yellow>", err)
	}

	s.log.Infof(
		"\U0001F4E1 <green>UDP Listener Ready, Addr: <cyan>%s</cyan>, Readers: <cyan>%d</cyan>, Workers: <cyan>%d</cyan>, Queue: <cyan>%d</cyan></green>",
		s.cfg.Address(),
		s.cfg.UDPReaders,
		s.cfg.DNSRequestWorkers,
		s.cfg.MaxConcurrentRequests,
	)

	reqCh := make(chan request, s.cfg.MaxConcurrentRequests)
	var workerWG sync.WaitGroup
	cleanupDone := make(chan struct{})

	go func() {
		defer close(cleanupDone)
		s.sessionCleanupLoop(runCtx)
	}()
	s.deferredSession.Start(runCtx)

	for i := range s.cfg.DNSRequestWorkers {
		workerWG.Add(1)
		go func(workerID int) {
			defer workerWG.Done()
			s.worker(runCtx, conn, reqCh, workerID)
		}(i + 1)
	}

	go func() {
		<-runCtx.Done()
		_ = conn.Close()
	}()

	readErrCh := make(chan error, s.cfg.UDPReaders)
	var readerWG sync.WaitGroup
	for i := range s.cfg.UDPReaders {
		readerWG.Add(1)
		go func(readerID int) {
			defer readerWG.Done()
			if err := s.readLoop(runCtx, conn, reqCh, readerID); err != nil {
				select {
				case readErrCh <- err:
				default:
				}
			}
		}(i + 1)
	}

	readerWG.Wait()
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

func (s *Server) sessionCleanupLoop(ctx context.Context) {
	interval := s.cfg.SessionCleanupInterval()
	if interval <= 0 {
		interval = 30 * time.Second
	}
	sessionTimeout := s.cfg.SessionTimeout()
	closedRetention := s.cfg.ClosedSessionRetention()
	invalidCookieWindow := s.invalidCookieWindow

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			expired := s.sessions.Cleanup(now, sessionTimeout, closedRetention)
			s.sessions.SweepTerminalStreams(now, 45*time.Second)
			s.invalidCookieTracker.Cleanup(now, invalidCookieWindow)
			s.purgeDNSQueryFragments(now)
			s.purgeSOCKS5SynFragments(now)
			if len(expired) == 0 {
				continue
			}
			for _, sessionID := range expired {
				s.cleanupClosedSession(sessionID)
			}
			s.log.Infof(
				"\U0001F4E1 <green>Expired Sessions Cleaned, Count: <cyan>%d</cyan></green>",
				len(expired),
			)
		}
	}
}

func (s *Server) readLoop(ctx context.Context, conn *net.UDPConn, reqCh chan<- request, readerID int) error {
	for {
		buffer := s.packetPool.Get().([]byte)
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			s.packetPool.Put(buffer)

			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			s.log.Debugf(
				"\U0001F4A5 <yellow>UDP Read Error, Reader: <cyan>%d</cyan>, Error: <cyan>%v</cyan></yellow>",
				readerID,
				err,
			)
			return err
		}

		select {
		case reqCh <- request{buf: buffer, size: n, addr: addr}:
		case <-ctx.Done():
			s.packetPool.Put(buffer)
			return nil
		default:
			s.packetPool.Put(buffer)
			s.onDrop(addr)
		}
	}
}

func (s *Server) worker(ctx context.Context, conn *net.UDPConn, reqCh <-chan request, workerID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-reqCh:
			if !ok {
				return
			}

			response := s.safeHandlePacket(req.buf[:req.size])
			if len(response) != 0 {
				if _, err := conn.WriteToUDP(response, req.addr); err != nil {
					s.log.Debugf(
						"\U0001F4A5 <yellow>UDP Write Error, Worker: <cyan>%d</cyan>, Remote: <cyan>%v</cyan>, Error: <cyan>%v</cyan></yellow>",
						workerID,
						req.addr,
						err,
					)
				}
			}

			s.packetPool.Put(req.buf)
		}
	}
}

func (s *Server) safeHandlePacket(packet []byte) (response []byte) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if s.log != nil {
				s.log.Errorf(
					"\U0001F4A5 <red>Packet Handler Panic Recovered, <yellow>%v</yellow></red>",
					recovered,
				)
			}
			response = nil
		}
	}()
	return s.handlePacket(packet)
}

func (s *Server) handlePacket(packet []byte) []byte {
	parsed, err := DnsParser.ParseDNSRequestLite(packet)
	if err != nil {
		if s.debugLoggingEnabled() {
			s.log.Debugf("\u26a0\ufe0f <yellow>DNS Parse Failed</yellow> <magenta>|</magenta> <blue>Error</blue>: <cyan>%v</cyan>", err)
		}
		if errors.Is(err, DnsParser.ErrNotDNSRequest) || errors.Is(err, DnsParser.ErrPacketTooShort) {
			return nil
		}

		return s.buildNoDataResponseLogged(packet, "request-parse-failed")
	}

	if !parsed.HasQuestion {
		return s.buildNoDataResponseLogged(packet, "request-has-no-question")
	}

	decision := s.domainMatcher.Match(parsed)
	if decision.Action == domainMatcher.ActionProcess {
		return s.handleTunnelCandidate(packet, parsed, decision)
	}

	if decision.Action == domainMatcher.ActionFormatError || decision.Action == domainMatcher.ActionNoData {
		return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-no-data")
	}

	return nil
}

func (s *Server) handleTunnelCandidate(packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision) []byte {
	vpnPacket, err := VpnProto.ParseInflatedFromLabels(decision.Labels, s.codec)
	if err != nil {
		if s.debugLoggingEnabled() {
			s.log.Debugf("\u26a0\ufe0f <yellow>VPN Proto Parse Failed</yellow> <magenta>|</magenta> <blue>Error</blue>: <cyan>%v</cyan>", err)
		}
		return s.buildNoDataResponseLiteLogged(packet, parsed, "vpn-proto-parse-failed")
	}

	if vpnPacket.PacketType == Enums.PACKET_SESSION_CLOSE {
		s.handleSessionCloseNotice(vpnPacket, time.Now())
		return nil
	}

	if !isPreSessionRequestType(vpnPacket.PacketType) {
		validation := s.validatePostSessionPacket(packet, decision.RequestName, vpnPacket)
		if !validation.ok {
			return validation.response
		}

		if !s.handlePostSessionPacket(decision, vpnPacket, validation.record) {
			return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("post-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
		}

		return s.serveQueuedOrPong(packet, decision.RequestName, validation.record, time.Now())
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_MTU_UP_REQ:
		return s.handleMTUUpRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_MTU_DOWN_REQ:
		return s.handleMTUDownRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_SESSION_INIT:
		return s.handleSessionInitRequest(packet, decision, vpnPacket)
	default:
		return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("pre-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
	}
}

func (s *Server) handlePostSessionPacket(decision domainMatcher.Decision, vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if handled := s.handleClosedStreamPacket(vpnPacket); handled {
		return true
	}
	if handled := s.preprocessInboundPacket(vpnPacket); handled {
		return true
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_PACKED_CONTROL_BLOCKS:
		return s.handlePackedControlBlocksRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_PING:
		return s.handlePingRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND:
		return s.handleStreamDataRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_FIN_ACK, Enums.PACKET_STREAM_RST_ACK, Enums.PACKET_STREAM_SYN_ACK:
		return s.handleStreamAckPacket(vpnPacket, sessionRecord)
	case Enums.PACKET_SOCKS5_CONNECTED_ACK,
		Enums.PACKET_SOCKS5_CONNECT_FAIL_ACK,
		Enums.PACKET_SOCKS5_RULESET_DENIED_ACK,
		Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_HOST_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_CONNECTION_REFUSED_ACK,
		Enums.PACKET_SOCKS5_TTL_EXPIRED_ACK,
		Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_AUTH_FAILED_ACK,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK:
		return s.handleSocksAckPacket(vpnPacket, sessionRecord)
	case Enums.PACKET_DNS_QUERY_REQ:
		return s.handleDNSQueryRequest(decision, vpnPacket, sessionRecord)
	case Enums.PACKET_DNS_QUERY_RES_ACK:
		return s.handleDNSQueryResponseAck(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_SYN:
		return s.handleStreamSynRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_SOCKS5_SYN:
		return s.handleSOCKS5SynRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_FIN:
		return s.handleStreamFinRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_RST:
		return s.handleStreamRSTRequest(vpnPacket, sessionRecord)
	default:
		return false
	}
}

func (s *Server) handleClosedStreamPacket(vpnPacket VpnProto.Packet) bool {
	if s == nil || vpnPacket.StreamID == 0 || !isClosedStreamAwarePacketType(vpnPacket.PacketType) {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}

	now := time.Now()
	if !record.isRecentlyClosed(vpnPacket.StreamID, now) {
		return false
	}

	return s.enqueueMissingStreamReset(record, vpnPacket)
}

func (s *Server) enqueueMissingStreamReset(record *sessionRecord, vpnPacket VpnProto.Packet) bool {
	if s == nil || record == nil || vpnPacket.StreamID == 0 {
		return false
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_STREAM_RST:
		record.enqueueOrphanReset(Enums.PACKET_STREAM_RST_ACK, vpnPacket.StreamID, vpnPacket.SequenceNum)
	case Enums.PACKET_STREAM_RST_ACK:
		return true
	default:
		record.enqueueOrphanReset(Enums.PACKET_STREAM_RST, vpnPacket.StreamID, 0)
	}
	return true
}

func isStreamCreationPacketType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_STREAM_SYN, Enums.PACKET_SOCKS5_SYN:
		return true
	default:
		return false
	}
}

func (s *Server) queueImmediateControlAck(record *sessionRecord, packet VpnProto.Packet) bool {
	if s == nil || record == nil {
		return false
	}

	ackType, ok := Enums.ControlAckFor(packet.PacketType)
	if !ok {
		return false
	}

	ackPacket := VpnProto.Packet{
		PacketType:     ackType,
		StreamID:       packet.StreamID,
		SequenceNum:    packet.SequenceNum,
		FragmentID:     packet.FragmentID,
		TotalFragments: packet.TotalFragments,
	}

	if packet.StreamID == 0 {
		return s.queueSessionPacket(record.ID, ackPacket)
	}

	stream, exists := record.getStream(packet.StreamID)
	if (!exists || stream == nil) && isStreamCreationPacketType(packet.PacketType) {
		stream = record.getOrCreateStream(packet.StreamID, s.streamARQConfig(packet.PacketType == Enums.PACKET_SOCKS5_SYN), nil, s.log)
		exists = stream != nil
	}
	if !exists || stream == nil {
		return false
	}

	return stream.PushTXPacket(
		Enums.DefaultPacketPriority(ackType),
		ackType,
		packet.SequenceNum,
		packet.FragmentID,
		packet.TotalFragments,
		0,
		nil,
	)
}

func (s *Server) preprocessInboundPacket(vpnPacket VpnProto.Packet) bool {
	if s == nil {
		return true
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND, Enums.PACKET_PACKED_CONTROL_BLOCKS:
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}

	if vpnPacket.HasStreamID && vpnPacket.StreamID != 0 {
		now := time.Now()
		if isStreamCreationPacketType(vpnPacket.PacketType) && record.isRecentlyClosed(vpnPacket.StreamID, now) {
			return s.enqueueMissingStreamReset(record, vpnPacket)
		}
		if !isStreamCreationPacketType(vpnPacket.PacketType) {
			if _, exists := record.getStream(vpnPacket.StreamID); !exists {
				return s.enqueueMissingStreamReset(record, vpnPacket)
			}
		}
		if record.isRecentlyClosed(vpnPacket.StreamID, now) {
			return s.enqueueMissingStreamReset(record, vpnPacket)
		}
	}

	_ = s.queueImmediateControlAck(record, vpnPacket)
	return false
}

func (s *Server) validatePostSessionPacket(questionPacket []byte, requestName string, vpnPacket VpnProto.Packet) postSessionValidation {
	now := time.Now()
	validation := s.sessions.ValidateAndTouch(vpnPacket.SessionID, vpnPacket.SessionCookie, now)
	if validation.Valid {
		// ARQ handles its own config
		return postSessionValidation{
			record: validation.Active,
			ok:     true,
		}
	}

	if !validation.Known {
		mode := s.nextUnknownInvalidDropMode()
		s.logInvalidSessionDrop("unknown session", vpnPacket.SessionID, vpnPacket.SessionCookie, 0, mode)
		return postSessionValidation{
			response: s.buildInvalidSessionErrorResponse(questionPacket, requestName, vpnPacket.SessionID, mode),
		}
	}

	if validation.Lookup.State == sessionLookupClosed {
		s.logInvalidSessionDrop("recently closed session", vpnPacket.SessionID, vpnPacket.SessionCookie, validation.Lookup.Cookie, validation.Lookup.ResponseMode)
		return postSessionValidation{
			response: s.buildInvalidSessionErrorResponse(questionPacket, requestName, vpnPacket.SessionID, validation.Lookup.ResponseMode),
		}
	}

	if !s.invalidCookieTracker.Note(
		vpnPacket.SessionID,
		validation.Lookup,
		validation.Known,
		vpnPacket.SessionCookie,
		now.UnixNano(),
		s.invalidCookieWindowNanos,
		s.invalidCookieThreshold,
	) {
		return postSessionValidation{}
	}

	if s.debugLoggingEnabled() {
		s.logInvalidSessionThreshold(vpnPacket.SessionID, vpnPacket.SessionCookie, validation.Lookup, validation.Known)
	}
	s.logInvalidSessionDrop("invalid cookie threshold", vpnPacket.SessionID, vpnPacket.SessionCookie, validation.Lookup.Cookie, validation.Lookup.ResponseMode)

	return postSessionValidation{
		response: s.buildInvalidSessionErrorResponse(questionPacket, requestName, vpnPacket.SessionID, validation.Lookup.ResponseMode),
	}
}

func (s *Server) handleSessionCloseNotice(vpnPacket VpnProto.Packet, now time.Time) {
	if s == nil || vpnPacket.SessionID == 0 {
		return
	}

	lookup, known := s.sessions.Lookup(vpnPacket.SessionID)
	if !known || lookup.State != sessionLookupActive || lookup.Cookie != vpnPacket.SessionCookie {
		return
	}
	if !s.sessions.Close(vpnPacket.SessionID, now, s.cfg.ClosedSessionRetention()) {
		return
	}

	s.cleanupClosedSession(vpnPacket.SessionID)
	if s.log != nil {
		s.log.Infof(
			"\U0001F6AA <green>Session Closed By Client, Session: <cyan>%d</cyan></green>",
			vpnPacket.SessionID,
		)
	}
}

func (s *Server) logInvalidSessionThreshold(sessionID uint8, receivedCookie uint8, lookup sessionLookupResult, known bool) {
	if !known {
		s.log.Debugf(
			"\U0001F9D7 <yellow>Unknown Session Cookie Threshold Reached, Session: <cyan>%d</cyan>, Received: <cyan>%d</cyan></yellow>",
			sessionID,
			receivedCookie,
		)
		return
	}

	if lookup.State == sessionLookupClosed {
		s.log.Debugf(
			"\U0001F9D7 <yellow>Stale Closed Session Cookie Threshold Reached, Session: <cyan>%d</cyan>, Expected: <cyan>%d</cyan>, Received: <cyan>%d</cyan></yellow>",
			sessionID,
			lookup.Cookie,
			receivedCookie,
		)
		return
	}

	s.log.Debugf(
		"\U0001F9D7 <yellow>Invalid Session Cookie Threshold Reached, Session: <cyan>%d</cyan>, Expected: <cyan>%d</cyan>, Received: <cyan>%d</cyan></yellow>",
		sessionID,
		lookup.Cookie,
		receivedCookie,
	)
}

func (s *Server) logInvalidSessionDrop(reason string, sessionID uint8, receivedCookie uint8, expectedCookie uint8, responseMode uint8) {
	if !s.debugLoggingEnabled() {
		return
	}
	if expectedCookie == 0 {
		s.log.Debugf(
			"ðŸª‚ <yellow>Sending Session Drop</yellow> <magenta>|</magenta> <blue>Reason</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Received</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Mode</blue>: <cyan>%s</cyan>",
			reason,
			sessionID,
			receivedCookie,
			sessionResponseModeName(responseMode),
		)
		return
	}
	s.log.Debugf(
		"ðŸª‚ <yellow>Sending Session Drop</yellow> <magenta>|</magenta> <blue>Reason</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Expected</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Received</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Mode</blue>: <cyan>%s</cyan>",
		reason,
		sessionID,
		expectedCookie,
		receivedCookie,
		sessionResponseModeName(responseMode),
	)
}

func (s *Server) buildInvalidSessionErrorResponse(questionPacket []byte, requestName string, sessionID uint8, responseMode uint8) []byte {
	payload := s.nextInvalidDropPayload()
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, requestName, VpnProto.Packet{
		SessionID:  sessionID,
		PacketType: Enums.PACKET_ERROR_DROP,
		Payload:    payload[:],
	}, responseMode == mtuProbeModeBase64)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) buildSessionBusyResponse(questionPacket []byte, requestName string, responseMode uint8, verifyCode []byte) []byte {
	if len(verifyCode) < mtuProbeCodeLength {
		return nil
	}
	var payload [mtuProbeCodeLength]byte
	copy(payload[:], verifyCode[:mtuProbeCodeLength])
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, requestName, VpnProto.Packet{
		SessionID:  0,
		PacketType: Enums.PACKET_SESSION_BUSY,
		Payload:    payload[:],
	}, responseMode == mtuProbeModeBase64)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) buildSessionVPNResponse(questionPacket []byte, requestName string, record *sessionRuntimeView, packet VpnProto.Packet) []byte {
	if record == nil {
		return nil
	}
	packet.SessionID = record.ID
	packet.SessionCookie = record.Cookie
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, requestName, packet, record.ResponseBase64)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) queueSessionPacket(sessionID uint8, packet VpnProto.Packet) bool {
	s.sessions.mu.Lock()
	record := s.sessions.byID[sessionID]
	s.sessions.mu.Unlock()
	if record == nil {
		return false
	}

	// Push to corresponding stream's TXQueue. Stream 0 is initialized in findOrCreate.
	stream := record.getOrCreateStream(packet.StreamID, s.streamARQConfig(false), nil, s.log)
	return stream.PushTXPacket(getEffectivePriority(packet.PacketType, 3), packet.PacketType, packet.SequenceNum, packet.FragmentID, packet.TotalFragments, packet.CompressionType, packet.Payload)
}

func (s *Server) streamARQConfig(isSocks bool) arq.Config {
	return arq.Config{
		WindowSize:               s.cfg.ARQWindowSize,
		RTO:                      0.2,
		MaxRTO:                   1.5,
		IsSocks:                  isSocks,
		IsClient:                 false,
		EnableControlReliability: true,
		ControlRTO:               0.8,
		ControlMaxRTO:            2.5,
		ControlMaxRetries:        40,
		InactivityTimeout:        1200.0,
		DataPacketTTL:            600.0,
		MaxDataRetries:           400,
		ControlPacketTTL:         600.0,
		FinDrainTimeout:          300.0,
		GracefulDrainTimeout:     600.0,
		TerminalDrainTimeout:     60.0,
		TerminalAckWaitTimeout:   30.0,
	}
}

func (s *Server) queueMainSessionPacket(sessionID uint8, packet VpnProto.Packet) bool {
	packet.StreamID = 0
	return s.queueSessionPacket(sessionID, packet)
}

func (s *Server) cleanupClosedSession(sessionID uint8) {
	if s == nil || sessionID == 0 {
		return
	}
	// s.streams.RemoveSession(sessionID) (removed)
	// s.streamOutbound.RemoveSession(sessionID)
	s.deferredSession.RemoveSession(sessionID)
	s.removeDNSQueryFragmentsForSession(sessionID)
	s.removeStreamDataFragmentsForSession(sessionID)
}

func (s *Server) serveQueuedOrPong(questionPacket []byte, requestName string, record *sessionRuntimeView, now time.Time) []byte {
	if record == nil {
		return nil
	}
	sessionID := record.ID

	// New MLQ-based Round-Robin dispatcher
	if pkt, ok := s.dequeueSessionResponse(sessionID, now); ok {
		if s.log != nil && s.debugLoggingEnabled() && shouldLogServerPacketFlow(pkt.PacketType) {
			s.log.Debugf(
				"\U0001F4E4 <blue>Serving Queued Packet</blue> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Type</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
				sessionID,
				Enums.PacketTypeName(pkt.PacketType),
				pkt.StreamID,
				pkt.SequenceNum,
			)
		}
		resp := s.buildSessionVPNResponse(questionPacket, requestName, record, *pkt)
		// No pooling here since rebuildSessionVPNResponse might use it or it's a temp packet
		return resp
	}

	payload := s.nextPongPayload()

	return s.buildSessionVPNResponse(questionPacket, requestName, record, VpnProto.Packet{
		PacketType: Enums.PACKET_PONG,
		Payload:    payload[:],
	})
}

func (s *Server) dequeueSessionResponse(sessionID uint8, now time.Time) (*VpnProto.Packet, bool) {
	s.sessions.mu.Lock()
	record := s.sessions.byID[sessionID]
	s.sessions.mu.Unlock()

	if record == nil {
		return nil, false
	}

	record.mu.Lock()
	defer record.mu.Unlock()

	if pkt, ok := record.dequeueOrphanReset(); ok && pkt != nil {
		return pkt, true
	}

	// Round-Robin through ActiveStreams (includes Stream 0 which replaces MainQueue)
	if len(record.ActiveStreams) == 0 {
		return nil, false
	}

	record.StreamsMu.RLock()
	defer record.StreamsMu.RUnlock()

	// Pure Round-Robin logic: start from RRStreamID
	startIdx := 0
	for i, id := range record.ActiveStreams {
		if id >= record.RRStreamID {
			startIdx = i
			break
		}
	}

	for i := 0; i < len(record.ActiveStreams); i++ {
		idx := (startIdx + i) % len(record.ActiveStreams)
		streamID := record.ActiveStreams[idx]
		stream := record.Streams[streamID]
		if stream == nil || stream.TXQueue == nil {
			continue
		}

		if item, _, ok := stream.TXQueue.Pop(txPacketKeyExtractor); ok {
			record.RRStreamID = streamID + 1 // Move to next for next call
			if VpnProto.IsPackableControlPacket(item.PacketType, len(item.Payload)) && record.MaxPackedBlocks > 1 {
				return s.packControlBlocks(record, item, streamID), true
			}
			pkt := vpnPacketFromTX(item, streamID)
			return &pkt, true
		}
	}

	return nil, false
}

func (s *Server) packControlBlocks(record *sessionRecord, first *serverStreamTXPacket, initialStreamID uint16) *VpnProto.Packet {
	limit := record.MaxPackedBlocks
	if limit <= 1 {
		pkt := vpnPacketFromTX(first, initialStreamID)
		return &pkt
	}

	payload := make([]byte, 0, limit*VpnProto.PackedControlBlockSize)
	payload = VpnProto.AppendPackedControlBlock(payload, first.PacketType, initialStreamID, first.SequenceNum, 0, 0)
	blocks := 1

	// Cross-stream packing (Any priority)
	// Start with the initial stream first to grab more blocks from it
	streamIDs := make([]uint16, 0, len(record.ActiveStreams))
	streamIDs = append(streamIDs, initialStreamID)
	for _, sid := range record.ActiveStreams {
		if sid != initialStreamID {
			streamIDs = append(streamIDs, sid)
		}
	}

	for _, streamID := range streamIDs {
		if blocks >= limit {
			break
		}
		stream := record.Streams[streamID]
		if stream == nil {
			continue
		}

		for blocks < limit {
			popped, ok := stream.TXQueue.PopAnyIf(func(p *serverStreamTXPacket) bool {
				return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
			}, txPacketKeyExtractor)

			if !ok {
				break
			}

			payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, streamID, popped.SequenceNum, 0, 0)
			blocks++
		}
	}

	if blocks <= 1 {
		pkt := vpnPacketFromTX(first, initialStreamID)
		return &pkt
	}

	return &VpnProto.Packet{
		PacketType:  Enums.PACKET_PACKED_CONTROL_BLOCKS,
		Payload:     payload,
		StreamID:    0,
		HasStreamID: true,
	}
}

func txPacketKeyExtractor(p *serverStreamTXPacket) uint32 {
	return getTrackingKey(p.PacketType, p.SequenceNum, p.FragmentID)
}

func vpnPacketFromTX(p *serverStreamTXPacket, streamID uint16) VpnProto.Packet {
	return VpnProto.Packet{
		PacketType:     p.PacketType,
		StreamID:       streamID,
		SequenceNum:    p.SequenceNum,
		Payload:        p.Payload,
		HasSequenceNum: p.SequenceNum != 0,
		HasStreamID:    true,
	}
}

func (s *Server) QueueTargetForPacket(streamExists bool, packetType uint8, streamID uint16) (QueueTarget, bool) {
	if streamID == 0 {
		return QueueTargetMain, true
	}
	if streamExists {
		return QueueTargetStream, true
	}
	// Fallback to Main if stream recently closed
	return QueueTargetMain, true
}

func (s *Server) nextPongPayload() [7]byte {
	var payload [7]byte
	payload[0] = 'P'
	payload[1] = 'O'
	payload[2] = ':'

	nonce := s.pongNonce.Add(1)
	nonce ^= nonce << 13
	nonce ^= nonce >> 17
	nonce ^= nonce << 5
	binary.BigEndian.PutUint32(payload[3:], nonce)

	return payload
}

func (s *Server) nextInvalidDropPayload() [8]byte {
	var payload [8]byte
	payload[0] = 'I'
	payload[1] = 'N'
	payload[2] = 'V'

	nonce := s.pongNonce.Add(1)
	nonce ^= nonce << 13
	nonce ^= nonce >> 17
	nonce ^= nonce << 5
	binary.BigEndian.PutUint32(payload[3:7], nonce)
	payload[7] = byte(nonce)
	return payload
}

func (s *Server) nextUnknownInvalidDropMode() uint8 {
	if s == nil {
		return mtuProbeModeRaw
	}
	if s.invalidDropMode.Add(1)&1 == 0 {
		return mtuProbeModeRaw
	}
	return mtuProbeModeBase64
}

func deferredSessionLaneForPacket(packet VpnProto.Packet) deferredSessionLane {
	return deferredSessionLane{
		sessionID: packet.SessionID,
		streamID:  packet.StreamID,
	}
}

func isDeferredPostSessionPacketType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_DNS_QUERY_REQ,
		Enums.PACKET_STREAM_SYN,
		Enums.PACKET_SOCKS5_SYN,
		Enums.PACKET_STREAM_DATA,
		Enums.PACKET_STREAM_RESEND:
		return true
	default:
		return false
	}
}

func (s *Server) dispatchDeferredSessionPacket(packet VpnProto.Packet, run func()) bool {
	if s == nil || s.deferredSession == nil || !isDeferredPostSessionPacketType(packet.PacketType) {
		return false
	}
	return s.deferredSession.Enqueue(deferredSessionLaneForPacket(packet), run)
}

func isPreSessionRequestType(packetType uint8) bool {
	return preSessionPacketTypes[packetType]
}

func buildPreSessionPacketTypes() [256]bool {
	var values [256]bool
	values[Enums.PACKET_SESSION_INIT] = true
	values[Enums.PACKET_MTU_UP_REQ] = true
	values[Enums.PACKET_MTU_DOWN_REQ] = true
	return values
}

func (s *Server) handleSessionInitRequest(questionPacket []byte, decision domainMatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if vpnPacket.SessionID != 0 || len(vpnPacket.Payload) != sessionInitDataSize {
		return nil
	}

	requestedUpload, requestedDownload := compression.SplitPair(vpnPacket.Payload[1])
	resolvedUpload := resolveCompressionType(requestedUpload, s.uploadCompressionMask)
	resolvedDownload := resolveCompressionType(requestedDownload, s.downloadCompressionMask)

	record, reused, err := s.sessions.findOrCreate(
		vpnPacket.Payload,
		resolvedUpload,
		resolvedDownload,
		s.cfg.MaxPacketsPerBatch,
	)

	if err != nil {
		if err == ErrSessionTableFull {
			if s.log != nil {
				s.log.Errorf(
					"\U0001F6AB <red>Session Table Full Request: <cyan>SESSION_INIT</cyan>, Domain: <cyan>%s</cyan></red>",
					decision.RequestName,
				)
			}
			return s.buildSessionBusyResponse(questionPacket, decision.RequestName, vpnPacket.Payload[0], vpnPacket.Payload[6:10])
		}
		return nil
	}
	if record == nil {
		return nil
	}

	if !reused && s.log != nil {
		s.log.Infof(
			"\U0001F9DD <green>Session Created, ID: <cyan>%d</cyan>, Mode: <cyan>%s</cyan>, Upload Compression: <cyan>%s</cyan>, Download Compression: <cyan>%s</cyan>, Client Upload MTU: <cyan>%d</cyan>, Client Download MTU: <cyan>%d</cyan>, Max Packed Blocks: <cyan>%d</cyan></green>",
			record.ID,
			sessionResponseModeName(record.ResponseMode),
			compression.TypeName(record.UploadCompression),
			compression.TypeName(record.DownloadCompression),
			record.UploadMTU,
			record.DownloadMTU,
			record.MaxPackedBlocks,
		)
	}

	var responsePayload [sessionAcceptSize]byte
	responsePayload[0] = record.ID
	responsePayload[1] = record.Cookie
	responsePayload[2] = compression.PackPair(record.UploadCompression, record.DownloadCompression)
	copy(responsePayload[3:], record.VerifyCode[:])

	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, decision.RequestName, VpnProto.Packet{
		SessionID:  0,
		PacketType: Enums.PACKET_SESSION_ACCEPT,
		Payload:    responsePayload[:],
	}, record.ResponseMode == mtuProbeModeBase64)

	if err != nil {
		return nil
	}

	return response
}

func resolveCompressionType(requested uint8, allowedMask uint8) uint8 {
	if requested <= compression.TypeZLIB && allowedMask&(1<<requested) != 0 {
		return requested
	}
	return compression.TypeOff
}

func (s *Server) onDrop(addr *net.UDPAddr) {
	total := s.droppedPackets.Add(1)

	now := logger.NowUnixNano()
	last := s.lastDropLogUnix.Load()
	interval := s.dropLogIntervalNanos
	if interval <= 0 {
		interval = 2_000_000_000
	}
	if now-last < interval {
		return
	}
	if !s.lastDropLogUnix.CompareAndSwap(last, now) {
		return
	}

	s.log.Warnf(
		"\U0001F6A8 <yellow>Request Queue Overloaded</yellow> <magenta>|</magenta> <blue>Dropped</blue>: <magenta>%d</magenta> <magenta>|</magenta> <blue>Remote</blue>: <cyan>%v</cyan>",
		total,
		addr,
	)
}

func (s *Server) handleMTUUpRequest(questionPacket []byte, _ DnsParser.LitePacket, decision domainMatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if len(vpnPacket.Payload) < mtuProbeUpMinSize {
		return nil
	}

	baseEncode, ok := parseMTUProbeBaseEncoding(vpnPacket.Payload[0])
	if !ok {
		return nil
	}

	responsePayload := buildMTUProbeMetaPayload(vpnPacket.Payload[1:mtuProbeUpMinSize], len(vpnPacket.Payload))
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, decision.RequestName, VpnProto.Packet{
		SessionID:  vpnPacket.SessionID,
		PacketType: Enums.PACKET_MTU_UP_RES,
		Payload:    responsePayload[:],
	}, baseEncode)

	if err != nil {
		return nil
	}

	return response
}

func (s *Server) handleMTUDownRequest(questionPacket []byte, _ DnsParser.LitePacket, decision domainMatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if len(vpnPacket.Payload) < mtuProbeDownMinSize {
		return nil
	}

	baseEncode, ok := parseMTUProbeBaseEncoding(vpnPacket.Payload[0])
	if !ok {
		return nil
	}
	downloadSize := int(binary.BigEndian.Uint16(vpnPacket.Payload[mtuProbeUpMinSize:mtuProbeDownMinSize]))
	if downloadSize < mtuProbeMinDownSize || downloadSize > mtuProbeMaxDownSize {
		return nil
	}

	payloadBuffer := s.mtuProbePayloadPool.Get().([]byte)
	defer s.mtuProbePayloadPool.Put(payloadBuffer)
	payload := payloadBuffer[:downloadSize]
	copy(payload[:mtuProbeCodeLength], vpnPacket.Payload[1:mtuProbeUpMinSize])
	binary.BigEndian.PutUint16(payload[mtuProbeCodeLength:], uint16(downloadSize))
	if downloadSize > mtuProbeMetaLength {
		fillMTUProbeBytes(payload[mtuProbeMetaLength:], s.mtuProbeFillPattern[:])
	}

	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, decision.RequestName, VpnProto.Packet{
		SessionID:      vpnPacket.SessionID,
		PacketType:     Enums.PACKET_MTU_DOWN_RES,
		StreamID:       vpnPacket.StreamID,
		SequenceNum:    vpnPacket.SequenceNum,
		FragmentID:     vpnPacket.FragmentID,
		TotalFragments: vpnPacket.TotalFragments,
		Payload:        payload,
	}, baseEncode)

	if err != nil {
		return nil
	}

	return response
}

func (s *Server) handlePingRequest(_ VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	return sessionRecord != nil
}

func (s *Server) handlePackedControlBlocksRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if sessionRecord == nil || len(vpnPacket.Payload) < VpnProto.PackedControlBlockSize {
		return false
	}

	handled := false
	sawBlock := false
	VpnProto.ForEachPackedControlBlock(vpnPacket.Payload, func(packetType uint8, streamID uint16, sequenceNum uint16, fragmentID uint8, totalFragments uint8) bool {
		if packetType == Enums.PACKET_PACKED_CONTROL_BLOCKS {
			return true
		}
		sawBlock = true
		block := VpnProto.Packet{
			SessionID:     vpnPacket.SessionID,
			SessionCookie: vpnPacket.SessionCookie,
			PacketType:    packetType,
			StreamID:      streamID,
			// Packed blocks always carry explicit stream/sequence fields, and seq=0 is valid.
			HasStreamID:    true,
			SequenceNum:    sequenceNum,
			HasSequenceNum: true,
			FragmentID:     fragmentID,
			TotalFragments: totalFragments,
		}
		if s.preprocessInboundPacket(block) {
			handled = true
			return true
		}
		if s.handlePackedPostSessionBlock(block, sessionRecord) {
			handled = true
		}
		return true
	})
	return handled || sawBlock
}

func (s *Server) handlePackedPostSessionBlock(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	switch vpnPacket.PacketType {
	case Enums.PACKET_PING:
		return s.handlePingRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_DNS_QUERY_RES_ACK:
		return s.handleDNSQueryResponseAck(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_FIN_ACK, Enums.PACKET_STREAM_RST_ACK, Enums.PACKET_STREAM_SYN_ACK:
		return s.handleStreamAckPacket(vpnPacket, sessionRecord)
	case Enums.PACKET_SOCKS5_CONNECTED_ACK,
		Enums.PACKET_SOCKS5_CONNECT_FAIL_ACK,
		Enums.PACKET_SOCKS5_RULESET_DENIED_ACK,
		Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_HOST_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_CONNECTION_REFUSED_ACK,
		Enums.PACKET_SOCKS5_TTL_EXPIRED_ACK,
		Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_AUTH_FAILED_ACK,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK:
		return s.handleSocksAckPacket(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_FIN:
		return s.handleStreamFinRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_RST:
		return s.handleStreamRSTRequest(vpnPacket, sessionRecord)
	default:
		return false
	}
}

func (s *Server) processDeferredDNSQuery(sessionID uint8, sequenceNum uint16, downloadCompression uint8, downloadMTUBytes int, assembledQuery []byte) {
	if !s.sessions.HasActive(sessionID) {
		return
	}
	rawResponse := s.buildDNSQueryResponsePayload(assembledQuery, sessionID, sequenceNum)
	if len(rawResponse) == 0 {
		return
	}
	fragments := s.fragmentDNSResponsePayload(rawResponse, downloadMTUBytes)
	if len(fragments) == 0 {
		return
	}
	totalFragments := uint8(len(fragments))
	for fragmentID, fragmentPayload := range fragments {
		_ = s.queueMainSessionPacket(sessionID, VpnProto.Packet{
			PacketType:      Enums.PACKET_DNS_QUERY_RES,
			StreamID:        0,
			SequenceNum:     sequenceNum,
			FragmentID:      uint8(fragmentID),
			TotalFragments:  totalFragments,
			CompressionType: downloadCompression,
			Payload:         fragmentPayload,
		})
	}
}

func (s *Server) processDeferredStreamSyn(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) {
	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return
	}

	if VpnProto.IsTCPForwardSynPayload(vpnPacket.Payload) {
		if s.cfg.ForwardIP == "" || s.cfg.ForwardPort <= 0 {
			_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
				PacketType:  Enums.PACKET_STREAM_RST,
				StreamID:    vpnPacket.StreamID,
				SequenceNum: vpnPacket.SequenceNum,
			})
			return
		}

		record.StreamsMu.RLock()
		existing, ok := record.Streams[vpnPacket.StreamID]
		record.StreamsMu.RUnlock()

		if ok && existing != nil && existing.Connected && existing.TargetHost == s.cfg.ForwardIP && existing.TargetPort == uint16(s.cfg.ForwardPort) {
			if s.log != nil {
				s.log.Debugf("🧦 <green>STREAM_SYN Fast-Ack (Existing), Session: <cyan>%d</cyan> | Stream: <cyan>%d</cyan></green>", vpnPacket.SessionID, vpnPacket.StreamID)
			}
			return
		}

		if s.log != nil {
			s.log.Debugf("🧦 <blue>STREAM_SYN Processing, Session: <cyan>%d</cyan> | Stream: <cyan>%d</cyan> | Forwarding</blue>", vpnPacket.SessionID, vpnPacket.StreamID)
		}

		stream := record.getOrCreateStream(vpnPacket.StreamID, s.streamARQConfig(false), nil, s.log)
		upstreamConn, err := s.dialSOCKSStreamTarget(s.cfg.ForwardIP, uint16(s.cfg.ForwardPort), nil)
		if err != nil {
			_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
				PacketType:  Enums.PACKET_STREAM_RST,
				StreamID:    vpnPacket.StreamID,
				SequenceNum: vpnPacket.SequenceNum,
			})
			return
		}

		stream.mu.Lock()
		stream.UpstreamConn = upstreamConn
		stream.TargetHost = s.cfg.ForwardIP
		stream.TargetPort = uint16(s.cfg.ForwardPort)
		stream.Connected = true
		stream.mu.Unlock()

		stream.ARQ.SetLocalConn(upstreamConn)
	} else {
		record.getOrCreateStream(vpnPacket.StreamID, s.streamARQConfig(false), nil, s.log)
	}

}

func (s *Server) processDeferredSOCKS5Syn(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) {
	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return
	}
	now := time.Now()
	if s.log != nil {
		s.log.Debugf(
			"🧦 <blue>Processing SOCKS5 SYN</blue> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Frag</blue>: <cyan>%d/%d</cyan>",
			vpnPacket.SessionID,
			vpnPacket.StreamID,
			vpnPacket.FragmentID+1,
			max(1, int(vpnPacket.TotalFragments)),
		)
	}
	totalFragments := vpnPacket.TotalFragments
	if totalFragments == 0 {
		totalFragments = 1
	}
	assembledTarget, ready, completed := s.collectSOCKS5SynFragments(
		vpnPacket.SessionID,
		vpnPacket.StreamID,
		vpnPacket.SequenceNum,
		vpnPacket.Payload,
		vpnPacket.FragmentID,
		totalFragments,
		now,
	)

	if completed || !ready {
		return
	}

	target, err := SocksProto.ParseTargetPayload(assembledTarget)
	if err != nil {
		packetType := uint8(Enums.PACKET_SOCKS5_CONNECT_FAIL)
		if errors.Is(err, SocksProto.ErrUnsupportedAddressType) || errors.Is(err, SocksProto.ErrInvalidDomainLength) {
			packetType = uint8(Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED)
		}
		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:  packetType,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
		return
	}

	stream := record.getOrCreateStream(vpnPacket.StreamID, s.streamARQConfig(true), nil, s.log)
	stream.mu.RLock()
	prevConnected := stream.Connected
	prevHost := stream.TargetHost
	prevPort := stream.TargetPort
	stream.mu.RUnlock()

	if prevConnected {
		if prevHost == target.Host && prevPort == target.Port {
			if s.log != nil {
				s.log.Debugf("🧦 <green>SOCKS5_SYN Fast-Ack (Existing), Session: <cyan>%d</cyan> | Stream: <cyan>%d</cyan></green>", vpnPacket.SessionID, vpnPacket.StreamID)
			}
			_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
				PacketType:  Enums.PACKET_SOCKS5_CONNECTED,
				StreamID:    vpnPacket.StreamID,
				SequenceNum: vpnPacket.SequenceNum,
			})
			return
		}

		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:  Enums.PACKET_SOCKS5_CONNECT_FAIL,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
		return
	}

	upstreamConn, err := s.dialSOCKSStreamTarget(target.Host, target.Port, assembledTarget)
	if err != nil {
		packetType := s.mapSOCKSConnectError(err)
		if s.log != nil {
			s.log.Debugf(
				"\U0001F9E6 <yellow>SOCKS5 Upstream Connect Failed</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Target</blue>: <cyan>%s:%d</cyan> <magenta>|</magenta> <blue>Packet</blue>: <yellow>%s</yellow> <magenta>|</magenta> <cyan>%v</cyan>",
				vpnPacket.SessionID,
				vpnPacket.StreamID,
				target.Host,
				target.Port,
				Enums.PacketTypeName(packetType),
				err,
			)
		}
		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:  packetType,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
		return
	}

	stream.mu.Lock()
	stream.UpstreamConn = upstreamConn
	stream.TargetHost = target.Host
	stream.TargetPort = target.Port
	stream.Connected = true
	stream.mu.Unlock()

	// Legacy Attach (removed)

	stream.ARQ.SetLocalConn(upstreamConn)
	stream.ARQ.MarkSocksConnected()

	if s.log != nil {
		s.log.Debugf(
			"\U0001F9E6 <green>SOCKS5 Stream Prepared</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Target</blue>: <cyan>%s:%d</cyan>",
			vpnPacket.SessionID,
			vpnPacket.StreamID,
			target.Host,
			target.Port,
		)
	}

	_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
		PacketType:  Enums.PACKET_SOCKS5_CONNECTED,
		StreamID:    vpnPacket.StreamID,
		SequenceNum: vpnPacket.SequenceNum,
	})
}

func (s *Server) processDeferredStreamData(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) {
	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return
	}
	now := time.Now()
	totalFragments := vpnPacket.TotalFragments
	if totalFragments == 0 {
		totalFragments = 1
	}

	assembledPayload, ready, complete := s.collectStreamDataFragments(vpnPacket, now)
	if complete {
		_ = s.queueSessionPacket(vpnPacket.SessionID, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_DATA_ACK,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
		return
	}
	if !ready {
		return
	}

	stream := record.getOrCreateStream(vpnPacket.StreamID, s.streamARQConfig(false), nil, s.log)
	stream.ARQ.ReceiveData(vpnPacket.SequenceNum, assembledPayload)
}

func (s *Server) handleDNSQueryRequest(decision domainMatcher.Decision, vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if sessionRecord == nil || vpnPacket.StreamID != 0 || !vpnPacket.HasSequenceNum {
		return false
	}
	totalFragments := vpnPacket.TotalFragments
	if totalFragments == 0 {
		totalFragments = 1
	}
	now := time.Now()
	if s.log != nil && totalFragments == 1 {
		s.log.Debugf(
			"\U0001F4E8 <green>Tunnel DNS Query Received</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Frag</blue>: <cyan>%d/%d</cyan> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan>",
			vpnPacket.SessionID,
			vpnPacket.SequenceNum,
			vpnPacket.FragmentID+1,
			max(1, int(totalFragments)),
			decision.RequestName,
		)
	}
	assembledQuery, ready, completed := s.collectDNSQueryFragments(
		vpnPacket.SessionID,
		vpnPacket.SequenceNum,
		vpnPacket.Payload,
		vpnPacket.FragmentID,
		totalFragments,
		now,
	)
	if completed {
		return true
	}
	if !ready {
		if s.log != nil && totalFragments == 1 {
			s.log.Debugf(
				"\U0001F9E9 <green>Tunnel DNS Fragment Buffered</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Frag</blue>: <cyan>%d/%d</cyan>",
				vpnPacket.SessionID,
				vpnPacket.SequenceNum,
				vpnPacket.FragmentID+1,
				max(1, int(totalFragments)),
			)
		}
		return true
	}

	run := func() {
		s.processDeferredDNSQuery(
			vpnPacket.SessionID,
			vpnPacket.SequenceNum,
			sessionRecord.DownloadCompression,
			sessionRecord.DownloadMTUBytes,
			assembledQuery,
		)
	}
	if !s.dispatchDeferredSessionPacket(vpnPacket, run) {
		run()
	}
	return true
}

func (s *Server) handleDNSQueryResponseAck(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if sessionRecord == nil || vpnPacket.StreamID != 0 || !vpnPacket.HasSequenceNum {
		return false
	}
	totalFragments := vpnPacket.TotalFragments
	if totalFragments == 0 {
		totalFragments = 1
	}
	// DNS response ACKs are now handled via handleStreamAckPacket logic
	// But we need to make sure the ARQ knows it's a control ACK if it was tracked.
	return s.handleStreamAckPacket(vpnPacket, sessionRecord)
}

func (s *Server) handleStreamSynRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum || sessionRecord == nil {
		return false
	}
	run := func() {
		s.processDeferredStreamSyn(vpnPacket, sessionRecord)
	}
	if !s.dispatchDeferredSessionPacket(vpnPacket, run) {
		run()
	}
	return true
}

func (s *Server) handleSOCKS5SynRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum || sessionRecord == nil {
		return false
	}
	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}
	if record.isRecentlyClosed(vpnPacket.StreamID, time.Now()) {
		record.enqueueOrphanReset(Enums.PACKET_STREAM_RST, vpnPacket.StreamID, 0)
		return true
	}
	run := func() {
		s.processDeferredSOCKS5Syn(vpnPacket, sessionRecord)
	}
	if !s.dispatchDeferredSessionPacket(vpnPacket, run) {
		run()
	}
	return true
}

func (s *Server) mapSOCKSConnectError(err error) uint8 {
	if err == nil {
		return Enums.PACKET_SOCKS5_CONNECT_FAIL
	}

	var upstreamErr *upstreamSOCKS5Error
	if errors.As(err, &upstreamErr) {
		return upstreamErr.packetType
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return Enums.PACKET_SOCKS5_HOST_UNREACHABLE
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Timeout() {
		return Enums.PACKET_SOCKS5_TTL_EXPIRED
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return Enums.PACKET_SOCKS5_TTL_EXPIRED
	}

	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "connection refused"):
		return Enums.PACKET_SOCKS5_CONNECTION_REFUSED
	case strings.Contains(message, "network is unreachable"):
		return Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE
	case strings.Contains(message, "no route to host"),
		strings.Contains(message, "host is unreachable"),
		strings.Contains(message, "no such host"):
		return Enums.PACKET_SOCKS5_HOST_UNREACHABLE
	case strings.Contains(message, "i/o timeout"),
		strings.Contains(message, "timed out"):
		return Enums.PACKET_SOCKS5_TTL_EXPIRED
	default:
		return Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE
	}
}

func (s *Server) handleStreamDataRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum || sessionRecord == nil {
		return false
	}
	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}
	if _, exists := record.getStream(vpnPacket.StreamID); !exists {
		return s.enqueueMissingStreamReset(record, vpnPacket)
	}
	run := func() {
		s.processDeferredStreamData(vpnPacket, sessionRecord)
	}
	if !s.dispatchDeferredSessionPacket(vpnPacket, run) {
		run()
	}
	return true
}

func (s *Server) handleStreamFinRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}
	stream, exists := record.getStream(vpnPacket.StreamID)
	if !exists || stream == nil {
		return s.enqueueMissingStreamReset(record, vpnPacket)
	}
	stream.ARQ.MarkFinReceived(vpnPacket.SequenceNum)
	return true
}

func (s *Server) handleStreamRSTRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}

	now := time.Now()
	stream, ok := record.getStream(vpnPacket.StreamID)
	if ok && stream != nil {
		stream.ARQ.MarkRstReceived(vpnPacket.SequenceNum)
		// A peer-originated reset is terminal immediately. Do not route it through the
		// server's local-abort path, otherwise pending server data can incorrectly defer
		// a fresh STREAM_RST even though the peer already cancelled the stream.
		stream.ARQ.Abort("peer reset before/while connect", false)
		stream.mu.Lock()
		stream.Status = "CLOSED"
		stream.CloseTime = now
		stream.mu.Unlock()
		record.removeStream(vpnPacket.StreamID, now)
	} else {
		record.noteStreamClosed(vpnPacket.StreamID, now)
	}

	s.removeSOCKS5SynFragmentsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
	s.removeStreamDataFragmentsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
	return true
}

func (s *Server) handleStreamAckPacket(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}
	stream, exists := record.getStream(vpnPacket.StreamID)
	if !exists || stream == nil {
		return s.enqueueMissingStreamReset(record, vpnPacket)
	}

	if vpnPacket.PacketType == Enums.PACKET_STREAM_DATA_ACK {
		stream.ARQ.ReceiveAck(vpnPacket.SequenceNum)
	} else {
		stream.ARQ.ReceiveControlAck(vpnPacket.PacketType, vpnPacket.SequenceNum, vpnPacket.FragmentID)
	}

	// Update legacy state for visibility (removed)
	now := time.Now()

	if vpnPacket.PacketType == Enums.PACKET_STREAM_RST_ACK {
		s.removeStreamDataFragmentsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
		record.removeStream(vpnPacket.StreamID, now)
	} else if vpnPacket.PacketType == Enums.PACKET_STREAM_FIN_ACK {
		// If ARQ considers it done, we can remove it.
		if stream.ARQ.IsClosed() {
			record.removeStream(vpnPacket.StreamID, now)
		}
	}

	return true
}

func (s *Server) handleSocksAckPacket(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if sessionRecord == nil || !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}

	stream, exists := record.getStream(vpnPacket.StreamID)
	if !exists || stream == nil || stream.ARQ == nil {
		return s.enqueueMissingStreamReset(record, vpnPacket)
	}

	stream.ARQ.ReceiveControlAck(vpnPacket.PacketType, vpnPacket.SequenceNum, vpnPacket.FragmentID)
	return true
}

func (s *Server) expireStalledOutboundStreams(sessionID uint8, now time.Time) {
	// Refactored: STALLED streams are now handled by ARQ's inactivityTimeout and maxRetries internally.
	// This function remains to support legacy cleanup if needed, but primary logic is moved to ARQ.
}
