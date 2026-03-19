// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/compression"
	"masterdnsvpn-go/internal/config"
	dnsCache "masterdnsvpn-go/internal/dnscache"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	SocksProto "masterdnsvpn-go/internal/socksproto"
	streamUtil "masterdnsvpn-go/internal/streamutil"
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
	streams                  *streamStateStore
	streamOutbound           *streamOutboundStore
	invalidCookieTracker     *invalidCookieTracker
	dnsCache                 *dnsCache.Store
	dnsResolveInflight       *dnsResolveInflightManager
	dnsUpstreamServers       []string
	dnsUpstreamBufferPool    sync.Pool
	dnsFragmentMu            sync.Mutex
	dnsFragments             map[dnsFragmentKey]*dnsFragmentEntry
	resolveDNSQueryFn        func([]byte) ([]byte, error)
	dialStreamUpstreamFn     func(string, string, time.Duration) (net.Conn, error)
	uploadCompressionMask    uint8
	downloadCompressionMask  uint8
	dropLogIntervalNanos     int64
	invalidCookieWindow      time.Duration
	invalidCookieWindowNanos int64
	invalidCookieThreshold   int
	socksConnectTimeout      time.Duration
	streamOutboundTTL        time.Duration
	streamOutboundMaxRetry   int
	mtuProbePayloadPool      sync.Pool
	mtuProbeFillPattern      [256]byte
	packetPool               sync.Pool
	droppedPackets           atomic.Uint64
	lastDropLogUnix          atomic.Int64
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
	return &Server{
		cfg:                  cfg,
		log:                  log,
		codec:                codec,
		domainMatcher:        domainMatcher.New(cfg.Domain, cfg.MinVPNLabelLength),
		sessions:             newSessionStore(),
		streams:              newStreamStateStore(),
		streamOutbound:       newStreamOutboundStore(cfg.StreamOutboundWindow, cfg.StreamOutboundQueueLimit),
		invalidCookieTracker: newInvalidCookieTracker(),
		dnsCache: dnsCache.New(
			cfg.DNSCacheMaxRecords,
			time.Duration(cfg.DNSCacheTTLSeconds*float64(time.Second)),
			cfg.DNSFragmentAssemblyTimeout(),
		),
		dnsResolveInflight: newDNSResolveInflightManager(cfg.DNSFragmentAssemblyTimeout()),
		dnsUpstreamServers: append([]string(nil), cfg.DNSUpstreamServers...),
		dnsFragments:       make(map[dnsFragmentKey]*dnsFragmentEntry, 32),
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
		dropLogIntervalNanos:     cfg.DropLogInterval().Nanoseconds(),
		invalidCookieWindow:      invalidCookieWindow,
		invalidCookieWindowNanos: invalidCookieWindow.Nanoseconds(),
		invalidCookieThreshold:   cfg.InvalidCookieErrorThreshold,
		socksConnectTimeout:      cfg.SOCKSConnectTimeout(),
		streamOutboundTTL:        cfg.StreamOutboundTTL(),
		streamOutboundMaxRetry:   cfg.StreamOutboundMaxRetries,
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
		s.log.Warnf("⚠️ <yellow>UDP Read Buffer Setup Failed, <cyan>%v</cyan></yellow>", err)
	}

	if err := conn.SetWriteBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("⚠️ <yellow>UDP Write Buffer Setup Failed, <cyan>%v</cyan></yellow>", err)
	}

	s.log.Infof(
		"🛰️ <green>UDP Listener Ready, Addr: <cyan>%s</cyan>, Readers: <cyan>%d</cyan>, Workers: <cyan>%d</cyan>, Queue: <cyan>%d</cyan></green>",
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
			s.invalidCookieTracker.Cleanup(now, invalidCookieWindow)
			s.purgeDNSQueryFragments(now)
			if len(expired) == 0 {
				continue
			}
			for _, sessionID := range expired {
				s.streams.RemoveSession(sessionID)
				s.streamOutbound.RemoveSession(sessionID)
			}
			s.log.Infof(
				"🧹 <green>Expired Sessions Cleaned, Count: <cyan>%d</cyan></green>",
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
				"📥 <yellow>UDP Read Error, Reader: <cyan>%d</cyan>, Error: <cyan>%v</cyan></yellow>",
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
						"📤 <yellow>UDP Write Error, Worker: <cyan>%d</cyan>, Remote: <cyan>%v</cyan>, Error: <cyan>%v</cyan></yellow>",
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
					"💥 <red>Packet Handler Panic Recovered, <yellow>%v</yellow></red>",
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
		if errors.Is(err, DnsParser.ErrNotDNSRequest) || errors.Is(err, DnsParser.ErrPacketTooShort) {
			return nil
		}

		return buildNoDataResponse(packet)
	}

	if !parsed.HasQuestion {
		return buildNoDataResponse(packet)
	}

	decision := s.domainMatcher.Match(parsed)
	if decision.Action == domainMatcher.ActionProcess {
		return s.handleTunnelCandidate(packet, parsed, decision)
	}

	if decision.Action == domainMatcher.ActionFormatError || decision.Action == domainMatcher.ActionNoData {
		return buildNoDataResponseLite(packet, parsed)
	}

	return nil
}

func (s *Server) handleTunnelCandidate(packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision) []byte {
	vpnPacket, err := VpnProto.ParseInflatedFromLabels(decision.Labels, s.codec)
	if err != nil {
		return buildNoDataResponseLite(packet, parsed)
	}

	var sessionRecord *sessionRuntimeView
	if !isPreSessionRequestType(vpnPacket.PacketType) {
		validation := s.validatePostSessionPacket(packet, decision.RequestName, vpnPacket)
		if !validation.ok {
			return validation.response
		}

		sessionRecord = validation.record
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_SESSION_INIT:
		return s.handleSessionInitRequest(packet, decision, vpnPacket)
	case Enums.PACKET_MTU_UP_REQ:
		return s.handleMTUUpRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_MTU_DOWN_REQ:
		return s.handleMTUDownRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_PING:
		return s.handlePingRequest(packet, decision, vpnPacket, sessionRecord)
	case Enums.PACKET_DNS_QUERY_REQ:
		return s.handleDNSQueryRequest(packet, parsed, decision, vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_SYN:
		return s.handleStreamSynRequest(packet, decision, vpnPacket, sessionRecord)
	case Enums.PACKET_SOCKS5_SYN:
		return s.handleSOCKS5SynRequest(packet, decision, vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND:
		return s.handleStreamDataRequest(packet, decision, vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_FIN:
		return s.handleStreamFinRequest(packet, decision, vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_RST:
		return s.handleStreamRSTRequest(packet, decision, vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_FIN_ACK, Enums.PACKET_STREAM_RST_ACK, Enums.PACKET_STREAM_SYN_ACK:
		return s.handleStreamAckPacket(packet, decision, vpnPacket, sessionRecord)
	default:
		return buildNoDataResponseLite(packet, parsed)
	}
}

func (s *Server) validatePostSessionPacket(questionPacket []byte, requestName string, vpnPacket VpnProto.Packet) postSessionValidation {
	now := time.Now()
	validation := s.sessions.ValidateAndTouch(vpnPacket.SessionID, vpnPacket.SessionCookie, now)
	if validation.Valid {
		return postSessionValidation{
			record: validation.Active,
			ok:     true,
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

	if !validation.Known {
		return postSessionValidation{}
	}

	return postSessionValidation{
		response: s.buildInvalidSessionErrorResponse(questionPacket, requestName, vpnPacket.SessionID, validation.Lookup.ResponseMode),
	}
}

func (s *Server) logInvalidSessionThreshold(sessionID uint8, receivedCookie uint8, lookup sessionLookupResult, known bool) {
	if !known {
		s.log.Debugf(
			"🧷 <yellow>Unknown Session Cookie Threshold Reached, Session: <cyan>%d</cyan>, Received: <cyan>%d</cyan></yellow>",
			sessionID,
			receivedCookie,
		)
		return
	}

	if lookup.State == sessionLookupClosed {
		s.log.Debugf(
			"🧷 <yellow>Stale Closed Session Cookie Threshold Reached, Session: <cyan>%d</cyan>, Expected: <cyan>%d</cyan>, Received: <cyan>%d</cyan></yellow>",
			sessionID,
			lookup.Cookie,
			receivedCookie,
		)
		return
	}

	s.log.Debugf(
		"🧷 <yellow>Invalid Session Cookie Threshold Reached, Session: <cyan>%d</cyan>, Expected: <cyan>%d</cyan>, Received: <cyan>%d</cyan></yellow>",
		sessionID,
		lookup.Cookie,
		receivedCookie,
	)
}

func (s *Server) debugLoggingEnabled() bool {
	return s != nil && s.log != nil && s.log.Enabled(logger.LevelDebug)
}

func buildNoDataResponse(packet []byte) []byte {
	response, err := DnsParser.BuildEmptyNoErrorResponse(packet)
	if err != nil {
		return nil
	}
	return response
}

func buildNoDataResponseLite(packet []byte, parsed DnsParser.LitePacket) []byte {
	response, err := DnsParser.BuildEmptyNoErrorResponseFromLite(packet, parsed)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) buildInvalidSessionErrorResponse(questionPacket []byte, requestName string, sessionID uint8, responseMode uint8) []byte {
	payload := make([]byte, 8)
	payload[0] = 'I'
	payload[1] = 'N'
	payload[2] = 'V'
	if _, err := rand.Read(payload[3:]); err != nil {
		return nil
	}

	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, requestName, VpnProto.Packet{
		SessionID:  sessionID,
		PacketType: Enums.PACKET_ERROR_DROP,
		Payload:    payload,
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
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, requestName, packet, record.ResponseMode == mtuProbeModeBase64)
	if err != nil {
		return nil
	}
	return response
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

	record, _, err := s.sessions.findOrCreate(
		vpnPacket.Payload,
		resolvedUpload,
		resolvedDownload,
		s.cfg.MaxPacketsPerBatch,
	)

	if err != nil || record == nil {
		return nil
	}

	responsePayload := make([]byte, sessionAcceptSize)
	responsePayload[0] = record.ID
	responsePayload[1] = record.Cookie
	responsePayload[2] = compression.PackPair(record.UploadCompression, record.DownloadCompression)
	copy(responsePayload[3:], record.VerifyCode[:])

	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, decision.RequestName, VpnProto.Packet{
		SessionID:  0,
		PacketType: Enums.PACKET_SESSION_ACCEPT,
		Payload:    responsePayload,
	}, record.ResponseMode == mtuProbeModeBase64)

	if err != nil {
		return nil
	}

	return response
}

func buildCompressionMask(values []int) uint8 {
	var mask uint8 = 1 << compression.TypeOff
	for _, value := range values {
		if value < compression.TypeOff || value > compression.TypeZLIB || !compression.IsTypeAvailable(uint8(value)) {
			continue
		}
		mask |= 1 << uint8(value)
	}
	return mask
}

func resolveCompressionType(requested uint8, allowedMask uint8) uint8 {
	if requested > compression.TypeZLIB {
		return compression.TypeOff
	}
	if allowedMask&(1<<requested) != 0 {
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
		"🚧 <yellow>Request Queue Overloaded</yellow> <magenta>|</magenta> <blue>Dropped</blue>: <magenta>%d</magenta> <magenta>|</magenta> <blue>Remote</blue>: <cyan>%v</cyan>",
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

func parseMTUProbeBaseEncoding(mode uint8) (bool, bool) {
	switch mode {
	case mtuProbeModeRaw:
		return false, true
	case mtuProbeModeBase64:
		return true, true
	default:
		return false, false
	}
}

func buildMTUProbeMetaPayload(probeCode []byte, payloadLen int) [mtuProbeMetaLength]byte {
	var payload [mtuProbeMetaLength]byte
	copy(payload[:mtuProbeCodeLength], probeCode)
	binary.BigEndian.PutUint16(payload[mtuProbeCodeLength:], uint16(payloadLen))
	return payload
}

func buildMTUProbeFillPattern() [256]byte {
	var pattern [256]byte
	var state uint32 = 0x9E3779B9
	for i := range pattern {
		state = state*1664525 + 1013904223
		pattern[i] = byte(state >> 24)
	}
	return pattern
}

func fillMTUProbeBytes(dst []byte, pattern []byte) {
	if len(dst) == 0 || len(pattern) == 0 {
		return
	}

	copied := copy(dst, pattern)
	for copied < len(dst) {
		copied += copy(dst[copied:], dst[:copied])
	}
}

func (s *Server) handlePingRequest(questionPacket []byte, decision domainMatcher.Decision, vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) []byte {
	if sessionRecord == nil {
		return nil
	}
	now := time.Now()
	s.expireStalledOutboundStreams(vpnPacket.SessionID, now)
	if queued, ok := s.streamOutbound.Next(vpnPacket.SessionID, now); ok {
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, queued)
	}

	payload := []byte{'P', 'O', ':'}
	randomPart := make([]byte, 4)
	if _, err := rand.Read(randomPart); err != nil {
		return nil
	}
	payload = append(payload, randomPart...)

	return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
		PacketType: Enums.PACKET_PONG,
		Payload:    payload,
	})
}

func (s *Server) handleDNSQueryRequest(questionPacket []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision, vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) []byte {
	if sessionRecord == nil {
		return nil
	}
	now := time.Now()

	if vpnPacket.StreamID != 0 || !vpnPacket.HasSequenceNum {
		return nil
	}

	if s.log != nil {
		s.log.Debugf(
			"📨 <green>Tunnel DNS Query Received</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Frag</blue>: <cyan>%d/%d</cyan> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan>",
			vpnPacket.SessionID,
			vpnPacket.SequenceNum,
			vpnPacket.FragmentID+1,
			max(1, int(vpnPacket.TotalFragments)),
			decision.RequestName,
		)
	}

	assembledQuery, ready := s.collectDNSQueryFragments(
		vpnPacket.SessionID,
		vpnPacket.SequenceNum,
		vpnPacket.Payload,
		vpnPacket.FragmentID,
		vpnPacket.TotalFragments,
		now,
	)
	if !ready {
		if s.log != nil {
			s.log.Debugf(
				"🧩 <green>Tunnel DNS Fragment Buffered</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Frag</blue>: <cyan>%d/%d</cyan>",
				vpnPacket.SessionID,
				vpnPacket.SequenceNum,
				vpnPacket.FragmentID+1,
				max(1, int(vpnPacket.TotalFragments)),
			)
		}
		return buildNoDataResponseLite(questionPacket, parsed)
	}

	rawResponse := s.buildDNSQueryResponsePayload(assembledQuery, vpnPacket.SessionID, vpnPacket.SequenceNum)
	if len(rawResponse) == 0 {
		return nil
	}

	return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
		PacketType:      Enums.PACKET_DNS_QUERY_RES,
		StreamID:        0,
		SequenceNum:     vpnPacket.SequenceNum,
		FragmentID:      0,
		TotalFragments:  1,
		CompressionType: sessionRecord.DownloadCompression,
		Payload:         rawResponse,
	})
}

func (s *Server) handleStreamSynRequest(questionPacket []byte, decision domainMatcher.Decision, vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) []byte {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum {
		return nil
	}
	if sessionRecord == nil {
		return nil
	}
	now := time.Now()
	if VpnProto.IsTCPForwardSynPayload(vpnPacket.Payload) {
		if s.cfg.ForwardIP == "" || s.cfg.ForwardPort <= 0 {
			return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
				PacketType:  Enums.PACKET_STREAM_RST,
				StreamID:    vpnPacket.StreamID,
				SequenceNum: vpnPacket.SequenceNum,
			})
		}
		if existing, ok := s.streams.Lookup(vpnPacket.SessionID, vpnPacket.StreamID); ok && existing != nil && existing.Connected && existing.TargetHost == s.cfg.ForwardIP && existing.TargetPort == uint16(s.cfg.ForwardPort) {
			return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
				PacketType:     Enums.PACKET_STREAM_SYN_ACK,
				StreamID:       vpnPacket.StreamID,
				SequenceNum:    vpnPacket.SequenceNum,
				FragmentID:     0,
				TotalFragments: 0,
			})
		}
		s.streams.EnsureOpen(vpnPacket.SessionID, vpnPacket.StreamID, now)
		upstreamConn, err := s.dialSOCKSStreamTarget(s.cfg.ForwardIP, uint16(s.cfg.ForwardPort))
		if err != nil {
			return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
				PacketType:  Enums.PACKET_STREAM_RST,
				StreamID:    vpnPacket.StreamID,
				SequenceNum: vpnPacket.SequenceNum,
			})
		}
		record, ok := s.streams.AttachUpstream(vpnPacket.SessionID, vpnPacket.StreamID, s.cfg.ForwardIP, uint16(s.cfg.ForwardPort), upstreamConn, now)
		if !ok || record == nil {
			streamUtil.SafeClose(upstreamConn)
			return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
				PacketType:  Enums.PACKET_STREAM_RST,
				StreamID:    vpnPacket.StreamID,
				SequenceNum: vpnPacket.SequenceNum,
			})
		}
		s.startStreamUpstreamReadLoop(vpnPacket.SessionID, vpnPacket.StreamID, upstreamConn, sessionRecord.DownloadCompression, int(sessionRecord.DownloadMTU))
	} else {
		s.streams.EnsureOpen(vpnPacket.SessionID, vpnPacket.StreamID, now)
	}
	return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
		PacketType:     Enums.PACKET_STREAM_SYN_ACK,
		StreamID:       vpnPacket.StreamID,
		SequenceNum:    vpnPacket.SequenceNum,
		FragmentID:     0,
		TotalFragments: 0,
	})
}

func (s *Server) handleSOCKS5SynRequest(questionPacket []byte, decision domainMatcher.Decision, vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) []byte {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum {
		return nil
	}
	if sessionRecord == nil {
		return nil
	}
	now := time.Now()

	target, err := SocksProto.ParseTargetPayload(vpnPacket.Payload)
	if err != nil {
		packetType := uint8(Enums.PACKET_SOCKS5_CONNECT_FAIL)
		if errors.Is(err, SocksProto.ErrUnsupportedAddressType) || errors.Is(err, SocksProto.ErrInvalidDomainLength) {
			packetType = uint8(Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED)
		}
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
			PacketType:  packetType,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
	}

	existingRecord, ok := s.streams.Lookup(vpnPacket.SessionID, vpnPacket.StreamID)
	if !ok || existingRecord == nil {
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
			PacketType:  Enums.PACKET_SOCKS5_CONNECT_FAIL,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
	}
	if existingRecord.Connected && existingRecord.TargetHost == target.Host && existingRecord.TargetPort == target.Port {
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
			PacketType:  Enums.PACKET_SOCKS5_SYN_ACK,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
	}
	if existingRecord.Connected && (existingRecord.TargetHost != target.Host || existingRecord.TargetPort != target.Port) {
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
			PacketType:  Enums.PACKET_SOCKS5_CONNECT_FAIL,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
	}

	upstreamConn, err := s.dialSOCKSStreamTarget(target.Host, target.Port)
	if err != nil {
		packetType := s.mapSOCKSConnectError(err)
		if s.log != nil {
			s.log.Debugf(
				"🧦 <yellow>SOCKS5 Upstream Connect Failed</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Target</blue>: <cyan>%s:%d</cyan> <magenta>|</magenta> <blue>Packet</blue>: <yellow>%s</yellow> <magenta>|</magenta> <cyan>%v</cyan>",
				vpnPacket.SessionID,
				vpnPacket.StreamID,
				target.Host,
				target.Port,
				Enums.PacketTypeName(packetType),
				err,
			)
		}
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
			PacketType:  packetType,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
	}

	record, ok := s.streams.AttachUpstream(vpnPacket.SessionID, vpnPacket.StreamID, target.Host, target.Port, upstreamConn, now)
	if !ok || record == nil {
		streamUtil.SafeClose(upstreamConn)
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
			PacketType:  Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
	}
	s.startStreamUpstreamReadLoop(vpnPacket.SessionID, vpnPacket.StreamID, upstreamConn, sessionRecord.DownloadCompression, int(sessionRecord.DownloadMTU))

	if s.log != nil {
		s.log.Debugf(
			"🧦 <green>SOCKS5 Stream Prepared</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Target</blue>: <cyan>%s:%d</cyan>",
			record.SessionID,
			record.StreamID,
			record.TargetHost,
			record.TargetPort,
		)
	}

	return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
		PacketType:  Enums.PACKET_SOCKS5_SYN_ACK,
		StreamID:    vpnPacket.StreamID,
		SequenceNum: vpnPacket.SequenceNum,
	})
}

func (s *Server) dialSOCKSStreamTarget(host string, port uint16) (net.Conn, error) {
	dialFn := s.dialStreamUpstreamFn
	if dialFn == nil {
		dialFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(network, address, timeout)
		}
	}
	timeout := s.socksConnectTimeout
	if timeout <= 0 {
		timeout = s.cfg.SOCKSConnectTimeout()
	}
	return dialFn("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), timeout)
}

func (s *Server) mapSOCKSConnectError(err error) uint8 {
	if err == nil {
		return Enums.PACKET_SOCKS5_CONNECT_FAIL
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

func (s *Server) handleStreamDataRequest(questionPacket []byte, decision domainMatcher.Decision, vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) []byte {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum {
		return nil
	}
	if sessionRecord == nil {
		return nil
	}
	now := time.Now()
	streamRecord, ok, isNew := s.streams.ClassifyInboundData(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now)
	if !ok || streamRecord == nil {
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_RST,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: 0,
		})
	}
	switch streamRecord.State {
	case Enums.STREAM_STATE_OPEN, Enums.STREAM_STATE_HALF_CLOSED_LOCAL, Enums.STREAM_STATE_HALF_CLOSED_REMOTE, Enums.STREAM_STATE_DRAINING, Enums.STREAM_STATE_CLOSING, Enums.STREAM_STATE_TIME_WAIT:
		if !isNew {
			return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
				PacketType:  Enums.PACKET_STREAM_DATA_ACK,
				StreamID:    vpnPacket.StreamID,
				SequenceNum: vpnPacket.SequenceNum,
			})
		}
		if streamRecord.UpstreamConn == nil || !streamRecord.Connected {
			return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
				PacketType:  Enums.PACKET_STREAM_RST,
				StreamID:    vpnPacket.StreamID,
				SequenceNum: 0,
			})
		}
		if _, err := streamRecord.UpstreamConn.Write(vpnPacket.Payload); err != nil {
			if s.log != nil {
				s.log.Debugf(
					"📤 <yellow>Upstream Write Failed</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <cyan>%v</cyan>",
					vpnPacket.SessionID,
					vpnPacket.StreamID,
					err,
				)
			}
			_ = s.streams.MarkReset(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now)
			s.streamOutbound.ClearStream(vpnPacket.SessionID, vpnPacket.StreamID)
			return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
				PacketType:  Enums.PACKET_STREAM_RST,
				StreamID:    vpnPacket.StreamID,
				SequenceNum: 0,
			})
		}
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_DATA_ACK,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
	default:
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_RST,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: 0,
		})
	}
}

func (s *Server) handleStreamFinRequest(questionPacket []byte, decision domainMatcher.Decision, vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) []byte {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum {
		return nil
	}
	if sessionRecord == nil {
		return nil
	}
	now := time.Now()
	if existing, ok, duplicate := s.streams.IsDuplicateRemoteFin(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now); ok && existing != nil && duplicate {
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_FIN_ACK,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: vpnPacket.SequenceNum,
		})
	}
	if _, ok := s.streams.MarkRemoteFin(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now); !ok {
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_RST,
			StreamID:    vpnPacket.StreamID,
			SequenceNum: 0,
		})
	}
	return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_FIN_ACK,
		StreamID:    vpnPacket.StreamID,
		SequenceNum: vpnPacket.SequenceNum,
	})
}

func (s *Server) handleStreamRSTRequest(questionPacket []byte, decision domainMatcher.Decision, vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) []byte {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum {
		return nil
	}
	if sessionRecord == nil {
		return nil
	}
	now := time.Now()
	_ = s.streams.MarkReset(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now)
	s.streamOutbound.ClearStream(vpnPacket.SessionID, vpnPacket.StreamID)
	return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_RST_ACK,
		StreamID:    vpnPacket.StreamID,
		SequenceNum: vpnPacket.SequenceNum,
	})
}

func (s *Server) handleStreamAckPacket(questionPacket []byte, decision domainMatcher.Decision, vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) []byte {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || !vpnPacket.HasSequenceNum {
		return nil
	}
	if sessionRecord == nil {
		return nil
	}
	now := time.Now()
	switch vpnPacket.PacketType {
	case Enums.PACKET_STREAM_RST_ACK:
		_ = s.streams.MarkReset(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now)
		s.streamOutbound.Ack(vpnPacket.SessionID, vpnPacket.PacketType, vpnPacket.StreamID, vpnPacket.SequenceNum)
		s.streamOutbound.ClearStream(vpnPacket.SessionID, vpnPacket.StreamID)
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_FIN_ACK, Enums.PACKET_STREAM_SYN_ACK:
		_, _ = s.streams.Touch(vpnPacket.SessionID, vpnPacket.StreamID, vpnPacket.SequenceNum, now)
		s.streamOutbound.Ack(vpnPacket.SessionID, vpnPacket.PacketType, vpnPacket.StreamID, vpnPacket.SequenceNum)
	}
	s.expireStalledOutboundStreams(vpnPacket.SessionID, now)
	if queued, ok := s.streamOutbound.Next(vpnPacket.SessionID, now); ok {
		return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, queued)
	}
	return s.buildSessionVPNResponse(questionPacket, decision.RequestName, sessionRecord, VpnProto.Packet{
		PacketType: Enums.PACKET_PONG,
		Payload:    []byte("PO:ack"),
	})
}

func (s *Server) expireStalledOutboundStreams(sessionID uint8, now time.Time) {
	if s == nil {
		return
	}
	expired := s.streamOutbound.ExpireStalled(sessionID, now, s.streamOutboundMaxRetry, s.streamOutboundTTL)
	for _, streamID := range expired {
		sequenceNum, ok := s.streams.NextOutboundSequence(sessionID, streamID, now)
		if !ok {
			continue
		}
		_ = s.streams.MarkReset(sessionID, streamID, sequenceNum, now)
		_ = s.streamOutbound.Enqueue(sessionID, VpnProto.Packet{
			PacketType:  Enums.PACKET_STREAM_RST,
			StreamID:    streamID,
			SequenceNum: sequenceNum,
		})
		if s.log != nil {
			s.log.Warnf(
				"🚧 <yellow>Stream ARQ Retry Budget Exhausted</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan>",
				sessionID,
				streamID,
			)
		}
	}
}
