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
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/compression"
	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	"masterdnsvpn-go/internal/domainmatcher"
	ENUMS "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	VPNProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	mtuProbeModeRaw    = 0
	mtuProbeModeBase64 = 1
	mtuProbeCodeLength = 4
	mtuProbeMetaLength = mtuProbeCodeLength + 2
	sessionAcceptSize  = 7
)

type Server struct {
	cfg                     config.ServerConfig
	log                     *logger.Logger
	codec                   *security.Codec
	domainMatcher           *domainmatcher.Matcher
	sessions                *sessionStore
	uploadCompressionMask   uint8
	downloadCompressionMask uint8
	packetPool              sync.Pool
	droppedPackets          atomic.Uint64
	lastDropLogUnix         atomic.Int64
}

type request struct {
	buf  []byte
	size int
	addr *net.UDPAddr
}

func New(cfg config.ServerConfig, log *logger.Logger, codec *security.Codec) *Server {
	return &Server{
		cfg:                     cfg,
		log:                     log,
		codec:                   codec,
		domainMatcher:           domainmatcher.New(cfg.Domain, cfg.MinVPNLabelLength),
		sessions:                newSessionStore(),
		uploadCompressionMask:   buildCompressionMask(cfg.SupportedUploadCompressionTypes),
		downloadCompressionMask: buildCompressionMask(cfg.SupportedDownloadCompressionTypes),
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
		s.log.Warnf("⚠️ <yellow>UDP Read Buffer Setup Failed</yellow> <magenta>|</magenta> <cyan>%v</cyan>", err)
	}
	if err := conn.SetWriteBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("⚠️ <yellow>UDP Write Buffer Setup Failed</yellow> <magenta>|</magenta> <cyan>%v</cyan>", err)
	}

	s.log.Infof(
		"🛰️ <green>UDP Listener Ready</green> <magenta>|</magenta> <blue>Addr</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Readers</blue>: <magenta>%d</magenta> <magenta>|</magenta> <blue>Workers</blue>: <magenta>%d</magenta> <magenta>|</magenta> <blue>Queue</blue>: <magenta>%d</magenta>",
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

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			expired := s.sessions.Cleanup(now, s.cfg.SessionTimeout(), s.cfg.ClosedSessionRetention())
			if len(expired) == 0 {
				continue
			}
			s.log.Infof(
				"🧹 <green>Expired Sessions Cleaned</green> <magenta>|</magenta> <blue>Count</blue>: <cyan>%d</cyan>",
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
				"📥 <yellow>UDP Read Error</yellow> <magenta>|</magenta> <blue>Reader</blue>: <cyan>%d</cyan> <magenta>|</magenta> <cyan>%v</cyan>",
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

			payload := req.buf[:req.size]
			response := s.handlePacket(payload)
			if len(response) == 0 {
				s.packetPool.Put(req.buf)
				continue
			}

			if _, err := conn.WriteToUDP(response, req.addr); err != nil {
				s.log.Debugf(
					"📤 <yellow>UDP Write Error</yellow> <magenta>|</magenta> <blue>Worker</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Remote</blue>: <cyan>%s</cyan> <magenta>|</magenta> <cyan>%v</cyan>",
					workerID,
					req.addr.String(),
					err,
				)
				s.packetPool.Put(req.buf)
				continue
			}

			s.packetPool.Put(req.buf)
		}
	}
}

func (s *Server) handlePacket(packet []byte) []byte {
	if !DnsParser.LooksLikeDNSRequest(packet) {
		return nil
	}

	parsed, err := DnsParser.ParsePacketLite(packet)
	if err != nil {
		response, responseErr := DnsParser.BuildFormatErrorResponse(packet)
		if responseErr == nil {
			return response
		}
		return nil
	}

	if !parsed.HasQuestion {
		response, responseErr := DnsParser.BuildFormatErrorResponse(packet)
		if responseErr == nil {
			return response
		}
		return nil
	}

	decision := s.domainMatcher.Match(parsed)
	switch decision.Action {
	case domainmatcher.ActionProcess:
		return s.handleTunnelCandidate(packet, parsed, decision)
	case domainmatcher.ActionFormatError:
		response, responseErr := DnsParser.BuildFormatErrorResponseFromLite(packet, parsed)
		if responseErr == nil {
			return response
		}
		return nil
	case domainmatcher.ActionNoData:
		response, responseErr := DnsParser.BuildEmptyNoErrorResponseFromLite(packet, parsed)
		if responseErr == nil {
			return response
		}
		return nil
	default:
		return nil
	}
}

func (s *Server) handleTunnelCandidate(packet []byte, parsed DnsParser.LitePacket, decision domainmatcher.Decision) []byte {
	vpnPacket, err := VPNProto.ParseFromLabels(decision.Labels, s.codec)
	if err != nil {
		response, responseErr := DnsParser.BuildEmptyNoErrorResponseFromLite(packet, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}
	vpnPacket, err = VPNProto.InflatePayload(vpnPacket)
	if err != nil {
		response, responseErr := DnsParser.BuildEmptyNoErrorResponseFromLite(packet, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	switch vpnPacket.PacketType {
	case ENUMS.PacketSessionInit:
		return s.handleSessionInitRequest(packet, decision, vpnPacket)
	case ENUMS.PacketMTUUpReq:
		return s.handleMTUUpRequest(packet, parsed, decision, vpnPacket)
	case ENUMS.PacketMTUDownReq:
		return s.handleMTUDownRequest(packet, parsed, decision, vpnPacket)
	default:
		response, responseErr := DnsParser.BuildEmptyNoErrorResponseFromLite(packet, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}
}

func (s *Server) handleSessionInitRequest(questionPacket []byte, decision domainmatcher.Decision, vpnPacket VPNProto.Packet) []byte {
	if vpnPacket.SessionID != 0 {
		return nil
	}
	requestedUpload, requestedDownload := compression.SplitPair(vpnPacket.Payload[1])
	resolvedUpload := resolveCompressionType(requestedUpload, s.uploadCompressionMask)
	resolvedDownload := resolveCompressionType(requestedDownload, s.downloadCompressionMask)

	record, _, err := s.sessions.findOrCreate(vpnPacket.Payload, resolvedUpload, resolvedDownload)
	if err != nil || record == nil {
		return nil
	}

	responsePayload := make([]byte, sessionAcceptSize)
	responsePayload[0] = record.ID
	responsePayload[1] = record.Cookie
	responsePayload[2] = compression.PackPair(record.UploadCompression, record.DownloadCompression)
	copy(responsePayload[3:], record.VerifyCode[:])

	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, decision.RequestName, VPNProto.Packet{
		SessionID:  0,
		PacketType: ENUMS.PacketSessionAccept,
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
	requested = compression.NormalizeType(requested)
	if allowedMask&(1<<requested) != 0 {
		return requested
	}
	return compression.TypeOff
}

func (s *Server) onDrop(addr *net.UDPAddr) {
	total := s.droppedPackets.Add(1)

	now := logger.NowUnixNano()
	last := s.lastDropLogUnix.Load()
	interval := s.cfg.DropLogInterval().Nanoseconds()
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
		"🚧 <yellow>Request Queue Overloaded</yellow> <magenta>|</magenta> <blue>Dropped</blue>: <magenta>%d</magenta> <magenta>|</magenta> <blue>Remote</blue>: <cyan>%s</cyan>",
		total,
		addr.String(),
	)
}

func (s *Server) handleMTUUpRequest(questionPacket []byte, _ DnsParser.LitePacket, decision domainmatcher.Decision, vpnPacket VPNProto.Packet) []byte {
	if len(vpnPacket.Payload) < 1+mtuProbeCodeLength {
		return nil
	}

	baseEncode := vpnPacket.Payload[0] == mtuProbeModeBase64
	if vpnPacket.Payload[0] != mtuProbeModeRaw && vpnPacket.Payload[0] != mtuProbeModeBase64 {
		return nil
	}
	probeCode := vpnPacket.Payload[1 : 1+mtuProbeCodeLength]
	responsePayload := make([]byte, mtuProbeMetaLength)
	copy(responsePayload, probeCode)
	binary.BigEndian.PutUint16(responsePayload[mtuProbeCodeLength:], uint16(len(vpnPacket.Payload)))
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, decision.RequestName, VPNProto.Packet{
		SessionID:  vpnPacket.SessionID,
		PacketType: ENUMS.PacketMTUUpRes,
		Payload:    responsePayload,
	}, baseEncode)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) handleMTUDownRequest(questionPacket []byte, _ DnsParser.LitePacket, decision domainmatcher.Decision, vpnPacket VPNProto.Packet) []byte {
	if len(vpnPacket.Payload) < 1+mtuProbeCodeLength+2 {
		return nil
	}

	baseEncode := vpnPacket.Payload[0] == mtuProbeModeBase64
	if vpnPacket.Payload[0] != mtuProbeModeRaw && vpnPacket.Payload[0] != mtuProbeModeBase64 {
		return nil
	}
	downloadSize := int(binary.BigEndian.Uint16(vpnPacket.Payload[1+mtuProbeCodeLength : 1+mtuProbeCodeLength+2]))
	if downloadSize < 30 || downloadSize > 4096 {
		return nil
	}

	probeCode := vpnPacket.Payload[1 : 1+mtuProbeCodeLength]
	payload := make([]byte, downloadSize)
	copy(payload, probeCode)
	binary.BigEndian.PutUint16(payload[mtuProbeCodeLength:], uint16(downloadSize))
	if downloadSize > mtuProbeMetaLength {
		if _, err := rand.Read(payload[mtuProbeMetaLength:]); err != nil {
			return nil
		}
	}

	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, decision.RequestName, VPNProto.Packet{
		SessionID:      vpnPacket.SessionID,
		PacketType:     ENUMS.PacketMTUDownRes,
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
