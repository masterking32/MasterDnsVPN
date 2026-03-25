// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"encoding/binary"
	"time"

	"masterdnsvpn-go/internal/arq"
	"masterdnsvpn-go/internal/compression"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func (s *Server) validatePostSessionPacket(questionPacket []byte, requestName string, vpnPacket VpnProto.Packet) postSessionValidation {
	now := time.Now()
	validation := s.sessions.ValidateAndTouch(vpnPacket.SessionID, vpnPacket.SessionCookie, now)
	if validation.Valid {
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
		if s.debugLoggingEnabled() {
			s.log.Debugf(
				"\U0001F6AA <yellow>Session close rejected <magenta>|</magenta> Session: <cyan>%d</cyan> <magenta>|</magenta> Known: <cyan>%t</cyan> <magenta>|</magenta> Cookie match: <cyan>%t</cyan></yellow>",
				vpnPacket.SessionID, known, known && lookup.Cookie == vpnPacket.SessionCookie,
			)
		}
		return
	}

	record, ok := s.sessions.Close(vpnPacket.SessionID, now, s.cfg.ClosedSessionRetention())
	if !ok {
		return
	}

	s.cleanupClosedSession(vpnPacket.SessionID, record)
	if s.log != nil {
		s.log.Infof(
			"\U0001F6AA <green>Session Closed By Client, Session: <cyan>%d</cyan></green>",
			vpnPacket.SessionID,
		)
	}
}

func (s *Server) logInvalidSessionDrop(reason string, sessionID uint8, receivedCookie uint8, expectedCookie uint8, responseMode uint8) {
	if !s.debugLoggingEnabled() {
		return
	}
	if expectedCookie == 0 {
		s.log.Debugf(
			"\U0001F44B <yellow>Sending Session Drop</yellow> <magenta>|</magenta> <blue>Reason</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Received</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Mode</blue>: <cyan>%s</cyan>",
			reason,
			sessionID,
			receivedCookie,
			sessionResponseModeName(responseMode),
		)
		return
	}
	s.log.Debugf(
		"\U0001F44B <yellow>Sending Session Drop</yellow> <magenta>|</magenta> <blue>Reason</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Expected</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Received</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Mode</blue>: <cyan>%s</cyan>",
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
	record, ok := s.sessions.Get(sessionID)
	if !ok {
		return false
	}

	if packet.StreamID == 0 {
		record.ensureStream0(s.log)
		stream, exists := record.getStream(0)
		if !exists || stream == nil {
			return false
		}
		return stream.PushTXPacket(getEffectivePriority(packet.PacketType, 3), packet.PacketType, packet.SequenceNum, packet.FragmentID, packet.TotalFragments, packet.CompressionType, 0, packet.Payload)
	}

	stream, exists := record.getStream(packet.StreamID)
	if !exists || stream == nil {
		return false
	}

	return stream.PushTXPacket(getEffectivePriority(packet.PacketType, 3), packet.PacketType, packet.SequenceNum, packet.FragmentID, packet.TotalFragments, packet.CompressionType, 0, packet.Payload)
}

func (s *Server) streamARQConfig(compressionType uint8) arq.Config {
	return arq.Config{
		WindowSize:               s.cfg.ARQWindowSize,
		RTO:                      s.cfg.ARQInitialRTOSeconds,
		MaxRTO:                   s.cfg.ARQMaxRTOSeconds,
		EnableControlReliability: true,
		ControlRTO:               s.cfg.ARQControlInitialRTOSeconds,
		ControlMaxRTO:            s.cfg.ARQControlMaxRTOSeconds,
		ControlMaxRetries:        s.cfg.ARQMaxControlRetries,
		InactivityTimeout:        s.cfg.ARQInactivityTimeoutSeconds,
		DataPacketTTL:            s.cfg.ARQDataPacketTTLSeconds,
		MaxDataRetries:           s.cfg.ARQMaxDataRetries,
		DataNackMaxGap:           s.cfg.ARQDataNackMaxGap,
		DataNackRepeatSeconds:    s.cfg.ARQDataNackRepeatSeconds,
		ControlPacketTTL:         s.cfg.ARQControlPacketTTLSeconds,
		TerminalDrainTimeout:     s.cfg.ARQTerminalDrainTimeoutSec,
		TerminalAckWaitTimeout:   s.cfg.ARQTerminalAckWaitTimeoutSec,
		CompressionType:          compressionType,
	}
}

func (s *Server) queueMainSessionPacket(sessionID uint8, packet VpnProto.Packet) bool {
	packet.StreamID = 0
	return s.queueSessionPacket(sessionID, packet)
}

func (s *Server) cleanupClosedSession(sessionID uint8, record *sessionRecord) {
	if s == nil || sessionID == 0 {
		return
	}
	s.clearDeferredPacketsForSession(sessionID)
	s.removeSOCKS5SynFragmentsForSession(sessionID)
	if record != nil {
		record.closeAllStreams("session closed cleanup")
	}
	if s.deferredDNSSession != nil {
		s.deferredDNSSession.RemoveSession(sessionID)
	}
	if s.deferredConnectSession != nil {
		s.deferredConnectSession.RemoveSession(sessionID)
	}
	s.removeDNSQueryFragmentsForSession(sessionID)
}

func (s *Server) cleanupStreamArtifacts(sessionID uint8, streamID uint16) {
	if s == nil || sessionID == 0 || streamID == 0 {
		return
	}
	s.clearDeferredPacketsForStream(sessionID, streamID)
	s.removeSOCKS5SynFragmentsForStream(sessionID, streamID)
}

func (s *Server) serveQueuedOrPong(questionPacket []byte, requestName string, record *sessionRuntimeView, now time.Time) []byte {
	if record == nil {
		return nil
	}
	sessionID := record.ID

	if pkt, ok := s.dequeueSessionResponse(sessionID, now); ok {
		return s.buildSessionVPNResponse(questionPacket, requestName, record, *pkt)
	}

	payload := s.nextPongPayload()
	return s.buildSessionVPNResponse(questionPacket, requestName, record, VpnProto.Packet{
		PacketType: Enums.PACKET_PONG,
		Payload:    payload[:],
	})
}

func (s *Server) dequeueSessionResponse(sessionID uint8, now time.Time) (*VpnProto.Packet, bool) {
	record, ok := s.sessions.Get(sessionID)
	if !ok {
		return nil, false
	}

	record.mu.Lock()
	if pkt, ok := s.dequeueDuplicatedPackedControlBlock(record); ok {
		record.mu.Unlock()
		return pkt, true
	}
	rrStreamID := record.RRStreamID
	record.mu.Unlock()

	activeIDs, activeStreams := record.activeStreamSnapshot()
	hasOrphan := record.OrphanQueue != nil && record.OrphanQueue.Size() > 0
	totalCandidates := len(activeIDs)
	if hasOrphan {
		totalCandidates++
	}
	if totalCandidates == 0 {
		return nil, false
	}

	startIdx := 0
	candidateAt := func(idx int) (int32, *Stream_server) {
		if hasOrphan {
			if idx == 0 {
				return -1, nil
			}
			idx--
		}
		if idx < 0 || idx >= len(activeIDs) {
			return 0, nil
		}
		return activeIDs[idx], activeStreams[idx]
	}

	for i := 0; i < totalCandidates; i++ {
		id, _ := candidateAt(i)
		if id >= rrStreamID {
			startIdx = i
			break
		}
	}

	for i := 0; i < totalCandidates; i++ {
		idx := (startIdx + i) % totalCandidates
		id, stream := candidateAt(idx)

		var item *serverStreamTXPacket
		var ok bool
		var selectedStreamID uint16

		if id == -1 {
			p, _, popOk := record.OrphanQueue.Pop(func(p VpnProto.Packet) uint64 {
				return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
			})
			if popOk {
				item = &serverStreamTXPacket{
					PacketType:     p.PacketType,
					SequenceNum:    p.SequenceNum,
					FragmentID:     p.FragmentID,
					TotalFragments: p.TotalFragments,
					Payload:        p.Payload,
				}
				selectedStreamID = p.StreamID
				ok = true
			}
		} else {
			if stream == nil || stream.TXQueue == nil {
				continue
			}
			if stream.ARQ != nil && stream.ARQ.IsClosed() {
				stream.ClearTXQueue()
				record.deactivateStream(uint16(id))
				continue
			}
			var popped *serverStreamTXPacket
			popped, _, ok = stream.TXQueue.Pop(func(p *serverStreamTXPacket) uint64 {
				return Enums.PacketIdentityKey(uint16(id), p.PacketType, p.SequenceNum, p.FragmentID)
			})
			if ok {
				stream.NoteTXPacketDequeued(popped)
				if (popped.PacketType == Enums.PACKET_STREAM_DATA || popped.PacketType == Enums.PACKET_STREAM_RESEND) &&
					stream.ARQ != nil && !stream.ARQ.HasPendingSequence(popped.SequenceNum) {
					putTXPacketToPool(popped)
					continue
				}
				item = popped
				selectedStreamID = uint16(id)
			}
		}

		if ok && item != nil {
			record.mu.Lock()
			record.RRStreamID = id + 1
			if VpnProto.IsPackableControlPacket(item.PacketType, len(item.Payload)) && record.MaxPackedBlocks > 1 {
				pkt := s.packControlBlocks(record, item, id, selectedStreamID)
				s.cachePackedControlBlockDuplicate(record, pkt)
				record.mu.Unlock()
				return pkt, true
			}
			record.mu.Unlock()
			pkt := vpnPacketFromTX(item, selectedStreamID)
			if id != -1 {
				putTXPacketToPool(item)
			}
			return &pkt, true
		}
	}

	return nil, false
}

func cloneVPNPacket(packet *VpnProto.Packet) *VpnProto.Packet {
	if packet == nil {
		return nil
	}
	cloned := *packet
	if len(packet.Payload) > 0 {
		cloned.Payload = append([]byte(nil), packet.Payload...)
	}
	return &cloned
}

func (s *Server) dequeueDuplicatedPackedControlBlock(record *sessionRecord) (*VpnProto.Packet, bool) {
	if s == nil || record == nil || record.LastPackedControlBlock == nil || record.LastPackedControlBlockRemaining <= 0 {
		return nil, false
	}
	packet := cloneVPNPacket(record.LastPackedControlBlock)
	record.LastPackedControlBlockRemaining--
	if record.LastPackedControlBlockRemaining <= 0 {
		record.LastPackedControlBlock = nil
		record.LastPackedControlBlockRemaining = 0
	}
	return packet, packet != nil
}

func (s *Server) cachePackedControlBlockDuplicate(record *sessionRecord, packet *VpnProto.Packet) {
	if s == nil || record == nil {
		return
	}
	duplication := s.cfg.PacketBlockControlDuplication
	if duplication <= 1 || packet == nil || packet.PacketType != Enums.PACKET_PACKED_CONTROL_BLOCKS {
		record.LastPackedControlBlock = nil
		record.LastPackedControlBlockRemaining = 0
		return
	}
	record.LastPackedControlBlock = cloneVPNPacket(packet)
	record.LastPackedControlBlockRemaining = duplication - 1
}

func (s *Server) packControlBlocks(record *sessionRecord, first *serverStreamTXPacket, initialID int32, initialStreamID uint16) *VpnProto.Packet {
	limit := record.MaxPackedBlocks
	if limit <= 1 {
		pkt := vpnPacketFromTX(first, initialStreamID)
		return &pkt
	}

	payload := make([]byte, 0, limit*VpnProto.PackedControlBlockSize)
	payload = VpnProto.AppendPackedControlBlock(payload, first.PacketType, initialStreamID, first.SequenceNum, first.FragmentID, first.TotalFragments)
	blocks := 1

	activeIDs, activeStreams := record.activeStreamSnapshot()
	hasOrphan := record.OrphanQueue != nil && record.OrphanQueue.Size() > 0

	processID := func(id int32, stream *Stream_server) bool {
		if blocks >= limit {
			return true
		}

		if id == -1 {
			for blocks < limit {
				popped, ok := record.OrphanQueue.PopAnyIf(2, func(p VpnProto.Packet) bool {
					return VpnProto.IsPackableControlPacket(p.PacketType, 0)
				}, func(p VpnProto.Packet) uint64 {
					return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
				})
				if !ok {
					return false
				}
				payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, popped.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
				blocks++
			}
			return false
		}

		if stream == nil || stream.TXQueue == nil {
			return false
		}

		for blocks < limit {
			popped, ok := stream.TXQueue.PopAnyIf(2, func(p *serverStreamTXPacket) bool {
				return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
			}, func(p *serverStreamTXPacket) uint64 {
				return Enums.PacketIdentityKey(uint16(id), p.PacketType, p.SequenceNum, p.FragmentID)
			})
			if !ok {
				return false
			}
			stream.NoteTXPacketDequeued(popped)
			payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, uint16(id), popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
			blocks++
			putTXPacketToPool(popped)
		}
		return false
	}

	var initialStream *Stream_server
	var initialIndex int = -1
	if initialID != -1 {
		for i, id := range activeIDs {
			if id == initialID {
				initialIndex = i
				initialStream = activeStreams[i]
				break
			}
		}
	}
	if processID(initialID, initialStream) {
		goto buildResult
	}

	if hasOrphan && initialID != -1 {
		if processID(-1, nil) {
			goto buildResult
		}
	}

	if initialIndex >= 0 {
		for i := initialIndex + 1; i < len(activeIDs); i++ {
			if processID(activeIDs[i], activeStreams[i]) {
				goto buildResult
			}
		}
		for i := 0; i < initialIndex; i++ {
			if processID(activeIDs[i], activeStreams[i]) {
				goto buildResult
			}
		}
	} else {
		for i, id := range activeIDs {
			if processID(id, activeStreams[i]) {
				goto buildResult
			}
		}
	}

	if initialID == -1 && hasOrphan {
		for i, id := range activeIDs {
			if processID(id, activeStreams[i]) {
				goto buildResult
			}
		}
	}

buildResult:
	if blocks <= 1 {
		pkt := vpnPacketFromTX(first, initialStreamID)
		if initialID != -1 {
			putTXPacketToPool(first)
		}
		return &pkt
	}

	if initialID != -1 {
		putTXPacketToPool(first)
	}

	return &VpnProto.Packet{
		PacketType:  Enums.PACKET_PACKED_CONTROL_BLOCKS,
		Payload:     payload,
		StreamID:    0,
		HasStreamID: true,
	}
}

func vpnPacketFromTX(p *serverStreamTXPacket, streamID uint16) VpnProto.Packet {
	return VpnProto.Packet{
		PacketType:         p.PacketType,
		StreamID:           streamID,
		SequenceNum:        p.SequenceNum,
		FragmentID:         p.FragmentID,
		TotalFragments:     p.TotalFragments,
		CompressionType:    p.CompressionType,
		HasCompressionType: p.CompressionType != compression.TypeOff,
		Payload:            p.Payload,
		HasSequenceNum:     p.SequenceNum != 0,
		HasFragmentInfo:    p.FragmentID != 0 || p.TotalFragments != 0,
		HasStreamID:        true,
	}
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
		Enums.PACKET_SOCKS5_SYN:
		return true
	default:
		return false
	}
}

func (s *Server) dispatchDeferredSessionPacket(packet VpnProto.Packet, run func()) bool {
	if s == nil || !isDeferredPostSessionPacketType(packet.PacketType) {
		return false
	}
	var processor *deferredSessionProcessor
	switch packet.PacketType {
	case Enums.PACKET_DNS_QUERY_REQ:
		processor = s.deferredDNSSession
	case Enums.PACKET_STREAM_SYN, Enums.PACKET_SOCKS5_SYN:
		processor = s.deferredConnectSession
	default:
		return false
	}
	if processor == nil {
		return false
	}
	return processor.Enqueue(deferredSessionLaneForPacket(packet), run)
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
	record.streamCleanup = s.cleanupStreamArtifacts

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
