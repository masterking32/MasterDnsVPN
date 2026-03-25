// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"encoding/binary"
	"sort"
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
	s.sessions.mu.Lock()
	record := s.sessions.byID[sessionID]
	s.sessions.mu.Unlock()
	if record == nil {
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

func (s *Server) streamARQConfig(isSocks bool, compressionType uint8) arq.Config {
	return arq.Config{
		WindowSize:               s.cfg.ARQWindowSize,
		RTO:                      s.cfg.ARQInitialRTOSeconds,
		MaxRTO:                   s.cfg.ARQMaxRTOSeconds,
		StartPaused:              isSocks,
		EnableControlReliability: true,
		ControlRTO:               s.cfg.ARQControlInitialRTOSeconds,
		ControlMaxRTO:            s.cfg.ARQControlMaxRTOSeconds,
		ControlMaxRetries:        s.cfg.ARQMaxControlRetries,
		InactivityTimeout:        s.cfg.ARQInactivityTimeoutSeconds,
		DataPacketTTL:            s.cfg.ARQDataPacketTTLSeconds,
		MaxDataRetries:           s.cfg.ARQMaxDataRetries,
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
	if record != nil {
		record.closeAllStreams("session closed cleanup")
	}
	s.deferredSession.RemoveSession(sessionID)
	s.removeDNSQueryFragmentsForSession(sessionID)
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
	s.sessions.mu.Lock()
	record := s.sessions.byID[sessionID]
	s.sessions.mu.Unlock()
	if record == nil {
		return nil, false
	}

	record.mu.Lock()
	defer record.mu.Unlock()

	if pkt, ok := s.dequeueDuplicatedPackedControlBlock(record); ok {
		return pkt, true
	}

	record.StreamsMu.RLock()
	streamCount := len(record.ActiveStreams)
	ids := make([]int32, 0, streamCount+1)
	for _, id := range record.ActiveStreams {
		ids = append(ids, int32(id))
	}
	record.StreamsMu.RUnlock()

	if record.OrphanQueue != nil && record.OrphanQueue.Size() > 0 {
		ids = append(ids, -1)
	}
	if len(ids) == 0 {
		return nil, false
	}

	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	startIdx := 0
	for i, id := range ids {
		if id >= record.RRStreamID {
			startIdx = i
			break
		}
	}

	for i := 0; i < len(ids); i++ {
		idx := (startIdx + i) % len(ids)
		id := ids[idx]

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
			record.StreamsMu.RLock()
			stream := record.Streams[uint16(id)]
			record.StreamsMu.RUnlock()
			if stream == nil || stream.TXQueue == nil {
				continue
			}
			var popped *serverStreamTXPacket
			popped, _, ok = stream.TXQueue.Pop(func(p *serverStreamTXPacket) uint64 {
				return Enums.PacketIdentityKey(uint16(id), p.PacketType, p.SequenceNum, p.FragmentID)
			})
			if ok {
				item = popped
				selectedStreamID = uint16(id)
			}
		}

		if ok && item != nil {
			record.RRStreamID = id + 1
			if VpnProto.IsPackableControlPacket(item.PacketType, len(item.Payload)) && record.MaxPackedBlocks > 1 {
				pkt := s.packControlBlocks(record, item, id, selectedStreamID)
				s.cachePackedControlBlockDuplicate(record, pkt)
				return pkt, true
			}
			pkt := vpnPacketFromTX(item, selectedStreamID)
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

	record.StreamsMu.RLock()
	ids := make([]int32, 0, len(record.ActiveStreams)+1)
	if record.OrphanQueue != nil && record.OrphanQueue.Size() > 0 {
		ids = append(ids, -1)
	}
	for _, sid := range record.ActiveStreams {
		ids = append(ids, int32(sid))
	}
	record.StreamsMu.RUnlock()

	orderedIDs := make([]int32, 0, len(ids))
	orderedIDs = append(orderedIDs, initialID)
	for _, id := range ids {
		if id != initialID {
			orderedIDs = append(orderedIDs, id)
		}
	}

	for _, id := range orderedIDs {
		if blocks >= limit {
			break
		}

		if id == -1 {
			for blocks < limit {
				popped, ok := record.OrphanQueue.PopAnyIf(func(p VpnProto.Packet) bool {
					return VpnProto.IsPackableControlPacket(p.PacketType, 0)
				}, func(p VpnProto.Packet) uint64 {
					return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
				})
				if !ok {
					break
				}
				payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, popped.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
				blocks++
			}
		} else {
			record.StreamsMu.RLock()
			stream := record.Streams[uint16(id)]
			record.StreamsMu.RUnlock()
			if stream == nil || stream.TXQueue == nil {
				continue
			}
			for blocks < limit {
				popped, ok := stream.TXQueue.PopAnyIf(func(p *serverStreamTXPacket) bool {
					return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
				}, func(p *serverStreamTXPacket) uint64 {
					return Enums.PacketIdentityKey(uint16(id), p.PacketType, p.SequenceNum, p.FragmentID)
				})
				if !ok {
					break
				}
				payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, uint16(id), popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
				blocks++
			}
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

func (s *Server) QueueTargetForPacket(streamExists bool, packetType uint8, streamID uint16) (QueueTarget, bool) {
	if streamID == 0 {
		return QueueTargetMain, true
	}
	if streamExists {
		return QueueTargetStream, true
	}
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
