// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func (s *Server) handlePostSessionPacket(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if handled := s.preprocessInboundPacket(vpnPacket); handled {
		return true
	}

	if vpnPacket.PacketType == Enums.PACKET_PACKED_CONTROL_BLOCKS {
		s.handlePackedControlBlocksRequest(vpnPacket, sessionRecord)
		return true
	}

	s.dispatchPostSessionPacket(vpnPacket, sessionRecord)
	return true
}

func (s *Server) dispatchPostSessionPacket(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	switch vpnPacket.PacketType {
	case Enums.PACKET_PING:
		return true
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND:
		return s.handleStreamDataRequest(vpnPacket)
	case Enums.PACKET_DNS_QUERY_REQ:
		return s.handleDNSQueryRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_SYN:
		return s.handleStreamSynRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_SOCKS5_SYN:
		return s.handleSOCKS5SynRequest(vpnPacket, sessionRecord)
	case Enums.PACKET_STREAM_FIN:
		return s.handleStreamFinRequest(vpnPacket)
	case Enums.PACKET_STREAM_RST:
		return s.handleStreamRSTRequest(vpnPacket)
	default:
		return false
	}
}

func (s *Server) enqueueMissingStreamReset(record *sessionRecord, vpnPacket VpnProto.Packet) bool {
	if s == nil || record == nil || vpnPacket.StreamID == 0 ||
		vpnPacket.PacketType == Enums.PACKET_STREAM_SYN ||
		vpnPacket.PacketType == Enums.PACKET_SOCKS5_SYN ||
		vpnPacket.PacketType == Enums.PACKET_PACKED_CONTROL_BLOCKS ||
		vpnPacket.PacketType == Enums.PACKET_PING ||
		vpnPacket.PacketType == Enums.PACKET_DNS_QUERY_REQ {
		return false
	}

	if vpnPacket.PacketType == Enums.PACKET_STREAM_DATA_ACK {
		return true
	}

	if _, ok := Enums.ReverseControlAckFor(vpnPacket.PacketType); ok {
		return true
	}

	if vpnPacket.PacketType == Enums.PACKET_STREAM_RST {
		record.enqueueOrphanReset(Enums.PACKET_STREAM_RST_ACK, vpnPacket.StreamID, vpnPacket.SequenceNum)
		return true
	}

	ack_answer, ok := Enums.GetPacketCloseStream(vpnPacket.PacketType)
	if ok && vpnPacket.PacketType != Enums.PACKET_STREAM_FIN {
		record.enqueueOrphanReset(ack_answer, vpnPacket.StreamID, 0)
	} else {
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

func isStreamScopedAckPacket(packetType uint8) bool {
	if packetType == Enums.PACKET_STREAM_DATA_ACK {
		return true
	}
	_, ok := Enums.ReverseControlAckFor(packetType)
	return ok
}

func (s *Server) consumeInboundStreamAck(vpnPacket VpnProto.Packet, stream *Stream_server) bool {
	if s == nil || stream == nil || stream.ARQ == nil {
		return false
	}

	handledAck := stream.ARQ.HandleAckPacket(vpnPacket.PacketType, vpnPacket.SequenceNum, vpnPacket.FragmentID)
	now := time.Now()

	if _, ok := Enums.GetPacketCloseStream(vpnPacket.PacketType); handledAck && ok {
		if stream.ARQ.IsClosed() {
			stream.mu.Lock()
			stream.Status = "CLOSED"
			if stream.CloseTime.IsZero() {
				stream.CloseTime = now
			}
			stream.mu.Unlock()
		}
	}

	if handledAck && vpnPacket.PacketType == Enums.PACKET_STREAM_RST_ACK {
		s.removeStreamDataFragmentsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
	}

	return handledAck
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
		stream = record.getOrCreateStream(packet.StreamID, s.streamARQConfig(packet.PacketType == Enums.PACKET_SOCKS5_SYN, record.DownloadCompression), nil, s.log)
		exists = stream != nil
	}

	if !exists || stream == nil {
		return false
	}

	if (packet.PacketType == Enums.PACKET_SOCKS5_SYN || packet.PacketType == Enums.PACKET_STREAM_SYN) && stream.ARQ != nil {
		return stream.ARQ.SendControlPacketWithTTL(
			ackType,
			packet.SequenceNum,
			packet.FragmentID,
			packet.TotalFragments,
			nil,
			Enums.DefaultPacketPriority(ackType),
			false,
			nil,
			s.cfg.StreamSetupAckTTL(),
		)
	}

	return stream.PushTXPacket(
		Enums.DefaultPacketPriority(ackType),
		ackType,
		packet.SequenceNum,
		packet.FragmentID,
		packet.TotalFragments,
		0,
		0,
		nil,
	)
}

func (s *Server) preprocessInboundPacket(vpnPacket VpnProto.Packet) bool {
	if s == nil {
		return true
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return false
	}

	if vpnPacket.StreamID != 0 && record.isRecentlyClosed(vpnPacket.StreamID, time.Now()) {
		switch vpnPacket.PacketType {
		case Enums.PACKET_STREAM_SYN, Enums.PACKET_SOCKS5_SYN:
			record.enqueueOrphanReset(Enums.PACKET_STREAM_RST, vpnPacket.StreamID, 0)
			return true
		default:
			return s.enqueueMissingStreamReset(record, vpnPacket)
		}
	}

	existingStream, streamExists := record.getStream(vpnPacket.StreamID)
	if vpnPacket.StreamID != 0 && (!streamExists || existingStream == nil) {
		return s.enqueueMissingStreamReset(record, vpnPacket)
	}

	_ = s.queueImmediateControlAck(record, vpnPacket)

	if s.consumeInboundStreamAck(vpnPacket, existingStream) {
		return true
	}

	return false
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
			SessionID:      vpnPacket.SessionID,
			SessionCookie:  vpnPacket.SessionCookie,
			PacketType:     packetType,
			StreamID:       streamID,
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

		if s.dispatchPostSessionPacket(block, sessionRecord) {
			handled = true
		}

		return true
	})
	return handled || sawBlock
}

func (s *Server) handleDNSQueryRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if sessionRecord == nil {
		return false
	}

	totalFragments := vpnPacket.TotalFragments
	if totalFragments == 0 {
		totalFragments = 1
	}

	now := time.Now()
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

func (s *Server) handleStreamSynRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || sessionRecord == nil {
		return false
	}

	run := func() {
		s.processDeferredStreamSyn(vpnPacket)
	}

	if !s.dispatchDeferredSessionPacket(vpnPacket, run) {
		run()
	}

	return true
}

func (s *Server) handleSOCKS5SynRequest(vpnPacket VpnProto.Packet, sessionRecord *sessionRuntimeView) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 || sessionRecord == nil {
		return false
	}

	run := func() {
		s.processDeferredSOCKS5Syn(vpnPacket)
	}

	if !s.dispatchDeferredSessionPacket(vpnPacket, run) {
		run()
	}

	return true
}

func (s *Server) handleStreamDataRequest(vpnPacket VpnProto.Packet) bool {
	run := func() {
		record, ok := s.sessions.Get(vpnPacket.SessionID)
		if !ok {
			return
		}

		stream, exists := record.getStream(vpnPacket.StreamID)
		if !exists || stream == nil {
			return
		}

		stream.ARQ.ReceiveData(vpnPacket.SequenceNum, vpnPacket.Payload)
	}

	if !s.dispatchDeferredSessionPacket(vpnPacket, run) {
		run()
	}

	return true
}

func (s *Server) handleStreamFinRequest(vpnPacket VpnProto.Packet) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return true
	}

	stream, exists := record.getStream(vpnPacket.StreamID)
	if !exists || stream == nil {
		return true
	}

	stream.ARQ.MarkFinReceived()
	return true
}

func (s *Server) handleStreamRSTRequest(vpnPacket VpnProto.Packet) bool {
	if !vpnPacket.HasStreamID || vpnPacket.StreamID == 0 {
		return false
	}

	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return true
	}

	now := time.Now()
	stream, ok := record.getStream(vpnPacket.StreamID)
	if ok && stream != nil {
		stream.ARQ.MarkRstReceived()
		stream.ARQ.Close("peer reset before/while connect", arq.CloseOptions{Force: true})
		stream.mu.Lock()
		stream.Status = "CLOSED"
		stream.CloseTime = now
		stream.mu.Unlock()
	} else {
		record.noteStreamClosed(vpnPacket.StreamID, now)
	}

	s.removeSOCKS5SynFragmentsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
	s.removeStreamDataFragmentsForStream(vpnPacket.SessionID, vpnPacket.StreamID)
	return true
}
