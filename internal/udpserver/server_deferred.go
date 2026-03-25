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
	"strings"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	SocksProto "masterdnsvpn-go/internal/socksproto"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

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

func (s *Server) processDeferredStreamSyn(vpnPacket VpnProto.Packet) {
	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return
	}

	if VpnProto.IsTCPForwardSynPayload(vpnPacket.Payload) {
		if s.cfg.ForwardIP == "" || s.cfg.ForwardPort <= 0 {
			record.enqueueOrphanReset(Enums.PACKET_STREAM_RST, vpnPacket.StreamID, 0)
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

		stream := record.getOrCreateStream(vpnPacket.StreamID, s.streamARQConfig(false, record.DownloadCompression), nil, s.log)
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
		record.getOrCreateStream(vpnPacket.StreamID, s.streamARQConfig(false, record.DownloadCompression), nil, s.log)
	}
}

func (s *Server) processDeferredSOCKS5Syn(vpnPacket VpnProto.Packet) {
	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return
	}

	now := time.Now()
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

	stream := record.getOrCreateStream(vpnPacket.StreamID, s.streamARQConfig(true, record.DownloadCompression), nil, s.log)
	target, err := SocksProto.ParseTargetPayload(assembledTarget)
	if err != nil {
		packetType := uint8(Enums.PACKET_SOCKS5_CONNECT_FAIL)
		if errors.Is(err, SocksProto.ErrUnsupportedAddressType) || errors.Is(err, SocksProto.ErrInvalidDomainLength) {
			packetType = uint8(Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED)
		}

		stream.ARQ.SendControlPacketWithTTL(
			packetType,
			vpnPacket.SequenceNum,
			0,
			0,
			nil,
			Enums.DefaultPacketPriority(packetType),
			true,
			nil,
			s.cfg.StreamFailurePacketTTL(),
		)
		return
	}

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

			stream.ARQ.SendControlPacketWithTTL(
				Enums.PACKET_SOCKS5_CONNECTED,
				vpnPacket.SequenceNum,
				0,
				0,
				nil,
				Enums.DefaultPacketPriority(Enums.PACKET_SOCKS5_CONNECTED),
				true,
				nil,
				s.cfg.StreamResultPacketTTL(),
			)
			return
		}

		stream.ARQ.SendControlPacketWithTTL(
			Enums.PACKET_SOCKS5_CONNECT_FAIL,
			vpnPacket.SequenceNum,
			0,
			0,
			nil,
			Enums.DefaultPacketPriority(Enums.PACKET_SOCKS5_CONNECT_FAIL),
			true,
			nil,
			s.cfg.StreamFailurePacketTTL(),
		)
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
		stream.ARQ.SendControlPacketWithTTL(
			packetType,
			vpnPacket.SequenceNum,
			0,
			0,
			nil,
			Enums.DefaultPacketPriority(packetType),
			true,
			nil,
			s.cfg.StreamFailurePacketTTL(),
		)
		return
	}

	stream.mu.Lock()
	stream.UpstreamConn = upstreamConn
	stream.TargetHost = target.Host
	stream.TargetPort = target.Port
	stream.Connected = true
	stream.mu.Unlock()

	stream.ARQ.SetLocalConn(upstreamConn)
	stream.ARQ.SetIOReady(true)

	if s.log != nil {
		s.log.Debugf(
			"\U0001F9E6 <green>SOCKS5 Stream Prepared</green> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Target</blue>: <cyan>%s:%d</cyan>",
			vpnPacket.SessionID,
			vpnPacket.StreamID,
			target.Host,
			target.Port,
		)
	}

	stream.ARQ.SendControlPacketWithTTL(
		Enums.PACKET_SOCKS5_CONNECTED,
		vpnPacket.SequenceNum,
		0,
		0,
		nil,
		Enums.DefaultPacketPriority(Enums.PACKET_SOCKS5_CONNECTED),
		true,
		nil,
		s.cfg.StreamResultPacketTTL(),
	)
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
