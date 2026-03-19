// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"errors"
	"fmt"
	"time"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var ErrStreamHandshakeFailed = errors.New("stream handshake failed")

func (c *Client) nextStreamID() uint16 {
	if c == nil {
		return 1
	}
	c.lastStreamID++
	if c.lastStreamID == 0 {
		c.lastStreamID = 1
	}
	return c.lastStreamID
}

func (c *Client) OpenSOCKS5Stream(targetPayload []byte, timeout time.Duration) (uint16, error) {
	if c == nil {
		return 0, ErrStreamHandshakeFailed
	}
	if !c.SessionReady() {
		return 0, ErrSessionInitFailed
	}
	if len(targetPayload) == 0 {
		return 0, ErrStreamHandshakeFailed
	}
	timeout = normalizeTimeout(timeout, defaultRuntimeTimeout)

	streamID := c.nextStreamID()
	synPacket, err := c.exchangeStreamControlPacket(Enums.PACKET_STREAM_SYN, streamID, 1, nil, timeout)
	if err != nil {
		return 0, err
	}
	if synPacket.PacketType != Enums.PACKET_STREAM_SYN_ACK || synPacket.StreamID != streamID {
		return 0, ErrStreamHandshakeFailed
	}

	socksPacket, err := c.exchangeStreamControlPacket(Enums.PACKET_SOCKS5_SYN, streamID, 2, targetPayload, timeout)
	if err != nil {
		return 0, err
	}
	if socksPacket.StreamID != streamID {
		return 0, ErrStreamHandshakeFailed
	}
	if socksPacket.PacketType == Enums.PACKET_SOCKS5_SYN_ACK {
		return streamID, nil
	}
	if isSOCKS5ErrorPacket(socksPacket.PacketType) {
		return 0, fmt.Errorf("%w: %s", ErrStreamHandshakeFailed, Enums.PacketTypeName(socksPacket.PacketType))
	}
	return 0, ErrStreamHandshakeFailed
}

func (c *Client) OpenTCPStream(timeout time.Duration) (uint16, error) {
	if c == nil {
		return 0, ErrStreamHandshakeFailed
	}
	if !c.SessionReady() {
		return 0, ErrSessionInitFailed
	}
	timeout = normalizeTimeout(timeout, defaultRuntimeTimeout)

	streamID := c.nextStreamID()
	synPacket, err := c.exchangeStreamControlPacket(
		Enums.PACKET_STREAM_SYN,
		streamID,
		1,
		VpnProto.TCPForwardSynPayload(),
		timeout,
	)
	if err != nil {
		return 0, err
	}
	if synPacket.PacketType != Enums.PACKET_STREAM_SYN_ACK || synPacket.StreamID != streamID {
		return 0, ErrStreamHandshakeFailed
	}
	return streamID, nil
}

func (c *Client) exchangeStreamControlPacket(packetType uint8, streamID uint16, sequenceNum uint16, payload []byte, timeout time.Duration) (VpnProto.Packet, error) {
	if c == nil {
		return VpnProto.Packet{}, ErrStreamHandshakeFailed
	}
	timeout = normalizeTimeout(timeout, defaultRuntimeTimeout)
	connections, err := c.runtimeConnections(nil)
	if err != nil {
		return VpnProto.Packet{}, err
	}
	return tryConnections(connections, ErrStreamHandshakeFailed, func(connection Connection) (VpnProto.Packet, error) {
		return c.sendStreamControlPacketWithConnection(connection, packetType, streamID, sequenceNum, payload, timeout)
	})
}

func (c *Client) sendStreamControlPacketWithConnection(connection Connection, packetType uint8, streamID uint16, sequenceNum uint16, payload []byte, timeout time.Duration) (VpnProto.Packet, error) {
	return c.sendFragmentedStreamPacketWithConnection(connection, packetType, streamID, sequenceNum, payload, timeout, ErrStreamHandshakeFailed)
}

func (c *Client) sendFragmentedStreamPacketWithConnection(connection Connection, packetType uint8, streamID uint16, sequenceNum uint16, payload []byte, timeout time.Duration, fallbackErr error) (VpnProto.Packet, error) {
	fragments, err := c.fragmentMainStreamPayload(connection.Domain, packetType, payload)
	if err != nil {
		return VpnProto.Packet{}, err
	}

	for fragmentID, fragmentPayload := range fragments {
		query, err := c.buildStreamQuery(
			connection.Domain,
			packetType,
			streamID,
			sequenceNum,
			uint8(fragmentID),
			uint8(len(fragments)),
			fragmentPayload,
		)
		if err != nil {
			return VpnProto.Packet{}, err
		}

		response, err := c.exchangeDNSOverConnection(connection, query, timeout)
		if err != nil {
			return VpnProto.Packet{}, err
		}
		if fragmentID < len(fragments)-1 {
			continue
		}

		packet, err := DnsParser.ExtractVPNResponse(response, c.responseMode == mtuProbeBase64Reply)
		if err != nil || !c.validateServerPacket(packet) {
			return VpnProto.Packet{}, fallbackErr
		}
		if packet.StreamID != streamID || packet.SequenceNum != sequenceNum {
			return VpnProto.Packet{}, fallbackErr
		}
		return packet, nil
	}

	return VpnProto.Packet{}, fallbackErr
}

func (c *Client) buildStreamQuery(domain string, packetType uint8, streamID uint16, sequenceNum uint16, fragmentID uint8, totalFragments uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelTXTQuery(domain, VpnProto.BuildOptions{
		SessionID:       c.sessionID,
		PacketType:      packetType,
		SessionCookie:   c.sessionCookie,
		StreamID:        streamID,
		SequenceNum:     sequenceNum,
		FragmentID:      fragmentID,
		TotalFragments:  totalFragments,
		CompressionType: c.uploadCompression,
		Payload:         payload,
	})
}

func isSOCKS5ErrorPacket(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_SOCKS5_CONNECT_FAIL,
		Enums.PACKET_SOCKS5_RULESET_DENIED,
		Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE,
		Enums.PACKET_SOCKS5_HOST_UNREACHABLE,
		Enums.PACKET_SOCKS5_CONNECTION_REFUSED,
		Enums.PACKET_SOCKS5_TTL_EXPIRED,
		Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED,
		Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
		Enums.PACKET_SOCKS5_AUTH_FAILED,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE:
		return true
	default:
		return false
	}
}
