// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"time"

	"masterdnsvpn-go/internal/arq"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var ErrTunnelDNSDispatchFailed = errors.New("dns tunnel dispatch failed")
var ErrTunnelDNSFragmentTooLarge = errors.New("dns tunnel payload exceeds fragment limit")

func (c *Client) dispatchDNSQuery(request *dnsDispatchRequest) (response []byte, err error) {
	if c == nil || request == nil || len(request.Query) == 0 {
		return nil, ErrTunnelDNSDispatchFailed
	}
	if c.sessionID == 0 {
		return nil, ErrSessionInitFailed
	}

	var packet VpnProto.Packet
	if c.stream0Runtime != nil && c.stream0Runtime.IsRunning() {
		timeout := time.Duration(c.cfg.LocalDNSPendingTimeoutSec * float64(time.Second))
		packet, err = c.stream0Runtime.ExchangeDNSQuery(request.Query, timeout)
	} else {
		packet, err = c.exchangeMainStreamPacket(Enums.PACKET_DNS_QUERY_REQ, request.Query)
	}
	if err != nil {
		return nil, err
	}
	if packet.PacketType != Enums.PACKET_DNS_QUERY_RES {
		return nil, ErrTunnelDNSDispatchFailed
	}
	if len(packet.Payload) < 12 {
		return nil, ErrTunnelDNSDispatchFailed
	}
	if shouldCacheTunnelDNSResponse(packet.Payload) {
		c.localDNSCache.SetReady(
			request.CacheKey,
			request.Domain,
			request.QType,
			request.QClass,
			packet.Payload,
			c.now(),
		)
	}
	return packet.Payload, nil
}

func (c *Client) exchangeMainStreamPacket(packetType uint8, payload []byte) (VpnProto.Packet, error) {
	if c == nil {
		return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
	}

	timeout := time.Duration(c.cfg.LocalDNSPendingTimeoutSec * float64(time.Second))
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	connections := c.GetUniqueConnections(3)
	if len(connections) == 0 {
		return VpnProto.Packet{}, ErrNoValidConnections
	}

	sequenceNum := c.nextMainSequence()
	return c.sendMainStreamPacket(packetType, sequenceNum, payload, connections, timeout)
}

func (c *Client) sendMainStreamPacket(packetType uint8, sequenceNum uint16, payload []byte, connections []Connection, timeout time.Duration) (VpnProto.Packet, error) {
	if c == nil {
		return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
	}
	if len(connections) == 0 {
		connections = c.GetUniqueConnections(3)
	}
	if len(connections) == 0 {
		return VpnProto.Packet{}, ErrNoValidConnections
	}

	lastErr := ErrTunnelDNSDispatchFailed
	for _, connection := range connections {
		packet, err := c.sendMainStreamPacketWithConnection(connection, packetType, sequenceNum, payload, timeout)
		if err == nil {
			return packet, nil
		}
		lastErr = err
	}

	return VpnProto.Packet{}, lastErr
}

func (c *Client) sendMainStreamPacketWithConnection(connection Connection, packetType uint8, sequenceNum uint16, payload []byte, timeout time.Duration) (VpnProto.Packet, error) {
	fragments, err := c.fragmentMainStreamPayload(connection.Domain, packetType, payload)
	if err != nil {
		return VpnProto.Packet{}, err
	}
	for fragmentID, fragmentPayload := range fragments {
		query, err := c.buildMainStreamQuery(
			connection.Domain,
			packetType,
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
			return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
		}
		if packet.StreamID != 0 || packet.SequenceNum != sequenceNum {
			return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
		}
		return packet, nil
	}

	return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
}

func (c *Client) sendStream0Packet(packet arq.QueuedPacket) (VpnProto.Packet, error) {
	if c == nil {
		return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
	}

	timeout := time.Duration(c.cfg.LocalDNSPendingTimeoutSec * float64(time.Second))
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	connections := c.GetUniqueConnections(3)
	if len(connections) == 0 {
		return VpnProto.Packet{}, ErrNoValidConnections
	}

	switch packet.PacketType {
	case Enums.PACKET_DNS_QUERY_REQ:
		return c.sendMainStreamPacket(packet.PacketType, packet.SequenceNum, packet.Payload, connections, timeout)
	case Enums.PACKET_PING:
		return c.sendSessionControlPacket(packet.PacketType, packet.Payload, connections, timeout)
	default:
		return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
	}
}

func (c *Client) buildMainStreamQuery(domain string, packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, payload []byte) ([]byte, error) {
	encoded, err := VpnProto.BuildEncodedAuto(VpnProto.BuildOptions{
		SessionID:       c.sessionID,
		PacketType:      packetType,
		SessionCookie:   c.sessionCookie,
		StreamID:        0,
		SequenceNum:     sequenceNum,
		FragmentID:      fragmentID,
		TotalFragments:  totalFragments,
		CompressionType: c.uploadCompression,
		Payload:         payload,
	}, c.codec, c.cfg.CompressionMinSize)
	if err != nil {
		return nil, err
	}

	name, err := DnsParser.BuildTunnelQuestionName(domain, encoded)
	if err != nil {
		return nil, err
	}
	return DnsParser.BuildTXTQuestionPacket(name, Enums.DNS_RECORD_TYPE_TXT, EDnsSafeUDPSize)
}

func (c *Client) buildSessionControlQuery(domain string, packetType uint8, payload []byte) ([]byte, error) {
	encoded, err := VpnProto.BuildEncodedAuto(VpnProto.BuildOptions{
		SessionID:     c.sessionID,
		PacketType:    packetType,
		SessionCookie: c.sessionCookie,
		Payload:       payload,
	}, c.codec, c.cfg.CompressionMinSize)
	if err != nil {
		return nil, err
	}

	name, err := DnsParser.BuildTunnelQuestionName(domain, encoded)
	if err != nil {
		return nil, err
	}
	return DnsParser.BuildTXTQuestionPacket(name, Enums.DNS_RECORD_TYPE_TXT, EDnsSafeUDPSize)
}

func (c *Client) fragmentMainStreamPayload(domain string, packetType uint8, payload []byte) ([][]byte, error) {
	if len(payload) == 0 {
		return [][]byte{{}}, nil
	}

	limit := c.maxMainStreamFragmentPayload(domain, packetType)
	if limit < 1 {
		return nil, ErrTunnelDNSDispatchFailed
	}
	if len(payload) <= limit {
		return [][]byte{payload}, nil
	}

	total := (len(payload) + limit - 1) / limit
	if total > 255 {
		return nil, ErrTunnelDNSFragmentTooLarge
	}

	fragments := make([][]byte, 0, total)
	for start := 0; start < len(payload); start += limit {
		end := start + limit
		if end > len(payload) {
			end = len(payload)
		}
		fragments = append(fragments, payload[start:end])
	}
	return fragments, nil
}

func (c *Client) exchangeDNSOverConnection(connection Connection, packet []byte, timeout time.Duration) ([]byte, error) {
	if c != nil && c.exchangeQueryFn != nil {
		return c.exchangeQueryFn(connection, packet, timeout)
	}

	transport, err := newUDPQueryTransport(connection.ResolverLabel)
	if err != nil {
		return nil, err
	}
	defer transport.conn.Close()
	return exchangeUDPQuery(transport, packet, timeout)
}

func (c *Client) nextMainSequence() uint16 {
	if c == nil {
		return 1
	}
	c.mainSequence++
	if c.mainSequence == 0 {
		c.mainSequence = 1
	}
	return c.mainSequence
}

func (c *Client) maxMainStreamFragmentPayload(domain string, packetType uint8) int {
	if c == nil {
		return 0
	}

	cacheKey := domain + "|" + strconv.Itoa(int(packetType))
	if cached, ok := c.fragmentLimits.Load(cacheKey); ok {
		return cached.(int)
	}

	high := c.syncedUploadMTU
	if high <= 0 {
		high = EDnsSafeUDPSize
	}
	best := 0
	low := 1
	for low <= high {
		mid := (low + high) / 2
		if c.canBuildMainStreamPayload(domain, packetType, mid) {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}

	c.fragmentLimits.Store(cacheKey, best)
	return best
}

func (c *Client) canBuildMainStreamPayload(domain string, packetType uint8, payloadLen int) bool {
	if payloadLen < 0 {
		return false
	}
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = 0xAB
	}
	_, err := c.buildMainStreamQuery(domain, packetType, 1, 0, 1, payload)
	return err == nil
}

func shouldCacheTunnelDNSResponse(response []byte) bool {
	if len(response) < 4 {
		return false
	}
	return binary.BigEndian.Uint16(response[2:4])&0x000F != Enums.DNSR_CODE_SERVER_FAILURE
}

type udpQueryTransport struct {
	conn   *net.UDPConn
	buffer []byte
}

func newUDPQueryTransport(resolverLabel string) (*udpQueryTransport, error) {
	addr, err := net.ResolveUDPAddr("udp", resolverLabel)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	return &udpQueryTransport{
		conn:   conn,
		buffer: make([]byte, EDnsSafeUDPSize),
	}, nil
}

func exchangeUDPQuery(transport *udpQueryTransport, packet []byte, timeout time.Duration) ([]byte, error) {
	if transport == nil || transport.conn == nil {
		return nil, net.ErrClosed
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	if err := transport.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := transport.conn.Write(packet); err != nil {
		return nil, err
	}

	n, err := transport.conn.Read(transport.buffer)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), transport.buffer[:n]...), nil
}

func (c *Client) sendSessionControlPacket(packetType uint8, payload []byte, connections []Connection, timeout time.Duration) (VpnProto.Packet, error) {
	if c == nil {
		return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
	}
	if len(connections) == 0 {
		connections = c.GetUniqueConnections(3)
	}
	if len(connections) == 0 {
		return VpnProto.Packet{}, ErrNoValidConnections
	}

	lastErr := ErrTunnelDNSDispatchFailed
	for _, connection := range connections {
		query, err := c.buildSessionControlQuery(connection.Domain, packetType, payload)
		if err != nil {
			lastErr = err
			continue
		}

		response, err := c.exchangeDNSOverConnection(connection, query, timeout)
		if err != nil {
			lastErr = err
			continue
		}

		packet, err := DnsParser.ExtractVPNResponse(response, c.responseMode == mtuProbeBase64Reply)
		if err != nil || !c.validateServerPacket(packet) {
			lastErr = ErrTunnelDNSDispatchFailed
			continue
		}
		return packet, nil
	}

	return VpnProto.Packet{}, lastErr
}
