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
	"os"
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
	if !c.SessionReady() {
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

	timeout := normalizeTimeout(time.Duration(c.cfg.LocalDNSPendingTimeoutSec*float64(time.Second)), defaultRuntimeTimeout)
	connections, err := c.runtimeConnections(nil)
	if err != nil {
		return VpnProto.Packet{}, err
	}

	sequenceNum := c.nextMainSequence()
	return c.sendMainStreamPacket(packetType, sequenceNum, payload, connections, timeout)
}

func (c *Client) sendMainStreamPacket(packetType uint8, sequenceNum uint16, payload []byte, connections []Connection, timeout time.Duration) (VpnProto.Packet, error) {
	if c == nil {
		return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
	}
	timeout = normalizeTimeout(timeout, defaultRuntimeTimeout)
	connections, err := c.runtimeConnections(connections)
	if err != nil {
		return VpnProto.Packet{}, err
	}
	return tryConnections(connections, ErrTunnelDNSDispatchFailed, func(connection Connection) (VpnProto.Packet, error) {
		return c.sendMainStreamPacketWithConnection(connection, packetType, sequenceNum, payload, timeout)
	})
}

func (c *Client) sendMainStreamPacketWithConnection(connection Connection, packetType uint8, sequenceNum uint16, payload []byte, timeout time.Duration) (VpnProto.Packet, error) {
	return c.sendFragmentedStreamPacketWithConnection(connection, packetType, 0, sequenceNum, payload, timeout, ErrTunnelDNSDispatchFailed)
}

func (c *Client) sendScheduledPacket(packet arq.QueuedPacket) (VpnProto.Packet, error) {
	if c == nil {
		return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
	}

	timeout := normalizeTimeout(time.Duration(c.cfg.LocalDNSPendingTimeoutSec*float64(time.Second)), defaultRuntimeTimeout)
	connections, err := c.runtimeConnections(nil)
	if err != nil {
		return VpnProto.Packet{}, err
	}

	switch packet.PacketType {
	case Enums.PACKET_DNS_QUERY_REQ:
		return c.sendMainStreamPacket(packet.PacketType, packet.SequenceNum, packet.Payload, connections, timeout)
	case Enums.PACKET_PING:
		return c.sendSessionControlPacket(packet.PacketType, packet.Payload, connections, timeout)
	default:
		if packet.StreamID == 0 {
			return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
		}
		return c.sendStreamPacket(packet, connections, timeout)
	}
}

func (c *Client) sendStreamPacket(packet arq.QueuedPacket, connections []Connection, timeout time.Duration) (VpnProto.Packet, error) {
	if c == nil {
		return VpnProto.Packet{}, ErrStreamHandshakeFailed
	}
	timeout = normalizeTimeout(timeout, defaultRuntimeTimeout)
	connections, err := c.runtimeConnections(connections)
	if err != nil {
		return VpnProto.Packet{}, err
	}
	return tryConnections(connections, ErrStreamHandshakeFailed, func(connection Connection) (VpnProto.Packet, error) {
		return c.sendStreamControlPacketWithConnection(
			connection,
			packet.PacketType,
			packet.StreamID,
			packet.SequenceNum,
			packet.Payload,
			timeout,
		)
	})
}

func (c *Client) buildSessionControlQuery(domain string, packetType uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelTXTQuery(domain, VpnProto.BuildOptions{
		SessionID:     c.sessionID,
		PacketType:    packetType,
		SessionCookie: c.sessionCookie,
		Payload:       payload,
	})
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
	startedAt := time.Now()
	c.noteResolverSend(connection.Key)

	if c != nil && c.exchangeQueryFn != nil {
		response, err := c.exchangeQueryFn(connection, packet, timeout)
		if err != nil {
			if isResolverTimeout(err) {
				c.noteResolverTimeout(connection.Key)
			}
			return nil, err
		}
		c.noteResolverSuccess(connection.Key, time.Since(startedAt))
		return response, nil
	}

	transport, err := newUDPQueryTransport(connection.ResolverLabel)
	if err != nil {
		return nil, err
	}
	defer transport.conn.Close()
	response, err := exchangeUDPQuery(transport, packet, timeout)
	if err != nil {
		if isResolverTimeout(err) {
			c.noteResolverTimeout(connection.Key)
		}
		return nil, err
	}
	c.noteResolverSuccess(connection.Key, time.Since(startedAt))
	return response, nil
}

func isResolverTimeout(err error) bool {
	if err == nil {
		return false
	}
	if os.IsTimeout(err) {
		return true
	}
	timeoutErr, ok := err.(net.Error)
	return ok && timeoutErr.Timeout()
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
	_, err := c.buildStreamQuery(domain, packetType, 0, 1, 0, 1, payload)
	return err == nil
}

func shouldCacheTunnelDNSResponse(response []byte) bool {
	if len(response) < 4 {
		return false
	}
	return binary.BigEndian.Uint16(response[2:4])&0x000F != Enums.DNSR_CODE_SERVER_FAILURE
}

func (c *Client) buildTunnelTXTQuery(domain string, options VpnProto.BuildOptions) ([]byte, error) {
	encoded, err := VpnProto.BuildEncodedAuto(options, c.codec, c.cfg.CompressionMinSize)
	if err != nil {
		return nil, err
	}
	return buildTunnelTXTQuestion(domain, encoded)
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
	timeout = normalizeTimeout(timeout, time.Second)
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
	timeout = normalizeTimeout(timeout, defaultRuntimeTimeout)
	connections, err := c.runtimeConnections(connections)
	if err != nil {
		return VpnProto.Packet{}, err
	}
	return tryConnections(connections, ErrTunnelDNSDispatchFailed, func(connection Connection) (VpnProto.Packet, error) {
		query, err := c.buildSessionControlQuery(connection.Domain, packetType, payload)
		if err != nil {
			return VpnProto.Packet{}, err
		}

		response, err := c.exchangeDNSOverConnection(connection, query, timeout)
		if err != nil {
			return VpnProto.Packet{}, err
		}

		packet, err := DnsParser.ExtractVPNResponse(response, c.responseMode == mtuProbeBase64Reply)
		if err != nil || !c.validateServerPacket(packet) {
			return VpnProto.Packet{}, ErrTunnelDNSDispatchFailed
		}
		return packet, nil
	})
}
