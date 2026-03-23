// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	SOCKS5_VERSION = 0x05

	SOCKS5_AUTH_METHOD_NO_AUTH       = 0x00
	SOCKS5_AUTH_METHOD_USER_PASS     = 0x02
	SOCKS5_AUTH_METHOD_NO_ACCEPTABLE = 0xFF

	SOCKS5_CMD_CONNECT       = 0x01
	SOCKS5_CMD_UDP_ASSOCIATE = 0x03

	SOCKS5_ATYP_IPV4   = 0x01
	SOCKS5_ATYP_DOMAIN = 0x03
	SOCKS5_ATYP_IPV6   = 0x04

	SOCKS5_REPLY_SUCCESS             = 0x00
	SOCKS5_REPLY_GENERAL_FAILURE     = 0x01
	SOCKS5_REPLY_RULESET_DENIED      = 0x02
	SOCKS5_REPLY_NETWORK_UNREACHABLE = 0x03
	SOCKS5_REPLY_HOST_UNREACHABLE    = 0x04
	SOCKS5_REPLY_CONNECTION_REFUSED  = 0x05
	SOCKS5_REPLY_TTL_EXPIRED         = 0x06
	SOCKS5_REPLY_CMD_NOT_SUPPORTED   = 0x07
	SOCKS5_REPLY_ATYP_NOT_SUPPORTED  = 0x08

	SOCKS5_USER_AUTH_VERSION = 0x01
	SOCKS5_USER_AUTH_SUCCESS = 0x00
	SOCKS5_USER_AUTH_FAILURE = 0x01
)

var errLateSocksResult = errors.New("late socks result for closed or terminal local stream")

// HandleSOCKS5 manages the SOCKS5 handshake and specialized requests.
func (c *Client) HandleSOCKS5(ctx context.Context, conn net.Conn) {

	// 1. Greeting
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		_ = conn.Close()
		return
	}

	if header[0] != SOCKS5_VERSION {
		_ = conn.Close()
		return
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		_ = conn.Close()
		return
	}

	methodSelected := byte(SOCKS5_AUTH_METHOD_NO_ACCEPTABLE)
	if c.cfg.SOCKS5Auth {
		for _, m := range methods {
			if m == SOCKS5_AUTH_METHOD_USER_PASS {
				methodSelected = SOCKS5_AUTH_METHOD_USER_PASS
				break
			}
		}
	} else {
		for _, m := range methods {
			if m == SOCKS5_AUTH_METHOD_NO_AUTH {
				methodSelected = SOCKS5_AUTH_METHOD_NO_AUTH
				break
			}
		}
	}

	_, _ = conn.Write([]byte{SOCKS5_VERSION, methodSelected})
	if methodSelected == SOCKS5_AUTH_METHOD_NO_ACCEPTABLE {
		_ = conn.Close()
		return
	}

	// 2. Authentication
	if methodSelected == SOCKS5_AUTH_METHOD_USER_PASS {
		authHeader := make([]byte, 2)
		if _, err := io.ReadFull(conn, authHeader); err != nil {
			_ = conn.Close()
			_ = conn.Close()
			return
		}
		if authHeader[0] != SOCKS5_USER_AUTH_VERSION {
			_ = conn.Close()
			return
		}

		userLen := int(authHeader[1])
		user := make([]byte, userLen)
		if _, err := io.ReadFull(conn, user); err != nil {
			_ = conn.Close()
			return
		}

		passLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, passLenBuf); err != nil {
			_ = conn.Close()
			return
		}
		passLen := int(passLenBuf[0])
		pass := make([]byte, passLen)
		if _, err := io.ReadFull(conn, pass); err != nil {
			_ = conn.Close()
			return
		}

		if string(user) != c.cfg.SOCKS5User || string(pass) != c.cfg.SOCKS5Pass {
			_, _ = conn.Write([]byte{SOCKS5_USER_AUTH_VERSION, SOCKS5_USER_AUTH_FAILURE})
			c.log.Warnf("🔒 <yellow>SOCKS5 Authentication failed for user: <cyan>%s</cyan></yellow>", string(user))
			_ = conn.Close()
			return
		}
		_, _ = conn.Write([]byte{SOCKS5_USER_AUTH_VERSION, SOCKS5_USER_AUTH_SUCCESS})
	}

	// 3. Request
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		_ = conn.Close()
		return
	}

	if reqHeader[0] != SOCKS5_VERSION || reqHeader[2] != 0x00 {
		_ = conn.Close()
		return
	}

	cmd := reqHeader[1]
	atyp := reqHeader[3]
	var addr string

	switch atyp {
	case SOCKS5_ATYP_IPV4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			_ = conn.Close()
			return
		}
		addr = net.IP(ip).String()
	case SOCKS5_ATYP_DOMAIN:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			_ = conn.Close()
			return
		}
		domainLen := int(lenBuf[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			_ = conn.Close()
			return
		}
		addr = string(domain)
	case SOCKS5_ATYP_IPV6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			_ = conn.Close()
			return
		}
		addr = net.IP(ip).String()
	default:
		_ = conn.Close()
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		_ = conn.Close()
		return
	}
	port := binary.BigEndian.Uint16(portBuf)

	if cmd == SOCKS5_CMD_CONNECT {
		c.HandleSOCKS5Connect(ctx, conn, addr, port, atyp)
		return
	}

	if cmd == SOCKS5_CMD_UDP_ASSOCIATE {
		c.handleSocksUDPAssociate(ctx, conn, addr, port, atyp)
		return
	}

	_ = c.sendSocksReply(conn, SOCKS5_REPLY_CMD_NOT_SUPPORTED, SOCKS5_ATYP_IPV4, net.IPv4zero, 0)
	_ = conn.Close()
}

func (c *Client) HandleSOCKS5Connect(ctx context.Context, conn net.Conn, addr string, port uint16, atyp byte) {
	// 1. Get a new Stream ID
	streamID, ok := c.get_new_stream_id()
	if !ok {
		c.log.Errorf("❌ <red>Failed to get new Stream ID for SOCKS5 CONNECT</red>")
		_ = c.sendSocksReply(conn, SOCKS5_REPLY_GENERAL_FAILURE, SOCKS5_ATYP_IPV4, net.IPv4zero, 0)
		return
	}

	c.log.Infof("🔌 <green>New SOCKS5 TCP CONNECT to <cyan>%s:%d</cyan>, Stream ID: <cyan>%d</cyan></green>", addr, port, streamID)

	// 2. Prepare Target Payload
	var targetPayload []byte
	targetPayload = append(targetPayload, atyp)
	switch atyp {
	case SOCKS5_ATYP_IPV4:
		targetPayload = append(targetPayload, net.ParseIP(addr).To4()...)
	case SOCKS5_ATYP_DOMAIN:
		targetPayload = append(targetPayload, byte(len(addr)))
		targetPayload = append(targetPayload, []byte(addr)...)
	case SOCKS5_ATYP_IPV6:
		targetPayload = append(targetPayload, net.ParseIP(addr).To16()...)
	}

	pBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(pBuf, port)
	targetPayload = append(targetPayload, pBuf...)

	// 3. Create Stream
	s := c.new_stream(streamID, conn, nil)
	if s == nil {
		_ = c.sendSocksReply(conn, SOCKS5_REPLY_GENERAL_FAILURE, SOCKS5_ATYP_IPV4, net.IPv4zero, 0)
		return
	}

	arqObj, ok := s.Stream.(*arq.ARQ)
	if !ok {
		return
	}

	// 4. Send SOCKS5_SYN via ARQ (Priority 0)
	fragments := fragmentPayload(targetPayload, c.syncedUploadMTU)
	total := uint8(len(fragments))
	sn := uint16(0) // Protocol usually uses 0 for SYN

	for i, frag := range fragments {
		arqObj.SendControlPacket(Enums.PACKET_SOCKS5_SYN, sn, uint8(i), total, frag, Enums.DefaultPacketPriority(Enums.PACKET_SOCKS5_SYN), true, nil)
	}
}

func (c *Client) getStream(streamID uint16) (*Stream_client, bool) {
	c.streamsMu.Lock()
	s, ok := c.active_streams[streamID]
	c.streamsMu.Unlock()
	return s, ok
}

func (c *Client) writeSocksConnectResult(streamID uint16, rep byte) error {
	s, ok := c.getStream(streamID)
	if !ok || s == nil || s.NetConn == nil {
		return errLateSocksResult
	}

	switch s.StatusValue() {
	case streamStatusCancelled, streamStatusDraining, streamStatusClosing, streamStatusTimeWait, streamStatusClosed:
		return errLateSocksResult
	}

	if !s.TerminalSince().IsZero() {
		return errLateSocksResult
	}

	s.stopPendingSOCKSWatch(true)

	if err := c.sendSocksReply(s.NetConn, rep, SOCKS5_ATYP_IPV4, net.IPv4zero, 0); err != nil {
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
			return errLateSocksResult
		}
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Err != nil {
			if errors.Is(opErr.Err, net.ErrClosed) || errors.Is(opErr.Err, io.ErrClosedPipe) {
				return errLateSocksResult
			}
		}
		return err
	}

	if rep == SOCKS5_REPLY_SUCCESS {
		s.SetStatus(streamStatusActive)
	} else {
		s.SetStatus(streamStatusSocksFailed)
	}

	return nil
}

func socksReplyForPacketType(packetType uint8) byte {
	switch packetType {
	case Enums.PACKET_SOCKS5_RULESET_DENIED:
		return SOCKS5_REPLY_RULESET_DENIED
	case Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE:
		return SOCKS5_REPLY_NETWORK_UNREACHABLE
	case Enums.PACKET_SOCKS5_HOST_UNREACHABLE:
		return SOCKS5_REPLY_HOST_UNREACHABLE
	case Enums.PACKET_SOCKS5_CONNECTION_REFUSED:
		return SOCKS5_REPLY_CONNECTION_REFUSED
	case Enums.PACKET_SOCKS5_TTL_EXPIRED:
		return SOCKS5_REPLY_TTL_EXPIRED
	case Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED:
		return SOCKS5_REPLY_CMD_NOT_SUPPORTED
	case Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED:
		return SOCKS5_REPLY_ATYP_NOT_SUPPORTED
	case Enums.PACKET_SOCKS5_AUTH_FAILED,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
		Enums.PACKET_SOCKS5_CONNECT_FAIL:
		return SOCKS5_REPLY_GENERAL_FAILURE
	default:
		return SOCKS5_REPLY_GENERAL_FAILURE
	}
}

func (c *Client) CloseStream(streamID uint16) {
	c.streamsMu.Lock()
	s, ok := c.active_streams[streamID]
	delete(c.active_streams, streamID)
	c.streamsMu.Unlock()

	if ok {
		s.Close()
	}
}

func (c *Client) removeStream(streamID uint16) {
	c.streamsMu.Lock()
	s, ok := c.active_streams[streamID]
	delete(c.active_streams, streamID)
	c.streamsMu.Unlock()

	if ok {
		s.Close()
	}
}

func (c *Client) handlePendingSOCKSLocalClose(streamID uint16, reason string) {
	s, ok := c.getStream(streamID)
	if !ok || s == nil || s.StatusValue() != streamStatusSocksConnecting {
		return
	}

	s.SetStatus(streamStatusCancelled)
	if s.NetConn != nil {
		_ = s.NetConn.Close()
	}

	arqObj, err := c.getStreamARQ(streamID)
	if err == nil {
		arqObj.CancelPendingSOCKS(reason)
	}
}

func (c *Client) sendSocksReply(conn net.Conn, rep byte, atyp byte, bndAddr net.IP, bndPort uint16) error {
	reply := []byte{SOCKS5_VERSION, rep, 0x00, atyp}

	if atyp == SOCKS5_ATYP_IPV4 {
		reply = append(reply, bndAddr.To4()...)
	} else if atyp == SOCKS5_ATYP_IPV6 {
		reply = append(reply, bndAddr.To16()...)
	} else if atyp == SOCKS5_ATYP_DOMAIN {
		// Just send zero IPv4 if it's domain atyp but we don't have a specific IP
		reply[3] = SOCKS5_ATYP_IPV4
		reply = append(reply, net.IPv4zero...)
	}

	pBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(pBuf, bndPort)
	reply = append(reply, pBuf...)
	_, err := conn.Write(reply)
	return err
}

func (c *Client) handleSocksUDPAssociate(ctx context.Context, conn net.Conn, clientAddr string, clientPort uint16, atyp byte) {
	// Create UDP socket for association
	bindAddr := &net.UDPAddr{
		IP:   net.ParseIP(c.cfg.ListenIP),
		Port: 0, // Random port
	}
	udpConn, err := net.ListenUDP("udp", bindAddr)
	if err != nil {
		_ = c.sendSocksReply(conn, SOCKS5_REPLY_GENERAL_FAILURE, SOCKS5_ATYP_IPV4, net.IPv4zero, 0)
		return
	}
	defer udpConn.Close()

	boundAddr := udpConn.LocalAddr().(*net.UDPAddr)
	err = c.sendSocksReply(conn, SOCKS5_REPLY_SUCCESS, SOCKS5_ATYP_IPV4, boundAddr.IP, uint16(boundAddr.Port))
	if err != nil {
		return
	}

	c.log.Debugf("📡 <green>SOCKS5 UDP Associate established on <cyan>%s</cyan></green>", boundAddr.String())

	// Start UDP relay loop
	buf := make([]byte, 4096)
	for {
		_ = udpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, peerAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		if n < 6 { // Min header size
			continue
		}

		// Header: RSV(2), FRAG(1), ATYP(1), ADDR, PORT, DATA
		// header[2] is FRAG, must be 0x00
		if buf[2] != 0x00 {
			continue
		}

		payloadOffset := 0
		var targetPort uint16

		var targetAddr string
		switch buf[3] {
		case SOCKS5_ATYP_IPV4:
			payloadOffset = 10
			targetAddr = net.IP(buf[4:8]).String()
			targetPort = binary.BigEndian.Uint16(buf[8:10])
		case SOCKS5_ATYP_DOMAIN:
			domainLen := int(buf[4])
			payloadOffset = 4 + 1 + domainLen + 2
			targetAddr = string(buf[5 : 5+domainLen])
			targetPort = binary.BigEndian.Uint16(buf[4+1+domainLen : payloadOffset])
		case SOCKS5_ATYP_IPV6:
			payloadOffset = 22
			targetAddr = net.IP(buf[4:20]).String()
			targetPort = binary.BigEndian.Uint16(buf[20:22])
		default:
			continue
		}

		// Check if it's DNS (Port 53)
		if targetPort != 53 {
			c.log.Debugf("⚠️ <yellow>SOCKS5 UDP packet to non-DNS port %s:%d dropped. Closing association.</yellow>", targetAddr, targetPort)
			return
		}

		c.log.Infof("📡 <green>Received DNS Query from SOCKS5 UDP: <cyan>%d bytes</cyan>, Target: <cyan>%s:%d</cyan></green>", n-payloadOffset, targetAddr, targetPort)

		dnsQuery := buf[payloadOffset:n]

		// Use ProcessDNSQuery. If Cache Miss (returns false), we close and rely on client retry.
		isHit := c.ProcessDNSQuery(dnsQuery, peerAddr, func(resp []byte) {
			// Encapsulate DNS response back into SOCKS5 UDP
			header := []byte{0x00, 0x00, 0x00, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 53}
			fullResp := append(header, resp...)
			_, _ = udpConn.WriteToUDP(fullResp, peerAddr)
		})

		if !isHit {
			c.log.Debugf("🧳 <yellow>SOCKS5 DNS Miss or Pending - Closing association to trigger client retry.</yellow>")
			return // Close association immediately as per requirement
		}
	}
}

func (c *Client) HandleSocksConnected(packet VpnProto.Packet) error {
	s, ok := c.getStream(packet.StreamID)
	if !ok || s == nil {
		c.handleMissingStreamPacket(packet)
		return nil
	}

	if ok && s.StatusValue() == streamStatusCancelled {
		if arqObj, err := c.getStreamARQ(packet.StreamID); err == nil {
			arqObj.MarkSocksFailed(Enums.PACKET_STREAM_RST)
		}
		c.removeStream(packet.StreamID)
		return nil
	}

	if err := c.writeSocksConnectResult(packet.StreamID, SOCKS5_REPLY_SUCCESS); err != nil {
		if errors.Is(err, errLateSocksResult) {
			return nil
		}
		c.handlePendingSOCKSLocalClose(packet.StreamID, "failed to write SOCKS success reply")
		return err
	}

	arqObj, err := c.getStreamARQ(packet.StreamID)
	if err == nil {
		arqObj.MarkSocksConnected()
		if s != nil {
			for _, chunk := range s.takePendingLocalData() {
				arqObj.InjectOutboundData(chunk)
			}
		}
	}

	c.log.Infof("🔌 <green>Socks5 successfully connected for stream %d</green>", packet.StreamID)
	return nil
}

func (c *Client) HandleSocksFailure(packet VpnProto.Packet) error {
	s, ok := c.getStream(packet.StreamID)
	if !ok || s == nil {
		c.handleMissingStreamPacket(packet)
		return nil
	}

	if ok && s.StatusValue() == streamStatusCancelled {
		arqObj, err := c.getStreamARQ(packet.StreamID)
		if err == nil {
			arqObj.MarkSocksFailed(packet.PacketType)
		}
		c.removeStream(packet.StreamID)
		return nil
	}

	if err := c.writeSocksConnectResult(packet.StreamID, socksReplyForPacketType(packet.PacketType)); err != nil {
		if errors.Is(err, errLateSocksResult) {
			return nil
		}
		c.handlePendingSOCKSLocalClose(packet.StreamID, "failed to write SOCKS failure reply")
		return err
	}

	arqObj, err := c.getStreamARQ(packet.StreamID)

	if err != nil {
		return nil
	}

	arqObj.MarkSocksFailed(packet.PacketType)
	c.removeStream(packet.StreamID)
	return nil
}

func (c *Client) HandleSocksControlAck(packet VpnProto.Packet) error {
	arqObj, err := c.getStreamARQ(packet.StreamID)

	if err != nil {
		c.handleMissingStreamPacket(packet)
		return nil
	}

	arqObj.ReceiveControlAck(packet.PacketType, packet.SequenceNum, packet.FragmentID)
	return nil
}
