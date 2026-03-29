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
	"slices"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	SOCKS4_VERSION = 0x04
	SOCKS5_VERSION = 0x05

	SOCKS4_CMD_CONNECT = 0x01

	SOCKS4_REPLY_GRANTED  = 0x5A
	SOCKS4_REPLY_REJECTED = 0x5B

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

func (c *Client) supportsSOCKS4() bool {
	if !c.cfg.SOCKS5Auth {
		return true
	}

	return c.cfg.SOCKS5User != "" && c.cfg.SOCKS5Pass == ""
}

// HandleSOCKS5 manages the local SOCKS handshake and supports SOCKS4/4a and SOCKS5.
func (c *Client) HandleSOCKS5(ctx context.Context, conn net.Conn) {
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil {
		_ = conn.Close()
		return
	}

	switch version[0] {
	case SOCKS5_VERSION:
		c.handleSOCKS5Request(ctx, conn)
	case SOCKS4_VERSION:
		if !c.supportsSOCKS4() {
			_ = conn.Close()
			return
		}
		c.handleSOCKS4Request(ctx, conn)
	default:
		_ = conn.Close()
	}
}

func (c *Client) handleSOCKS5Request(ctx context.Context, conn net.Conn) {
	header := make([]byte, 1)
	if _, err := io.ReadFull(conn, header); err != nil {
		_ = conn.Close()
		return
	}

	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		_ = conn.Close()
		return
	}

	methodSelected := byte(SOCKS5_AUTH_METHOD_NO_ACCEPTABLE)
	if c.cfg.SOCKS5Auth {
		if slices.Contains(methods, SOCKS5_AUTH_METHOD_USER_PASS) {
			methodSelected = SOCKS5_AUTH_METHOD_USER_PASS
		}
	} else {
		if slices.Contains(methods, SOCKS5_AUTH_METHOD_NO_AUTH) {
			methodSelected = SOCKS5_AUTH_METHOD_NO_AUTH
		}
	}

	_, _ = conn.Write([]byte{SOCKS5_VERSION, methodSelected})
	if methodSelected == SOCKS5_AUTH_METHOD_NO_ACCEPTABLE {
		_ = conn.Close()
		return
	}

	if methodSelected == SOCKS5_AUTH_METHOD_USER_PASS {
		authHeader := make([]byte, 2)
		if _, err := io.ReadFull(conn, authHeader); err != nil {
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
		c.handleSOCKSConnect(ctx, conn, addr, port, atyp, SOCKS5_VERSION)
		return
	}

	if cmd == SOCKS5_CMD_UDP_ASSOCIATE {
		c.handleSocksUDPAssociate(ctx, conn, addr, port, atyp)
		return
	}

	_ = c.sendSocksReply(conn, SOCKS5_REPLY_CMD_NOT_SUPPORTED, SOCKS5_ATYP_IPV4, net.IPv4zero, 0)
	_ = conn.Close()
}

func (c *Client) handleSOCKS4Request(ctx context.Context, conn net.Conn) {
	req := make([]byte, 7)
	if _, err := io.ReadFull(conn, req); err != nil {
		_ = conn.Close()
		return
	}

	if req[0] != SOCKS4_CMD_CONNECT {
		_ = c.sendSocks4Reply(conn, false)
		_ = conn.Close()
		return
	}

	port := binary.BigEndian.Uint16(req[1:3])
	dstIP := net.IPv4(req[3], req[4], req[5], req[6])

	userID, err := readNullTerminatedSocksField(conn)
	if err != nil {
		_ = conn.Close()
		return
	}

	if c.cfg.SOCKS5Auth && c.cfg.SOCKS5User != string(userID) {
		_ = c.sendSocks4Reply(conn, false)
		_ = conn.Close()
		return
	}

	atyp := byte(SOCKS5_ATYP_IPV4)
	addr := dstIP.String()

	// SOCKS4a: 0.0.0.x, with the hostname appended after USERID.
	if req[3] == 0x00 && req[4] == 0x00 && req[5] == 0x00 && req[6] != 0x00 {
		domain, err := readNullTerminatedSocksField(conn)
		if err != nil || len(domain) == 0 {
			_ = c.sendSocks4Reply(conn, false)
			_ = conn.Close()
			return
		}
		atyp = SOCKS5_ATYP_DOMAIN
		addr = string(domain)
	}

	c.handleSOCKSConnect(ctx, conn, addr, port, atyp, SOCKS4_VERSION)
}

func readNullTerminatedSocksField(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 0, 64)
	single := make([]byte, 1)
	for {
		if _, err := io.ReadFull(conn, single); err != nil {
			return nil, err
		}
		if single[0] == 0x00 {
			return buf, nil
		}
		if len(buf) >= 255 {
			return nil, errors.New("socks field too long")
		}
		buf = append(buf, single[0])
	}
}

func (c *Client) handleSOCKSConnect(ctx context.Context, conn net.Conn, addr string, port uint16, atyp byte, socksVersion byte) {
	streamID, ok := c.get_new_stream_id()
	if !ok {
		c.log.Errorf("❌ <red>Failed to get new Stream ID for SOCKS CONNECT</red>")
		if socksVersion == SOCKS4_VERSION {
			_ = c.sendSocks4Reply(conn, false)
		} else {
			_ = c.sendSocksReply(conn, SOCKS5_REPLY_GENERAL_FAILURE, SOCKS5_ATYP_IPV4, net.IPv4zero, 0)
		}
		return
	}

	socksLabel := "SOCKS5"
	if socksVersion == SOCKS4_VERSION {
		socksLabel = "SOCKS4"
	}

	c.log.Infof("🔌 <green>New %s TCP CONNECT to <cyan>%s:%d</cyan>, Stream ID: <cyan>%d</cyan></green>", socksLabel, addr, port, streamID)

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

	s := c.new_stream(streamID, conn, nil)
	if s == nil {
		if socksVersion == SOCKS4_VERSION {
			_ = c.sendSocks4Reply(conn, false)
		} else {
			_ = c.sendSocksReply(conn, SOCKS5_REPLY_GENERAL_FAILURE, SOCKS5_ATYP_IPV4, net.IPv4zero, 0)
		}
		return
	}

	s.LocalSocksVersion = socksVersion

	arqObj, ok := s.Stream.(*arq.ARQ)
	if !ok {
		return
	}

	fragments := fragmentPayload(targetPayload, c.syncedUploadMTU)
	total := uint8(len(fragments))
	sn := uint16(0)

	for i, frag := range fragments {
		arqObj.SendControlPacketWithTTL(
			Enums.PACKET_SOCKS5_SYN,
			sn,
			uint8(i),
			total,
			frag,
			Enums.DefaultPacketPriority(Enums.PACKET_SOCKS5_SYN),
			true,
			nil,
			120*time.Second,
		)
	}
}

func (c *Client) writeSocksConnectResult(streamID uint16, rep byte) error {
	s, ok := c.getStream(streamID)
	if !ok || s == nil {
		return errLateSocksResult
	}

	s.socksResultMu.Lock()
	defer s.socksResultMu.Unlock()

	return c.writeSocksConnectResultLocked(s, rep)
}

func (c *Client) writeSocksConnectResultLocked(s *Stream_client, rep byte) error {
	if s == nil || s.NetConn == nil {
		return errLateSocksResult
	}

	switch s.StatusValue() {
	case streamStatusCancelled, streamStatusDraining, streamStatusClosing, streamStatusTimeWait, streamStatusClosed:
		return errLateSocksResult
	}

	if !s.TerminalSince().IsZero() {
		return errLateSocksResult
	}

	var err error
	if s.LocalSocksVersion == SOCKS4_VERSION {
		err = c.sendSocks4Reply(s.NetConn, rep == SOCKS5_REPLY_SUCCESS)
	} else {
		err = c.sendSocksReply(s.NetConn, rep, SOCKS5_ATYP_IPV4, net.IPv4zero, 0)
	}

	if err != nil {
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

func (c *Client) CloseStream(streamID uint16, force bool, ttl time.Duration) {
	c.streamsMu.RLock()
	s, ok := c.active_streams[streamID]
	c.streamsMu.RUnlock()

	if ok {
		s.CloseStream(force, ttl)
	}
}

func (c *Client) removeStream(streamID uint16) {
	c.streamsMu.Lock()
	s, ok := c.active_streams[streamID]
	delete(c.active_streams, streamID)
	c.streamsMu.Unlock()
	c.bumpStreamSetVersion()

	if ok {
		s.Close()
	}
}

func (c *Client) handlePendingSOCKSLocalClose(streamID uint16, reason string) {
	s, ok := c.getStream(streamID)
	if !ok || s == nil {
		return
	}

	s.socksResultMu.Lock()
	if s.StatusValue() != streamStatusSocksConnecting {
		s.socksResultMu.Unlock()
		return
	}
	s.SetStatus(streamStatusCancelled)
	if s.NetConn != nil {
		_ = s.NetConn.Close()
	}
	s.MarkTerminal(time.Now())
	s.socksResultMu.Unlock()

	arqObj, err := c.getStreamARQ(streamID)
	if err == nil {
		arqObj.Close(reason, arq.CloseOptions{SendRST: true})
	}
}

func (c *Client) sendSocks4Reply(conn net.Conn, success bool) error {
	replyCode := byte(SOCKS4_REPLY_REJECTED)
	if success {
		replyCode = SOCKS4_REPLY_GRANTED
	}
	_, err := conn.Write([]byte{0x00, replyCode, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return err
}

func (c *Client) sendSocksReply(conn net.Conn, rep byte, atyp byte, bndAddr net.IP, bndPort uint16) error {
	reply := []byte{SOCKS5_VERSION, rep, 0x00, atyp}

	if atyp == SOCKS5_ATYP_IPV4 {
		reply = append(reply, bndAddr.To4()...)
	} else if atyp == SOCKS5_ATYP_IPV6 {
		reply = append(reply, bndAddr.To16()...)
	} else if atyp == SOCKS5_ATYP_DOMAIN {
		reply[3] = SOCKS5_ATYP_IPV4
		reply = append(reply, net.IPv4zero...)
	}

	pBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(pBuf, bndPort)
	reply = append(reply, pBuf...)
	_, err := conn.Write(reply)
	return err
}

func (c *Client) rejectSocksUDPAssociateUnsupportedTarget(conn net.Conn, targetAddr string, targetPort uint16) {
	if c.log != nil {
		c.log.Debugf("⚠️ <yellow>SOCKS5 UDP packet to unsupported target %s:%d rejected (Only DNS/53 allowed).</yellow>", targetAddr, targetPort)
	}
}

func (c *Client) handleSocksUDPAssociate(ctx context.Context, conn net.Conn, clientAddr string, clientPort uint16, atyp byte) {
	replyIP := net.ParseIP(c.cfg.ListenIP)
	if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok && tcpAddr != nil && tcpAddr.IP != nil {
		replyIP = tcpAddr.IP
	}
	if replyIP == nil || replyIP.IsUnspecified() {
		replyIP = net.IPv4(127, 0, 0, 1)
	}

	replyATYP := byte(SOCKS5_ATYP_IPV4)
	if replyIP.To4() == nil {
		replyATYP = SOCKS5_ATYP_IPV6
	}

	bindAddr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 0,
	}
	udpConn, err := net.ListenUDP("udp", bindAddr)
	if err != nil {
		_ = c.sendSocksReply(conn, SOCKS5_REPLY_GENERAL_FAILURE, SOCKS5_ATYP_IPV4, net.IPv4zero, 0)
		return
	}
	defer udpConn.Close()

	boundAddr := udpConn.LocalAddr().(*net.UDPAddr)
	err = c.sendSocksReply(conn, SOCKS5_REPLY_SUCCESS, replyATYP, boundAddr.IP, uint16(boundAddr.Port))
	if err != nil {
		return
	}

	buf := make([]byte, 4096)
	for {
		_ = udpConn.SetReadDeadline(time.Now().Add(c.cfg.SOCKSUDPAssociateReadTimeout()))
		n, peerAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return
			}
			return
		}

		if n < 6 {
			continue
		}

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

		if payloadOffset > n {
			continue
		}

		if targetPort != 53 {
			c.rejectSocksUDPAssociateUnsupportedTarget(conn, targetAddr, targetPort)
			continue
		}

		c.log.Infof("📡 <green>Received DNS Query from SOCKS5 UDP: <cyan>%d bytes</cyan>, Target: <cyan>%s:%d</cyan></green>", n-payloadOffset, targetAddr, targetPort)

		dnsQuery := buf[payloadOffset:n]

		isHit := c.ProcessDNSQuery(dnsQuery, peerAddr, func(resp []byte) {
			header := []byte{0x00, 0x00, 0x00, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 53}
			fullResp := append(header, resp...)
			_, _ = udpConn.WriteToUDP(fullResp, peerAddr)
		})

		if !isHit {
			c.log.Debugf("🧳 <yellow>SOCKS5 DNS Miss or Pending - Closing association to trigger client retry.</yellow>")
			return
		}
	}
}

func (c *Client) HandleSocksConnected(packet VpnProto.Packet) error {
	s, ok := c.getStream(packet.StreamID)
	if !ok || s == nil {
		return nil
	}

	s.socksResultMu.Lock()
	switch s.StatusValue() {
	case streamStatusActive:
		s.socksResultMu.Unlock()
		return nil
	case streamStatusSocksFailed, streamStatusDraining, streamStatusClosing, streamStatusTimeWait, streamStatusClosed:
		s.socksResultMu.Unlock()
		return nil
	}

	if ok && s.StatusValue() == streamStatusCancelled {
		s.socksResultMu.Unlock()
		if arqObj, err := c.getStreamARQ(packet.StreamID); err == nil {
			arqObj.Close("late SOCKS success after local cancellation", arq.CloseOptions{SendRST: true})
		}
		return nil
	}

	err := c.writeSocksConnectResultLocked(s, SOCKS5_REPLY_SUCCESS)
	s.socksResultMu.Unlock()
	if err != nil {
		if errors.Is(err, errLateSocksResult) {
			if arqObj, arqErr := c.getStreamARQ(packet.StreamID); arqErr == nil {
				arqObj.Close("late SOCKS success result", arq.CloseOptions{SendRST: true})
			}
			return nil
		}
		c.handlePendingSOCKSLocalClose(packet.StreamID, "failed to write SOCKS success reply")
		return err
	}

	arqObj, err := c.getStreamARQ(packet.StreamID)
	if err == nil {
		arqObj.SetIOReady(true)
	}

	c.log.Debugf("🔌 <green>Socks successfully connected for stream %d</green>", packet.StreamID)
	return nil
}

func (c *Client) HandleSocksFailure(packet VpnProto.Packet) error {
	s, ok := c.getStream(packet.StreamID)
	if !ok || s == nil {
		return nil
	}

	s.socksResultMu.Lock()
	switch s.StatusValue() {
	case streamStatusSocksFailed, streamStatusDraining, streamStatusClosing, streamStatusTimeWait, streamStatusClosed:
		s.socksResultMu.Unlock()
		return nil
	}

	if ok && s.StatusValue() == streamStatusCancelled {
		s.socksResultMu.Unlock()
		arqObj, err := c.getStreamARQ(packet.StreamID)
		if err == nil {
			arqObj.Close("SOCKS failure received after local cancellation", arq.CloseOptions{SendRST: true})
		}
		return nil
	}

	err := c.writeSocksConnectResultLocked(s, socksReplyForPacketType(packet.PacketType))
	s.socksResultMu.Unlock()
	if err != nil {
		if errors.Is(err, errLateSocksResult) {
			if arqObj, arqErr := c.getStreamARQ(packet.StreamID); arqErr == nil {
				arqObj.Close("late SOCKS failure result", arq.CloseOptions{SendRST: true})
			}
			return nil
		}
		c.handlePendingSOCKSLocalClose(packet.StreamID, "failed to write SOCKS failure reply")
		return err
	}

	arqObj, err := c.getStreamARQ(packet.StreamID)
	if err != nil {
		return nil
	}

	arqObj.Close("SOCKS failure received", arq.CloseOptions{Force: true})
	return nil
}

func (c *Client) HandleSocksControlAck(packet VpnProto.Packet) error {
	arqObj, err := c.getStreamARQ(packet.StreamID)
	if err != nil {
		return nil
	}

	arqObj.HandleAckPacket(packet.PacketType, packet.SequenceNum, packet.FragmentID)
	return nil
}
