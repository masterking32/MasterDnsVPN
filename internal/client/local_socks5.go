// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	SocksProto "masterdnsvpn-go/internal/socksproto"
)

var errSOCKS5UnsupportedCommand = errors.New("unsupported socks5 command")

type socks5HandshakeRequest struct {
	Command       byte
	TargetPayload []byte
}

func (c *Client) RunLocalSOCKS5Listener(ctx context.Context) error {
	if c == nil || !c.cfg.LocalSOCKS5Enabled {
		return nil
	}
	if err := c.startStream0Runtime(ctx); err != nil {
		return err
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(c.cfg.LocalSOCKS5IP, strconvItoa(c.cfg.LocalSOCKS5Port)))
	if err != nil {
		return err
	}
	defer listener.Close()

	c.log.Infof(
		"🧦 <green>Local SOCKS5 Listener Ready</green> <magenta>|</magenta> <blue>Addr</blue>: <cyan>%s:%d</cyan>",
		c.cfg.LocalSOCKS5IP,
		c.cfg.LocalSOCKS5Port,
	)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go c.handleLocalSOCKS5Conn(conn)
	}
}

func (c *Client) handleLocalSOCKS5Conn(conn net.Conn) {
	handedOff := false
	defer func() {
		if recovered := recover(); recovered != nil && c.log != nil {
			c.log.Errorf(
				"💥 <red>SOCKS5 Handler Panic Recovered</red> <magenta>|</magenta> <yellow>%v</yellow>",
				recovered,
			)
		}
		if !handedOff {
			_ = conn.Close()
		}
	}()

	timeout := time.Duration(c.cfg.LocalSOCKS5HandshakeSec * float64(time.Second))
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	request, err := performSOCKS5Handshake(conn)
	if err != nil {
		_ = writeSOCKS5Failure(conn, 0x07)
		return
	}

	switch request.Command {
	case 0x01:
		streamID, openErr := c.OpenSOCKS5Stream(request.TargetPayload, timeout)
		if openErr != nil {
			_ = writeSOCKS5Failure(conn, mapSOCKS5FailureReply(openErr))
			return
		}
		if _, writeErr := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); writeErr != nil {
			return
		}
		_ = conn.SetDeadline(time.Time{})

		stream := c.createStream(streamID, conn)
		handedOff = true
		go c.runLocalStreamReadLoop(stream, timeout)
	case 0x03:
		_ = conn.SetDeadline(time.Time{})
		if err := c.runLocalSOCKS5UDPAssociate(conn); err != nil && c.log != nil {
			c.log.Debugf(
				"🧦 <yellow>SOCKS5 UDP Associate Closed</yellow> <magenta>|</magenta> <cyan>%v</cyan>",
				err,
			)
		}
	default:
		_ = writeSOCKS5Failure(conn, 0x07)
	}
}

func performSOCKS5Handshake(conn net.Conn) (socks5HandshakeRequest, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return socks5HandshakeRequest{}, err
	}
	if header[0] != 0x05 || header[1] == 0 {
		return socks5HandshakeRequest{}, errSOCKS5UnsupportedCommand
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return socks5HandshakeRequest{}, err
	}
	supportsNoAuth := false
	for _, method := range methods {
		if method == 0x00 {
			supportsNoAuth = true
			break
		}
	}
	if !supportsNoAuth {
		_, _ = conn.Write([]byte{0x05, 0xFF})
		return socks5HandshakeRequest{}, errSOCKS5UnsupportedCommand
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return socks5HandshakeRequest{}, err
	}

	requestHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, requestHeader); err != nil {
		return socks5HandshakeRequest{}, err
	}
	if requestHeader[0] != 0x05 || requestHeader[2] != 0x00 {
		return socks5HandshakeRequest{}, errSOCKS5UnsupportedCommand
	}
	if requestHeader[1] != 0x01 && requestHeader[1] != 0x03 {
		return socks5HandshakeRequest{}, errSOCKS5UnsupportedCommand
	}

	payload, err := readSOCKS5TargetPayload(conn, requestHeader[3])
	if err != nil {
		return socks5HandshakeRequest{}, err
	}
	return socks5HandshakeRequest{
		Command:       requestHeader[1],
		TargetPayload: payload,
	}, nil
}

func readSOCKS5TargetPayload(conn net.Conn, atyp byte) ([]byte, error) {
	switch atyp {
	case 0x01:
		payload := make([]byte, 1+4+2)
		payload[0] = atyp
		if _, err := io.ReadFull(conn, payload[1:]); err != nil {
			return nil, err
		}
		return payload, nil
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return nil, err
		}
		if length[0] == 0 {
			return nil, SocksProto.ErrInvalidDomainLength
		}
		payload := make([]byte, 1+1+int(length[0])+2)
		payload[0] = atyp
		payload[1] = length[0]
		if _, err := io.ReadFull(conn, payload[2:]); err != nil {
			return nil, err
		}
		return payload, nil
	case 0x04:
		payload := make([]byte, 1+16+2)
		payload[0] = atyp
		if _, err := io.ReadFull(conn, payload[1:]); err != nil {
			return nil, err
		}
		return payload, nil
	default:
		return nil, SocksProto.ErrUnsupportedAddressType
	}
}

func writeSOCKS5Failure(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func mapSOCKS5FailureReply(err error) byte {
	if err == nil {
		return 0x01
	}
	switch {
	case errors.Is(err, errSOCKS5UnsupportedCommand):
		return 0x07
	case errors.Is(err, SocksProto.ErrUnsupportedAddressType):
		return 0x08
	default:
		name := strings.ToUpper(err.Error())
		switch name {
		case "PACKET_SOCKS5_CONNECTION_REFUSED":
			return 0x05
		case "PACKET_SOCKS5_NETWORK_UNREACHABLE":
			return 0x03
		case "PACKET_SOCKS5_HOST_UNREACHABLE":
			return 0x04
		case "PACKET_SOCKS5_TTL_EXPIRED":
			return 0x06
		default:
			switch {
			case strings.Contains(name, "PACKET_SOCKS5_CONNECTION_REFUSED"):
				return 0x05
			case strings.Contains(name, "PACKET_SOCKS5_NETWORK_UNREACHABLE"):
				return 0x03
			case strings.Contains(name, "PACKET_SOCKS5_HOST_UNREACHABLE"):
				return 0x04
			case strings.Contains(name, "PACKET_SOCKS5_TTL_EXPIRED"):
				return 0x06
			}
			return 0x01
		}
	}
}

func strconvItoa(value int) string {
	return strconv.Itoa(value)
}

func (c *Client) runLocalSOCKS5UDPAssociate(conn net.Conn) error {
	if c == nil || conn == nil {
		return errSOCKS5UnsupportedCommand
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(c.cfg.LocalSOCKS5IP),
		Port: 0,
	})
	if err != nil {
		_ = writeSOCKS5Failure(conn, 0x01)
		return err
	}
	defer udpConn.Close()

	if err := writeSOCKS5UDPAssociateReply(conn, udpConn.LocalAddr().(*net.UDPAddr)); err != nil {
		return err
	}

	controlClosed := make(chan struct{})
	go func() {
		defer close(controlClosed)
		sink := make([]byte, 1)
		_, _ = conn.Read(sink)
	}()

	buffer := make([]byte, EDnsSafeUDPSize+256)
	var clientAddr *net.UDPAddr
	for {
		_ = udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, readErr := udpConn.ReadFromUDP(buffer)
		if readErr != nil {
			if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				select {
				case <-controlClosed:
					return nil
				default:
					continue
				}
			}
			return readErr
		}

		if clientAddr == nil {
			clientAddr = addr
		} else if !addr.IP.Equal(clientAddr.IP) || addr.Port != clientAddr.Port {
			continue
		}

		response := c.handleSOCKS5UDPDatagram(buffer[:n])
		if len(response) == 0 {
			continue
		}
		if _, err := udpConn.WriteToUDP(response, clientAddr); err != nil {
			return err
		}
	}
}

func (c *Client) handleSOCKS5UDPDatagram(packet []byte) []byte {
	if c == nil {
		return nil
	}
	datagram, err := SocksProto.ParseUDPDatagram(packet)
	if err != nil {
		return nil
	}
	if datagram.Target.Port != 53 {
		return nil
	}
	response := c.resolveDNSQueryPacket(datagram.Payload)
	if len(response) == 0 {
		return nil
	}
	return SocksProto.BuildUDPDatagram(datagram.Target, response)
}

func writeSOCKS5UDPAssociateReply(conn net.Conn, addr *net.UDPAddr) error {
	if conn == nil || addr == nil {
		return errSOCKS5UnsupportedCommand
	}
	ipv4 := addr.IP.To4()
	if ipv4 == nil {
		ipv4 = net.IPv4zero.To4()
	}
	reply := make([]byte, 10)
	reply[0] = 0x05
	reply[1] = 0x00
	reply[2] = 0x00
	reply[3] = 0x01
	copy(reply[4:8], ipv4)
	reply[8] = byte(addr.Port >> 8)
	reply[9] = byte(addr.Port)
	_, err := conn.Write(reply)
	return err
}
