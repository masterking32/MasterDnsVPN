package client

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"

	"masterdnsvpn-go/internal/sockprotect"
)

func (c *Client) protectPath() string {
	if c == nil {
		return ""
	}
	return strings.TrimSpace(c.cfg.FDControlUnixSocket)
}

func (c *Client) protectControl(network, address string, rc syscall.RawConn) error {
	path := c.protectPath()
	if path == "" {
		return nil
	}

	var protectErr error
	if err := rc.Control(func(fd uintptr) {
		protectErr = sockprotect.ProtectFD(path, fd)
	}); err != nil {
		return fmt.Errorf("socket control failed for %s %s: %w", network, address, err)
	}
	if protectErr != nil {
		return fmt.Errorf("failed to protect upstream socket for %s %s: %w", network, address, protectErr)
	}
	return nil
}

func (c *Client) dialUDPResolver(resolverLabel string) (*net.UDPConn, error) {
	if c.protectPath() == "" {
		addr, err := net.ResolveUDPAddr("udp", resolverLabel)
		if err != nil {
			return nil, err
		}
		return net.DialUDP("udp", nil, addr)
	}

	dialer := net.Dialer{
		Control: c.protectControl,
	}
	conn, err := dialer.DialContext(context.Background(), "udp", resolverLabel)
	if err != nil {
		return nil, err
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected udp resolver connection type %T", conn)
	}
	return udpConn, nil
}

func (c *Client) listenUDPProtected(ctx context.Context, addr *net.UDPAddr) (*net.UDPConn, error) {
	if c.protectPath() == "" {
		return net.ListenUDP("udp", addr)
	}

	if addr == nil {
		addr = &net.UDPAddr{}
	}
	lc := net.ListenConfig{
		Control: c.protectControl,
	}
	packetConn, err := lc.ListenPacket(ctx, "udp", addr.String())
	if err != nil {
		return nil, err
	}

	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return nil, fmt.Errorf("unexpected udp listener connection type %T", packetConn)
	}
	return udpConn, nil
}
