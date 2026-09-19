// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (protected_socket.go) creates the upstream UDP sockets and, when
// FD_CONTROL_UNIX_SOCKET is set, passes each new socket fd to an Android
// VpnService protect server before the socket is connected or bound.
// ==============================================================================

package client

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"masterdnsvpn-go/internal/sockprotect"
)

// protectControl is the net.Dialer / net.ListenConfig Control hook for every
// upstream UDP socket. When FD_CONTROL_UNIX_SOCKET is set it hands the new
// socket fd to the protect server before connect/bind, so an Android
// VpnService host can keep it outside the tunnel. Otherwise it does nothing.
func (c *Client) protectControl(network, address string, rc syscall.RawConn) error {
	path := c.cfg.FDControlUnixSocket
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
		return fmt.Errorf("protect upstream socket %s %s: %w", network, address, protectErr)
	}
	return nil
}

// dialUDPResolver opens a connected UDP socket to the resolver.
func (c *Client) dialUDPResolver(ctx context.Context, resolverLabel string) (*net.UDPConn, error) {
	dialer := net.Dialer{Control: c.protectControl}
	conn, err := dialer.DialContext(ctx, "udp", resolverLabel)
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

// listenUDPProtected opens an unconnected UDP socket used to exchange tunnel
// datagrams with upstream resolvers.
func (c *Client) listenUDPProtected(ctx context.Context, address string) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: c.protectControl}
	packetConn, err := lc.ListenPacket(ctx, "udp", address)
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
