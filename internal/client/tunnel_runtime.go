// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (tunnel_runtime.go) handles low-level UDP network operations,
// including sending DNS-encapsulated packets and receiving responses.
// ==============================================================================

package client

import (
	"errors"
	"net"
	"time"

	"masterdnsvpn-go/internal/dnsparser"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	// RuntimeUDPReadBufferSize defines the maximum size of the UDP read buffer.
	RuntimeUDPReadBufferSize = 65535
)

// exchangeUDPQueryWithConn sends one UDP packet through the provided connection
// and waits for a response with a matching DNS transaction ID.
func (c *Client) exchangeUDPQueryWithConn(conn *net.UDPConn, packet []byte, timeout time.Duration) ([]byte, error) {
	if len(packet) < 2 {
		return nil, errors.New("malformed dns query")
	}
	expectedID0 := packet[0]
	expectedID1 := packet[1]

	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}

	buffer := c.getRuntimeUDPBuffer()

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			c.putRuntimeUDPBuffer(buffer)
			return nil, err
		}

		if n >= 2 && buffer[0] == expectedID0 && buffer[1] == expectedID1 {
			// Copy matched response out so the pooled buffer can be recycled.
			result := make([]byte, n)
			copy(result, buffer[:n])
			c.putRuntimeUDPBuffer(buffer)
			return result, nil
		}
	}
}

func (c *Client) sendOneWayDNSQuery(resolver Connection, packet []byte, deadline time.Time) error {
	udpConn, err := c.getUDPConn(resolver.ResolverLabel)
	if err != nil {
		return err
	}

	if err := udpConn.SetWriteDeadline(deadline); err != nil {
		_ = udpConn.Close()
		return err
	}

	if _, err := udpConn.Write(packet); err != nil {
		_ = udpConn.Close()
		return err
	}

	c.putUDPConn(resolver.ResolverLabel, udpConn)
	return nil
}

// getUDPConn retrieves a UDP connection from the pool for the specified resolver.
// If no connection is available in the pool, it dials a new one.
func (c *Client) getUDPConn(resolverLabel string) (*net.UDPConn, error) {
	c.resolverConnsMu.Lock()
	pool, ok := c.resolverConns[resolverLabel]
	if !ok {
		pool = make(chan *net.UDPConn, c.cfg.ResolverUDPConnectionPoolSize)
		c.resolverConns[resolverLabel] = pool
	}
	c.resolverConnsMu.Unlock()

	select {
	case conn := <-pool:
		return conn, nil
	default:
		return dialUDPResolver(resolverLabel)
	}
}

// putUDPConn returns a UDP connection to the pool for the specified resolver.
// If the pool is full, the connection is closed.
func (c *Client) putUDPConn(resolverLabel string, conn *net.UDPConn) {
	if conn == nil {
		return
	}

	c.resolverConnsMu.Lock()
	pool := c.resolverConns[resolverLabel]
	c.resolverConnsMu.Unlock()

	if pool == nil {
		_ = conn.Close()
		return
	}

	select {
	case pool <- conn:
	default:
		_ = conn.Close()
	}
}

func (c *Client) closeResolverConnPools() {
	if c == nil {
		return
	}

	c.resolverConnsMu.Lock()
	pools := c.resolverConns
	c.resolverConns = make(map[string]chan *net.UDPConn)
	c.resolverConnsMu.Unlock()

	for _, pool := range pools {
		for {
			select {
			case conn := <-pool:
				if conn != nil {
					_ = conn.Close()
				}
			default:
				goto nextPool
			}
		}
	nextPool:
	}
}

// getRuntimeUDPBuffer retrieves a byte slice from the internal buffer pool.
// This is used to reduce allocations during high-frequency network operations.
func (c *Client) getRuntimeUDPBuffer() []byte {
	if c == nil {
		return make([]byte, RuntimeUDPReadBufferSize)
	}

	buf, _ := c.udpBufferPool.Get().([]byte)
	if cap(buf) < RuntimeUDPReadBufferSize {
		return make([]byte, RuntimeUDPReadBufferSize)
	}

	return buf[:RuntimeUDPReadBufferSize]
}

// putRuntimeUDPBuffer returns a byte slice to the internal buffer pool.
func (c *Client) putRuntimeUDPBuffer(buf []byte) {
	if c == nil || buf == nil {
		return
	}
	if cap(buf) < RuntimeUDPReadBufferSize {
		return
	}

	c.udpBufferPool.Put(buf[:RuntimeUDPReadBufferSize])
}

// dialUDPResolver resolves the resolver address and establishes a new UDP connection.
func dialUDPResolver(resolverLabel string) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", resolverLabel)
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, addr)
}

// normalizeTimeout ensures the timeout is positive, falling back to a default if necessary.
func normalizeTimeout(timeout time.Duration, fallback time.Duration) time.Duration {
	if timeout <= 0 {
		return fallback
	}
	return timeout
}

// udpQueryTransport wraps a UDP connection for queries.
type udpQueryTransport struct {
	conn *net.UDPConn
}

// newUDPQueryTransport creates a new transport for UDP queries to the specified resolver.
func newUDPQueryTransport(resolverLabel string) (*udpQueryTransport, error) {
	conn, err := dialUDPResolver(resolverLabel)
	if err != nil {
		return nil, err
	}

	return &udpQueryTransport{
		conn: conn,
	}, nil
}

// exchangeUDPQuery performs a synchronous UDP request-response cycle using the provided transport.
func (c *Client) exchangeUDPQuery(transport *udpQueryTransport, packet []byte, timeout time.Duration) ([]byte, error) {
	if transport == nil || transport.conn == nil {
		return nil, net.ErrClosed
	}

	return c.exchangeUDPQueryWithConn(transport.conn, packet, timeout)
}

// exchangeDNSOverConnection sends a DNS query and returns the extracted VPN packet.
func (c *Client) exchangeDNSOverConnection(conn Connection, query []byte, timeout time.Duration) (VpnProto.Packet, error) {
	udpConn, err := c.getUDPConn(conn.ResolverLabel)
	if err != nil {
		return VpnProto.Packet{}, err
	}

	response, err := c.exchangeUDPQueryWithConn(udpConn, query, timeout)
	if err != nil {
		_ = udpConn.Close()
		return VpnProto.Packet{}, err
	}

	c.putUDPConn(conn.ResolverLabel, udpConn)

	packet, err := dnsparser.ExtractVPNResponse(response, c.responseMode == mtuProbeBase64Reply)
	if err != nil {
		return VpnProto.Packet{}, err
	}

	return packet, nil
}
