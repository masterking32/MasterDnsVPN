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
	"context"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"masterdnsvpn-go/internal/dnsparser"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	// RuntimeUDPReadBufferSize defines the maximum size of the UDP read buffer.
	RuntimeUDPReadBufferSize         = 65535
	runtimeUDPMaxMismatchedResponses = 64
	runtimeUDPDrainGrace             = time.Millisecond

	// pooledConnMaxAge is the maximum time a UDP connection can remain idle in
	// the resolver pool before it is discarded and re-dialed. Stale connections can have their
	// NAT mappings expired, causing silent packet loss (writes succeed but
	// responses route to a dead port).
	pooledConnMaxAge = 90 * time.Second
)

type pooledUDPConn struct {
	conn     *net.UDPConn
	pooledAt time.Time
}

func (c *Client) drainStaleUDPResponses(conn *net.UDPConn, buffer []byte) error {
	if conn == nil || len(buffer) == 0 {
		return nil
	}

	for drained := 0; drained < runtimeUDPMaxMismatchedResponses*2; drained++ {
		if err := conn.SetReadDeadline(time.Now().Add(runtimeUDPDrainGrace)); err != nil {
			return err
		}

		_, err := conn.Read(buffer)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil
			}
			return err
		}
	}

	return nil
}

// exchangeUDPQueryWithConn sends one UDP packet through the provided connection
// and waits for a response with a matching DNS transaction ID.
func (c *Client) exchangeUDPQueryWithConn(conn *net.UDPConn, packet []byte, timeout time.Duration) ([]byte, error) {
	if len(packet) < 2 {
		return nil, errors.New("malformed dns query")
	}
	expectedID := binary.BigEndian.Uint16(packet[:2])

	buffer := c.getRuntimeUDPBuffer()
	defer c.putRuntimeUDPBuffer(buffer)
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	if err := c.drainStaleUDPResponses(conn, buffer); err != nil {
		return nil, err
	}

	writeDeadline := time.Now().Add(timeout)
	if err := conn.SetWriteDeadline(writeDeadline); err != nil {
		return nil, err
	}

	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}

	if err := conn.SetReadDeadline(writeDeadline); err != nil {
		return nil, err
	}

	mismatchedResponses := 0

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return nil, err
		}

		if n >= 2 && binary.BigEndian.Uint16(buffer[:2]) == expectedID {
			// Copy matched response out so the pooled buffer can be recycled.
			result := make([]byte, n)
			copy(result, buffer[:n])
			return result, nil
		}

		mismatchedResponses++
		if mismatchedResponses >= runtimeUDPMaxMismatchedResponses {
			return nil, errors.New("too many mismatched dns responses on shared udp socket")
		}
	}
}

func (c *Client) sendOneWayDNSQuery(resolver Connection, packet []byte, deadline time.Time) error {
	udpConn, err := c.getUDPConn(context.Background(), resolver.ResolverLabel)
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
func (c *Client) getUDPConn(ctx context.Context, resolverLabel string) (*net.UDPConn, error) {
	c.resolverConnsMu.Lock()
	pool, ok := c.resolverConns[resolverLabel]
	if !ok {
		pool = make(chan pooledUDPConn, c.cfg.EffectiveResolverUDPConnectionPoolSize())
		c.resolverConns[resolverLabel] = pool
	}
	c.resolverConnsMu.Unlock()

	now := time.Now()
	for {
		select {
		case pc := <-pool:
			if now.Sub(pc.pooledAt) > pooledConnMaxAge {
				_ = pc.conn.Close()
				continue // discard stale, try next
			}
			return pc.conn, nil
		default:
			return c.dialUDPResolver(ctx, resolverLabel)
		}
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
	case pool <- pooledUDPConn{conn: conn, pooledAt: time.Now()}:
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
	c.resolverConns = make(map[string]chan pooledUDPConn)
	c.resolverConnsMu.Unlock()

	for _, pool := range pools {
		for {
			select {
			case pc := <-pool:
				if pc.conn != nil {
					_ = pc.conn.Close()
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
func (c *Client) newUDPQueryTransport(ctx context.Context, resolverLabel string) (*udpQueryTransport, error) {
	conn, err := c.dialUDPResolver(ctx, resolverLabel)
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
	udpConn, err := c.getUDPConn(context.Background(), conn.ResolverLabel)
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
