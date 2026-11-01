// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (prober_udp.go) implements ResolverProber using live UDP network exchanges.
// ==============================================================================
package client

import (
	"context"
	"fmt"
	"time"
)

// UDPResolverProber implements ResolverProber using live UDP network exchanges.
type UDPResolverProber struct {
	client *Client
}

// NewUDPResolverProber constructs a UDPResolverProber wrapping the given Client.
func NewUDPResolverProber(client *Client) *UDPResolverProber {
	return &UDPResolverProber{client: client}
}

// ProbeMTU executes live upload and download MTU discovery queries over UDP.
func (p *UDPResolverProber) ProbeMTU(
	ctx context.Context,
	conn Connection,
	maxUploadPayload int,
) (MTUProbeResult, error) {
	if p.client == nil {
		return MTUProbeResult{
			Success:      false,
			RejectReason: "client unavailable",
		}, fmt.Errorf("client unavailable")
	}

	if ctx != nil && ctx.Err() != nil {
		return MTUProbeResult{
			Success:      false,
			RejectReason: "context cancelled",
		}, ctx.Err()
	}

	if maxUploadPayload <= 0 {
		maxUploadPayload = p.client.maxUploadMTUPayload(conn.Domain)
	}

	result, reason := p.client.probeConnectionMTU(ctx, conn, maxUploadPayload)
	if ctx != nil && ctx.Err() != nil {
		return MTUProbeResult{
			Success:      false,
			RejectReason: "context cancelled",
		}, ctx.Err()
	}

	switch reason {
	case mtuRejectUpload:
		return MTUProbeResult{
			Success:      false,
			UploadBytes:  result.UploadBytes,
			UploadChars:  result.UploadChars,
			RejectReason: "upload mtu probe rejected",
		}, nil
	case mtuRejectDownload:
		return MTUProbeResult{
			Success:       false,
			UploadBytes:   result.UploadBytes,
			UploadChars:   result.UploadChars,
			DownloadBytes: result.DownloadBytes,
			RejectReason:  "download mtu probe rejected",
		}, nil
	default:
		return MTUProbeResult{
			Success:       true,
			UploadBytes:   result.UploadBytes,
			UploadChars:   result.UploadChars,
			DownloadBytes: result.DownloadBytes,
			ResolveTime:   result.ResolveTime,
		}, nil
	}
}

// ProbeBurst executes a live pipelined micro-burst train over UDP.
func (p *UDPResolverProber) ProbeBurst(
	ctx context.Context,
	conn Connection,
	packetCount int,
	downloadMTU int,
	uploadMTU int,
	timeout time.Duration,
) BurstProbeResult {
	if p.client == nil {
		return BurstProbeResult{
			SentCount:    packetCount,
			Qualified:    false,
			RejectReason: "client unavailable",
		}
	}
	return p.client.probeConnectionMicroBurst(ctx, conn, packetCount, downloadMTU, uploadMTU, timeout)
}

// probeConnectionMicroBurst handles transport allocation and cleanup for micro-burst testing.
func (c *Client) probeConnectionMicroBurst(
	ctx context.Context,
	conn Connection,
	packetCount int,
	downloadMTU int,
	uploadMTU int,
	timeout time.Duration,
) BurstProbeResult {
	if ctx != nil && ctx.Err() != nil {
		return BurstProbeResult{
			SentCount:    packetCount,
			Qualified:    false,
			RejectReason: "context cancelled",
		}
	}

	transport, err := c.newUDPQueryTransport(ctx, conn.ResolverLabel)
	if err != nil {
		return BurstProbeResult{
			SentCount:    packetCount,
			Qualified:    false,
			RejectReason: fmt.Sprintf("dial error: %v", err),
		}
	}
	defer func() {
		if transport.conn != nil {
			_ = transport.conn.Close()
		}
	}()

	return c.sendPipelinedMicroBurst(
		ctx,
		conn,
		transport,
		packetCount,
		downloadMTU,
		uploadMTU,
		timeout,
	)
}
