// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (micro_burst.go) handles automated micro-burst throughput testing
// and speed qualification for DNS resolvers.
// ==============================================================================
package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"sync"
	"time"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
)

// BurstProbeResult holds the measured metrics from a pipelined micro-burst test.
type BurstProbeResult struct {
	SentCount           int
	ReceivedCount       int
	LossRatio           float64
	TotalBytesRx        int
	ElapsedDuration     time.Duration
	ThroughputKBps      float64
	BurstThroughputKBps float64
	AverageRTT          time.Duration
	MinRTT              time.Duration
	MaxRTT              time.Duration
	DownloadMTUBytes    int
	Qualified           bool
	RejectReason        string
}

// QualifiedResolver represents a resolver with its qualification score and rank.
type QualifiedResolver struct {
	Connection  Connection
	BurstResult BurstProbeResult
	Score       float64
	Rank        int
}

type burstProbeItem struct {
	code       uint32
	sentAt     time.Time
	receivedAt time.Time
	bytesRx    int
	rtt        time.Duration
	received   bool
}

// sendPipelinedMicroBurst sends a train of N queries consecutively to measure
// burst drop rate, latency spread, and effective throughput.
func (c *Client) sendPipelinedMicroBurst(
	ctx context.Context,
	conn Connection,
	transport *udpQueryTransport,
	packetCount int,
	downloadMTU int,
	uploadMTU int,
	timeout time.Duration,
) BurstProbeResult {
	if packetCount < 1 {
		packetCount = 1
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	effectiveDownloadSize := effectiveDownloadMTUProbeSize(downloadMTU)
	if effectiveDownloadSize < minDownloadMTUFloor {
		effectiveDownloadSize = minDownloadMTUFloor
	}

	result := BurstProbeResult{
		SentCount:        packetCount,
		DownloadMTUBytes: effectiveDownloadSize,
	}

	if transport == nil || transport.conn == nil {
		result.RejectReason = "transport unavailable"
		return result
	}

	if ctx != nil {
		if ctx.Err() != nil {
			result.RejectReason = "context cancelled"
			return result
		}
		stop := context.AfterFunc(ctx, func() {
			if transport.conn != nil {
				_ = transport.conn.Close()
			}
		})
		defer stop()
	}

	requestLen := max(1+mtuProbeCodeLength+2, uploadMTU)
	items := make(map[uint32]*burstProbeItem, packetCount)
	queries := make([][]byte, 0, packetCount)
	codes := make([]uint32, 0, packetCount)
	useBase64Flag := false

	for i := 0; i < packetCount; i++ {
		payload, code, useBase64, err := c.buildMTUProbePayload(requestLen)
		if err != nil {
			result.RejectReason = fmt.Sprintf("payload build error: %v", err)
			return result
		}
		useBase64Flag = useBase64
		binary.BigEndian.PutUint16(payload[1+mtuProbeCodeLength:1+mtuProbeCodeLength+2], uint16(effectiveDownloadSize))

		query, err := c.buildMTUProbeQuery(conn.Domain, Enums.PACKET_MTU_DOWN_REQ, payload)
		if err != nil {
			result.RejectReason = fmt.Sprintf("query build error: %v", err)
			return result
		}

		items[code] = &burstProbeItem{
			code: code,
		}
		queries = append(queries, query)
		codes = append(codes, code)
	}

	// 1. Send queries paced while concurrently receiving responses
	_ = transport.conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() {
		_ = transport.conn.SetReadDeadline(time.Time{})
	}()

	var itemMu sync.Mutex
	firstSentAt := time.Now()
	senderDone := make(chan struct{})

	go func() {
		defer close(senderDone)
		for i, query := range queries {
			if ctx != nil && ctx.Err() != nil {
				return
			}

			code := codes[i]
			now := time.Now()
			itemMu.Lock()
			if item := items[code]; item != nil {
				item.sentAt = now
			}
			itemMu.Unlock()

			if _, err := transport.conn.Write(query); err != nil {
				_ = transport.conn.Close()
				return
			}

			if i < len(queries)-1 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Millisecond):
				}
			}
		}
	}()

	readBuf := c.getRuntimeUDPBuffer()
	defer c.putRuntimeUDPBuffer(readBuf)

	var lastReceivedAt time.Time
	var sumRTT time.Duration
	minRTT := time.Duration(math.MaxInt64)
	var maxRTT time.Duration

	for result.ReceivedCount < packetCount {
		if ctx != nil && ctx.Err() != nil {
			break
		}

		n, err := transport.conn.Read(readBuf)
		if err != nil {
			break // Timeout or connection error
		}

		now := time.Now()
		packet, err := DnsParser.ExtractVPNResponse(readBuf[:n], useBase64Flag)
		if err != nil || packet.PacketType != Enums.PACKET_MTU_DOWN_RES || len(packet.Payload) != effectiveDownloadSize || len(packet.Payload) < mtuProbeCodeLength+2 {
			continue
		}

		if int(binary.BigEndian.Uint16(packet.Payload[mtuProbeCodeLength:mtuProbeCodeLength+2])) != effectiveDownloadSize {
			continue
		}

		respCode := binary.BigEndian.Uint32(packet.Payload[:mtuProbeCodeLength])
		itemMu.Lock()
		item, exists := items[respCode]
		if !exists || item.received {
			itemMu.Unlock()
			continue
		}

		item.received = true
		item.receivedAt = now
		if !item.sentAt.IsZero() {
			item.rtt = item.receivedAt.Sub(item.sentAt)
		} else {
			item.rtt = item.receivedAt.Sub(firstSentAt)
		}
		item.bytesRx = len(packet.Payload)
		rtt := item.rtt
		bytesRx := item.bytesRx
		itemMu.Unlock()

		result.ReceivedCount++
		result.TotalBytesRx += bytesRx
		sumRTT += rtt
		if rtt < minRTT {
			minRTT = rtt
		}
		if rtt > maxRTT {
			maxRTT = rtt
		}
		lastReceivedAt = now
	}

	<-senderDone

	if ctx != nil && ctx.Err() != nil {
		result.Qualified = false
		result.RejectReason = "context cancelled"
		return result
	}

	// 3. Compute loss, timing, and throughput
	lostCount := packetCount - result.ReceivedCount
	result.LossRatio = float64(lostCount) / float64(packetCount)

	if result.ReceivedCount > 0 {
		result.AverageRTT = sumRTT / time.Duration(result.ReceivedCount)
		result.MinRTT = minRTT
		result.MaxRTT = maxRTT
		result.ElapsedDuration = lastReceivedAt.Sub(firstSentAt)
		if result.ElapsedDuration <= 0 {
			result.ElapsedDuration = result.AverageRTT
		}

		seconds := result.ElapsedDuration.Seconds()
		if seconds > 0 {
			result.BurstThroughputKBps = (float64(result.TotalBytesRx) / 1024.0) / seconds
		}
		baseSpeed, _ := CalculateResolverScore(effectiveDownloadSize, result.AverageRTT, result.LossRatio)
		result.ThroughputKBps = baseSpeed
	} else {
		result.ElapsedDuration = time.Since(firstSentAt)
		result.RejectReason = "100% loss during burst"
	}

	// 4. Determine qualification status
	maxLossAllowed := c.cfg.MaxBurstLossRatio
	if maxLossAllowed < 0 {
		maxLossAllowed = 0.20
	}

	if result.ReceivedCount == 0 {
		result.Qualified = false
		result.RejectReason = "no responses received"
	} else if result.LossRatio > maxLossAllowed {
		result.Qualified = false
		result.RejectReason = fmt.Sprintf("excessive burst loss: %.1f%% > %.1f%%", result.LossRatio*100, maxLossAllowed*100)
	} else if c.cfg.MinBurstThroughputKBps > 0 && result.BurstThroughputKBps < c.cfg.MinBurstThroughputKBps {
		result.Qualified = false
		result.RejectReason = fmt.Sprintf("low throughput: %.1f KB/s < %.1f KB/s", result.BurstThroughputKBps, c.cfg.MinBurstThroughputKBps)
	} else {
		result.Qualified = true
	}

	return result
}

// calculateBurstScore computes a ranking score based on throughput, loss, and RTT.
// Higher score = better resolver.
func calculateBurstScore(result BurstProbeResult) float64 {
	if !result.Qualified || result.ReceivedCount == 0 {
		return 0.0
	}

	speedKBps := result.BurstThroughputKBps
	if speedKBps <= 0 {
		speedKBps = result.ThroughputKBps
	}
	downloadMTU := result.DownloadMTUBytes
	if downloadMTU <= 0 && result.ReceivedCount > 0 && result.TotalBytesRx > 0 {
		downloadMTU = result.TotalBytesRx / result.ReceivedCount
	}

	ev := EvaluateResolver(ResolverMetrics{
		DownloadMTUBytes: downloadMTU,
		RTT:              result.AverageRTT,
		LossRatio:        result.LossRatio,
		ThroughputKBps:   speedKBps,
	})
	if math.IsNaN(ev.CompositeScore) || ev.CompositeScore <= 0 {
		return 0.0
	}
	return ev.CompositeScore
}
