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
	"sort"
	"sync"
	"time"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
)

// BurstProbeResult holds the measured metrics from a pipelined micro-burst test.
type BurstProbeResult struct {
	SentCount       int
	ReceivedCount   int
	LossRatio       float64
	TotalBytesRx    int
	ElapsedDuration time.Duration
	ThroughputKBps  float64
	AverageRTT      time.Duration
	MinRTT          time.Duration
	MaxRTT          time.Duration
	Qualified       bool
	RejectReason    string
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

	result := BurstProbeResult{
		SentCount: packetCount,
	}

	if transport == nil || transport.conn == nil {
		result.RejectReason = "transport unavailable"
		return result
	}

	effectiveDownloadSize := effectiveDownloadMTUProbeSize(downloadMTU)
	if effectiveDownloadSize < minDownloadMTUFloor {
		effectiveDownloadSize = minDownloadMTUFloor
	}

	requestLen := max(1+mtuProbeCodeLength+2, uploadMTU)
	items := make(map[uint32]*burstProbeItem, packetCount)
	queries := make([][]byte, 0, packetCount)
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
	}

	// 1. Send all queries pipelined with slight pacing to prevent local socket overflow
	firstSentAt := time.Now()
	for i, query := range queries {
		if ctx.Err() != nil {
			result.RejectReason = "context cancelled"
			return result
		}

		code := binary.BigEndian.Uint32(queries[i][len(queries[i])-mtuProbeCodeLength:]) // will be tracked via items
		_ = code

		now := time.Now()
		for _, item := range items {
			if item.sentAt.IsZero() {
				item.sentAt = now
				break
			}
		}

		if _, err := transport.conn.Write(query); err != nil {
			result.RejectReason = fmt.Sprintf("write error: %v", err)
			return result
		}

		if i < len(queries)-1 {
			time.Sleep(2 * time.Millisecond)
		}
	}

	// 2. Read incoming responses until all received or timeout
	_ = transport.conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() {
		_ = transport.conn.SetReadDeadline(time.Time{})
	}()

	readBuf := c.getRuntimeUDPBuffer()
	defer c.putRuntimeUDPBuffer(readBuf)

	var lastReceivedAt time.Time
	var sumRTT time.Duration
	minRTT := time.Duration(math.MaxInt64)
	var maxRTT time.Duration

	for result.ReceivedCount < packetCount {
		if ctx.Err() != nil {
			break
		}

		n, err := transport.conn.Read(readBuf)
		if err != nil {
			break // Timeout or connection error
		}

		now := time.Now()
		packet, err := DnsParser.ExtractVPNResponse(readBuf[:n], useBase64Flag)
		if err != nil || packet.PacketType != Enums.PACKET_MTU_DOWN_RES || len(packet.Payload) < mtuProbeCodeLength {
			continue
		}

		respCode := binary.BigEndian.Uint32(packet.Payload[:mtuProbeCodeLength])
		item, exists := items[respCode]
		if !exists || item.received {
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

		result.ReceivedCount++
		result.TotalBytesRx += item.bytesRx
		sumRTT += item.rtt
		if item.rtt < minRTT {
			minRTT = item.rtt
		}
		if item.rtt > maxRTT {
			maxRTT = item.rtt
		}
		lastReceivedAt = now
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
			result.ThroughputKBps = (float64(result.TotalBytesRx) / 1024.0) / seconds
		}
	} else {
		result.ElapsedDuration = time.Since(firstSentAt)
		result.RejectReason = "100% loss during burst"
	}

	// 4. Determine qualification status
	maxLossAllowed := c.cfg.MaxBurstLossRatio
	if maxLossAllowed <= 0 {
		maxLossAllowed = 0.20
	}

	if result.ReceivedCount == 0 {
		result.Qualified = false
		result.RejectReason = "no responses received"
	} else if result.LossRatio > maxLossAllowed {
		result.Qualified = false
		result.RejectReason = fmt.Sprintf("excessive burst loss: %.1f%% > %.1f%%", result.LossRatio*100, maxLossAllowed*100)
	} else if c.cfg.MinBurstThroughputKBps > 0 && result.ThroughputKBps < c.cfg.MinBurstThroughputKBps {
		result.Qualified = false
		result.RejectReason = fmt.Sprintf("low throughput: %.1f KB/s < %.1f KB/s", result.ThroughputKBps, c.cfg.MinBurstThroughputKBps)
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

	// Base score is throughput adjusted for loss
	deliveryRatio := 1.0 - result.LossRatio
	if deliveryRatio < 0 {
		deliveryRatio = 0
	}

	speedComponent := result.ThroughputKBps * deliveryRatio

	// Penalize high latency: score / (1 + rtt_seconds)
	latencyPenalty := 1.0 + float64(result.AverageRTT.Milliseconds())/500.0
	if latencyPenalty <= 0 {
		latencyPenalty = 1.0
	}

	return speedComponent / latencyPenalty
}

// runMicroBurstQualification runs parallel pipelined bursts across all MTU-tested resolvers,
// ranks them, and selects the top active candidates.
func (c *Client) runMicroBurstQualification(ctx context.Context, validConns []Connection) ([]Connection, []QualifiedResolver) {
	if len(validConns) == 0 {
		return nil, nil
	}

	parallelism := c.cfg.MicroBurstParallelism
	if parallelism < 1 {
		parallelism = 8
	}
	if parallelism > len(validConns) {
		parallelism = len(validConns)
	}

	packetCount := c.cfg.MicroBurstPacketCount
	if packetCount < 2 {
		packetCount = 6
	}

	timeout := c.resolverHealthProbeTimeout()
	results := make([]QualifiedResolver, len(validConns))

	if c.log != nil && c.log.Enabled(logger.LevelInfo) {
		c.log.Infof("%s", "================================================================================")
		c.log.Infof("<yellow>⚡ Running Micro-Burst Qualification (%d packets per resolver, parallel=%d)...</yellow>", packetCount, parallelism)
	}

	jobs := make(chan int, len(validConns))
	var wg sync.WaitGroup

	for range parallelism {
		wg.Go(func() {
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				conn := validConns[idx]
				transport, err := newUDPQueryTransport(conn.ResolverLabel)
				if err != nil {
					results[idx] = QualifiedResolver{
						Connection: conn,
						BurstResult: BurstProbeResult{
							SentCount:    packetCount,
							RejectReason: fmt.Sprintf("dial error: %v", err),
						},
						Score: 0.0,
					}
					continue
				}

				burstResult := c.sendPipelinedMicroBurst(
					ctx,
					conn,
					transport,
					packetCount,
					c.syncedDownloadMTU,
					c.syncedUploadMTU,
					timeout,
				)
				_ = transport.conn.Close()

				score := calculateBurstScore(burstResult)
				results[idx] = QualifiedResolver{
					Connection:  conn,
					BurstResult: burstResult,
					Score:       score,
				}
			}
		})
	}

	for i := range validConns {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	// Sort by Score descending, with Loss and RTT tie-breaking
	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		if results[i].BurstResult.LossRatio != results[j].BurstResult.LossRatio {
			return results[i].BurstResult.LossRatio < results[j].BurstResult.LossRatio
		}
		return results[i].BurstResult.AverageRTT < results[j].BurstResult.AverageRTT
	})

	for i := range results {
		results[i].Rank = i + 1
	}

	// Filter qualified vs standby/disqualified
	qualifiedConns := make([]Connection, 0, len(results))
	for _, r := range results {
		if r.BurstResult.Qualified {
			qualifiedConns = append(qualifiedConns, r.Connection)
		}
	}

	// If no resolver qualified under strict criteria, fall back to best scoring
	if len(qualifiedConns) == 0 {
		if c.log != nil && c.log.Enabled(logger.LevelWarn) {
			c.log.Warnf("<yellow>⚠️ No resolvers met strict burst qualification; selecting top available resolvers.</yellow>")
		}
		for _, r := range results {
			if r.BurstResult.ReceivedCount > 0 {
				qualifiedConns = append(qualifiedConns, r.Connection)
			}
		}
		if len(qualifiedConns) == 0 {
			qualifiedConns = validConns
		}
	}

	// Apply MaxActiveResolvers limit
	maxActive := c.cfg.MaxActiveResolvers
	if maxActive > 0 && len(qualifiedConns) > maxActive {
		qualifiedConns = qualifiedConns[:maxActive]
	}

	// Seed Balancer connection stats and validity
	activeMap := make(map[string]bool, len(qualifiedConns))
	for _, conn := range qualifiedConns {
		activeMap[conn.Key] = true
	}

	for _, r := range results {
		isActive := activeMap[r.Connection.Key]
		c.balancer.SetConnectionValidity(r.Connection.Key, isActive)
		if isActive {
			c.balancer.SeedBurstStats(
				r.Connection.Key,
				r.BurstResult.SentCount,
				r.BurstResult.ReceivedCount,
				r.BurstResult.AverageRTT,
			)
		}
	}

	c.logMicroBurstCompletion(results, len(qualifiedConns))
	return qualifiedConns, results
}
