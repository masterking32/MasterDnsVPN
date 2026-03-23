// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"sort"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func (c *Client) selectTargetConnections(packetType uint8, streamID uint16) []Connection {
	targetCount := c.cfg.PacketDuplicationCount
	if targetCount < 1 {
		targetCount = 1
	}

	// SYN packets often use higher duplication for reliability during handshake
	if packetType == Enums.PACKET_STREAM_SYN || packetType == Enums.PACKET_SOCKS5_SYN {
		if c.cfg.SetupPacketDuplicationCount > targetCount {
			targetCount = c.cfg.SetupPacketDuplicationCount
		}
	}

	// If duplication is disabled, just return the best connection (preferred if possible)
	if targetCount <= 1 {
		if streamID > 0 {
			c.streamsMu.RLock()
			s := c.active_streams[streamID]
			c.streamsMu.RUnlock()
			if s != nil && s.PreferredServerKey != "" {
				if idx, ok := c.connectionsByKey[s.PreferredServerKey]; ok {
					return []Connection{c.connections[idx]}
				}
			}
		}
		best, ok := c.balancer.GetBestConnection()
		if ok {
			return []Connection{best}
		}
		return nil
	}

	// For multiple packets, use unique connections from balancer
	return c.balancer.GetUniqueConnections(targetCount)
}

// asyncStreamDispatcher cycles through all active streams using a fair Round-Robin algorithm
// and transmits the highest priority packets to the TX workers, packing control blocks when possible.
func (c *Client) asyncStreamDispatcher(ctx context.Context) {
	c.log.Debugf("🚀 <cyan>Stream Dispatcher started</cyan>")
	defer c.asyncWG.Done()

	var rrCursor uint16 = 0
	idleTimer := time.NewTimer(20 * time.Millisecond)
	defer idleTimer.Stop()

	for {
		// Wait for signal or timeout
		select {
		case <-ctx.Done():
			return
		case <-c.txSignal:
		case <-idleTimer.C:
		}
		if !idleTimer.Stop() {
			select {
			case <-idleTimer.C:
			default:
			}
		}
		idleTimer.Reset(20 * time.Millisecond)

		if orphanPacket, ok := c.dequeueOrphanReset(); ok && orphanPacket != nil {
			c.pingManager.NotifyPacket(orphanPacket.PacketType, false)

			conns := c.selectTargetConnections(orphanPacket.PacketType, orphanPacket.StreamID)
			if len(conns) == 0 {
				continue
			}

			for _, conn := range conns {
				domain := conn.Domain
				if domain == "" {
					domain = c.cfg.Domains[0]
				}

				opts := VpnProto.BuildOptions{
					SessionID:     c.sessionID,
					SessionCookie: c.sessionCookie,
					PacketType:    orphanPacket.PacketType,
					StreamID:      orphanPacket.StreamID,
					SequenceNum:   orphanPacket.SequenceNum,
				}

			encoded, err := VpnProto.BuildEncodedAuto(opts, c.codec, c.cfg.CompressionMinSize)
			if err != nil {
				continue
			}

			dnsPacket, err := buildTunnelTXTQuestion(domain, encoded)
			if err != nil {
				continue
			}

				select {
				case c.txChannel <- asyncPacket{
					conn:       conn,
					packetType: orphanPacket.PacketType,
					payload:    dnsPacket,
				}:
				default:
				}
			}
			continue
		}

		c.streamsMu.RLock()
		streamCount := len(c.active_streams)
		if streamCount == 0 {
			c.streamsMu.RUnlock()
			continue
		}

		ids := make([]uint16, 0, streamCount)
		streams := make(map[uint16]*Stream_client, streamCount)
		for id, stream := range c.active_streams {
			ids = append(ids, id)
			streams[id] = stream
		}
		c.streamsMu.RUnlock()

		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

		// Find the next stream to serve using fair Round-Robin across all active streams.
		var selected *Stream_client
		var item *clientStreamTXPacket
		var ok bool
		rrApplied := false

		// Start search from rrCursor
		startIndex := -1
		for i, id := range ids {
			if id >= rrCursor {
				startIndex = i
				break
			}
		}
		if startIndex == -1 {
			startIndex = 0
		}

		for i := 0; i < len(ids); i++ {
			idx := (startIndex + i) % len(ids)
			id := ids[idx]

			s := streams[id]

			if s == nil || s.txQueue == nil {
				continue
			}

			// PopNextTXPacket returns the highest priority packet available for this stream.
			item, _, ok = s.PopNextTXPacket()
			if ok && item != nil {
				// Mark the next RR start immediately based on the first stream that had data/ping.
				// This ensures fairness even if we substitute a PING for another stream's data.
				if !rrApplied {
					rrCursor = id + 1
					rrApplied = true
				}

				// If it's a PING from Stream 0, try to find useful data from other streams to send instead.
				if id == 0 && item.PacketType == Enums.PACKET_PING {
					hasOtherWork := false
					for _, otherID := range ids {
						if otherID == 0 {
							continue
						}
						os := streams[otherID]
						if os != nil && os.txQueue != nil && os.txQueue.Size() > 0 {
							hasOtherWork = true
							break
						}
					}
					if hasOtherWork {
						s.ReleaseTXPacket(item) // Drop the PING as explained in the audio
						item = nil
						continue // Find the next stream with real data in this round
					}
				}

				selected = s
				break
			}
		}

		if selected == nil || item == nil {
			continue
		}

		var finalPacket asyncPacket
		wasPacked := false
		maxBlocks := c.maxPackedBlocks
		if maxBlocks < 1 {
			maxBlocks = 1
		}

		if VpnProto.IsPackableControlPacket(item.PacketType, len(item.Payload)) && maxBlocks > 1 {
			payload := make([]byte, 0, maxBlocks*VpnProto.PackedControlBlockSize)
			payload = VpnProto.AppendPackedControlBlock(payload, item.PacketType, selected.StreamID, item.SequenceNum, item.FragmentID, item.TotalFragments)
			blocks := 1

			// Pop more from current stream if possible (Any priority)
			for blocks < maxBlocks {
				popped, poppedOk := selected.txQueue.PopAnyIf(func(p *clientStreamTXPacket) bool {
					return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
				}, func(p *clientStreamTXPacket) uint32 {
					return getTrackingKey(p.PacketType, p.SequenceNum, p.FragmentID)
				})
				if !poppedOk {
					break
				}
				payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, selected.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
				blocks++
				selected.ReleaseTXPacket(popped)
			}

			// Pop from other streams to fill block if space remains (Any priority)
			if blocks < maxBlocks {
				for _, sid := range ids {
					if blocks >= maxBlocks {
						break
					}
					if sid == selected.StreamID {
						continue
					}

					otherStream := streams[sid]

					if otherStream == nil || otherStream.txQueue == nil {
						continue
					}
					for blocks < maxBlocks {
						popped, poppedOk := otherStream.txQueue.PopAnyIf(func(p *clientStreamTXPacket) bool {
							return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
						}, func(p *clientStreamTXPacket) uint32 {
							return getTrackingKey(p.PacketType, p.SequenceNum, p.FragmentID)
						})
						if !poppedOk {
							break
						}
						payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, sid, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
						blocks++
						otherStream.ReleaseTXPacket(popped)
					}
				}
			}

			if blocks > 1 {
				// Send as packed controls
				finalPacket = asyncPacket{
					packetType: Enums.PACKET_PACKED_CONTROL_BLOCKS,
					payload:    payload,
				}
				selected.ReleaseTXPacket(item)
				wasPacked = true
			} else {
				// Fallback natively if only 1 block found
				finalPacket = asyncPacket{
					packetType: item.PacketType,
					payload:    item.Payload,
				}
			}
		} else {
			finalPacket = asyncPacket{
				packetType: item.PacketType,
				payload:    item.Payload,
			}
		}

		// Notify Ping Manager of outbound activity
		c.pingManager.NotifyPacket(finalPacket.packetType, false)

		// Packet Duplication Logic
		conns := c.selectTargetConnections(finalPacket.packetType, selected.StreamID)
		if len(conns) == 0 {
			if !wasPacked {
				selected.ReleaseTXPacket(item)
			}
			continue
		}

		for _, conn := range conns {
			// Choose domain for this connection
			domain := conn.Domain
			if domain == "" {
				domain = c.cfg.Domains[0]
			}

			// Build THE final wrapped DNS packet
			opts := VpnProto.BuildOptions{
				SessionID:     c.sessionID,
				PacketType:    finalPacket.packetType,
				SessionCookie: c.sessionCookie,
			}

			if !wasPacked {
				opts.StreamID = selected.StreamID
				opts.SequenceNum = item.SequenceNum
				opts.FragmentID = item.FragmentID
				opts.TotalFragments = item.TotalFragments
				opts.Payload = item.Payload
			} else {
				opts.Payload = finalPacket.payload
			}

			encoded, err := VpnProto.BuildEncodedAuto(opts, c.codec, c.cfg.CompressionMinSize)
			if err != nil {
				c.log.Errorf("Failed to encode packet <magenta>|</magenta> <blue>Type</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Frag</blue>: <cyan>%d/%d</cyan> <magenta>|</magenta> <blue>Error</blue>: <cyan>%v</cyan>", Enums.PacketTypeName(item.PacketType), selected.StreamID, item.SequenceNum, item.FragmentID+1, max(1, int(item.TotalFragments)), err)
				continue
			}

			dnsPacket, err := buildTunnelTXTQuestion(domain, encoded)
			if err != nil {
				c.log.Errorf("Failed to build DNS question <magenta>|</magenta> <blue>Type</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Stream</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Resolver</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Error</blue>: <cyan>%v</cyan>", Enums.PacketTypeName(item.PacketType), selected.StreamID, item.SequenceNum, domain, err)
				continue
			}

			pkt := finalPacket
			pkt.conn = conn
			pkt.payload = dnsPacket

			// Send to TX channel
			select {
			case c.txChannel <- pkt:
			default:
			}
		}

		if !wasPacked {
			selected.ReleaseTXPacket(item)
		}

		// Loop quickly if there's more potential work
		select {
		case c.txSignal <- struct{}{}:
		default:
		}
	}
}
