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
	connections, err := c.selectTargetConnectionsForPacket(packetType, streamID)
	if err != nil {
		return nil
	}
	return connections
}

// asyncStreamDispatcher cycles through all active streams using a fair Round-Robin algorithm
// and transmits the highest priority packets to the TX workers, packing control blocks when possible.
func (c *Client) asyncStreamDispatcher(ctx context.Context) {
	c.log.Debugf("🚀 <cyan>Stream Dispatcher started</cyan>")
	defer c.asyncWG.Done()

	var rrCursor int32 = -1
	idlePoll := c.cfg.DispatcherIdlePollInterval()
	idleTimer := time.NewTimer(idlePoll)
	defer idleTimer.Stop()

dispatchLoop:
	for {
		c.streamsMu.RLock()
		streamCount := len(c.active_streams)
		ids := make([]int32, 0, streamCount+1)
		streams := make(map[uint16]*Stream_client, streamCount)
		for id, stream := range c.active_streams {
			ids = append(ids, int32(id))
			streams[id] = stream
		}
		c.streamsMu.RUnlock()

		if c.orphanQueue != nil && c.orphanQueue.Size() > 0 {
			ids = append(ids, -1)
		}

		if len(ids) == 0 {
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
			idleTimer.Reset(idlePoll)
			continue
		}

		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

		// Find the next stream to serve using fair Round-Robin across all active streams.
		var selected *Stream_client
		var item *clientStreamTXPacket
		var ok bool
		var selectedStreamID uint16
		var selectedID int32 = -2 // -2 means nothing selected
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

			if id == -1 {
				if c.orphanQueue == nil || c.orphanQueue.Size() == 0 {
					continue
				}
				p, _, popOk := c.orphanQueue.Pop(func(p VpnProto.Packet) uint64 {
					return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
				})
				if !popOk {
					continue
				}
				item = &clientStreamTXPacket{
					PacketType:     p.PacketType,
					SequenceNum:    p.SequenceNum,
					FragmentID:     p.FragmentID,
					TotalFragments: p.TotalFragments,
					Payload:        nil,
				}
				selectedStreamID = p.StreamID
				selectedID = -1
				ok = true
			} else {
				s := streams[uint16(id)]
				if s == nil || s.txQueue == nil {
					continue
				}
				item, _, ok = s.PopNextTXPacket()
				if ok {
					selectedStreamID = uint16(id)
					selectedID = int32(id)
					selected = s
				}
			}

			if ok && item != nil {
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
						if otherID == -1 {
							if c.orphanQueue != nil && c.orphanQueue.Size() > 0 {
								hasOtherWork = true
								break
							}
							continue
						}
						os := streams[uint16(otherID)]
						if os != nil && os.txQueue != nil && os.txQueue.Size() > 0 {
							hasOtherWork = true
							break
						}
					}
					if hasOtherWork {
						if selected != nil {
							selected.ReleaseTXPacket(item)
						}
						item = nil
						ok = false
						continue // Find the next stream with real data in this round
					}
				}

				break
			}
		}

		if selectedID == -2 || item == nil {
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
			idleTimer.Reset(idlePoll)
			continue
		}

		if selected != nil &&
			(item.PacketType == Enums.PACKET_STREAM_DATA || item.PacketType == Enums.PACKET_STREAM_RESEND) &&
			!c.shouldTransmitQueuedStreamPacket(selected, item) {
			selected.ReleaseTXPacket(item)
			select {
			case c.txSignal <- struct{}{}:
			default:
			}
			continue dispatchLoop
		}

		var finalPacket asyncPacket
		wasPacked := false
		maxBlocks := c.maxPackedBlocks
		if maxBlocks < 1 {
			maxBlocks = 1
		}

		if VpnProto.IsPackableControlPacket(item.PacketType, len(item.Payload)) && maxBlocks > 1 {
			payload := make([]byte, 0, maxBlocks*VpnProto.PackedControlBlockSize)
			payload = VpnProto.AppendPackedControlBlock(payload, item.PacketType, selectedStreamID, item.SequenceNum, item.FragmentID, item.TotalFragments)
			blocks := 1

			// Pop more from current stream if possible
			if selected != nil {
				for blocks < maxBlocks {
					popped, poppedOk := selected.txQueue.PopAnyIf(func(p *clientStreamTXPacket) bool {
						return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
					}, func(p *clientStreamTXPacket) uint64 {
						return Enums.PacketIdentityKey(selected.StreamID, p.PacketType, p.SequenceNum, p.FragmentID)
					})
					if !poppedOk {
						break
					}
					payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, selected.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
					blocks++
					selected.ReleaseTXPacket(popped)
				}
			} else if selectedID == -1 {
				// Packing from orphanQueue
				for blocks < maxBlocks {
					popped, poppedOk := c.orphanQueue.PopAnyIf(func(p VpnProto.Packet) bool {
						return VpnProto.IsPackableControlPacket(p.PacketType, 0)
					}, func(p VpnProto.Packet) uint64 {
						return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
					})
					if !poppedOk {
						break
					}
					payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, popped.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
					blocks++
				}
			}

			// Pop from other streams to fill block if space remains
			if blocks < maxBlocks {
				for _, otherID := range ids {
					if blocks >= maxBlocks {
						break
					}
					if otherID == selectedID {
						continue
					}

					if otherID == -1 {
						for blocks < maxBlocks {
							popped, poppedOk := c.orphanQueue.PopAnyIf(func(p VpnProto.Packet) bool {
								return VpnProto.IsPackableControlPacket(p.PacketType, 0)
							}, func(p VpnProto.Packet) uint64 {
								return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
							})
							if !poppedOk {
								break
							}
							payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, popped.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
							blocks++
						}
						continue
					}

					otherStream := streams[uint16(otherID)]
					if otherStream == nil || otherStream.txQueue == nil {
						continue
					}
					for blocks < maxBlocks {
						popped, poppedOk := otherStream.txQueue.PopAnyIf(func(p *clientStreamTXPacket) bool {
							return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
						}, func(p *clientStreamTXPacket) uint64 {
							return Enums.PacketIdentityKey(uint16(otherID), p.PacketType, p.SequenceNum, p.FragmentID)
						})
						if !poppedOk {
							break
						}
						payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, uint16(otherID), popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
						blocks++
						otherStream.ReleaseTXPacket(popped)
					}
				}
			}

			if blocks > 1 {
				finalPacket.packetType = Enums.PACKET_PACKED_CONTROL_BLOCKS
				finalPacket.payload = payload
				wasPacked = true
				if selected != nil {
					selected.ReleaseTXPacket(item)
				}
			} else {
				finalPacket.packetType = item.PacketType
				finalPacket.payload = item.Payload
			}
		} else {
			finalPacket.packetType = item.PacketType
			finalPacket.payload = item.Payload
		}

		c.pingManager.NotifyPacket(finalPacket.packetType, false)

		conns := c.selectTargetConnections(finalPacket.packetType, selectedStreamID)
		if len(conns) == 0 {
			if !wasPacked {
				if selected != nil {
					key := Enums.PacketIdentityKey(selected.StreamID, item.PacketType, item.SequenceNum, item.FragmentID)
					selected.txQueue.Push(0, key, item)
				} else if selectedID == -1 {
					c.enqueueOrphanReset(item.PacketType, selectedStreamID, item.SequenceNum)
				}
			}
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
				PacketType:    finalPacket.packetType,
				CompressionType: func() uint8 {
					if wasPacked {
						return c.uploadCompression
					}
					return item.CompressionType
				}(),
				Payload: finalPacket.payload,
			}

			if wasPacked {
				opts.StreamID = 0
			} else {
				opts.StreamID = selectedStreamID
				opts.SequenceNum = item.SequenceNum
				opts.FragmentID = item.FragmentID
				opts.TotalFragments = item.TotalFragments
			}

			encoded, err := c.buildEncodedAutoWithCompressionTrace(opts)
			if err != nil {
				continue
			}

			dnsPacket, err := buildTunnelTXTQuestion(domain, encoded)
			if err != nil {
				continue
			}

			pkt := finalPacket
			pkt.conn = conn
			pkt.payload = dnsPacket

			select {
			case c.txChannel <- pkt:
			default:
			}
		}

		if !wasPacked && selected != nil {
			selected.ReleaseTXPacket(item)
		}

		select {
		case c.txSignal <- struct{}{}:
		default:
		}
	}
}
