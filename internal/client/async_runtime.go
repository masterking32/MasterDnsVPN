// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (async_runtime.go) handles async parallel background workers.
// ==============================================================================
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"masterdnsvpn-go/internal/arq"
	"masterdnsvpn-go/internal/client/handlers"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	fragmentStore "masterdnsvpn-go/internal/fragmentstore"
	"masterdnsvpn-go/internal/logger"
)

const clientRXDropLogInterval = 2 * time.Second

type asyncPacket struct {
	conn       Connection
	payload    []byte
	packetType uint8
	streamID   uint16
}

type asyncReadPacket struct {
	data []byte
	addr *net.UDPAddr
}

// StopAsyncRuntime stops all running workers (Readers, Writers, Processors).
// It ensures the UDP socket is closed and all goroutines exit.
func (c *Client) StopAsyncRuntime() {
	if c.asyncCancel != nil {
		c.log.Debugf("\U0001F6D1 <yellow>Stopping Async Runtime...</yellow>")
		c.CloseAllStreams()
		c.asyncCancel()
		c.asyncWG.Wait()
		c.asyncCancel = nil

		// Final drain to return all buffers to the pool and prevent memory leaks.
		c.drainQueues()
		c.log.Debugf("\U0001F232 <green>Async Runtime stopped cleanly.</green>")
	}

	if c.tcpListener != nil {
		c.tcpListener.Stop()
	}

	if c.dnsListener != nil {
		c.dnsListener.Stop()
	}

	if c.tunnelConn != nil {
		_ = c.tunnelConn.Close()
		c.tunnelConn = nil
	}

	if c.pingManager != nil {
		c.pingManager.Stop()
	}

	c.resetRuntimeBindings(false)
}

func (c *Client) resetRuntimeBindings(resetSession bool) {
	if c == nil {
		return
	}

	c.CloseAllStreams()

	c.streamsMu.Lock()
	c.last_stream_id = 0
	c.streamsMu.Unlock()
	c.bumpStreamSetVersion()

	c.dnsResponses = fragmentStore.New[dnsFragmentKey](c.cfg.DNSResponseFragmentStoreCap)
	if c.localDNSCache != nil {
		c.localDNSCache.ClearPending()
	}

	c.closeResolverConnPools()
	c.clearTxSignal()
	c.clearTxSpaceSignal()
	c.clearSessionResetPending()
	if resetSession {
		c.resetSessionState(true)
	}
}

func (c *Client) clearTxSignal() {
	if c == nil || c.txSignal == nil {
		return
	}
	for {
		select {
		case <-c.txSignal:
		default:
			return
		}
	}
}

func (c *Client) clearTxSpaceSignal() {
	if c == nil || c.txSpaceSignal == nil {
		return
	}
	for {
		select {
		case <-c.txSpaceSignal:
		default:
			return
		}
	}
}

func (c *Client) signalTxSpace() {
	if c == nil || c.txSpaceSignal == nil {
		return
	}
	select {
	case c.txSpaceSignal <- struct{}{}:
	default:
	}
}

func (c *Client) txChannelHasCapacity(needed int) bool {
	if c == nil || c.txChannel == nil {
		return false
	}
	if needed <= 0 {
		needed = 1
	}
	return cap(c.txChannel)-len(c.txChannel) >= needed
}

func (c *Client) onRXDrop(addr *net.UDPAddr) {
	if c == nil {
		return
	}

	total := c.rxDroppedPackets.Add(1)
	now := time.Now().UnixNano()
	last := c.lastRXDropLogUnix.Load()
	if now-last < clientRXDropLogInterval.Nanoseconds() {
		return
	}
	if !c.lastRXDropLogUnix.CompareAndSwap(last, now) {
		return
	}

	queueLen := 0
	queueCap := 0
	if c.rxChannel != nil {
		queueLen = len(c.rxChannel)
		queueCap = cap(c.rxChannel)
	}

	c.log.Warnf(
		"🚨 <yellow>RX queue overloaded</yellow> <magenta>|</magenta> <blue>Dropped</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Remote</blue>: <cyan>%v</cyan> <magenta>|</magenta> <blue>Queue</blue>: <cyan>%d/%d</cyan>",
		total,
		addr,
		queueLen,
		queueCap,
	)
}

func (c *Client) resetSessionState(resetSessionCookie bool) {
	if c == nil {
		return
	}
	c.sessionReady = false
	c.sessionID = 0
	if resetSessionCookie {
		c.sessionCookie = 0
	}
	c.responseMode = 0
	c.clearSessionInitBusyUntil()
	c.resetSessionInitState()
}

func (c *Client) requestSessionRestart(reason string) {
	if c == nil {
		return
	}
	if !c.runtimeResetPending.CompareAndSwap(false, true) {
		return
	}
	if c.log != nil {
		c.log.Warnf("🔄 <yellow>Session restart requested</yellow>: <cyan>%s</cyan>", reason)
	}
	if c.sessionResetSignal != nil {
		select {
		case c.sessionResetSignal <- struct{}{}:
		default:
		}
	}
}

func (c *Client) clearRuntimeResetRequest() {
	if c == nil {
		return
	}
	c.runtimeResetPending.Store(false)
	if c.sessionResetSignal == nil {
		return
	}
	for {
		select {
		case <-c.sessionResetSignal:
		default:
			return
		}
	}
}

// StartAsyncRuntime initializes the parallel system for tunnel I/O and processing.
func (c *Client) StartAsyncRuntime(parentCtx context.Context) error {
	// 1. Ensure any previous instance is completely stopped.
	c.StopAsyncRuntime()

	// 2. Setup session context.
	runtimeCtx, cancel := context.WithCancel(parentCtx)
	c.asyncCancel = cancel

	// 3. Open shared UDP socket.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		cancel()
		c.asyncCancel = nil
		return fmt.Errorf("failed to open tunnel socket: %w", err)
	}

	c.tunnelConn = conn

	c.log.Infof("\U0001F4E1 <cyan>Async Runtime Initialized: <green>%d Writes</green>, <green>%d Reads</green>, <green>%d Processors</green></cyan>",
		c.tunnelWriterWorkers, c.tunnelReaderWorkers, c.tunnelProcessWorkers)

	// Start TCP/SOCKS Proxy Listener
	c.tcpListener = NewTCPListener(c, c.cfg.ProtocolType)
	if err := c.tcpListener.Start(runtimeCtx, c.cfg.ListenIP, c.cfg.ListenPort); err != nil {
		c.log.Errorf("<red>❌ Failed to start %s proxy: %v</red>", c.cfg.ProtocolType, err)
		return err
	}

	// Start DNS Listener if enabled
	if c.cfg.LocalDNSEnabled {
		c.dnsListener = NewDNSListener(c)
		if err := c.dnsListener.Start(runtimeCtx, c.cfg.LocalDNSIP, c.cfg.LocalDNSPort); err != nil {
			c.log.Errorf("<red>❌ Failed to start DNS resolver: %v</red>", err)
			return err
		}
	}

	// 6. Spawn Reader Workers (High-speed ingestion)
	for i := 0; i < c.tunnelReaderWorkers; i++ {
		c.asyncWG.Add(1)
		go c.asyncReaderWorker(runtimeCtx, i, conn)
	}

	// 5. Spawn Processor Workers (Parallel data analysis)
	for i := 0; i < c.tunnelProcessWorkers; i++ {
		c.asyncWG.Add(1)
		go c.asyncProcessorWorker(runtimeCtx, i)
	}

	// 6. Spawn Writer Workers (Burst transmission)
	for i := 0; i < c.tunnelWriterWorkers; i++ {
		c.asyncWG.Add(1)
		go c.asyncWriterWorker(runtimeCtx, i, conn)
	}

	// 7. Spawn Dispatcher (Fair Queuing & Packing)
	c.asyncWG.Add(1)
	go c.asyncStreamDispatcher(runtimeCtx)

	// 8. Stream lifecycle cleanup.
	c.asyncWG.Add(1)
	go c.asyncStreamCleanupWorker(runtimeCtx)

	// 9. Resolver health runtime.
	if c.cfg.AutoDisableTimeoutServers || c.cfg.RecheckInactiveServersEnabled {
		c.asyncWG.Add(1)
		go func() {
			defer c.asyncWG.Done()
			c.runResolverHealthLoop(runtimeCtx)
		}()
	}

	// 10. Periodic stats logger.
	c.asyncWG.Add(1)
	go c.asyncStatsLogger(runtimeCtx)

	// 11. Lifecycle cleanup.
	c.asyncWG.Add(1)
	go func() {
		defer c.asyncWG.Done()
		<-runtimeCtx.Done()
		conn.Close()
	}()

	return nil
}

func (c *Client) asyncStreamCleanupWorker(ctx context.Context) {
	defer c.asyncWG.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			c.cleanupRecentlyClosedStreams(now)

			c.streamsMu.RLock()
			streams := make([]*Stream_client, 0, len(c.active_streams))
			for _, s := range c.active_streams {
				if s != nil {
					streams = append(streams, s)
				}
			}
			c.streamsMu.RUnlock()

			var removeIDs []uint16
			for _, s := range streams {
				if s == nil || s.StreamID == 0 {
					continue
				}
				a, ok := s.Stream.(*arq.ARQ)
				if !ok || a == nil {
					continue
				}

				switch a.State() {
				case arq.StateDraining:
					if s.StatusValue() != streamStatusCancelled {
						s.SetStatus(streamStatusDraining)
					}
				case arq.StateHalfClosedLocal, arq.StateHalfClosedRemote, arq.StateClosing:
					if s.StatusValue() != streamStatusCancelled {
						s.SetStatus(streamStatusClosing)
					}
				case arq.StateTimeWait:
					if s.StatusValue() != streamStatusCancelled {
						s.SetStatus(streamStatusTimeWait)
					}
				}

				if !a.IsClosed() {
					if s.StatusValue() == streamStatusCancelled {
						if since := s.TerminalSince(); !since.IsZero() && now.Sub(since) >= c.cfg.ClientCancelledSetupRetention() {
							removeIDs = append(removeIDs, s.StreamID)
						}
					}
					continue
				}

				s.MarkTerminal(now)
				if s.StatusValue() != streamStatusCancelled {
					s.SetStatus(streamStatusTimeWait)
				}
				if since := s.TerminalSince(); !since.IsZero() && now.Sub(since) >= c.cfg.ClientTerminalStreamRetention() {
					removeIDs = append(removeIDs, s.StreamID)
				}
			}

			for _, streamID := range removeIDs {
				c.removeStream(streamID)
			}
		}
	}
}

// asyncStatsLogger periodically logs connection and stream statistics.
func (c *Client) asyncStatsLogger(ctx context.Context) {
	defer c.asyncWG.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.logPeriodicStats()
		}
	}
}

func (c *Client) logPeriodicStats() {
	if c.log == nil {
		return
	}

	// Stream stats
	c.streamsMu.RLock()
	total := len(c.active_streams)
	active, draining, pending := 0, 0, 0
	for _, s := range c.active_streams {
		if s == nil {
			continue
		}
		switch s.StatusValue() {
		case streamStatusActive:
			active++
		case streamStatusDraining, streamStatusClosing, streamStatusTimeWait:
			draining++
		case streamStatusPending, streamStatusSocksConnecting:
			pending++
		}
	}
	c.streamsMu.RUnlock()

	// Balancer stats
	bs := c.balancer.Stats()

	c.log.Debugf(
		"📊 <green>Stats <magenta>|</magenta> Streams: <cyan>%d</cyan> active, <cyan>%d</cyan> pending, <cyan>%d</cyan> draining (<cyan>%d</cyan> total) <magenta>|</magenta> Resolvers: <cyan>%d</cyan>/<cyan>%d</cyan> valid</green>",
		active, pending, draining, total, bs.Valid, bs.Total,
	)

	if c.log.Enabled(logger.LevelDebug) {
		for _, e := range bs.Entries {
			var lossStr string
			if e.Sent > 0 {
				lossPct := float64(e.Sent-e.Acked) * 100 / float64(e.Sent)
				lossStr = fmt.Sprintf("%.1f%%", lossPct)
			} else {
				lossStr = "N/A"
			}
			c.log.Debugf(
				"📊 <cyan>Resolver %s <magenta>|</magenta> Valid: <cyan>%t</cyan> <magenta>|</magenta> Sent: <cyan>%d</cyan> <magenta>|</magenta> Acked: <cyan>%d</cyan> <magenta>|</magenta> Loss: <cyan>%s</cyan> <magenta>|</magenta> AvgRTT: <cyan>%dms</cyan></cyan>",
				e.Key, e.Valid, e.Sent, e.Acked, lossStr, e.AvgRTTMicro/1000,
			)
		}
	}
}

// drainQueues removes any stale packets from TX and RX channels.
// Buffers from the RX channel are returned to the pool to prevent leaks.
func (c *Client) drainQueues() {
	// Drain TX
	for {
		select {
		case <-c.txChannel:
		default:
			goto drainRX
		}
	}
drainRX:
	// Drain RX and return buffers to pool
	for {
		select {
		case pkt := <-c.rxChannel:
			if pkt.data != nil {
				c.udpBufferPool.Put(pkt.data[:cap(pkt.data)])
			}
		default:
			return
		}
	}
}

// asyncWriterWorker fires packets from txChannel at the destination.
func (c *Client) asyncWriterWorker(ctx context.Context, id int, conn *net.UDPConn) {
	defer c.asyncWG.Done()
	c.log.Debugf("\U0001F680 <green>Writer Worker <cyan>#%d</cyan> started</green>", id)
	var lastDeadline time.Time
	refreshWindow := c.tunnelPacketTimeout / 2
	if refreshWindow < 250*time.Millisecond {
		refreshWindow = 250 * time.Millisecond
	}
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-c.txChannel:
			c.signalTxSpace()
			addr, err := c.getResolverUDPAddr(pkt.conn)
			if err != nil {
				continue
			}

			if c.tunnelPacketTimeout > 0 {
				now := time.Now()
				if lastDeadline.IsZero() || now.Add(refreshWindow).After(lastDeadline) {
					lastDeadline = now.Add(c.tunnelPacketTimeout)
					_ = conn.SetWriteDeadline(lastDeadline)
				}
			}

			sentAt := time.Now()
			if _, err := conn.WriteToUDP(pkt.payload, addr); err == nil {
				c.trackResolverSend(pkt.payload, addr.String(), pkt.conn.Key, sentAt)
			}
		}
	}
}

// asyncReaderWorker reads raw UDP data and pushes to the rxChannel (Internal Queue).
func (c *Client) asyncReaderWorker(ctx context.Context, id int, conn *net.UDPConn) {
	defer c.asyncWG.Done()
	c.log.Debugf("\U0001F442 <green>Reader Worker <cyan>#%d</cyan> started</green>", id)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buf := c.udpBufferPool.Get().([]byte)
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				c.udpBufferPool.Put(buf)
				if ctx.Err() != nil {
					return
				}
				continue
			}

			if n < 12 { // Basic DNS header length
				c.udpBufferPool.Put(buf)
				continue
			}

			// Shallow check: DNS Response bit (QR=1)
			// DNS Header: ID(2), Flags(2)... Flags first byte bit 7 is QR.
			if (buf[2] & 0x80) == 0 {
				// Not a response, we are a client, we only care about responses.
				c.udpBufferPool.Put(buf)
				continue
			}

			packetData := buf[:n]

			select {
			case c.rxChannel <- asyncReadPacket{data: packetData, addr: addr}:
			default:
				// Queue full! Drop packet and RECYCLE buffer.
				c.udpBufferPool.Put(buf)
				c.onRXDrop(addr)
			}
		}
	}
}

// asyncProcessorWorker pulls from rxChannel and performs the actual packet handling.
func (c *Client) asyncProcessorWorker(ctx context.Context, id int) {
	defer c.asyncWG.Done()
	c.log.Debugf("\U0001F3D7  <green>Processor Worker <cyan>#%d</cyan> started</green>", id)
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-c.rxChannel:
			c.handleInboundPacket(pkt.data, pkt.addr)

			// RECYCLE buffer back to the pool.
			c.udpBufferPool.Put(pkt.data[:cap(pkt.data)])
		}
	}
}

// handleInboundPacket is the central entry point for all received tunnel packets.
func (c *Client) handleInboundPacket(data []byte, addr *net.UDPAddr) {
	// c.log.Debugf("Inbound packet from %v (%d bytes)", addr, len(data))

	// 1. Extract VPN Packet from DNS Response
	vpnPacket, err := DnsParser.ExtractVPNResponse(data, c.responseMode == mtuProbeBase64Reply)
	if err != nil {
		if errors.Is(err, DnsParser.ErrTXTAnswerMissing) {
			receivedAt := time.Now()
			// summary := DnsParser.DescribeResponseWithoutTunnelPayload(data)
			if parsed, parseErr := DnsParser.ParsePacketLite(data); parseErr == nil && parsed.Header.RCode != 0 {
				c.trackResolverFailure(data, addr, receivedAt)
			} else {
				c.trackResolverSuccess(data, addr, receivedAt)
			}
			// c.log.Debugf("DNS response from %v had no tunnel TXT payload | %s", addr, summary)
			return
		}
		// c.log.Debugf("\U0001F6A8 <red>Failed to parse VPN packet from DNS response: %v from %v</red>", err, addr)
		return
	}

	// packedSummary := ""
	// if vpnPacket.PacketType == Enums.PACKET_PACKED_CONTROL_BLOCKS {
	// 	packedSummary = " | " + VpnProto.DescribePackedControlBlocks(vpnPacket.Payload, 4)
	// }
	// c.logInboundPacket(vpnPacket.PacketType, vpnPacket.SessionID, len(vpnPacket.Payload), vpnPacket.StreamID, vpnPacket.SequenceNum, vpnPacket.FragmentID, vpnPacket.TotalFragments, packedSummary)
	c.trackResolverSuccess(data, addr, time.Now())

	// 2. Notify activity monitor (PingManager)
	c.NotifyPacket(vpnPacket.PacketType, true)

	// 3. Queue deterministic non-data ACKs before any handler logic runs.
	if handled := c.preprocessInboundPacket(vpnPacket); handled {
		return
	}

	// 4. Dispatch to Packet Handlers via Registry
	if err := handlers.Dispatch(c, vpnPacket, addr); err != nil {
		c.log.Warnf("\U0001F6A8 <red>Handler execution failed: %v</red>", err)
	}

}
