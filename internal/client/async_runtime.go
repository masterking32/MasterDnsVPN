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
	Enums "masterdnsvpn-go/internal/enums"
	fragmentStore "masterdnsvpn-go/internal/fragmentstore"
)

const clientRXDropLogInterval = 2 * time.Second

type asyncReadPacket struct {
	data      []byte
	addr      *net.UDPAddr
	localAddr string
}

func (c *Client) runtimePacketDuplicationCount(packetType uint8) int {
	if c == nil {
		return 1
	}

	count := c.cfg.PacketDuplicationCount
	if count < 1 {
		count = 1
	}

	if packetType == Enums.PACKET_STREAM_SYN ||
		packetType == Enums.PACKET_PACKED_CONTROL_BLOCKS ||
		packetType == Enums.PACKET_SOCKS5_SYN ||
		packetType == Enums.PACKET_STREAM_CLOSE_READ ||
		packetType == Enums.PACKET_STREAM_CLOSE_WRITE {
		if c.cfg.SetupPacketDuplicationCount > count {
			count = c.cfg.SetupPacketDuplicationCount
		}
	}

	if packetType == Enums.PACKET_PING {
		return min(count, 2)
	}

	return count
}

// StopAsyncRuntime stops all running workers (Readers, Writers, Processors).
// It ensures the UDP socket is closed and all goroutines exit.
func (c *Client) StopAsyncRuntime() {
	if c.asyncCancel != nil {
		c.log.Debugf("\U0001F6D1 <yellow>Stopping Async Runtime...</yellow>")
		c.asyncCancel()
		c.closeTunnelSockets()
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

	c.dnsResponses = fragmentStore.New[dnsFragmentKey](c.cfg.EffectiveDNSResponseFragmentStoreCap())

	if c.localDNSCache != nil {
		c.localDNSCache.ClearPending()
	}

	if c.socksRateLimit == nil {
		c.socksRateLimit = newSocksRateLimiter()
	} else {
		c.socksRateLimit.Reset()
	}

	c.closeResolverConnPools()
	c.clearDispatchSignal()
	c.clearPlannerQueueSpaceSignal()
	c.clearWriterQueueSpaceSignal()
	c.clearSessionResetPending()
	if resetSession {
		c.resetSessionState(true)
	}
}

func (c *Client) clearDispatchSignal() {
	if c == nil || c.dispatchSignal == nil {
		return
	}
	for {
		select {
		case <-c.dispatchSignal:
		default:
			return
		}
	}
}

func (c *Client) clearPlannerQueueSpaceSignal() {
	if c == nil || c.plannerQueueSpaceSignal == nil {
		return
	}
	for {
		select {
		case <-c.plannerQueueSpaceSignal:
		default:
			return
		}
	}
}

func (c *Client) clearWriterQueueSpaceSignal() {
	if c == nil || c.writerQueueSpaceSignal == nil {
		return
	}
	for {
		select {
		case <-c.writerQueueSpaceSignal:
		default:
			return
		}
	}
}

func (c *Client) signalPlannerQueueSpace() {
	if c == nil || c.plannerQueueSpaceSignal == nil {
		return
	}
	select {
	case c.plannerQueueSpaceSignal <- struct{}{}:
	default:
	}
}

func (c *Client) signalWriterQueueSpace() {
	if c == nil || c.writerQueueSpaceSignal == nil {
		return
	}
	select {
	case c.writerQueueSpaceSignal <- struct{}{}:
	default:
	}
}

func (c *Client) plannerQueueHasCapacity(needed int) bool {
	if c == nil || c.plannerQueue == nil {
		return false
	}

	if needed <= 0 {
		needed = 1
	}

	return cap(c.plannerQueue)-len(c.plannerQueue) >= needed
}

func (c *Client) encodedTXChannelHasCapacity(needed int) bool {
	if c == nil || c.encodedTXChannel == nil {
		return false
	}
	if needed <= 0 {
		needed = 1
	}
	return cap(c.encodedTXChannel)-len(c.encodedTXChannel) >= needed
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
	started := false
	defer func() {
		if started {
			return
		}
		cancel()
		if c.tcpListener != nil {
			c.tcpListener.Stop()
			c.tcpListener = nil
		}
		if c.dnsListener != nil {
			c.dnsListener.Stop()
			c.dnsListener = nil
		}
		c.closeTunnelSockets()
		c.asyncCancel = nil
		c.resetRuntimeBindings(false)
	}()

	// 3. Open dedicated UDP sockets for each RX/TX worker.
	conns := make([]*net.UDPConn, 0, c.tunnelRX_TX_Workers)
	for i := 0; i < c.tunnelRX_TX_Workers; i++ {
		conn, err := c.listenUDPProtected(runtimeCtx, &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			for _, opened := range conns {
				_ = opened.Close()
			}
			cancel()
			c.asyncCancel = nil
			return fmt.Errorf("failed to open tunnel socket %d/%d: %w", i+1, c.tunnelRX_TX_Workers, err)
		}
		conns = append(conns, conn)
	}

	c.tunnelConns = conns

	c.log.Infof("\U0001F4E1 <cyan>Async Runtime Initialized: <green>%d RX/TX Workers</green>, <green>%d Processors</green></cyan>",
		c.tunnelRX_TX_Workers, c.tunnelProcessWorkers)

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
	for i := 0; i < c.tunnelRX_TX_Workers; i++ {
		c.asyncWG.Add(1)
		go c.asyncReaderWorker(runtimeCtx, i, conns[i])
	}

	// 5. Spawn Processor Workers (Parallel data analysis)
	for i := 0; i < c.tunnelProcessWorkers; i++ {
		c.asyncWG.Add(1)
		go c.asyncProcessorWorker(runtimeCtx, i)
	}

	// 6. Spawn Planner/Encoder Workers (routing + packet build stage)
	for i := 0; i < c.tunnelRX_TX_Workers; i++ {
		c.asyncWG.Add(1)
		go c.asyncPlanEncodeWorker(runtimeCtx, i)
	}

	// 7. Spawn Writer Workers (UDP send stage)
	for i := 0; i < c.tunnelRX_TX_Workers; i++ {
		c.asyncWG.Add(1)
		go c.asyncWriterWorker(runtimeCtx, i, conns[i])
	}

	// 8. Spawn Dispatcher (Fair Queuing & Packing)
	c.asyncWG.Add(1)
	go c.asyncStreamDispatcher(runtimeCtx)

	// 9. Stream lifecycle cleanup.
	c.asyncWG.Add(1)
	go c.asyncStreamCleanupWorker(runtimeCtx)

	started = true
	return nil
}

func (c *Client) asyncStreamCleanupWorker(ctx context.Context) {
	defer c.asyncWG.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	fragmentPurgeCounter := 0

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			c.cleanupRecentlyClosedStreams(now)

			// Purge stale DNS response fragments every 10 seconds to prevent
			// memory leaks when no new fragments arrive for a given key.
			fragmentPurgeCounter++
			if fragmentPurgeCounter >= 10 {
				fragmentPurgeCounter = 0
				if c.dnsResponses != nil {
					c.dnsResponses.Purge(now, c.cfg.DNSResponseFragmentTimeout())
				}
			}

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

// drainQueues removes any stale packets from TX and RX channels.
// Buffers from the RX channel are returned to the pool to prevent leaks.
func (c *Client) drainQueues() {
	// Drain TX
	for {
		select {
		case task := <-c.plannerQueue:
			if !task.wasPacked && task.selected != nil && task.item != nil {
				task.selected.ReleaseTXPacket(task.item)
			}
		default:
			goto drainEncoded
		}
	}
drainEncoded:
	for {
		select {
		case task := <-c.encodedTXChannel:
			if !task.wasPacked && task.selected != nil && task.item != nil {
				task.selected.ReleaseTXPacket(task.item)
			}
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

func (c *Client) closeTunnelSockets() {
	if c == nil || len(c.tunnelConns) == 0 {
		return
	}
	for _, conn := range c.tunnelConns {
		if conn != nil {
			_ = conn.Close()
		}
	}
	c.tunnelConns = nil
}

// asyncPlanEncodeWorker chooses runtime targets, applies fan-out policy, encodes
// the tunnel payload, and emits writer-ready DNS datagrams.
func (c *Client) asyncPlanEncodeWorker(ctx context.Context, id int) {
	defer c.asyncWG.Done()
	c.log.Debugf("\U0001F9E9 <green>Planner/Encoder Worker <cyan>#%d</cyan> started</green>", id)
	defaultDomain := ""
	if len(c.cfg.Domains) > 0 {
		defaultDomain = c.cfg.Domains[0]
	}

	var packetByDomain map[string][]byte
	var preparedDomainByName map[string]preparedTunnelDomain
	var frames []encodedOutboundDatagram
	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-c.plannerQueue:
			c.signalPlannerQueueSpace()
			if !ok {
				return
			}

			targetCount := task.dupCount
			if targetCount < 1 {
				targetCount = 1
			}

			var (
				conns []Connection
				err   error
			)

			conns, err = c.balancer.SelectTargets(task.opts.PacketType, task.opts.StreamID, targetCount)
			if err != nil {
				conns = nil
			}

			if len(conns) == 0 {
				c.applyPlannerNoConnectionPolicy(task)
				continue
			}

			frames, err = c.buildPlannedOutboundFrames(task, conns, defaultDomain, packetByDomain, preparedDomainByName, frames)
			if err != nil {
				if !task.wasPacked && task.selected != nil {
					task.selected.ReleaseTXPacket(task.item)
				}
				continue
			}

			if len(frames) == 0 {
				if !task.wasPacked && task.selected != nil {
					task.selected.ReleaseTXPacket(task.item)
				}
				continue
			}

			if !c.waitForWriterCapacity(ctx, task, frames) {
				return
			}

			encodedTask := writerTask{
				wasPacked: task.wasPacked,
				item:      task.item,
				selected:  task.selected,
				frames:    append([]encodedOutboundDatagram(nil), frames...),
			}

			select {
			case c.encodedTXChannel <- encodedTask:
			case <-ctx.Done():
				if !task.wasPacked && task.selected != nil {
					task.selected.ReleaseTXPacket(task.item)
				}
				return
			}
		}
	}
}

func (c *Client) applyPlannerNoConnectionPolicy(task plannerTask) {
	switch {
	case c.shouldRetainPlannerTaskWithoutConnection(task):
		c.requeuePlannerTaskForRetry(task)
	case c.shouldDropPlannerTaskWithoutConnection(task):
		c.releasePlannerTask(task)
	default:
		c.releasePlannerTask(task)
	}
}

func (c *Client) shouldRetainPlannerTaskWithoutConnection(task plannerTask) bool {
	return task.opts.PacketType == Enums.PACKET_STREAM_DATA || task.opts.PacketType == Enums.PACKET_STREAM_RESEND
}

func (c *Client) shouldDropPlannerTaskWithoutConnection(task plannerTask) bool {
	return !c.shouldRetainPlannerTaskWithoutConnection(task)
}

func (c *Client) requeuePlannerTaskForRetry(task plannerTask) {
	if task.selected == nil || task.item == nil || task.wasPacked {
		return
	}
	task.selected.PushTXPacket(
		Enums.DefaultPacketPriority(task.item.PacketType),
		task.item.PacketType,
		task.item.SequenceNum,
		task.item.FragmentID,
		task.item.TotalFragments,
		task.item.CompressionType,
		task.item.TTL,
		task.item.Payload,
	)
	c.releasePlannerTask(task)
}

func (c *Client) releasePlannerTask(task plannerTask) {
	if !task.wasPacked && task.selected != nil {
		task.selected.ReleaseTXPacket(task.item)
	}
}

func (c *Client) requiredWriterSlotsForFrames(frames []encodedOutboundDatagram) int {
	if len(frames) == 0 {
		return 0
	}
	// The writer queue is a queue of writerTask batches, not individual datagrams.
	// A planner task with N duplications/fan-out frames still occupies one writer
	// queue slot because all frames are flushed together by a single writer worker.
	return 1
}

func (c *Client) waitForWriterCapacity(ctx context.Context, task plannerTask, frames []encodedOutboundDatagram) bool {
	requiredWriterSlots := c.requiredWriterSlotsForFrames(frames)
	if requiredWriterSlots < 1 {
		return true
	}

	for !c.encodedTXChannelHasCapacity(requiredWriterSlots) {
		select {
		case <-ctx.Done():
			if !task.wasPacked && task.selected != nil {
				task.selected.ReleaseTXPacket(task.item)
			}
			return false
		case <-c.writerQueueSpaceSignal:
		}
	}
	return true
}

func (c *Client) buildPlannedOutboundFrames(
	task plannerTask,
	conns []Connection,
	defaultDomain string,
	packetByDomain map[string][]byte,
	preparedDomainByName map[string]preparedTunnelDomain,
	frames []encodedOutboundDatagram,
) ([]encodedOutboundDatagram, error) {
	encoded, err := c.buildEncodedAutoWithCompressionTrace(task.opts)
	if err != nil {
		return nil, err
	}

	var (
		firstDomain    string
		firstDNSPacket []byte
	)

	if packetByDomain != nil {
		clear(packetByDomain)
	}

	if preparedDomainByName != nil {
		clear(preparedDomainByName)
	}

	frames = frames[:0]

	for _, resolverConn := range conns {
		domain := resolverConn.Domain
		if domain == "" {
			domain = defaultDomain
		}

		addr, err := c.getResolverUDPAddr(resolverConn)
		if err != nil {
			continue
		}

		prepared, cachedPrepared := preparedDomainByName[domain]
		if !cachedPrepared {
			prepared, err = prepareTunnelDomain(domain)
			if err != nil {
				continue
			}
			if preparedDomainByName == nil {
				preparedDomainByName = make(map[string]preparedTunnelDomain, len(conns))
			}
			preparedDomainByName[domain] = prepared
		}

		var dnsPacket []byte
		switch {
		case firstDNSPacket == nil:
			dnsPacket, err = DnsParser.BuildTunnelTXTQuestionPacketPrepared(prepared.normalized, prepared.qname, encoded, Enums.DNS_RECORD_TYPE_TXT, EDnsSafeUDPSize)
			if err != nil {
				continue
			}
			firstDomain = domain
			firstDNSPacket = dnsPacket
		case domain == firstDomain:
			dnsPacket = firstDNSPacket
		default:
			if packetByDomain == nil {
				packetByDomain = make(map[string][]byte, max(0, len(conns)-1))
			}
			var cached bool
			dnsPacket, cached = packetByDomain[domain]
			if !cached {
				dnsPacket, err = DnsParser.BuildTunnelTXTQuestionPacketPrepared(prepared.normalized, prepared.qname, encoded, Enums.DNS_RECORD_TYPE_TXT, EDnsSafeUDPSize)
				if err != nil {
					continue
				}
				packetByDomain[domain] = dnsPacket
			}
		}

		frames = append(frames, encodedOutboundDatagram{
			addr:      addr,
			serverKey: resolverConn.Key,
			packet:    dnsPacket,
		})
	}

	return frames, nil
}

// asyncWriterWorker sends already-built DNS packets on the assigned socket.
func (c *Client) asyncWriterWorker(ctx context.Context, id int, conn *net.UDPConn) {
	defer c.asyncWG.Done()
	c.log.Debugf("\U0001F680 <green>Writer Worker <cyan>#%d</cyan> started</green>", id)
	var lastDeadline time.Time
	localAddr := ""
	if conn != nil && conn.LocalAddr() != nil {
		localAddr = conn.LocalAddr().String()
	}
	refreshWindow := c.tunnelPacketTimeout / 2
	if refreshWindow < 250*time.Millisecond {
		refreshWindow = 250 * time.Millisecond
	}
	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-c.encodedTXChannel:
			if !ok {
				return
			}
			c.signalWriterQueueSpace()
			now := time.Now()
			if c.tunnelPacketTimeout > 0 {
				if lastDeadline.IsZero() || now.Add(refreshWindow).After(lastDeadline) {
					lastDeadline = now.Add(c.tunnelPacketTimeout)
					_ = conn.SetWriteDeadline(lastDeadline)
				}
			}
			for _, frame := range task.frames {
				if frame.addr == nil || len(frame.packet) == 0 {
					continue
				}
				if _, err := conn.WriteToUDP(frame.packet, frame.addr); err == nil {
					c.balancer.TrackResolverSend(
						frame.packet,
						frame.addr.String(),
						localAddr,
						frame.serverKey,
						now,
						c.tunnelPacketTimeout,
					)
				}
			}
			if !task.wasPacked && task.selected != nil {
				task.selected.ReleaseTXPacket(task.item)
			}
		}
	}
}

// asyncReaderWorker reads raw UDP data and pushes to the rxChannel (Internal Queue).
func (c *Client) asyncReaderWorker(ctx context.Context, id int, conn *net.UDPConn) {
	defer c.asyncWG.Done()
	c.log.Debugf("\U0001F442 <green>Reader Worker <cyan>#%d</cyan> started</green>", id)
	localAddr := ""
	if conn != nil && conn.LocalAddr() != nil {
		localAddr = conn.LocalAddr().String()
	}

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
			case c.rxChannel <- asyncReadPacket{data: packetData, addr: addr, localAddr: localAddr}:
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
			c.handleInboundPacket(pkt.data, pkt.addr, pkt.localAddr)

			// RECYCLE buffer back to the pool.
			c.udpBufferPool.Put(pkt.data[:cap(pkt.data)])
		}
	}
}

// handleInboundPacket is the central entry point for all received tunnel packets.
func (c *Client) handleInboundPacket(data []byte, addr *net.UDPAddr, localAddr string) {
	// c.log.Debugf("Inbound packet from %v (%d bytes)", addr, len(data))

	// 1. Extract VPN Packet from DNS Response
	vpnPacket, err := DnsParser.ExtractVPNResponse(data, c.responseMode == mtuProbeBase64Reply)
	if err != nil {
		if errors.Is(err, DnsParser.ErrTXTAnswerMissing) {
			receivedAt := time.Now()
			if parsed, parseErr := DnsParser.ParsePacketLite(data); parseErr == nil && parsed.Header.RCode != 0 {
				c.balancer.TrackResolverFailure(
					data,
					addr,
					localAddr,
					receivedAt,
				)
			} else {
				c.balancer.TrackResolverSuccess(
					data,
					addr,
					localAddr,
					receivedAt,
					0,
				)
			}
			// summary := DnsParser.DescribeResponseWithoutTunnelPayload(data)
			// c.log.Debugf("DNS response from %v had no tunnel TXT payload | %s", addr, summary)
			return
		}
		// c.log.Debugf("\U0001F6A8 <red>Failed to parse VPN packet from DNS response: %v from %v</red>", err, addr)
		return
	}

	c.balancer.TrackResolverSuccess(
		data,
		addr,
		localAddr,
		time.Now(),
		0,
	)
	// if c.log != nil && c.log.Enabled(logger.LevelDebug) && vpnPacket.PacketType != Enums.PACKET_PONG {
	// 	if vpnPacket.PacketType == Enums.PACKET_STREAM_DATA_ACK {
	// 		c.log.Debugf("Client received ACK | Stream: %d | Seq: %d", vpnPacket.StreamID, vpnPacket.SequenceNum)
	// 	} else {
	// 		c.log.Debugf("Client received inbound VPN packet | Packet: %s | Stream: %d | Seq: %d | Payload: %d | Frag: %d/%d",
	// 			Enums.PacketTypeName(vpnPacket.PacketType), vpnPacket.StreamID, vpnPacket.SequenceNum, len(vpnPacket.Payload), vpnPacket.FragmentID, vpnPacket.TotalFragments)
	// 	}
	// }

	// 2. Notify activity monitor (PingManager)
	c.NotifyPacket(vpnPacket.PacketType, true)

	// 3. Queue deterministic non-data ACKs before any handler logic runs.
	if handled := c.preprocessInboundPacket(vpnPacket); handled {
		return
	}

	// 4. Dispatch to Packet Handlers via Registry
	if err := handlers.Dispatch(c, vpnPacket, addr); err != nil {
		c.log.Debugf("\U0001F6A8 <red>Handler execution failed: %v</red>", err)
	}

}
