// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (client_utils.go) handles common client utility functions.
// ==============================================================================
package client

import (
	"container/heap"
	"crypto/rand"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/version"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// randomBytes generates random bytes using a cryptographically secure PRNG.
// This is used for generating sensitive identifiers like session codes and verify tokens.
func randomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return []byte{}, nil
	}
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// fragmentPayload splits a payload into chunks of max mtu size.
func fragmentPayload(payload []byte, mtu int) [][]byte {
	if len(payload) <= mtu {
		return [][]byte{payload}
	}
	var fragments [][]byte
	for i := 0; i < len(payload); i += mtu {
		end := i + mtu
		if end > len(payload) {
			end = len(payload)
		}
		fragments = append(fragments, payload[i:end])
	}
	return fragments
}

func formatResolverEndpoint(resolver string, port int) string {
	if strings.IndexByte(resolver, ':') >= 0 && !strings.HasPrefix(resolver, "[") {
		return fmt.Sprintf("[%s]:%d", resolver, port)
	}
	return fmt.Sprintf("%s:%d", resolver, port)
}

func makeConnectionKey(resolver string, port int, domain string) string {
	return resolver + "|" + strconv.Itoa(port) + "|" + domain
}

func isHotPacketLogType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_STREAM_DATA,
		Enums.PACKET_STREAM_DATA_ACK,
		Enums.PACKET_STREAM_DATA_NACK,
		Enums.PACKET_STREAM_RESEND,
		Enums.PACKET_PACKED_CONTROL_BLOCKS,
		Enums.PACKET_PING,
		Enums.PACKET_PONG:
		return true
	default:
		return false
	}
}

func (c *Client) logInboundPacket(packetType uint8, sessionID uint8, payloadLen int, streamID uint16, sequenceNum uint16, fragmentID uint8, totalFragments uint8, packedSummary string) {
	if c == nil || c.log == nil || packetType == Enums.PACKET_PONG {
		return
	}
	format := "<green>Receiving Packet, Packet: %s | Session %d | Payload Len(%d) | Stream: %d | Seq: %d | Fg: %d | TF: %d%s</green>"
	if isHotPacketLogType(packetType) {
		if c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf(format, Enums.PacketTypeName(packetType), sessionID, payloadLen, streamID, sequenceNum, fragmentID, totalFragments, packedSummary)
		}
		return
	}
	c.log.Debugf(format, Enums.PacketTypeName(packetType), sessionID, payloadLen, streamID, sequenceNum, fragmentID, totalFragments, packedSummary)
}

func (c *Client) logOutboundPacket(packetType uint8, sessionID uint8, payloadLen int, streamID uint16, sequenceNum uint16, fragmentID uint8, totalFragments uint8, packedSummary string) {
	if c == nil || c.log == nil || packetType == Enums.PACKET_PING {
		return
	}
	format := "<cyan>Sending Packet, Packet: Packet: %s | Session %d | Payload Len(%d) | Stream: %d | Seq: %d | Fg: %d | TF: %d%s</cyan>"
	if isHotPacketLogType(packetType) {
		if c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf(format, Enums.PacketTypeName(packetType), sessionID, payloadLen, streamID, sequenceNum, fragmentID, totalFragments, packedSummary)
		}
		return
	}
	c.log.Debugf(format, Enums.PacketTypeName(packetType), sessionID, payloadLen, streamID, sequenceNum, fragmentID, totalFragments, packedSummary)
}

func (c *Client) getResolverUDPAddr(conn Connection) (*net.UDPAddr, error) {
	if c == nil {
		return nil, ErrNoValidConnections
	}

	label := conn.ResolverLabel
	if label == "" {
		label = formatResolverEndpoint(conn.Resolver, conn.ResolverPort)
	}

	c.resolverAddrMu.RLock()
	if addr, ok := c.resolverAddrCache[label]; ok && addr != nil {
		c.resolverAddrMu.RUnlock()
		return addr, nil
	}
	c.resolverAddrMu.RUnlock()

	var addr *net.UDPAddr
	if ip := net.ParseIP(conn.Resolver); ip != nil {
		addr = &net.UDPAddr{IP: ip, Port: conn.ResolverPort}
	} else {
		resolved, err := net.ResolveUDPAddr("udp", label)
		if err != nil {
			return nil, err
		}
		addr = resolved
	}

	c.resolverAddrMu.Lock()
	if existing, ok := c.resolverAddrCache[label]; ok && existing != nil {
		c.resolverAddrMu.Unlock()
		return existing, nil
	}
	c.resolverAddrCache[label] = addr
	c.resolverAddrMu.Unlock()
	return addr, nil
}

// now returns the current time.
func (c *Client) now() time.Time {
	if c != nil && c.nowFn != nil {
		return c.nowFn()
	}
	return time.Now()
}

func (c *Client) bumpStreamSetVersion() {
	if c == nil {
		return
	}
	c.streamSetVersion.Add(1)
}

func (c *Client) SessionReady() bool {
	if c == nil {
		return false
	}
	return c.sessionReady
}

func (c *Client) SessionID() uint8 {
	return c.sessionID
}

func (c *Client) IsSessionReady() bool {
	return c.SessionReady()
}

func (c *Client) ResponseMode() uint8 {
	return c.responseMode
}

func (c *Client) NotifyPacket(packetType uint8, isInbound bool) {
	if c.pingManager != nil {
		c.pingManager.NotifyPacket(packetType, isInbound)
	}
}

func (c *Client) Log() *logger.Logger {
	return c.log
}

func orphanResetKey(packetType uint8, streamID uint16) uint64 {
	return Enums.PacketTypeStreamKey(streamID, packetType)
}

func (c *Client) enqueueOrphanReset(packetType uint8, streamID uint16, sequenceNum uint16) {
	if c == nil || c.orphanQueue == nil || streamID == 0 {
		return
	}

	packet := VpnProto.Packet{
		PacketType:     packetType,
		StreamID:       streamID,
		HasStreamID:    true,
		SequenceNum:    sequenceNum,
		HasSequenceNum: sequenceNum != 0,
	}

	key := orphanResetKey(packetType, streamID)
	// Orphans usually have high priority. We'll use priority 0.
	c.orphanQueue.Push(0, key, packet)

	select {
	case c.dispatchSignal <- struct{}{}:
	default:
	}
}

func (c *Client) clearOrphanResets() {
	if c == nil || c.orphanQueue == nil {
		return
	}
	c.orphanQueue.Clear(nil)
}

func (c *Client) queueImmediateControlAck(stream *Stream_client, packet VpnProto.Packet) bool {
	if c == nil {
		return false
	}

	ackType, ok := Enums.ControlAckFor(packet.PacketType)
	if !ok {
		return false
	}

	if stream == nil || stream.txQueue == nil {
		return false
	}

	ok = stream.PushTXPacket(
		Enums.DefaultPacketPriority(ackType),
		ackType,
		packet.SequenceNum,
		packet.FragmentID,
		packet.TotalFragments,
		0,
		0,
		nil,
	)

	return ok
}

func (c *Client) consumeInboundStreamAck(packetType uint8, packet VpnProto.Packet, s *Stream_client) bool {
	if c == nil || s == nil {
		return false
	}

	_, ack_required := Enums.ReverseControlAckFor(packetType)
	if packetType != Enums.PACKET_STREAM_DATA_ACK && !ack_required {
		return false
	}

	if packetType == Enums.PACKET_STREAM_RST_ACK {
		c.rememberClosedStream(packet.StreamID, "ACK acknowledged", time.Now())
	}

	arqObj, ok := s.Stream.(*arq.ARQ)
	if !ok {
		return false
	}

	handledAck := arqObj.HandleAckPacket(packet.PacketType, packet.SequenceNum, packet.FragmentID)
	if handledAck {
		c.balancer.NoteStreamProgress(packet.StreamID)
	}

	if _, ok := Enums.GetPacketCloseStream(packet.PacketType); handledAck && ok {
		if s.StatusValue() == streamStatusCancelled || arqObj.IsClosed() {
			s.MarkTerminal(time.Now())
			if s.StatusValue() != streamStatusCancelled {
				s.SetStatus(streamStatusTimeWait)
			}
		}
	}

	if handledAck {
		return true
	}

	return false
}

func (c *Client) getStream(streamID uint16) (*Stream_client, bool) {
	c.streamsMu.RLock()
	s, ok := c.active_streams[streamID]
	c.streamsMu.RUnlock()
	return s, ok
}

func (c *Client) shouldRememberClosedStream(reason string) bool {
	if c == nil {
		return false
	}

	reason = strings.TrimSpace(reason)
	if reason == "" {
		return false
	}

	if reason == "close handshake completed" || reason == "client local disconnect completed" {
		return true
	}

	return strings.HasSuffix(reason, "acknowledged")
}

func (c *Client) rememberClosedStream(streamID uint16, reason string, now time.Time) {
	if c == nil || streamID == 0 || !c.shouldRememberClosedStream(reason) {
		return
	}

	retention := c.cfg.ClientTerminalStreamRetention()
	if retention <= 0 {
		retention = 15 * time.Second
	}

	expiresAt := now.Add(retention)

	c.recentlyClosedMu.Lock()
	// Cap the map to prevent unbounded growth during long sessions.
	// If at limit, evict the oldest entry before adding.
	const maxRecentlyClosed = 2000
	c.pruneRecentlyClosedLocked(now)
	c.recentlyClosedStreams[streamID] = expiresAt
	heap.Push(&c.recentlyClosedHeap, recentlyClosedEntry{streamID: streamID, expires: expiresAt})
	c.evictRecentlyClosedLocked(maxRecentlyClosed)
	c.recentlyClosedMu.Unlock()
}

func (c *Client) isRecentlyClosedStream(streamID uint16, now time.Time) bool {
	if c == nil || streamID == 0 {
		return false
	}

	c.recentlyClosedMu.Lock()
	defer c.recentlyClosedMu.Unlock()

	c.pruneRecentlyClosedLocked(now)
	expiresAt, ok := c.recentlyClosedStreams[streamID]
	if !ok {
		return false
	}
	if now.Before(expiresAt) {
		return true
	}

	delete(c.recentlyClosedStreams, streamID)
	return false
}

func (c *Client) cleanupRecentlyClosedStreams(now time.Time) {
	if c == nil {
		return
	}

	c.recentlyClosedMu.Lock()
	c.pruneRecentlyClosedLocked(now)
	c.recentlyClosedMu.Unlock()
}

func (c *Client) clearRecentlyClosedStreams() {
	if c == nil {
		return
	}

	c.recentlyClosedMu.Lock()
	clear(c.recentlyClosedStreams)
	c.recentlyClosedHeap = c.recentlyClosedHeap[:0]
	c.recentlyClosedMu.Unlock()
}

func (c *Client) pruneRecentlyClosedLocked(now time.Time) {
	if c == nil {
		return
	}
	for len(c.recentlyClosedHeap) > 0 {
		entry := c.recentlyClosedHeap[0]
		expiresAt, ok := c.recentlyClosedStreams[entry.streamID]
		if !ok || !expiresAt.Equal(entry.expires) {
			heap.Pop(&c.recentlyClosedHeap)
			continue
		}
		if now.Before(expiresAt) {
			break
		}
		delete(c.recentlyClosedStreams, entry.streamID)
		heap.Pop(&c.recentlyClosedHeap)
	}
	c.compactRecentlyClosedHeapLocked()
}

func (c *Client) compactRecentlyClosedHeapLocked() {
	mapLen := len(c.recentlyClosedStreams)
	threshold := mapLen + mapLen/2
	if threshold < mapLen+4 {
		threshold = mapLen + 4
	}
	if len(c.recentlyClosedHeap) <= threshold {
		return
	}
	rebuilt := make(recentlyClosedHeap, 0, mapLen)
	for streamID, expires := range c.recentlyClosedStreams {
		rebuilt = append(rebuilt, recentlyClosedEntry{streamID: streamID, expires: expires})
	}
	heap.Init(&rebuilt)
	c.recentlyClosedHeap = rebuilt
}

func (c *Client) evictRecentlyClosedLocked(capacity int) {
	for len(c.recentlyClosedStreams) > capacity && len(c.recentlyClosedHeap) > 0 {
		entry := heap.Pop(&c.recentlyClosedHeap).(recentlyClosedEntry)
		expiresAt, ok := c.recentlyClosedStreams[entry.streamID]
		if !ok || !expiresAt.Equal(entry.expires) {
			continue
		}
		delete(c.recentlyClosedStreams, entry.streamID)
	}
}

func (c *Client) handleMissingStreamPacket(packet VpnProto.Packet) bool {
	if c == nil {
		return false
	}

	if packet.PacketType == Enums.PACKET_PACKED_CONTROL_BLOCKS ||
		packet.PacketType == Enums.PACKET_PONG ||
		packet.PacketType == Enums.PACKET_DNS_QUERY_RES {
		return false
	}

	// No need to send Response for ACK packets
	if packet.PacketType == Enums.PACKET_STREAM_DATA_ACK || packet.PacketType == Enums.PACKET_STREAM_DATA_NACK {
		return true
	}

	if packet.PacketType == Enums.PACKET_STREAM_RST_ACK {
		c.rememberClosedStream(packet.StreamID, "ACK acknowledged", time.Now())
	}

	if _, ok := Enums.ReverseControlAckFor(packet.PacketType); ok {
		return true
	}

	if packet.PacketType == Enums.PACKET_STREAM_RST {
		c.enqueueOrphanReset(Enums.PACKET_STREAM_RST_ACK, packet.StreamID, packet.SequenceNum)
		return true
	}

	// GetPacketCloseStream
	ack_answer, ok := Enums.GetPacketCloseStream(packet.PacketType)
	if ok {
		c.enqueueOrphanReset(ack_answer, packet.StreamID, 0)
	} else {
		c.enqueueOrphanReset(Enums.PACKET_STREAM_RST, packet.StreamID, 0)
	}

	return true
}

func (c *Client) ackRecentlyClosedStreamPacket(packet VpnProto.Packet) bool {
	if c == nil || packet.StreamID == 0 {
		return false
	}

	if packet.PacketType == Enums.PACKET_STREAM_DATA_ACK || packet.PacketType == Enums.PACKET_STREAM_DATA_NACK {
		return true
	}

	if _, ok := Enums.ReverseControlAckFor(packet.PacketType); ok {
		return true
	}

	if ackType, ok := Enums.ControlAckFor(packet.PacketType); ok {
		c.enqueueOrphanReset(ackType, packet.StreamID, packet.SequenceNum)
		return true
	}

	return false
}

func (c *Client) preprocessInboundPacket(packet VpnProto.Packet) bool {
	if c == nil {
		return true
	}

	exists_stream, stream_exists := c.getStream(packet.StreamID)
	if packet.StreamID != 0 && (!stream_exists || exists_stream == nil) {
		if c.isRecentlyClosedStream(packet.StreamID, c.now()) {
			if packet.PacketType == Enums.PACKET_STREAM_DATA ||
				packet.PacketType == Enums.PACKET_STREAM_RESEND {
				c.enqueueOrphanReset(Enums.PACKET_STREAM_RST, packet.StreamID, 0)
				return true
			}
			if c.ackRecentlyClosedStreamPacket(packet) {
				return true
			}
			return true
		}

		c.handleMissingStreamPacket(packet)
		return true
	}

	// Add ACK to queue if thats control packet
	_ = c.queueImmediateControlAck(exists_stream, packet)

	// Handle all control packets
	if c.consumeInboundStreamAck(packet.PacketType, packet, exists_stream) {
		return true
	}

	return false
}

func (c *Client) PreprocessInboundPacket(packet VpnProto.Packet) bool {
	return c.preprocessInboundPacket(packet)
}

func (c *Client) getStreamARQ(streamID uint16) (*arq.ARQ, error) {
	c.streamsMu.RLock()
	s, ok := c.active_streams[streamID]
	c.streamsMu.RUnlock()

	if !ok || s == nil {
		return nil, fmt.Errorf("stream not found")
	}

	arqObj, ok := s.Stream.(*arq.ARQ)
	if !ok {
		return nil, fmt.Errorf("stream is not ARQ")
	}
	return arqObj, nil
}

func (c *Client) Balancer() *Balancer {
	return c.balancer
}

func (c *Client) ShortPrintBanner() {
	if c.log == nil {
		return
	}

	c.log.Infof("============================================================")
	c.log.Infof("<cyan>GitHub:</cyan> <yellow>https://github.com/masterking32/MasterDnsVPN</yellow>")
	c.log.Infof("<cyan>Telegram:</cyan> <yellow>@MasterDnsVPN</yellow>")
	c.log.Infof("<cyan>Build Version:</cyan> <yellow>%s</yellow>", version.GetVersion())
	c.log.Infof("============================================================")
}

func (c *Client) PrintBanner() {
	if c.log == nil {
		return
	}

	c.ShortPrintBanner()
	c.log.Infof("🚀 <green>Client Configuration Loaded</green>")

	c.log.Infof("🚀 <cyan>Client Mode, Protocol:</cyan> <yellow>%s</yellow> <cyan>Encryption:</cyan> <yellow>%d</yellow>", c.cfg.ProtocolType, c.cfg.DataEncryptionMethod)

	strategyName := "Round-Robin"
	switch c.cfg.ResolverBalancingStrategy {
	case 0:
		strategyName = "Round-Robin Default"
	case 1:
		strategyName = "Random"
	case 2:
		strategyName = "Round-Robin"
	case 3:
		strategyName = "Least Loss"
	case 4:
		strategyName = "Lowest Latency"
	}
	c.log.Infof("⚖  <cyan>Resolver Balancing, Strategy:</cyan> <yellow>%s (%d)</yellow>", strategyName, c.cfg.ResolverBalancingStrategy)

	domainList := ""
	if len(c.cfg.Domains) > 0 {
		domainList = c.cfg.Domains[0]
	}
	c.log.Infof("🌐 <cyan>Configured Domains:</cyan> <yellow>%d (%s)</yellow>", len(c.cfg.Domains), domainList)
	c.log.Infof("📡 <cyan>Loaded Resolvers:</cyan> <yellow>%d endpoints.</yellow>", len(c.cfg.Resolvers))
}

// BuildConnectionMap iterates through all domains and resolvers in the configuration
// and builds a comprehensive list of unique Connection objects, then entrusts them to the Balancer.
func (c *Client) BuildConnectionMap() error {
	domains := c.cfg.Domains
	resolvers := c.cfg.Resolvers

	total := len(domains) * len(resolvers)
	if total <= 0 {
		return fmt.Errorf("Domains or Resolvers are missing in config.")
	}

	connections := make([]Connection, 0, total)
	indexByKey := make(map[string]int, total)

	for _, domain := range domains {
		for _, resolver := range resolvers {
			label := formatResolverEndpoint(resolver.IP, resolver.Port)
			key := makeConnectionKey(resolver.IP, resolver.Port, domain)
			if _, exists := indexByKey[key]; exists {
				continue
			}

			indexByKey[key] = len(connections)
			connections = append(connections, Connection{
				Domain:        domain,
				Resolver:      resolver.IP,
				ResolverPort:  resolver.Port,
				ResolverLabel: label,
				Key:           key,
				IsValid:       false, // Initially all are inactive until MTU/Health checks pass
			})
			if ip := net.ParseIP(resolver.IP); ip != nil {
				c.resolverAddrMu.Lock()
				c.resolverAddrCache[label] = &net.UDPAddr{IP: ip, Port: resolver.Port}
				c.resolverAddrMu.Unlock()
			}
		}
	}

	pointers := make([]*Connection, len(connections))
	for i := range connections {
		pointers[i] = &connections[i]
	}

	if c.balancer != nil {
		c.balancer.SetConnections(pointers)
	}

	return nil
}
