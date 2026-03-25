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
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
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

// now returns the current time.
func (c *Client) now() time.Time {
	if c != nil && c.nowFn != nil {
		return c.nowFn()
	}
	return time.Now()
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

// connectionPtrByKey returns a pointer to a Connection object based on its unique key.
func (c *Client) connectionPtrByKey(key string) *Connection {
	if idx, ok := c.connectionsByKey[key]; ok {
		return &c.connections[idx]
	}
	return nil
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
	case c.txSignal <- struct{}{}:
	default:
	}
}

func (c *Client) dequeueOrphanReset() (*VpnProto.Packet, bool) {
	if c == nil || c.orphanQueue == nil {
		return nil, false
	}

	packet, _, ok := c.orphanQueue.Pop(func(p VpnProto.Packet) uint64 {
		return orphanResetKey(p.PacketType, p.StreamID)
	})
	if !ok {
		return nil, false
	}

	return &packet, true
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

	arqObj, ok := s.Stream.(*arq.ARQ)
	if !ok {
		return false
	}

	handledAck := arqObj.HandleAckPacket(packet.PacketType, packet.SequenceNum, packet.FragmentID)
	if handledAck {
		c.noteStreamProgress(packet.StreamID)
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
	c.streamsMu.Lock()
	s, ok := c.active_streams[streamID]
	c.streamsMu.Unlock()
	return s, ok
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
	if packet.PacketType == Enums.PACKET_STREAM_DATA_ACK {
		return true
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
	if ok && packet.PacketType != Enums.PACKET_STREAM_FIN {
		c.enqueueOrphanReset(ack_answer, packet.StreamID, 0)
	} else {
		c.enqueueOrphanReset(Enums.PACKET_STREAM_RST, packet.StreamID, 0)
	}

	return true
}

func (c *Client) preprocessInboundPacket(packet VpnProto.Packet) bool {
	if c == nil {
		return true
	}

	exists_stream, stream_exists := c.getStream(packet.StreamID)
	if packet.StreamID != 0 && (!stream_exists || exists_stream == nil) {
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
	c.streamsMu.Lock()
	s, ok := c.active_streams[streamID]
	c.streamsMu.Unlock()

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

func (c *Client) Connections() []Connection {
	return c.connections
}

// BuildConnectionMap iterates through all domains and resolvers in the configuration
// and builds a comprehensive list of unique Connection objects.
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
				IsValid:       true,
			})
		}
	}

	c.connections = connections
	c.connectionsByKey = indexByKey

	pointers := make([]*Connection, len(c.connections))
	for i := range c.connections {
		pointers[i] = &c.connections[i]
	}
	c.balancer.SetConnections(pointers)

	return nil
}
