package client

import (
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
)

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

	return count
}

func (c *Client) selectTargetConnectionsForPacket(packetType uint8, streamID uint16) ([]Connection, error) {
	targetCount := c.runtimePacketDuplicationCount(packetType)

	if c == nil || c.balancer == nil || streamID == 0 || c.balancer.ValidCount() <= 0 {
		return c.selectUniqueRuntimeConnections(targetCount)
	}

	if packetType != Enums.PACKET_STREAM_DATA && packetType != Enums.PACKET_STREAM_RESEND {
		return c.selectUniqueRuntimeConnections(targetCount)
	}

	stream, ok := c.getStream(streamID)
	if !ok || stream == nil {
		return c.selectUniqueRuntimeConnections(targetCount)
	}

	var (
		preferred Connection
		found     bool
	)

	if packetType == Enums.PACKET_STREAM_RESEND {
		preferred, found = c.selectStreamPreferredConnectionForResend(stream)
	} else {
		preferred, found = c.ensureStreamPreferredConnection(stream)
	}

	if !found {
		return c.selectUniqueRuntimeConnections(targetCount)
	}

	if targetCount <= 1 {
		return []Connection{preferred}, nil
	}

	selected := make([]Connection, 0, targetCount)
	selected = append(selected, preferred)
	seenKeys := map[string]struct{}{preferred.Key: {}}

	for _, connection := range c.balancer.GetUniqueConnections(targetCount) {
		if !connection.IsValid || connection.Key == "" {
			continue
		}
		if _, exists := seenKeys[connection.Key]; exists {
			continue
		}
		selected = append(selected, connection)
		seenKeys[connection.Key] = struct{}{}
		if len(selected) >= targetCount {
			return selected, nil
		}
	}

	if len(selected) == 0 {
		return nil, ErrNoValidConnections
	}
	return selected, nil
}

func (c *Client) selectUniqueRuntimeConnections(requiredCount int) ([]Connection, error) {
	if c == nil {
		return nil, ErrNoValidConnections
	}

	if c.balancer == nil {
		return nil, ErrNoValidConnections
	}

	connections := c.balancer.GetUniqueConnections(requiredCount)
	if len(connections) == 0 {
		return nil, ErrNoValidConnections
	}

	return connections, nil
}

func (c *Client) selectStreamPreferredConnectionForResend(stream *Stream_client) (Connection, bool) {
	if c == nil || stream == nil {
		return Connection{}, false
	}

	stream.resolverMu.Lock()
	stream.ResolverResendStreak++
	streak := stream.ResolverResendStreak
	stream.resolverMu.Unlock()

	if streak >= c.streamResolverFailoverResendThreshold {
		return c.maybeFailoverStreamPreferredConnection(stream)
	}
	return c.ensureStreamPreferredConnection(stream)
}

func (c *Client) getValidStreamPreferredConnection(stream *Stream_client) (Connection, bool) {
	if c == nil || stream == nil {
		return Connection{}, false
	}
	stream.resolverMu.Lock()
	preferredKey := stream.PreferredServerKey
	stream.resolverMu.Unlock()
	if preferredKey == "" {
		return Connection{}, false
	}
	connection, ok := c.GetConnectionByKey(preferredKey)
	if !ok || !connection.IsValid {
		return Connection{}, false
	}
	return connection, true
}

func (c *Client) selectAlternateStreamConnection(excludeKey string) (Connection, bool) {
	if c == nil || c.balancer == nil {
		return Connection{}, false
	}

	if excludeKey != "" {
		if replacement, ok := c.balancer.GetBestConnectionExcluding(excludeKey); ok {
			return replacement, true
		}
	}

	for _, connection := range c.balancer.GetAllValidConnections() {
		if !connection.IsValid || connection.Key == "" {
			continue
		}
		if excludeKey != "" && connection.Key == excludeKey {
			continue
		}
		return connection, true
	}

	return Connection{}, false
}

func (c *Client) assignStreamPreferredConnection(stream *Stream_client, connection Connection, markFailover bool) (Connection, bool) {
	if c == nil || stream == nil {
		return Connection{}, false
	}
	if !connection.IsValid || connection.Key == "" {
		stream.resolverMu.Lock()
		stream.PreferredServerKey = ""
		stream.resolverMu.Unlock()
		return Connection{}, false
	}

	stream.resolverMu.Lock()
	stream.PreferredServerKey = connection.Key
	stream.ResolverResendStreak = 0
	if markFailover {
		stream.LastResolverFailoverAt = time.Now()
	}
	stream.resolverMu.Unlock()
	return connection, true
}

func (c *Client) ensureStreamPreferredConnection(stream *Stream_client) (Connection, bool) {
	if preferred, ok := c.getValidStreamPreferredConnection(stream); ok {
		return preferred, true
	}
	if c.balancer == nil {
		return Connection{}, false
	}
	fallback, ok := c.balancer.GetBestConnection()
	if !ok {
		return Connection{}, false
	}
	return c.assignStreamPreferredConnection(stream, fallback, false)
}

func (c *Client) maybeFailoverStreamPreferredConnection(stream *Stream_client) (Connection, bool) {
	current, ok := c.getValidStreamPreferredConnection(stream)
	if !ok {
		return c.ensureStreamPreferredConnection(stream)
	}

	stream.resolverMu.Lock()
	lastSwitch := stream.LastResolverFailoverAt
	stream.resolverMu.Unlock()
	if !lastSwitch.IsZero() && time.Since(lastSwitch) < c.streamResolverFailoverCooldown {
		return current, true
	}

	replacement, ok := c.selectAlternateStreamConnection(current.Key)
	if !ok {
		return current, true
	}
	return c.assignStreamPreferredConnection(stream, replacement, true)
}

func (c *Client) noteStreamProgress(streamID uint16) {
	if c == nil || streamID == 0 {
		return
	}
	stream, ok := c.getStream(streamID)
	if !ok || stream == nil {
		return
	}
	stream.resolverMu.Lock()
	stream.ResolverResendStreak = 0
	stream.resolverMu.Unlock()
}

func (c *Client) shouldTransmitQueuedStreamPacket(stream *Stream_client, item *clientStreamTXPacket) bool {
	if c == nil || stream == nil || item == nil {
		return false
	}

	if item.PacketType != Enums.PACKET_STREAM_DATA && item.PacketType != Enums.PACKET_STREAM_RESEND {
		return true
	}

	arqObj, ok := stream.Stream.(*arq.ARQ)
	if !ok || arqObj == nil {
		return false
	}

	return arqObj.HasPendingSequence(item.SequenceNum)
}

func (c *Client) GetConnectionByKey(key string) (Connection, bool) {
	if c == nil || key == "" {
		return Connection{}, false
	}
	idx, ok := c.connectionsByKey[key]
	if !ok || idx < 0 || idx >= len(c.connections) {
		return Connection{}, false
	}
	return c.connections[idx], true
}
