// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"fmt"
	"net"
	"time"

	"masterdnsvpn-go/internal/arq"
	dnsCache "masterdnsvpn-go/internal/dnscache"
	dnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

type dnsFragmentKey struct {
	SessionID   uint8
	SequenceNum uint16
}

type DNSListener struct {
	client   *Client
	conn     *net.UDPConn
	stopChan chan struct{}
}

func NewDNSListener(c *Client) *DNSListener {
	return &DNSListener{
		client:   c,
		stopChan: make(chan struct{}),
	}
}

func (l *DNSListener) Start(ctx context.Context, ip string, port int) error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	l.conn = conn

	l.client.log.Infof("🚀 <green>DNS server is listening on <cyan>%s:%d</cyan></green>", ip, port)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, peerAddr, err := l.conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-l.stopChan:
					return
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			// Copy data for the handler to prevent overwrite race condition
			dataCopy := make([]byte, n)
			copy(dataCopy, buf[:n])
			go l.handleQuery(ctx, dataCopy, peerAddr)
		}
	}()

	return nil
}

func (l *DNSListener) Stop() {
	close(l.stopChan)
	if l.conn != nil {
		_ = l.conn.Close()
	}
}

// handleQuery manages incoming DNS queries by checking the local cache or redirecting to the tunnel.
func (l *DNSListener) handleQuery(ctx context.Context, data []byte, addr *net.UDPAddr) {
	if l.client == nil {
		return
	}

	l.client.ProcessDNSQuery(data, addr, func(resp []byte) {
		if l.conn != nil {
			_, _ = l.conn.WriteToUDP(resp, addr)
		}
	})
}

// DNS Cache Persistence Methods

func (c *Client) hasPersistableLocalDNSCache() bool {
	return c != nil &&
		c.localDNSCache != nil &&
		c.localDNSCachePersist &&
		c.localDNSCachePath != ""
}

func (c *Client) ensureLocalDNSCacheLoaded() {
	if !c.hasPersistableLocalDNSCache() {
		return
	}

	c.localDNSCacheLoadOnce.Do(func() {
		c.loadLocalDNSCache()
	})
}

func (c *Client) ensureLocalDNSCachePersistence(ctx context.Context) {
	if !c.hasPersistableLocalDNSCache() {
		return
	}

	c.ensureLocalDNSCacheLoaded()
	c.localDNSCacheFlushOnce.Do(func() {
		go c.runLocalDNSCacheFlushLoop(ctx)
	})
}

func (c *Client) loadLocalDNSCache() {
	if !c.hasPersistableLocalDNSCache() {
		return
	}

	loaded, err := c.localDNSCache.LoadFromFile(c.localDNSCachePath, time.Now())
	if err != nil {
		if c.log != nil {
			c.log.Warnf("💾 <yellow>Local DNS Cache <red>Load Failed:</red> %v</yellow>", err)
		}
		return
	}

	if loaded > 0 && c.log != nil {
		c.log.Infof("💾 <green>Local DNS Cache Loaded: <cyan>%d</cyan> records.</green>", loaded)
	}
}

func (c *Client) flushLocalDNSCache() {
	if !c.hasPersistableLocalDNSCache() {
		return
	}

	saved, err := c.localDNSCache.SaveToFile(c.localDNSCachePath, time.Now())
	if err != nil {
		if c.log != nil {
			c.log.Warnf("💾 <yellow>Local DNS Cache <red>Flush Failed:</red> %v</yellow>", err)
		}
		return
	}

	if saved > 0 && c.log != nil {
		c.log.Debugf("💾 <green>Local DNS Cache Flushed: <cyan>%d</cyan> records.</green>", saved)
	}
}

func (c *Client) runLocalDNSCacheFlushLoop(ctx context.Context) {
	if !c.hasPersistableLocalDNSCache() {
		return
	}

	ticker := time.NewTicker(c.localDNSCacheFlushTick)
	defer ticker.Stop()
	defer c.flushLocalDNSCache()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.flushLocalDNSCache()
		}
	}
}

func (c *Client) HandleDNSQueryAck(packet VpnProto.Packet) error {
	c.streamsMu.RLock()
	s0, ok := c.active_streams[0]
	c.streamsMu.RUnlock()

	if ok && s0 != nil {
		if arqObj, ok := s0.Stream.(*arq.ARQ); ok {
			arqObj.ReceiveControlAck(packet.PacketType, packet.SequenceNum, packet.FragmentID)
		}
	}
	return nil
}

func (c *Client) HandleDNSQueryRes(packet VpnProto.Packet) error {
	key := dnsFragmentKey{
		SessionID:   c.sessionID,
		SequenceNum: packet.SequenceNum,
	}

	assembled, ready, _ := c.dnsResponses.Collect(key, packet.Payload, packet.FragmentID, packet.TotalFragments, time.Now(), 10*time.Second)
	if !ready {
		return nil
	}

	if c.localDNSCache != nil {
		lite, err := dnsParser.ParsePacketLite(assembled)
		if err == nil && lite.HasQuestion {
			cacheKey := dnsCache.BuildKey(lite.FirstQuestion.Name, lite.FirstQuestion.Type, lite.FirstQuestion.Class)
			c.localDNSCache.SetReady(cacheKey, lite.FirstQuestion.Name, lite.FirstQuestion.Type, lite.FirstQuestion.Class, assembled, time.Now())
		}
	}

	return nil
}

// ProcessDNSQuery handles a DNS query by checking the local cache or dispatching to the tunnel.
// It only responds on cache hits and uses "fire-and-forget" for misses.
func (c *Client) ProcessDNSQuery(query []byte, addr net.Addr, respond func([]byte)) bool {
	if c == nil || !c.SessionReady() {
		return false
	}

	// 1. Lite Parse DNS Query
	lite, err := dnsParser.ParseDNSRequestLite(query)
	if err != nil || !lite.HasQuestion {
		return false
	}

	question := lite.FirstQuestion
	now := time.Now()

	// 2. Check Local Cache
	if c.localDNSCache != nil {
		key := dnsCache.BuildKey(question.Name, question.Type, question.Class)
		res := c.localDNSCache.LookupOrCreatePending(key, question.Name, question.Type, question.Class, now)

		if res.Status == dnsCache.StatusReady && len(res.Response) > 0 {
			// Cache Hit - Rewrite Transaction ID and send back
			if respond != nil {
				resp := dnsCache.PatchResponseForQuery(res.Response, query)
				respond(resp)
			}
			if c.log != nil {
				c.log.Debugf("🔍 <green>DNS Cache Hit: %s (%d)</green>", question.Name, question.Type)
			}
			return true
		}

		if res.Status == dnsCache.StatusPending && !res.DispatchNeeded {
			// Already pending in tunnel, don't re-dispatch
			if c.log != nil {
				c.log.Debugf("🔍 <yellow>DNS Query Pending: %s (%d)</yellow>", question.Name, question.Type)
			}
			return false
		}
	}

	// 3. Dispatch to Tunnel
	c.dispatchDNSQueryToTunnel(query)
	return false
}

func (c *Client) dispatchDNSQueryToTunnel(query []byte) {
	if !c.SessionReady() {
		return
	}

	c.streamsMu.RLock()
	s0, ok := c.active_streams[0]
	c.streamsMu.RUnlock()

	if !ok || s0 == nil {
		return
	}

	arqObj, ok := s0.Stream.(*arq.ARQ)
	if !ok {
		return
	}

	// Calculate target MTU for fragments
	mtu := c.syncedUploadMTU - VpnProto.MaxHeaderRawSize()
	if mtu < 100 {
		mtu = 120 // Absolute minimum fallback
	}

	fragments := fragmentPayload(query, mtu)
	total := uint8(len(fragments))

	// Generate a unique sequence number for this DNS query
	sn := uint16(c.mtuProbeCounter.Add(1) & 0xFFFF)

	for i, frag := range fragments {
		fragID := uint8(i)

		// Send via ARQ as a control packet
		arqObj.SendControlPacket(Enums.PACKET_DNS_QUERY_REQ, sn, fragID, total, frag, 3, true, nil)
	}
}
