// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (session.go) handles session states and initialization requests.
// ==============================================================================
package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"masterdnsvpn-go/internal/compression"
	Enums "masterdnsvpn-go/internal/enums"
	fragmentStore "masterdnsvpn-go/internal/fragmentstore"
	"masterdnsvpn-go/internal/mlq"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var (
	ErrSessionInitFailed = errors.New("session init failed")
	ErrSessionInitBusy   = errors.New("session init busy: server is at capacity or rejected the request")
)

const (
	sessionInitPayloadSize      = 10
	sessionAcceptPayloadSize    = VpnProto.SessionAcceptPayloadSize
	sessionBusyPayloadSize      = 4
	sessionCloseBurstMaxTargets = 10
	sessionCloseBurstRounds     = 3
)

func (c *Client) InitializeSession(maxAttempts int) error {
	if c.syncedUploadMTU <= 0 || c.syncedDownloadMTU <= 0 {
		return ErrSessionInitFailed
	}

	if maxAttempts < 1 {
		maxAttempts = 1
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := c.initializeSessionRequest(); err == nil {
			return nil
		} else if errors.Is(err, ErrNoValidConnections) || errors.Is(err, ErrSessionInitBusy) {
			return err
		}
	}

	return ErrSessionInitFailed
}

func (c *Client) initializeSessionRequest() error {
	conn, initPayload, verifyCode, err := c.nextSessionInitAttempt()
	if err != nil {
		return err
	}

	c.log.Infof("<green>Session init attempt with <cyan>%s</cyan> and resolver <cyan>%s</cyan>", conn.Domain, conn.Resolver)

	query, err := c.buildSessionQuery(conn.Domain, Enums.PACKET_SESSION_INIT, initPayload)
	if err != nil {
		return ErrSessionInitFailed
	}

	// Intra-Resolver Racing: Send 3 parallel requests to the same selected resolver.
	// We staggered each attempt by 100ms.
	const racingCount = 3
	const staggerDelay = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type result struct {
		err    error
		packet VpnProto.Packet
	}

	resChan := make(chan result, racingCount)

	for i := range racingCount {
		if i > 0 {
			select {
			case <-time.After(staggerDelay):
			case <-ctx.Done():
				goto waitPhase
			}
		}

		go func() {
			packet, err := c.exchangeDNSOverConnection(conn, query, c.mtuTestTimeout*3)
			select {
			case resChan <- result{err: err, packet: packet}:
			case <-ctx.Done():
			}
		}()
	}

waitPhase:
	var lastErr error
	responsesReceived := 0
	for {
		select {
		case res := <-resChan:
			responsesReceived++
			if res.err == nil {
				if err := c.applySessionInitPacket(res.packet, initPayload, verifyCode); err == nil {
					cancel()
					return nil
				} else if errors.Is(err, ErrSessionInitBusy) {
					cancel()
					return err
				}
				lastErr = res.err
			} else {
				lastErr = res.err
			}

			if responsesReceived >= racingCount {
				if lastErr == nil {
					return ErrSessionInitFailed
				}
				return lastErr
			}
		case <-time.After(30 * time.Second): // Hard safety timeout
			return ErrSessionInitFailed
		}
	}
}

func (c *Client) applySessionInitPacket(packet VpnProto.Packet, initPayload []byte, verifyCode [4]byte) error {
	if c.SessionReady() {
		return nil
	}

	switch packet.PacketType {
	case Enums.PACKET_SESSION_BUSY:
		if len(packet.Payload) < sessionBusyPayloadSize || !bytes.Equal(packet.Payload[:sessionBusyPayloadSize], verifyCode[:]) {
			return ErrSessionInitFailed
		}
		c.setSessionInitBusyUntil(time.Now().Add(c.cfg.SessionInitBusyRetryInterval()))
		return ErrSessionInitBusy
	case Enums.PACKET_SESSION_ACCEPT:
		sessionAccept, err := VpnProto.DecodeSessionAcceptPayload(packet.Payload)
		if err != nil || !bytes.Equal(sessionAccept.VerifyCode[:], verifyCode[:]) {
			return ErrSessionInitFailed
		}

		c.initStateMu.Lock()
		defer c.initStateMu.Unlock()

		if c.sessionReady {
			return nil
		}

		c.sessionID = sessionAccept.SessionID
		c.sessionCookie = sessionAccept.SessionCookie
		c.responseMode = initPayload[0]
		c.uploadCompression, c.downloadCompression = compression.SplitPair(sessionAccept.CompressionPair)
		if sessionAccept.HasClientPolicySync {
			c.applySessionClientPolicy(sessionAccept.ClientPolicy)
		}
		c.sessionReady = true
		c.applySessionCompressionPolicy()
		c.clearSessionInitBusyUntil()
		c.resetSessionInitStateLocked()
		c.clearSessionResetPending()
		return nil
	default:
		return ErrSessionInitFailed
	}
}

func (c *Client) applySessionClientPolicy(policy VpnProto.SessionAcceptClientPolicy) {
	if c == nil {
		return
	}

	before := VpnProto.SessionAcceptClientSettings{
		PacketDuplicationCount:      c.cfg.PacketDuplicationCount,
		SetupPacketDuplicationCount: c.cfg.SetupPacketDuplicationCount,
		MaxUploadMTU:                c.cfg.MaxUploadMTU,
		MaxDownloadMTU:              c.cfg.MaxDownloadMTU,
		RXTXWorkers:                 c.cfg.RX_TX_Workers,
		PingAggressiveInterval:      c.cfg.PingAggressiveIntervalSeconds,
		MaxPacketsPerBatch:          c.cfg.MaxPacketsPerBatch,
		ARQWindowSize:               c.cfg.ARQWindowSize,
		ARQDataNackMaxGap:           c.cfg.ARQDataNackMaxGap,
		CompressionMinSize:          c.cfg.CompressionMinSize,
		ARQInitialRTOSeconds:        c.cfg.ARQInitialRTOSeconds,
		ARQControlInitialRTOSeconds: c.cfg.ARQControlInitialRTOSeconds,
		ARQMaxRTOSeconds:            c.cfg.ARQMaxRTOSeconds,
		ARQControlMaxRTOSeconds:     c.cfg.ARQControlMaxRTOSeconds,
	}

	settings := VpnProto.ApplySessionAcceptClientPolicy(VpnProto.SessionAcceptClientSettings{
		PacketDuplicationCount:      before.PacketDuplicationCount,
		SetupPacketDuplicationCount: before.SetupPacketDuplicationCount,
		MaxUploadMTU:                before.MaxUploadMTU,
		MaxDownloadMTU:              before.MaxDownloadMTU,
		RXTXWorkers:                 before.RXTXWorkers,
		PingAggressiveInterval:      before.PingAggressiveInterval,
		MaxPacketsPerBatch:          before.MaxPacketsPerBatch,
		ARQWindowSize:               before.ARQWindowSize,
		ARQDataNackMaxGap:           before.ARQDataNackMaxGap,
		CompressionMinSize:          before.CompressionMinSize,
		ARQInitialRTOSeconds:        before.ARQInitialRTOSeconds,
		ARQControlInitialRTOSeconds: before.ARQControlInitialRTOSeconds,
		ARQMaxRTOSeconds:            before.ARQMaxRTOSeconds,
		ARQControlMaxRTOSeconds:     before.ARQControlMaxRTOSeconds,
	}, policy)

	c.cfg.PacketDuplicationCount = settings.PacketDuplicationCount
	c.cfg.SetupPacketDuplicationCount = settings.SetupPacketDuplicationCount
	c.cfg.MaxUploadMTU = settings.MaxUploadMTU
	c.cfg.MaxDownloadMTU = settings.MaxDownloadMTU
	c.cfg.RX_TX_Workers = settings.RXTXWorkers
	c.tunnelRX_TX_Workers = settings.RXTXWorkers
	c.cfg.PingAggressiveIntervalSeconds = settings.PingAggressiveInterval
	c.cfg.MaxPacketsPerBatch = settings.MaxPacketsPerBatch
	c.cfg.ARQWindowSize = settings.ARQWindowSize
	c.cfg.ARQDataNackMaxGap = settings.ARQDataNackMaxGap
	c.cfg.CompressionMinSize = settings.CompressionMinSize
	c.cfg.ARQInitialRTOSeconds = settings.ARQInitialRTOSeconds
	c.cfg.ARQControlInitialRTOSeconds = settings.ARQControlInitialRTOSeconds
	c.cfg.TunnelProcessWorkers = deriveSessionPolicyTunnelProcessWorkers(c.cfg.TunnelProcessWorkers, c.cfg.RX_TX_Workers)
	c.tunnelProcessWorkers = c.cfg.TunnelProcessWorkers

	c.syncSessionPolicyDerivedState()

	c.logSessionClientPolicyChanges(before, settings, policy)
}

func (c *Client) syncSessionPolicyDerivedState() {
	if c == nil {
		return
	}

	if c.syncedUploadMTU > 0 {
		c.syncedUploadMTU = min(c.syncedUploadMTU, c.cfg.MaxUploadMTU)
		c.syncedUploadChars = c.encodedCharsForPayload(c.syncedUploadMTU)
		c.safeUploadMTU = computeSafeUploadMTU(c.syncedUploadMTU, c.mtuCryptoOverhead)
		c.maxPackedBlocks = VpnProto.CalculateMaxPackedBlocks(c.syncedUploadMTU, 80, c.cfg.MaxPacketsPerBatch)
	} else {
		c.syncedUploadChars = 0
		c.safeUploadMTU = 0
		c.maxPackedBlocks = 1
	}

	if c.syncedDownloadMTU > 0 {
		c.syncedDownloadMTU = min(c.syncedDownloadMTU, c.cfg.MaxDownloadMTU)
	}

	if c.balancer != nil {
		c.balancer.SetSessionSynchronizedMTU(c.syncedUploadMTU, c.syncedDownloadMTU)
	}

	c.closeResolverConnPools()

	if c.asyncCancel != nil {
		return
	}

	c.plannerQueue = make(chan plannerTask, max(24, c.cfg.RX_TX_Workers*24))
	c.encodedTXChannel = make(chan writerTask, max(24, c.cfg.RX_TX_Workers*24))
	c.rxChannel = make(chan asyncReadPacket, c.cfg.EffectiveRXChannelSize())
	c.orphanQueue = mlq.New[VpnProto.Packet](c.cfg.EffectiveOrphanQueueInitialCapacity())
	c.dnsResponses = fragmentStore.New[dnsFragmentKey](c.cfg.EffectiveDNSResponseFragmentStoreCap())
}

func deriveSessionPolicyTunnelProcessWorkers(current int, rxWorkers int) int {
	if rxWorkers < 1 {
		rxWorkers = 1
	}

	recommended := max(4, rxWorkers+1)
	if recommended > 256 {
		recommended = 256
	}

	if current < recommended {
		current = recommended
	}

	if current < rxWorkers {
		return rxWorkers
	}

	if current > 256 {
		return 256
	}
	return current
}

func (c *Client) logSessionClientPolicyChanges(before VpnProto.SessionAcceptClientSettings, after VpnProto.SessionAcceptClientSettings, policy VpnProto.SessionAcceptClientPolicy) {
	if c == nil || c.log == nil {
		return
	}

	logInt := func(label string, oldValue int, newValue int, accepted string) {
		if oldValue == newValue {
			return
		}
		c.log.Warnf(
			"<yellow>Session policy adjusted %s because this server does not accept the requested value</yellow> <magenta>|</magenta> <blue>Requested</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Effective</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Server Rule</blue>: <cyan>%s</cyan>",
			label,
			oldValue,
			newValue,
			accepted,
		)
	}

	logFloat := func(label string, oldValue float64, newValue float64, accepted string) {
		if oldValue == newValue {
			return
		}
		c.log.Warnf(
			"<yellow>Session policy adjusted %s because this server does not accept the requested value</yellow> <magenta>|</magenta> <blue>Requested</blue>: <cyan>%.3f</cyan> <magenta>|</magenta> <blue>Effective</blue>: <cyan>%.3f</cyan> <magenta>|</magenta> <blue>Server Rule</blue>: <cyan>%s</cyan>",
			label,
			oldValue,
			newValue,
			accepted,
		)
	}

	logInt("PACKET_DUPLICATION_COUNT", before.PacketDuplicationCount, after.PacketDuplicationCount, "max="+itoaSafe(policy.MaxPacketDuplicationCount))
	logInt("SETUP_PACKET_DUPLICATION_COUNT", before.SetupPacketDuplicationCount, after.SetupPacketDuplicationCount, "max="+itoaSafe(policy.MaxSetupDuplicationCount))
	logInt("MAX_UPLOAD_MTU", before.MaxUploadMTU, after.MaxUploadMTU, "max="+itoaSafe(policy.MaxUploadMTU))
	logInt("MAX_DOWNLOAD_MTU", before.MaxDownloadMTU, after.MaxDownloadMTU, "max="+itoaSafe(policy.MaxDownloadMTU))
	logInt("RX_TX_WORKERS", before.RXTXWorkers, after.RXTXWorkers, "max="+itoaSafe(policy.MaxRxTxWorkers))
	logFloat("PING_AGGRESSIVE_INTERVAL_SECONDS", before.PingAggressiveInterval, after.PingAggressiveInterval, "min="+formatPolicyFloat(policy.MinPingAggressiveInterval))
	logInt("MAX_PACKETS_PER_BATCH", before.MaxPacketsPerBatch, after.MaxPacketsPerBatch, "max="+itoaSafe(policy.MaxPacketsPerBatch))
	logInt("ARQ_WINDOW_SIZE", before.ARQWindowSize, after.ARQWindowSize, "max="+itoaSafe(policy.MaxARQWindowSize))
	logInt("ARQ_DATA_NACK_MAX_GAP", before.ARQDataNackMaxGap, after.ARQDataNackMaxGap, "max="+itoaSafe(policy.MaxARQDataNackMaxGap))
	logInt("COMPRESSION_MIN_SIZE", before.CompressionMinSize, after.CompressionMinSize, "min="+itoaSafe(policy.MinCompressionMinSize))
	logFloat("ARQ_INITIAL_RTO_SECONDS", before.ARQInitialRTOSeconds, after.ARQInitialRTOSeconds, "min="+formatPolicyFloat(policy.MinARQInitialRTOSeconds))
	logFloat("ARQ_CONTROL_INITIAL_RTO_SECONDS", before.ARQControlInitialRTOSeconds, after.ARQControlInitialRTOSeconds, "min="+formatPolicyFloat(policy.MinARQInitialRTOSeconds))
}

func itoaSafe(value int) string {
	return fmt.Sprintf("%d", value)
}

func formatPolicyFloat(value float64) string {
	return fmt.Sprintf("%.3f", value)
}

func (c *Client) buildSessionInitPayload() ([]byte, bool, [4]byte, error) {
	var verifyCode [4]byte
	randomPart, err := randomBytes(len(verifyCode))
	if err != nil {
		return nil, false, verifyCode, err
	}
	copy(verifyCode[:], randomPart)

	payload := make([]byte, sessionInitPayloadSize)
	if c.cfg.BaseEncodeData {
		payload[0] = mtuProbeBase64Reply
	}
	payload[1] = compression.PackPair(c.uploadCompression, c.downloadCompression)
	binary.BigEndian.PutUint16(payload[2:4], uint16(c.syncedUploadMTU))
	binary.BigEndian.PutUint16(payload[4:6], uint16(c.syncedDownloadMTU))
	copy(payload[6:10], verifyCode[:])
	return payload, payload[0] == mtuProbeBase64Reply, verifyCode, nil
}

func (c *Client) nextSessionInitAttempt() (Connection, []byte, [4]byte, error) {
	var empty [4]byte
	if c == nil {
		return Connection{}, nil, empty, ErrSessionInitFailed
	}

	c.initStateMu.Lock()
	defer c.initStateMu.Unlock()

	// Persistence Check: reuse existing token/payload if already ready
	if !c.sessionInitReady {
		payload, responseBase64, verifyCode, err := c.buildSessionInitPayload()
		if err != nil {
			return Connection{}, nil, empty, err
		}
		c.sessionInitPayload = payload
		c.sessionInitBase64 = responseBase64
		c.sessionInitVerify = verifyCode
		c.sessionInitReady = true
		c.sessionInitCursor = 0
	}

	active := c.balancer.ActiveConnections()
	if len(active) == 0 {
		return Connection{}, nil, empty, ErrNoValidConnections
	}

	// Use the cursor to rotate between valid resolvers in a Round-Robin fashion.
	validLen := len(active)
	start := c.sessionInitCursor
	for checked := 0; checked < validLen; checked++ {
		idxInValid := (start + checked) % validLen
		conn := active[idxInValid]
		if !conn.IsValid || conn.Key == "" {
			continue
		}

		c.sessionInitCursor = (idxInValid + 1) % validLen
		return conn, c.sessionInitPayload, c.sessionInitVerify, nil
	}

	return Connection{}, nil, empty, ErrNoValidConnections
}

func (c *Client) resetSessionInitState() {
	if c == nil {
		return
	}
	c.initStateMu.Lock()
	c.resetSessionInitStateLocked()
	c.initStateMu.Unlock()
}

func (c *Client) resetSessionInitStateLocked() {
	c.sessionInitPayload = nil
	c.sessionInitVerify = [4]byte{}
	c.sessionInitBase64 = false
	c.sessionInitReady = false
	c.sessionInitCursor = 0
}

func (c *Client) setSessionInitBusyUntil(deadline time.Time) {
	if c == nil {
		return
	}
	c.sessionInitBusyUnix.Store(deadline.UnixNano())
}

func (c *Client) clearSessionInitBusyUntil() {
	if c == nil {
		return
	}
	c.sessionInitBusyUnix.Store(0)
}

func (c *Client) sessionInitBusyUntil() time.Time {
	if c == nil {
		return time.Time{}
	}
	unixNano := c.sessionInitBusyUnix.Load()
	if unixNano <= 0 {
		return time.Time{}
	}
	return time.Unix(0, unixNano)
}

func (c *Client) buildSessionQuery(domain string, packetType uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelQuery(domain, 0, packetType, payload)
}

func (c *Client) buildTunnelQuery(domain string, sessionID uint8, packetType uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelTXTQueryRaw(domain, VpnProto.BuildOptions{
		SessionID:  sessionID,
		PacketType: packetType,
		Payload:    payload,
	})
}

func (c *Client) clearSessionResetPending() {
	if c != nil {
		c.sessionResetPending.Store(false)
	}
}

func (c *Client) notifySessionCloseBurst(timeout time.Duration) {
	if c == nil || !c.SessionReady() || c.sessionID == 0 {
		return
	}
	if !c.sessionResetPending.CompareAndSwap(false, true) {
		return
	}

	targets := c.selectSessionCloseTargets(sessionCloseBurstMaxTargets)
	if len(targets) == 0 {
		c.sessionResetPending.Store(false)
		return
	}

	timeout = normalizeTimeout(timeout, time.Second)
	deadline := time.Now().Add(timeout)

	rounds := sessionCloseBurstRounds
	if rounds < 1 {
		rounds = 1
	}
	interval := timeout / time.Duration(rounds)
	if interval <= 0 {
		interval = timeout
	}

	for round := 0; round < rounds; round++ {
		c.sendSessionCloseRound(targets, deadline)
		if round == rounds-1 {
			break
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		sleepFor := interval
		if sleepFor > remaining {
			sleepFor = remaining
		}
		time.Sleep(sleepFor)
	}

	if c.log != nil {
		c.log.Debugf(
			"\U0001F6AA <yellow>Client Session Close Burst Sent</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Targets</blue>: <cyan>%d</cyan>",
			c.sessionID,
			len(targets),
		)
	}
}

func (c *Client) selectSessionCloseTargets(maxTargets int) []Connection {
	if c == nil {
		return nil
	}

	if maxTargets < 1 {
		maxTargets = 1
	}

	targets := c.balancer.GetUniqueConnections(maxTargets)
	if len(targets) > 0 {
		return targets
	}

	if best, ok := c.balancer.GetBestConnection(); ok {
		return []Connection{best}
	}
	return nil
}

func (c *Client) sendSessionCloseRound(targets []Connection, deadline time.Time) {
	if c == nil || len(targets) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, conn := range targets {
		conn := conn
		wg.Add(1)
		go func() {
			defer wg.Done()
			query, err := c.buildTunnelTXTQueryRaw(conn.Domain, VpnProto.BuildOptions{
				SessionID:     c.sessionID,
				SessionCookie: c.sessionCookie,
				PacketType:    Enums.PACKET_SESSION_CLOSE,
			})
			if err != nil {
				return
			}
			c.sendOneWayDNSQuery(conn, query, deadline)
		}()
	}
	wg.Wait()
}

// applySyncedMTUState updates the client's internal MTU state after successful probing.
func (c *Client) applySyncedMTUState(uploadMTU int, downloadMTU int, uploadChars int) {
	if c == nil {
		return
	}
	c.syncedUploadMTU = uploadMTU
	c.syncedDownloadMTU = downloadMTU
	c.syncedUploadChars = uploadChars
	c.safeUploadMTU = computeSafeUploadMTU(uploadMTU, c.mtuCryptoOverhead)
	c.maxPackedBlocks = VpnProto.CalculateMaxPackedBlocks(uploadMTU, 80, c.cfg.MaxPacketsPerBatch)
	c.applySessionCompressionPolicy()
	if c.balancer != nil {
		c.balancer.SetSessionSynchronizedMTU(uploadMTU, downloadMTU)
	}
	if c.log != nil && c.successMTUChecks {
		c.log.Infof("\U0001F4CF <green>MTU state applied: UP=%d, DOWN=%d</green>", uploadMTU, downloadMTU)
	}
}

func (c *Client) applySessionCompressionPolicy() {
	if c == nil {
		return
	}

	minSize := c.cfg.CompressionMinSize
	if minSize <= 0 {
		minSize = compression.DefaultMinSize
	}

	uploadCompression := compression.NormalizeAvailableType(c.uploadCompression)
	downloadCompression := compression.NormalizeAvailableType(c.downloadCompression)

	const mtuWarningThreshold = 100

	if c.syncedUploadMTU > 0 && c.syncedUploadMTU < mtuWarningThreshold {
		if uploadCompression != compression.TypeOff && c.log != nil {
			c.log.Warnf(
				"⚠️ <red>Session Compression Upload: <cyan>%s</cyan> (Disabled due to low MTU: <cyan>%d</cyan>)</red>",
				compression.TypeName(uploadCompression),
				c.syncedUploadMTU,
			)
		}
		uploadCompression = compression.TypeOff
		c.cfg.UploadCompressionType = int(compression.TypeOff)
	} else if c.syncedUploadMTU > 0 && c.syncedUploadMTU <= minSize {
		if uploadCompression != compression.TypeOff && c.log != nil {
			c.log.Infof(
				"\U0001F5DC <green>Session Compression Upload: <cyan>%s</cyan> (Disabled due to MinSize MTU: <cyan>%d</cyan>)</green>",
				compression.TypeName(uploadCompression),
				c.syncedUploadMTU,
			)
		}
		uploadCompression = compression.TypeOff
	}

	if c.syncedDownloadMTU > 0 && c.syncedDownloadMTU < mtuWarningThreshold {
		if downloadCompression != compression.TypeOff && c.log != nil {
			c.log.Warnf(
				"⚠️ <red>Session Compression Download: <cyan>%s</cyan> (Disabled due to low MTU: <cyan>%d</cyan>)</red>",
				compression.TypeName(downloadCompression),
				c.syncedDownloadMTU,
			)
		}
		downloadCompression = compression.TypeOff
		c.cfg.DownloadCompressionType = int(compression.TypeOff)
	} else if c.syncedDownloadMTU > 0 && c.syncedDownloadMTU <= minSize {
		if downloadCompression != compression.TypeOff && c.log != nil {
			c.log.Infof(
				"\U0001F5DC <green>Session Compression Download: <cyan>%s</cyan> (Disabled due to MinSize MTU: <cyan>%d</cyan>)</green>",
				compression.TypeName(downloadCompression),
				c.syncedDownloadMTU,
			)
		}
		downloadCompression = compression.TypeOff
	}

	c.uploadCompression = uploadCompression
	c.downloadCompression = downloadCompression

	if c.log != nil {
		c.log.Infof(
			"\U0001F9E9 <green>Effective Compression Upload: <cyan>%s</cyan> Download: <cyan>%s</cyan></green>",
			compression.TypeName(c.uploadCompression),
			compression.TypeName(c.downloadCompression),
		)
	}
}
