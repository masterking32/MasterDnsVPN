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
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"masterdnsvpn-go/internal/compression"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var (
	ErrSessionInitFailed = errors.New("session init failed")
	ErrSessionInitBusy   = errors.New("session init busy")
)

const (
	sessionInitPayloadSize      = 10
	sessionAcceptPayloadSize    = 7
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
		if err := c.initializeSessionOnce(); err == nil {
			return nil
		} else if errors.Is(err, ErrNoValidConnections) || errors.Is(err, ErrSessionInitBusy) {
			return err
		}
	}

	if c.log != nil {
		c.log.Debugf("⚠️ <yellow>Session init failed after <cyan>%d</cyan> attempts</yellow>", maxAttempts)
	}
	return ErrSessionInitFailed
}

func (c *Client) initializeSessionOnce() error {
	conn, initPayload, verifyCode, err := c.nextSessionInitAttempt()
	if err != nil {
		return err
	}

	query, err := c.buildSessionQuery(conn.Domain, Enums.PACKET_SESSION_INIT, initPayload)
	if err != nil {
		if c.log != nil {
			c.log.Debugf("⚠️ <yellow>Session init query build failed: <cyan>%v</cyan></yellow>", err)
		}
		return ErrSessionInitFailed
	}

	packet, err := c.exchangeDNSOverConnection(conn, query, c.mtuTestTimeout)
	if err != nil {
		if c.log != nil {
			c.log.Debugf("🔄 <yellow>Session init DNS exchange failed: <cyan>%v</cyan></yellow>", err)
		}
		return ErrSessionInitFailed
	}

	switch packet.PacketType {
	case Enums.PACKET_SESSION_BUSY:
		if len(packet.Payload) < sessionBusyPayloadSize || !bytes.Equal(packet.Payload[:sessionBusyPayloadSize], verifyCode[:]) {
			return ErrSessionInitFailed
		}
		busyRetry := c.cfg.SessionInitBusyRetryInterval()
		c.setSessionInitBusyUntil(time.Now().Add(busyRetry))
		if c.log != nil {
			c.log.Debugf("⚠️ <yellow>Server busy, retry after <cyan>%s</cyan></yellow>", busyRetry)
		}
		return ErrSessionInitBusy
	case Enums.PACKET_SESSION_ACCEPT:
		if len(packet.Payload) < sessionAcceptPayloadSize || !bytes.Equal(packet.Payload[3:7], verifyCode[:]) {
			return ErrSessionInitFailed
		}

		c.sessionID = packet.Payload[0]
		c.sessionCookie = packet.Payload[1]
		c.responseMode = initPayload[0]
		c.uploadCompression, c.downloadCompression = compression.SplitPair(packet.Payload[2])
		c.sessionReady = true
		c.applySessionCompressionPolicy()
		c.clearSessionInitBusyUntil()
		c.resetSessionInitState()
		c.clearSessionResetPending()
		if c.log != nil {
			c.log.Debugf(
				"✅ <green>Session Accepted <magenta>|</magenta> ID: <cyan>%d</cyan> <magenta>|</magenta> Cookie: <cyan>%d</cyan> <magenta>|</magenta> Upload: <cyan>%s</cyan> <magenta>|</magenta> Download: <cyan>%s</cyan></green>",
				c.sessionID, c.sessionCookie,
				compression.TypeName(c.uploadCompression),
				compression.TypeName(c.downloadCompression),
			)
		}
		return nil
	default:
		return ErrSessionInitFailed
	}
}

func (c *Client) buildSessionInitPayload() ([]byte, bool, [4]byte, error) {
	var verifyCode [4]byte
	randomPart, err := randomBytes(len(verifyCode))
	if err != nil {
		return nil, false, verifyCode, err
	}
	copy(verifyCode[:], randomPart)

	// Use pool for temporary buffer to avoid allocation
	buf := c.udpBufferPool.Get().([]byte)
	defer c.udpBufferPool.Put(buf)

	if sessionInitPayloadSize > len(buf) {
		return nil, false, verifyCode, errors.New("buffer pool slice too small")
	}

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

	snap := c.balancer.snapshot.Load()
	if snap == nil || len(snap.valid) == 0 {
		return Connection{}, nil, empty, ErrNoValidConnections
	}

	// Use the cursor to rotate between valid resolvers in a Round-Robin fashion
	validLen := len(snap.valid)
	start := c.sessionInitCursor
	for checked := 0; checked < validLen; checked++ {
		idxInValid := (start + checked) % validLen
		connIdx := snap.valid[idxInValid]

		if connIdx < 0 || connIdx >= len(c.connections) {
			continue
		}

		conn := c.connections[connIdx]
		if !conn.IsValid {
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
	c.sessionInitPayload = nil
	c.sessionInitVerify = [4]byte{}
	c.sessionInitBase64 = false
	c.sessionInitReady = false
	c.sessionInitCursor = 0
	c.initStateMu.Unlock()
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
				if c.log != nil {
					c.log.Debugf("⚠️ <yellow>Session close query build failed: <cyan>%v</cyan></yellow>", err)
				}
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
