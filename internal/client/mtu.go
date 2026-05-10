// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (mtu.go) handles MTU discovery and probing.
// ==============================================================================
package client

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var ErrNoValidConnections = errors.New("no valid connections after mtu testing")

const (
	mtuProbeCodeLength  = 4
	mtuProbeRawResponse = 0
	mtuProbeBase64Reply = 1
	defaultUploadMaxCap = 512
	minUploadMTUFloor   = 10
	minDownloadMTUFloor = VpnProto.SessionAcceptPayloadSize
)

var (
	maxUploadProbePacketType = VpnProto.MaxHeaderPacketType()
	mtuDownResponseReserve   = func() int {
		reserve := VpnProto.MaxHeaderRawSize() - VpnProto.HeaderRawSize(Enums.PACKET_MTU_DOWN_RES)
		if reserve < 0 {
			return 0
		}
		return reserve
	}()
)

type mtuRejectReason uint8

const (
	mtuRejectNone mtuRejectReason = iota
	mtuRejectUpload
	mtuRejectDownload
)

type mtuProbeOptions struct {
	IsRetry bool
	Quiet   bool
}

type mtuConnectionProbeResult struct {
	UploadBytes   int
	UploadChars   int
	DownloadBytes int
	ResolveTime   time.Duration
}

type mtuScanCounters struct {
	completed      atomic.Int32
	valid          atomic.Int32
	rejectUpload   atomic.Int32
	rejectDownload atomic.Int32
}

type mtuDecision struct {
	active        bool
	reason        mtuRejectReason
	rejectValue   int
	uploadBytes   int
	uploadChars   int
	downloadBytes int
	resolveTime   time.Duration
}

func (c *Client) RunInitialMTUTests(ctx context.Context) error {
	if c.balancer == nil {
		return ErrNoValidConnections
	}

	scanConnections := c.balancer.AllConnections()
	if len(scanConnections) == 0 {
		return ErrNoValidConnections
	}

	uploadCaps := c.precomputeUploadCaps()
	workerCount := min(max(1, c.cfg.EffectiveMTUTestParallelism()), len(scanConnections))
	c.logMTUStart(workerCount)
	c.prepareMTUSuccessOutputFile()

	counters := &mtuScanCounters{}
	if workerCount <= 1 {
		for idx := range scanConnections {
			if err := ctx.Err(); err != nil {
				return nil
			}
			conn := scanConnections[idx]
			c.runConnectionMTUTest(ctx, conn, idx+1, len(scanConnections), uploadCaps[conn.Domain], counters)
		}
	} else {
		jobs := make(chan int, len(scanConnections))
		var wg sync.WaitGroup
		for range workerCount {
			wg.Go(func() {
				for idx := range jobs {
					if err := ctx.Err(); err != nil {
						return
					}
					conn := scanConnections[idx]
					c.runConnectionMTUTest(ctx, conn, idx+1, len(scanConnections), uploadCaps[conn.Domain], counters)
				}
			})
		}

		for idx := range scanConnections {
			select {
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				return nil
			case jobs <- idx:
			}
		}
		close(jobs)
		wg.Wait()
	}

	activeConns := c.balancer.ActiveConnections()
	validConns, minUpload, minDownload, minUploadChars := summarizeValidMTUConnections(activeConns)
	if len(validConns) == 0 {
		if c.log != nil {
			c.log.Errorf("<red>No valid connections found after MTU testing!</red>")
		}
		return ErrNoValidConnections
	}

	c.applySyncedMTUState(minUpload, minDownload, minUploadChars)
	c.appendMTUUsageSeparatorOnce()
	c.logMTUCompletion(validConns)
	return nil
}

func (c *Client) runResolverHealthLoop(ctx context.Context) {
	if c == nil || c.balancer == nil {
		return
	}

	recheckInterval := c.resolverHealthRecheckInterval()
	parallelism := c.resolverHealthParallelism()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		c.balancer.CollectExpiredResolverTimeouts(
			c.now(),
			c.tunnelPacketTimeout,
		)

		if c.cfg.RecheckInactiveServersEnabled {
			c.runResolverHealthBatch(ctx, recheckInterval, parallelism)
		}

		timer := time.NewTimer(c.resolverHealthPollInterval(recheckInterval))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (c *Client) resolverHealthRecheckInterval() time.Duration {
	active, inactive, _ := c.resolverHealthCounts()
	return resolverHealthPerResolverInterval(active, inactive)
}

func (c *Client) resolverHealthPollInterval(recheckInterval time.Duration) time.Duration {
	if c == nil || c.balancer == nil {
		pollInterval := recheckInterval / 4
		if pollInterval < time.Second {
			return time.Second
		}
		if pollInterval > 5*time.Second {
			return 5 * time.Second
		}
		return pollInterval
	}
	window := time.Duration(c.cfg.AutoDisableTimeoutWindowSeconds * float64(time.Second))
	active := c.balancer.ActiveCount()
	if active < 1 {
		active = 1
	}
	return autoDisableCheckIntervalForActiveCount(active, window)
}

func (c *Client) resolverHealthParallelism() int {
	active, inactive, _ := c.resolverHealthCounts()
	return resolverHealthBatchSize(active, inactive)
}

func (c *Client) resolverHealthCounts() (active int, inactive int, total int) {
	if c == nil || c.balancer == nil {
		return 0, 0, 0
	}
	active = c.balancer.ActiveCount()
	total = c.balancer.TotalCount()
	if total < active {
		total = active
	}
	inactive = total - active
	return active, inactive, total
}

func resolverHealthPerResolverInterval(active int, inactive int) time.Duration {
	if inactive <= 0 {
		return 12 * time.Second
	}

	interval := 6 * time.Second
	switch {
	case inactive <= 3:
		interval = 12 * time.Second
	case inactive <= 6:
		interval = 10 * time.Second
	case inactive <= 12:
		interval = 8 * time.Second
	case inactive <= 24:
		interval = 6 * time.Second
	case inactive <= 48:
		interval = 5 * time.Second
	case inactive <= 96:
		interval = 4 * time.Second
	default:
		interval = 3 * time.Second
	}

	switch {
	case active <= 3:
		if interval < 12*time.Second {
			interval = 12 * time.Second
		}
	case active <= 5:
		if interval < 10*time.Second {
			interval = 10 * time.Second
		}
	case active <= 10:
		if interval < 8*time.Second {
			interval = 8 * time.Second
		}
	case active >= 100 && inactive >= 40:
		if interval > 2*time.Second {
			interval = 2 * time.Second
		}
	case active >= 50 && inactive >= 20:
		if interval > 3*time.Second {
			interval = 3 * time.Second
		}
	}

	if interval < 2*time.Second {
		interval = 2 * time.Second
	}
	if interval > 12*time.Second {
		interval = 12 * time.Second
	}
	return interval
}

func resolverHealthBatchSize(active int, inactive int) int {
	if inactive <= 0 {
		return 1
	}

	batch := 2
	switch {
	case inactive <= 2:
		batch = 1
	case inactive <= 5:
		batch = 2
	case inactive <= 10:
		batch = 3
	case inactive <= 20:
		batch = 4
	case inactive <= 40:
		batch = 6
	case inactive <= 80:
		batch = 8
	case inactive <= 120:
		batch = 10
	case inactive <= 200:
		batch = 12
	default:
		batch = 14
	}

	switch {
	case active <= 3:
		if batch > 2 {
			batch = 2
		}
	case active <= 5:
		if batch > 3 {
			batch = 3
		}
	case active <= 10:
		if batch > 4 {
			batch = 4
		}
	case active >= 100 && inactive >= 40:
		batch += 2
	case active >= 50 && inactive >= 20:
		batch++
	}

	if active >= 20 && inactive > 0 && inactive*4 < active && batch > 2 {
		batch--
	}

	if batch < 1 {
		batch = 1
	}
	if batch > 16 {
		batch = 16
	}
	if batch > inactive {
		batch = inactive
	}
	if batch < 1 {
		batch = 1
	}
	return batch
}

func (c *Client) runResolverHealthBatch(ctx context.Context, recheckInterval time.Duration, parallelism int) {
	connections := c.collectInactiveResolverHealthChecks(recheckInterval, parallelism)
	if len(connections) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, conn := range connections {
		wg.Add(1)
		go func(conn Connection) {
			defer wg.Done()
			c.recheckInactiveResolver(ctx, conn)
		}(conn)
	}
	wg.Wait()
}

func (c *Client) collectInactiveResolverHealthChecks(recheckInterval time.Duration, parallelism int) []Connection {
	connections := make([]Connection, 0, parallelism)
	now := c.now()
	for len(connections) < parallelism {
		conn, ok := c.balancer.NextInactiveConnectionForHealthCheck(now, recheckInterval)
		if !ok || conn.Key == "" || conn.IsValid {
			break
		}
		connections = append(connections, conn)
	}
	return connections
}

func (c *Client) recheckInactiveResolver(ctx context.Context, conn Connection) {
	if c == nil || c.balancer == nil || conn.Key == "" {
		return
	}

	transport, err := newUDPQueryTransport(conn.ResolverLabel)
	if err != nil {
		return
	}
	defer transport.conn.Close()

	if !c.recheckResolverUploadMTU(ctx, conn, transport) {
		return
	}
	if !c.recheckResolverDownloadMTU(ctx, conn, transport) {
		return
	}

	conn.UploadMTUBytes = c.syncedUploadMTU
	conn.UploadMTUChars = c.encodedCharsForPayload(c.syncedUploadMTU)
	conn.DownloadMTUBytes = c.syncedDownloadMTU

	if !c.balancer.SetConnectionMTU(
		conn.Key,
		conn.UploadMTUBytes,
		conn.UploadMTUChars,
		conn.DownloadMTUBytes,
	) {
		return
	}

	if !c.balancer.SetConnectionValidityWithLog(conn.Key, true, true) {
		return
	}

	c.balancer.SeedConservativeStats(conn.Key)

	conn.IsValid = true

	c.appendMTUReactiveAddedServerLine(&conn)
}

func (c *Client) recheckResolverUploadMTU(ctx context.Context, conn Connection, transport *udpQueryTransport) bool {
	timeout := c.resolverHealthProbeTimeout()
	for attempt := 0; attempt < c.mtuTestRetries; attempt++ {
		if ctx.Err() != nil {
			return false
		}
		passed, _, err := c.sendUploadMTUProbe(ctx, conn, transport, c.syncedUploadMTU, timeout, mtuProbeOptions{
			Quiet:   true,
			IsRetry: attempt > 0,
		})
		if err == nil && passed {
			return true
		}
	}
	return false
}

func (c *Client) recheckResolverDownloadMTU(ctx context.Context, conn Connection, transport *udpQueryTransport) bool {
	timeout := c.resolverHealthProbeTimeout()
	for attempt := 0; attempt < c.mtuTestRetries; attempt++ {
		if ctx.Err() != nil {
			return false
		}

		passed, _, err := c.sendDownloadMTUProbe(ctx, conn, transport, c.syncedDownloadMTU, c.syncedUploadMTU, timeout, mtuProbeOptions{
			Quiet:   true,
			IsRetry: attempt > 0,
		})

		if err == nil && passed {
			return true
		}
	}
	return false
}

func (c *Client) resolverHealthProbeTimeout() time.Duration {
	timeout := c.mtuTestTimeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	if c == nil || c.balancer == nil {
		return timeout
	}

	active := c.balancer.ActiveCount()
	if active < 1 {
		active = 1
	}

	switch {
	case active <= 3:
		if timeout < 7*time.Second {
			timeout = 7 * time.Second
		}
	case active <= 5:
		if timeout < 6*time.Second {
			timeout = 6 * time.Second
		}
	case active <= 8:
		if timeout < 5500*time.Millisecond {
			timeout = 5500 * time.Millisecond
		}
	case active <= 10:
		if timeout < 5*time.Second {
			timeout = 5 * time.Second
		}
	case active <= 15:
		if timeout < 4500*time.Millisecond {
			timeout = 4500 * time.Millisecond
		}
	}

	return timeout
}

func (c *Client) confirmResolverDown(conn *Connection, window time.Duration) bool {
	if c == nil || conn == nil || conn.Key == "" {
		return true
	}

	if !c.cfg.AutoDisableTimeoutServers {
		return true
	}

	transport, err := newUDPQueryTransport(conn.ResolverLabel)
	if err != nil {
		return true
	}
	defer transport.conn.Close()

	timeout := 350 * time.Millisecond
	if window > 0 && window < time.Second {
		timeout = window / 3
	}

	if timeout < 200*time.Millisecond {
		timeout = 200 * time.Millisecond
	}

	if timeout > time.Second {
		timeout = time.Second
	}

	mtuSize := c.syncedUploadMTU
	if mtuSize < 32 {
		mtuSize = 32
	}

	if mtuSize > 96 {
		mtuSize = 96
	}

	const attempts = 2
	for attempt := 0; attempt < attempts; attempt++ {
		ok, _, err := c.sendUploadMTUProbe(
			context.Background(),
			*conn,
			transport,
			mtuSize,
			timeout,
			mtuProbeOptions{Quiet: true, IsRetry: attempt > 0},
		)

		if err == nil && ok {
			return false
		}
	}
	return true
}

func (c *Client) runConnectionMTUTest(ctx context.Context, conn Connection, serverID int, total int, maxUploadPayload int, counters *mtuScanCounters) {
	if conn.Key == "" {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			c.applyMTUDecision(conn.Key, mtuDecision{})
			if c.log != nil {
				c.log.Errorf(
					"💥 <red>MTU Probe Worker Panic: <cyan>%v</cyan> (Resolver: <cyan>%s</cyan>)</red>",
					recovered,
					conn.ResolverLabel,
				)
			}

			if counters != nil {
				completed := counters.completed.Add(1)
				rejectedNow := counters.rejectUpload.Add(1) + counters.rejectDownload.Load()
				if c.log != nil && c.log.Enabled(logger.LevelWarn) {
					c.log.Warnf(
						"<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>PANIC</yellow> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
						completed,
						total,
						conn.Domain,
						conn.ResolverLabel,
						counters.valid.Load(),
						rejectedNow,
					)
				}
			}
		}
	}()

	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf(
			"<green>Testing Resolver: <cyan>%s</cyan> for Domain: <cyan>%s</cyan> (<cyan>%d / %d</cyan>)</green>",
			conn.ResolverLabel,
			conn.Domain,
			serverID,
			total,
		)
	}

	result, reason := c.probeConnectionMTU(ctx, conn, maxUploadPayload)
	if counters == nil {
		return
	}

	decision := buildMTUDecision(result, reason)
	c.applyMTUDecision(conn.Key, decision)

	switch reason {
	case mtuRejectUpload:
		completed := counters.completed.Add(1)
		rejectedNow := counters.rejectUpload.Add(1) + counters.rejectDownload.Load()
		if c.log != nil && c.log.Enabled(logger.LevelWarn) {
			c.log.Warnf(
				"<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>UPLOAD_MTU</yellow> | value=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
				completed,
				total,
				conn.Domain,
				conn.ResolverLabel,
				decision.rejectValue,
				counters.valid.Load(),
				rejectedNow,
			)
		}
		return
	case mtuRejectDownload:
		completed := counters.completed.Add(1)
		rejectedNow := counters.rejectUpload.Load() + counters.rejectDownload.Add(1)
		if c.log != nil && c.log.Enabled(logger.LevelWarn) {
			c.log.Warnf(
				"<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>DOWNLOAD_MTU</yellow> | value=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
				completed,
				total,
				conn.Domain,
				conn.ResolverLabel,
				decision.rejectValue,
				counters.valid.Load(),
				rejectedNow,
			)
		}
		return
	}

	completed := counters.completed.Add(1)
	validNow := counters.valid.Add(1)
	rejectedNow := counters.rejectUpload.Load() + counters.rejectDownload.Load()
	if c.log != nil && c.log.Enabled(logger.LevelInfo) {
		c.log.Infof(
			"<green>✅ Accepted (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | upload=<cyan>%d</cyan> | download=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></green>",
			completed,
			total,
			conn.Domain,
			conn.ResolverLabel,
			decision.uploadBytes,
			decision.downloadBytes,
			validNow,
			rejectedNow,
		)
	}
	if acceptedConn, ok := c.balancer.GetConnectionByKey(conn.Key); ok {
		c.appendMTUSuccessLine(&acceptedConn)
	}
}

func (c *Client) probeConnectionMTU(ctx context.Context, conn Connection, maxUploadPayload int) (mtuConnectionProbeResult, mtuRejectReason) {
	var result mtuConnectionProbeResult

	probeTransport, err := newUDPQueryTransport(conn.ResolverLabel)
	if err != nil {
		return result, mtuRejectUpload
	}
	defer probeTransport.conn.Close()

	upOK, upBytes, upChars, upRTT, err := c.testUploadMTU(ctx, conn, probeTransport, maxUploadPayload)
	if err != nil || !upOK {
		result.UploadBytes = upBytes
		result.UploadChars = upChars
		return result, mtuRejectUpload
	}

	result.UploadBytes = upBytes
	result.UploadChars = upChars

	downOK, downBytes, downRTT, err := c.testDownloadMTU(ctx, conn, probeTransport, upBytes)
	if err != nil || !downOK {
		result.DownloadBytes = downBytes
		return result, mtuRejectDownload
	}

	result.DownloadBytes = downBytes
	result.ResolveTime = averageMTUProbeRTT(upRTT, downRTT)
	return result, mtuRejectNone
}

func buildMTUDecision(result mtuConnectionProbeResult, reason mtuRejectReason) mtuDecision {
	decision := mtuDecision{
		active:        reason == mtuRejectNone,
		reason:        reason,
		uploadBytes:   result.UploadBytes,
		uploadChars:   result.UploadChars,
		downloadBytes: result.DownloadBytes,
		resolveTime:   result.ResolveTime,
	}
	switch reason {
	case mtuRejectUpload:
		decision.uploadBytes = 0
		decision.uploadChars = 0
		decision.downloadBytes = 0
		decision.resolveTime = 0
		decision.rejectValue = result.UploadBytes
	case mtuRejectDownload:
		decision.downloadBytes = 0
		decision.resolveTime = 0
		decision.rejectValue = result.DownloadBytes
	}
	return decision
}

func (c *Client) applyMTUDecision(key string, decision mtuDecision) {
	if c == nil || c.balancer == nil || key == "" {
		return
	}
	_ = c.balancer.ApplyMTUProbeResult(
		key,
		decision.uploadBytes,
		decision.uploadChars,
		decision.downloadBytes,
		decision.resolveTime,
		decision.active,
	)
}

func (c *Client) precomputeUploadCaps() map[string]int {
	caps := make(map[string]int, len(c.cfg.Domains))
	for _, domain := range c.cfg.Domains {
		if _, exists := caps[domain]; exists {
			continue
		}
		caps[domain] = c.maxUploadMTUPayload(domain)
	}
	return caps
}

func (c *Client) testUploadMTU(ctx context.Context, conn Connection, probeTransport *udpQueryTransport, maxPayload int) (bool, int, int, time.Duration, error) {
	if maxPayload <= 0 {
		return false, 0, 0, 0, nil
	}
	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf("<cyan>[MTU]</cyan> Testing upload MTU for %s", conn.Domain)
	}

	maxLimit := c.cfg.MaxUploadMTU
	if maxLimit <= 0 || maxLimit > defaultUploadMaxCap {
		maxLimit = defaultUploadMaxCap
	}
	if maxPayload > maxLimit {
		maxPayload = maxLimit
	}

	best, bestRTT := c.binarySearchMTU(
		ctx,
		"upload mtu",
		c.cfg.MinUploadMTU,
		maxPayload,
		minUploadMTUFloor,
		func(candidate int, isRetry bool) (bool, time.Duration, error) {
			return c.sendUploadMTUProbe(ctx, conn, probeTransport, candidate, c.mtuTestTimeout, mtuProbeOptions{
				IsRetry: isRetry,
			})
		},
	)
	if best < max(minUploadMTUFloor, c.cfg.MinUploadMTU) {
		return false, 0, 0, 0, nil
	}
	return true, best, c.encodedCharsForPayload(best), bestRTT, nil
}

func (c *Client) testDownloadMTU(ctx context.Context, conn Connection, probeTransport *udpQueryTransport, uploadMTU int) (bool, int, time.Duration, error) {
	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf("<cyan>[MTU]</cyan> Testing download MTU for %s", conn.Domain)
	}

	best, bestRTT := c.binarySearchMTU(
		ctx,
		"download mtu",
		c.cfg.MinDownloadMTU,
		c.cfg.MaxDownloadMTU,
		minDownloadMTUFloor,
		func(candidate int, isRetry bool) (bool, time.Duration, error) {
			return c.sendDownloadMTUProbe(ctx, conn, probeTransport, candidate, uploadMTU, c.mtuTestTimeout, mtuProbeOptions{
				IsRetry: isRetry,
			})
		},
	)

	if best < max(minDownloadMTUFloor, c.cfg.MinDownloadMTU) {
		return false, 0, 0, nil
	}

	return true, best, bestRTT, nil
}

func (c *Client) binarySearchMTU(ctx context.Context, label string, minValue, maxValue int, minFloor int, testFn func(int, bool) (bool, time.Duration, error)) (int, time.Duration) {
	if maxValue <= 0 {
		return 0, 0
	}

	low := max(minValue, minFloor)
	high := maxValue
	if high < low {
		if c.log != nil && c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf(
				"<cyan>[MTU]</cyan> Invalid %s range: low=%d, high=%d. Skipping.",
				label,
				low,
				high,
			)
		}
		return 0, 0
	}
	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf(
			"<cyan>[MTU]</cyan> Starting binary search for %s. Range: %d-%d",
			label,
			low,
			high,
		)
	}

	check := func(value int) (bool, time.Duration) {
		ok := false
		var rtt time.Duration
		for attempt := 0; attempt < c.mtuTestRetries; attempt++ {
			if err := ctx.Err(); err != nil {
				return false, 0
			}
			passed, measuredRTT, err := testFn(value, attempt > 0)
			if err != nil && c.log != nil && c.log.Enabled(logger.LevelDebug) {
				c.log.Debugf("MTU test callable raised for %d: %v", value, err)
			}
			if err == nil && passed {
				ok = true
				rtt = measuredRTT
				break
			}
		}
		return ok, rtt
	}

	if ok, rtt := check(high); ok {
		if c.log != nil && c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf("<cyan>[MTU]</cyan> Max MTU %d is valid.", high)
		}
		return high, rtt
	}
	if low == high {
		if c.log != nil && c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf(
				"<cyan>[MTU]</cyan> Only one MTU candidate (%d) existed and it failed.",
				low,
			)
		}
		return 0, 0
	}
	best := low
	bestRTT := time.Duration(0)
	if ok, rtt := check(low); !ok {
		if c.log != nil && c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf(
				"<cyan>[MTU]</cyan> Both boundary MTUs failed (min=%d, max=%d). Skipping middle checks.",
				low,
				high,
			)
		}
		return 0, 0
	} else {
		bestRTT = rtt
	}

	left := low + 1
	right := high - 1
	for left <= right {
		if err := ctx.Err(); err != nil {
			return 0, 0
		}
		mid := (left + right) / 2
		if ok, rtt := check(mid); ok {
			best = mid
			bestRTT = rtt
			left = mid + 1
		} else {
			right = mid - 1
		}
	}
	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf("<cyan>[MTU]</cyan> Binary search result: %d", best)
	}
	return best, bestRTT
}

func (c *Client) sendUploadMTUProbe(ctx context.Context, conn Connection, probeTransport *udpQueryTransport, mtuSize int, timeout time.Duration, options mtuProbeOptions) (bool, time.Duration, error) {
	if mtuSize < 1+mtuProbeCodeLength {
		return false, 0, nil
	}
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	c.logMTUProbe(
		options.IsRetry,
		options.Quiet,
		"<magenta>[MTU Probe]</magenta> Testing Upload MTU: <yellow>%d</yellow> bytes via <cyan>%s</cyan>",
		mtuSize,
		conn.ResolverLabel,
	)

	payload, code, useBase64, err := c.buildMTUProbePayload(mtuSize)
	if err != nil {
		return false, 0, err
	}

	query, err := c.buildMTUProbeQuery(conn.Domain, Enums.PACKET_MTU_UP_REQ, payload)
	if err != nil {
		return false, 0, nil
	}

	startedAt := time.Now()
	response, err := c.exchangeUDPQuery(probeTransport, query, timeout)
	if err != nil {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	rtt := time.Since(startedAt)

	packet, err := DnsParser.ExtractVPNResponse(response, useBase64)
	if err != nil {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	if packet.PacketType != Enums.PACKET_MTU_UP_RES {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	if len(packet.Payload) != 6 {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	if binary.BigEndian.Uint32(packet.Payload[:mtuProbeCodeLength]) != code {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}
	ok := int(binary.BigEndian.Uint16(packet.Payload[mtuProbeCodeLength:mtuProbeCodeLength+2])) == mtuSize
	if ok {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>🟢 Upload test passed: Upload MTU <green>%d</green> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
	} else {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Upload test failed: Upload MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
	}
	return ok, rtt, nil
}

func (c *Client) sendDownloadMTUProbe(ctx context.Context, conn Connection, probeTransport *udpQueryTransport, mtuSize int, uploadMTU int, timeout time.Duration, options mtuProbeOptions) (bool, time.Duration, error) {
	if mtuSize < minDownloadMTUFloor {
		return false, 0, nil
	}

	if err := ctx.Err(); err != nil {
		return false, 0, err
	}

	c.logMTUProbe(
		options.IsRetry,
		options.Quiet,
		"<magenta>[MTU Probe]</magenta> Testing Download MTU: <yellow>%d</yellow> bytes via <cyan>%s</cyan>",
		mtuSize,
		conn.ResolverLabel,
	)

	effectiveDownloadSize := effectiveDownloadMTUProbeSize(mtuSize)
	if effectiveDownloadSize < minDownloadMTUFloor {
		return false, 0, nil
	}

	requestLen := max(1+mtuProbeCodeLength+2, uploadMTU)
	payload, code, useBase64, err := c.buildMTUProbePayload(requestLen)
	if err != nil {
		return false, 0, err
	}

	binary.BigEndian.PutUint16(payload[1+mtuProbeCodeLength:1+mtuProbeCodeLength+2], uint16(effectiveDownloadSize))

	query, err := c.buildMTUProbeQuery(conn.Domain, Enums.PACKET_MTU_DOWN_REQ, payload)
	if err != nil {
		return false, 0, nil
	}

	startedAt := time.Now()
	response, err := c.exchangeUDPQuery(probeTransport, query, timeout)
	if err != nil {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (No Response)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}

	rtt := time.Since(startedAt)

	packet, err := DnsParser.ExtractVPNResponse(response, useBase64)
	if err != nil {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Unexpected Packet Type)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}

	if packet.PacketType != Enums.PACKET_MTU_DOWN_RES {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Unexpected Packet Type)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}

	if len(packet.Payload) != effectiveDownloadSize {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Data Size Mismatch)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}

	if len(packet.Payload) < 1+mtuProbeCodeLength+1 {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Data Size Mismatch)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}

	if binary.BigEndian.Uint32(packet.Payload[:mtuProbeCodeLength]) != code {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Data Size Mismatch)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
		return false, 0, nil
	}

	ok := int(binary.BigEndian.Uint16(packet.Payload[mtuProbeCodeLength:mtuProbeCodeLength+2])) == effectiveDownloadSize
	if ok {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>🟢 Download test passed: Download MTU <green>%d</green> bytes via <cyan>%s</cyan> for <cyan>%s</cyan></yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
	} else {
		c.logMTUProbe(
			options.IsRetry,
			options.Quiet,
			"<yellow>⚠️ Download test failed: Download MTU <cyan>%d</cyan> bytes via <cyan>%s</cyan> for <cyan>%s</cyan> (Data Size Mismatch)</yellow>",
			mtuSize,
			conn.ResolverLabel,
			conn.Domain,
		)
	}
	return ok, rtt, nil
}

func (c *Client) buildMTUProbeQuery(domain string, packetType uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelTXTQueryRaw(domain, VpnProto.BuildOptions{
		SessionID:      255,
		PacketType:     packetType,
		StreamID:       1,
		SequenceNum:    1,
		FragmentID:     0,
		TotalFragments: 1,
		Payload:        payload,
	})
}

func (c *Client) maxUploadMTUPayload(domain string) int {
	maxChars := DnsParser.CalculateMaxEncodedQNameChars(domain)
	if maxChars <= 0 {
		return 0
	}

	low := 0
	high := maxChars
	best := 0
	for low <= high {
		mid := (low + high) / 2
		if c.canBuildUploadPayload(domain, mid) {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return best
}

func (c *Client) canBuildUploadPayload(domain string, payloadLen int) bool {
	if payloadLen <= 0 {
		return true
	}

	buf := c.udpBufferPool.Get().([]byte)
	defer c.udpBufferPool.Put(buf)

	if payloadLen > len(buf) {
		return false
	}

	payload := buf[:payloadLen]
	encoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID:      255,
		PacketType:     Enums.PACKET_MTU_UP_REQ,
		SessionCookie:  255,
		StreamID:       0xFFFF,
		SequenceNum:    0xFFFF,
		FragmentID:     0xFF,
		TotalFragments: 0xFF,
		Payload:        payload,
	}, c.codec)
	if err != nil {
		return false
	}

	_, err = DnsParser.BuildTunnelQuestionName(domain, encoded)
	return err == nil
}

func (c *Client) buildMTUProbePayload(length int) ([]byte, uint32, bool, error) {
	if length <= 0 {
		return nil, 0, false, nil
	}

	payload := make([]byte, length)
	useBase64 := c != nil && c.cfg.BaseEncodeData
	payload[0] = mtuProbeRawResponse
	if useBase64 {
		payload[0] = mtuProbeBase64Reply
	}

	code := c.mtuProbeCounter.Add(1)
	binary.BigEndian.PutUint32(payload[1:1+mtuProbeCodeLength], code)

	return payload, code, useBase64, nil
}

func averageMTUProbeRTT(values ...time.Duration) time.Duration {
	var sum time.Duration
	count := 0
	for _, value := range values {
		if value <= 0 {
			continue
		}
		sum += value
		count++
	}
	if count == 0 {
		return 0
	}
	return sum / time.Duration(count)
}

func summarizeValidMTUConnections(connections []Connection) (validConns []Connection, minUpload int, minDownload int, minUploadChars int) {
	validConns = make([]Connection, 0, len(connections))
	for _, conn := range connections {
		if !conn.IsValid {
			continue
		}
		validConns = append(validConns, conn)

		minUpload = minPositive(minUpload, conn.UploadMTUBytes)
		minDownload = minPositive(minDownload, conn.DownloadMTUBytes)
		minUploadChars = minPositive(minUploadChars, conn.UploadMTUChars)
	}
	return validConns, minUpload, minDownload, minUploadChars
}

func minPositive(current, candidate int) int {
	if candidate <= 0 {
		return current
	}
	if current == 0 || candidate < current {
		return candidate
	}
	return current
}

func (c *Client) encodedCharsForPacketPayload(packetType uint8, payloadLen int) int {
	if payloadLen <= 0 {
		return 0
	}

	buf := c.udpBufferPool.Get().([]byte)
	defer c.udpBufferPool.Put(buf)

	if payloadLen > len(buf) {
		return 0
	}

	payload := buf[:payloadLen]
	encoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID:       255,
		PacketType:      packetType,
		SessionCookie:   255,
		StreamID:        0xFFFF,
		SequenceNum:     0xFFFF,
		FragmentID:      0xFF,
		TotalFragments:  0xFF,
		CompressionType: 0xFF,
		Payload:         payload,
	}, c.codec)

	if err != nil {
		return 0
	}

	return len(encoded)
}

func (c *Client) encodedCharsForPayload(payloadLen int) int {
	return c.encodedCharsForPacketPayload(maxUploadProbePacketType, payloadLen)
}

func effectiveDownloadMTUProbeSize(downloadMTU int) int {
	if downloadMTU <= 0 {
		return 0
	}

	return downloadMTU + mtuDownResponseReserve
}

func computeSafeUploadMTU(uploadMTU int, cryptoOverhead int) int {
	if uploadMTU <= 0 {
		return 0
	}

	safe := uploadMTU - cryptoOverhead
	if safe < 64 {
		safe = 64
	}

	if safe > uploadMTU {
		return uploadMTU
	}

	return safe
}

func mtuCryptoOverhead(method int) int {
	switch method {
	case 2:
		return 16
	case 3, 4, 5:
		return 28
	default:
		return 0
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
