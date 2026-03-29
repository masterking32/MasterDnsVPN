package client

import (
	"context"
	"math"
	"slices"
	"sort"
	"time"

	"masterdnsvpn-go/internal/logger"
)

type resolverHealthEvent struct {
	At time.Time
}

type resolverHealthState struct {
	Events           []resolverHealthEvent
	TimeoutOnlySince time.Time
	LastSuccessAt    time.Time
}

type resolverRecheckState struct {
	FailCount int
	NextAt    time.Time
}

type resolverDisabledState struct {
	DisabledAt  time.Time
	NextRetryAt time.Time
	RetryCount  int
	Cause       string
}

type resolverRecheckCandidate struct {
	key             string
	nextAt          time.Time
	failCount       int
	runtimePriority bool
}

func (c *Client) resolverHealthDebugEnabled() bool {
	return c != nil && c.log != nil && c.log.Enabled(logger.LevelDebug)
}

func (c *Client) initResolverRecheckMeta() {
	if c == nil {
		return
	}

	now := c.now()
	nextInactive := now.Add(c.recheckInactiveInterval())

	c.resolverStatsMu.Lock()
	c.resolverPending = make(map[resolverSampleKey]resolverSample)
	c.resolverStatsMu.Unlock()

	c.resolverHealthMu.Lock()
	defer c.resolverHealthMu.Unlock()

	c.resolverHealth = make(map[string]*resolverHealthState, len(c.connections))
	c.resolverRecheck = make(map[string]resolverRecheckState, len(c.connections))
	c.runtimeDisabled = make(map[string]resolverDisabledState)

	for idx := range c.connections {
		conn := &c.connections[idx]
		if conn.Key == "" {
			continue
		}
		c.resolverHealth[conn.Key] = &resolverHealthState{
			Events: make([]resolverHealthEvent, 0, 8),
		}
		meta := resolverRecheckState{}
		if !conn.IsValid {
			meta.NextAt = nextInactive
		}
		c.resolverRecheck[conn.Key] = meta
	}
}

func (c *Client) runResolverHealthLoop(ctx context.Context) {
	for {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
		}

		now := c.now()
		c.collectExpiredResolverTimeouts(now)
		c.runResolverAutoDisable(now)
		c.runResolverRecheckBatch(ctx, now)

		waitFor := c.nextResolverHealthWait(now)
		timer := time.NewTimer(waitFor)
		if ctx == nil {
			<-timer.C
			continue
		}
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (c *Client) nextResolverHealthWait(now time.Time) time.Duration {
	waitFor := 2 * time.Second
	if c == nil {
		return waitFor
	}
	if c.cfg.AutoDisableTimeoutServers {
		waitFor = minDuration(waitFor, c.autoDisableCheckInterval())
	}
	if !c.cfg.RecheckInactiveServersEnabled || !c.successMTUChecks {
		return clampResolverHealthWait(waitFor)
	}

	c.resolverHealthMu.Lock()
	defer c.resolverHealthMu.Unlock()

	for key, meta := range c.resolverRecheck {
		conn := c.connectionPtrByKey(key)
		if conn == nil || conn.IsValid || meta.NextAt.IsZero() {
			continue
		}
		dueIn := time.Until(meta.NextAt)
		if !meta.NextAt.After(now) {
			dueIn = 250 * time.Millisecond
		}
		waitFor = minDuration(waitFor, dueIn)
	}
	return clampResolverHealthWait(waitFor)
}

func clampResolverHealthWait(waitFor time.Duration) time.Duration {
	if waitFor < 250*time.Millisecond {
		return 250 * time.Millisecond
	}
	if waitFor > 5*time.Second {
		return 5 * time.Second
	}
	return waitFor
}

func (c *Client) noteResolverTimeout(serverKey string, at time.Time) {
	if c == nil || serverKey == "" {
		return
	}
	if at.IsZero() {
		at = c.now()
	}
	c.recordResolverHealthEvent(serverKey, false, at)
}
func (c *Client) recordResolverHealthEvent(serverKey string, success bool, now time.Time) {
	if c == nil || serverKey == "" {
		return
	}
	conn := c.connectionPtrByKey(serverKey)
	if conn == nil || !conn.IsValid {
		return
	}

	c.resolverHealthMu.Lock()
	defer c.resolverHealthMu.Unlock()

	state := c.resolverHealth[serverKey]
	if state == nil {
		state = &resolverHealthState{Events: make([]resolverHealthEvent, 0, 8)}
		c.resolverHealth[serverKey] = state
	}
	if success {
		state.Events = state.Events[:0]
		state.TimeoutOnlySince = time.Time{}
		state.LastSuccessAt = now
		return
	}

	c.insertResolverHealthEventLocked(state, resolverHealthEvent{At: now})
	if state.TimeoutOnlySince.IsZero() || now.Before(state.TimeoutOnlySince) {
		state.TimeoutOnlySince = now
	}
	c.pruneResolverHealthLocked(state, now)
	if len(state.Events) == 0 {
		state.TimeoutOnlySince = time.Time{}
	} else if state.TimeoutOnlySince.IsZero() {
		state.TimeoutOnlySince = state.Events[0].At
	}
}

func (c *Client) insertResolverHealthEventLocked(state *resolverHealthState, event resolverHealthEvent) {
	if state == nil {
		return
	}
	n := len(state.Events)
	if n == 0 || !event.At.Before(state.Events[n-1].At) {
		state.Events = append(state.Events, event)
		return
	}

	insertAt := sort.Search(n, func(i int) bool {
		return !state.Events[i].At.Before(event.At)
	})
	state.Events = append(state.Events, resolverHealthEvent{})
	copy(state.Events[insertAt+1:], state.Events[insertAt:])
	state.Events[insertAt] = event
}

func (c *Client) retractResolverTimeoutEvent(serverKey string, timedOutAt time.Time, now time.Time) {
	if c == nil || serverKey == "" || timedOutAt.IsZero() {
		return
	}

	c.resolverHealthMu.Lock()
	defer c.resolverHealthMu.Unlock()

	state := c.resolverHealth[serverKey]
	if state == nil || len(state.Events) == 0 {
		return
	}

	removeIdx := -1
	for i, event := range state.Events {
		if event.At.Equal(timedOutAt) {
			removeIdx = i
			break
		}
	}
	if removeIdx == -1 {
		return
	}

	state.Events = append(state.Events[:removeIdx], state.Events[removeIdx+1:]...)
	c.pruneResolverHealthLocked(state, now)
	if len(state.Events) == 0 {
		state.TimeoutOnlySince = time.Time{}
	} else {
		state.TimeoutOnlySince = state.Events[0].At
	}
}

func (c *Client) pruneResolverHealthLocked(state *resolverHealthState, now time.Time) {
	if state == nil || len(state.Events) == 0 {
		return
	}
	cutoff := now.Add(-c.autoDisableTimeoutWindow())
	dropCount := 0
	for dropCount < len(state.Events) && state.Events[dropCount].At.Before(cutoff) {
		dropCount++
	}
	if dropCount == 0 {
		return
	}
	state.Events = append(state.Events[:0], state.Events[dropCount:]...)
}

func (c *Client) runResolverAutoDisable(now time.Time) {
	if c == nil || !c.cfg.AutoDisableTimeoutServers || c.balancer.ValidCount() <= 3 {
		return
	}

	window := c.autoDisableTimeoutWindow()
	candidates := make([]string, 0, len(c.connections))
	c.resolverHealthMu.Lock()
	for key, state := range c.resolverHealth {
		if state == nil {
			continue
		}
		conn := c.connectionPtrByKey(key)
		if conn == nil || !conn.IsValid {
			continue
		}
		c.pruneResolverHealthLocked(state, now)
		if len(state.Events) < c.autoDisableMinObservations() {
			continue
		}
		if state.TimeoutOnlySince.IsZero() {
			continue
		}
		timeoutOnlyAge := now.Sub(state.TimeoutOnlySince)
		if timeoutOnlyAge < window {
			continue
		}
		if c.resolverHealthDebugEnabled() {
			span := state.Events[len(state.Events)-1].At.Sub(state.Events[0].At)
			oldestAge := now.Sub(state.Events[0].At)
			c.log.Debugf(
				"\U0001F6A8 <yellow>Resolver auto-disable candidate</yellow> <magenta>|</magenta> <blue>Resolver</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Events</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Span</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>OldestAge</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>TimeoutOnlyAge</blue>: <cyan>%s</cyan>",
				key,
				len(state.Events),
				span.Round(time.Millisecond),
				oldestAge.Round(time.Millisecond),
				timeoutOnlyAge.Round(time.Millisecond),
			)
		}
		candidates = append(candidates, key)
	}
	c.resolverHealthMu.Unlock()

	for _, key := range candidates {
		if c.balancer.ValidCount() <= 3 {
			return
		}
		c.disableResolverConnection(key, "100% timeout window")
	}
}

func (c *Client) disableResolverConnection(serverKey string, cause string) bool {
	if c == nil || serverKey == "" {
		return false
	}
	conn := c.connectionPtrByKey(serverKey)
	if conn == nil || !conn.IsValid || c.balancer.ValidCount() <= 3 {
		return false
	}
	if !c.balancer.SetConnectionValidity(serverKey, false) {
		return false
	}

	now := c.now()
	nextAt := now.Add(maxDuration(5*time.Second, c.recheckServerInterval()*2))

	c.resolverHealthMu.Lock()
	meta := c.resolverRecheck[serverKey]
	meta.NextAt = nextAt
	c.resolverRecheck[serverKey] = meta
	c.runtimeDisabled[serverKey] = resolverDisabledState{
		DisabledAt:  now,
		NextRetryAt: nextAt,
		RetryCount:  meta.FailCount,
		Cause:       cause,
	}
	delete(c.resolverHealth, serverKey)
	c.resolverHealthMu.Unlock()

	c.clearPreferredResolverReferences(serverKey)
	c.balancer.ResetServerStats(serverKey)
	if c.log != nil {
		c.log.Warnf(
			"\U0001F6D1 <yellow>DNS server <cyan>%s</cyan> disabled due to: <red>%s</red></yellow>",
			conn.ResolverLabel,
			cause,
		)
	}
	c.appendMTURemovedServerLine(conn, cause)
	return true
}

func (c *Client) clearPreferredResolverReferences(serverKey string) {
	if c == nil || serverKey == "" {
		return
	}

	c.streamsMu.RLock()
	streams := make([]*Stream_client, 0, len(c.active_streams))
	for _, stream := range c.active_streams {
		if stream != nil {
			streams = append(streams, stream)
		}
	}
	c.streamsMu.RUnlock()

	for _, stream := range streams {
		stream.resolverMu.Lock()
		if stream.PreferredServerKey == serverKey {
			stream.PreferredServerKey = ""
			stream.ResolverResendStreak = 0
		}
		stream.resolverMu.Unlock()
	}
}

func (c *Client) reactivateResolverConnection(serverKey string) bool {
	if c == nil || serverKey == "" {
		return false
	}
	conn := c.connectionPtrByKey(serverKey)
	if conn == nil || conn.IsValid {
		return false
	}
	if !c.balancer.SetConnectionValidity(serverKey, true) {
		return false
	}

	c.resolverHealthMu.Lock()
	delete(c.runtimeDisabled, serverKey)
	delete(c.resolverHealth, serverKey)
	c.resolverRecheck[serverKey] = resolverRecheckState{}
	// Periodically prune runtimeDisabled entries for connections no longer tracked
	if len(c.runtimeDisabled) > len(c.connections) {
		for k := range c.runtimeDisabled {
			if c.connectionPtrByKey(k) == nil {
				delete(c.runtimeDisabled, k)
			}
		}
	}
	c.resolverHealthMu.Unlock()

	c.balancer.ResetServerStats(serverKey)
	if c.log != nil {
		c.log.Infof(
			"\U0001F504 <green>DNS server <cyan>%s</cyan> re-activated after successful recheck.</green>",
			conn.ResolverLabel,
		)
	}
	c.appendMTUAddedServerLine(conn)
	return true
}

func (c *Client) scheduleResolverRecheckFailure(serverKey string, runtimePriority bool, now time.Time) {
	if c == nil || serverKey == "" {
		return
	}

	c.resolverHealthMu.Lock()
	defer c.resolverHealthMu.Unlock()

	meta := c.resolverRecheck[serverKey]
	meta.FailCount++

	var base time.Duration
	if runtimePriority {
		base = maxDuration(10*time.Second, c.recheckServerInterval()*2)
	} else {
		base = maxDuration(30*time.Second, c.recheckInactiveInterval()/4)
	}

	pow := math.Pow(1.8, float64(min(meta.FailCount, 6)))
	delay := time.Duration(float64(base) * pow)
	if delay > c.recheckInactiveInterval() {
		delay = c.recheckInactiveInterval()
	}
	delay += deterministicResolverJitter(serverKey, delay)
	meta.NextAt = now.Add(delay)
	c.resolverRecheck[serverKey] = meta

	if state, ok := c.runtimeDisabled[serverKey]; ok {
		state.NextRetryAt = meta.NextAt
		state.RetryCount = meta.FailCount
		c.runtimeDisabled[serverKey] = state
	}
}

func deterministicResolverJitter(serverKey string, delay time.Duration) time.Duration {
	if serverKey == "" || delay <= 0 {
		return 0
	}
	maxJitter := minDuration(2*time.Second, time.Duration(float64(delay)*0.15))
	if maxJitter <= 0 {
		return 0
	}
	var hash uint64 = 1469598103934665603
	for i := 0; i < len(serverKey); i++ {
		hash ^= uint64(serverKey[i])
		hash *= 1099511628211
	}
	return time.Duration(hash % uint64(maxJitter))
}

func (c *Client) runResolverRecheckBatch(ctx context.Context, now time.Time) {
	if c == nil || !c.cfg.RecheckInactiveServersEnabled || !c.successMTUChecks {
		return
	}

	candidates := c.collectDueResolverRechecks(now)
	if len(candidates) == 0 {
		return
	}

	limit := c.recheckBatchSize()
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}

	for _, candidate := range candidates {
		conn := c.connectionPtrByKey(candidate.key)
		if conn == nil || conn.IsValid {
			continue
		}

		if c.recheckResolverConnection(ctx, conn) {
			c.reactivateResolverConnection(candidate.key)
			continue
		}

		c.scheduleResolverRecheckFailure(candidate.key, candidate.runtimePriority, now)
	}
}

func (c *Client) collectDueResolverRechecks(now time.Time) []resolverRecheckCandidate {
	if c == nil {
		return nil
	}

	c.resolverHealthMu.Lock()
	defer c.resolverHealthMu.Unlock()

	runtimeCandidates := make([]resolverRecheckCandidate, 0, len(c.runtimeDisabled))
	normalCandidates := make([]resolverRecheckCandidate, 0, len(c.connections))
	for key, meta := range c.resolverRecheck {
		conn := c.connectionPtrByKey(key)
		if conn == nil || conn.IsValid {
			continue
		}
		if !meta.NextAt.IsZero() && meta.NextAt.After(now) {
			continue
		}

		candidateValue := resolverRecheckCandidate{
			key:       key,
			nextAt:    meta.NextAt,
			failCount: meta.FailCount,
		}
		if state, ok := c.runtimeDisabled[key]; ok {
			candidateValue.runtimePriority = true
			candidateValue.nextAt = state.NextRetryAt
			candidateValue.failCount = state.RetryCount
			runtimeCandidates = append(runtimeCandidates, candidateValue)
			continue
		}
		normalCandidates = append(normalCandidates, candidateValue)
	}

	slices.SortFunc(runtimeCandidates, func(a, b resolverRecheckCandidate) int {
		if cmp := a.nextAt.Compare(b.nextAt); cmp != 0 {
			return cmp
		}
		if a.failCount < b.failCount {
			return -1
		}
		if a.failCount > b.failCount {
			return 1
		}
		if a.key < b.key {
			return -1
		}
		if a.key > b.key {
			return 1
		}
		return 0
	})
	slices.SortFunc(normalCandidates, func(a, b resolverRecheckCandidate) int {
		if a.failCount < b.failCount {
			return -1
		}
		if a.failCount > b.failCount {
			return 1
		}
		if cmp := a.nextAt.Compare(b.nextAt); cmp != 0 {
			return cmp
		}
		if a.key < b.key {
			return -1
		}
		if a.key > b.key {
			return 1
		}
		return 0
	})

	candidates := make([]resolverRecheckCandidate, 0, len(runtimeCandidates)+len(normalCandidates))
	candidates = append(candidates, runtimeCandidates...)
	candidates = append(candidates, normalCandidates...)
	return candidates
}

func (c *Client) recheckResolverConnection(ctx context.Context, conn *Connection) bool {
	if c == nil || conn == nil || c.syncedUploadMTU <= 0 || c.syncedDownloadMTU <= 0 {
		return false
	}
	if c.recheckConnectionFn != nil {
		if !c.recheckConnectionFn(conn) {
			return false
		}
		conn.UploadMTUBytes = c.syncedUploadMTU
		conn.UploadMTUChars = c.encodedCharsForPayload(c.syncedUploadMTU)
		conn.DownloadMTUBytes = c.syncedDownloadMTU
		return true
	}

	transport, err := newUDPQueryTransport(conn.ResolverLabel)
	if err != nil {
		return false
	}
	defer transport.conn.Close()

	upOK, err := c.sendUploadMTUProbe(ctx, conn, transport, c.syncedUploadMTU, mtuProbeOptions{Quiet: true})
	if err != nil || !upOK {
		return false
	}
	downOK, err := c.sendDownloadMTUProbe(ctx, conn, transport, c.syncedDownloadMTU, c.syncedUploadMTU, mtuProbeOptions{Quiet: true})
	if err != nil || !downOK {
		return false
	}

	conn.UploadMTUBytes = c.syncedUploadMTU
	conn.UploadMTUChars = c.encodedCharsForPayload(c.syncedUploadMTU)
	conn.DownloadMTUBytes = c.syncedDownloadMTU
	return true
}

func (c *Client) isRuntimeDisabledResolver(serverKey string) bool {
	if c == nil || serverKey == "" {
		return false
	}
	c.resolverHealthMu.Lock()
	_, ok := c.runtimeDisabled[serverKey]
	c.resolverHealthMu.Unlock()
	return ok
}

func (c *Client) autoDisableTimeoutWindow() time.Duration {
	return time.Duration(c.cfg.AutoDisableTimeoutWindowSeconds * float64(time.Second))
}

func (c *Client) autoDisableCheckInterval() time.Duration {
	return time.Duration(c.cfg.AutoDisableCheckIntervalSeconds * float64(time.Second))
}

func (c *Client) autoDisableMinObservations() int {
	if c.cfg.AutoDisableMinObservations < 1 {
		return 1
	}
	return c.cfg.AutoDisableMinObservations
}

func (c *Client) recheckInactiveInterval() time.Duration {
	return time.Duration(c.cfg.RecheckInactiveIntervalSeconds * float64(time.Second))
}

func (c *Client) recheckServerInterval() time.Duration {
	return time.Duration(c.cfg.RecheckServerIntervalSeconds * float64(time.Second))
}

func (c *Client) recheckBatchSize() int {
	if c.cfg.RecheckBatchSize < 1 {
		return 1
	}
	return c.cfg.RecheckBatchSize
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
