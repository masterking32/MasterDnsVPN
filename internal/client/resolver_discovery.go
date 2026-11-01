// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (resolver_discovery.go) implements the autonomous DiscoveryEngine
// orchestrating candidate batching, worker pool parallelism, FastStart early
// context cancellation, micro-burst qualification, replenishment, and pool admission.
// ==============================================================================
package client

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/logger"
)

// MTUProbeResult holds the outcome and telemetry of an MTU probe.
type MTUProbeResult struct {
	Success       bool
	UploadBytes   int
	UploadChars   int
	DownloadBytes int
	ResolveTime   time.Duration
	RejectReason  string
}

// ResolverProber decouples physical DNS wire probing from discovery orchestration.
type ResolverProber interface {
	// ProbeMTU measures upload and download MTU capacity for a candidate connection.
	ProbeMTU(ctx context.Context, conn Connection, maxUploadPayload int) (MTUProbeResult, error)

	// ProbeBurst sends a pipelined train of DNS queries to measure packet loss, RTT, and throughput.
	ProbeBurst(
		ctx context.Context,
		conn Connection,
		packetCount int,
		downloadMTU int,
		uploadMTU int,
		timeout time.Duration,
	) BurstProbeResult
}

// DiscoveryConfig contains orchestration settings owned by DiscoveryEngine.
// Wire-probe thresholds and MTU search limits remain with the prober.
type DiscoveryConfig struct {
	// FastStart terminates discovery early once TargetResolvers quota is reached.
	FastStart bool

	// TargetResolvers is the quota of unique resolver endpoints required for FastStart.
	TargetResolvers int

	// Parallelism specifies the concurrency limit for parallel MTU worker goroutines.
	Parallelism int

	// MicroBurstEnabled specifies whether micro-burst qualification is executed.
	MicroBurstEnabled bool

	// MicroBurstPacketCount is the number of pipelined queries per burst.
	// Nonpositive values default to 6; a positive value below 2 is clamped to 2.
	MicroBurstPacketCount int

	// MicroBurstParallelism is burst worker concurrency (minimum/default: 1).
	// Client configuration translation supplies its production default of 8.
	MicroBurstParallelism int

	// MicroBurstTimeout is the burst probe timeout (default: 3 seconds).
	MicroBurstTimeout time.Duration

	// MaxActiveResolvers limits the maximum number of active resolvers admitted to the pool.
	MaxActiveResolvers int

	// Domains contains the list of tunnel domains to probe.
	Domains []string

	// UploadCaps maps each domain to its precomputed maximum upload payload.
	UploadCaps map[string]int
}

// DiscoveryEngine coordinates candidate batching, worker pool parallelism, quota tracking,
// early context cancellation, replenishment, and atomic pool admission.
type DiscoveryEngine struct {
	cfg      DiscoveryConfig
	prober   ResolverProber
	pool     *ResolverPool
	log      *logger.Logger
	counters *mtuScanCounters
}

// NewDiscoveryEngine constructs a DiscoveryEngine with the provided dependencies.
func NewDiscoveryEngine(
	cfg DiscoveryConfig,
	prober ResolverProber,
	pool *ResolverPool,
	log *logger.Logger,
) *DiscoveryEngine {
	// Normalize direct-engine defaults once. Client translation preserves its
	// own configuration defaults before constructing the engine.
	cfg.TargetResolvers = max(1, cfg.TargetResolvers)
	cfg.Parallelism = max(1, cfg.Parallelism)
	cfg.MicroBurstParallelism = max(1, cfg.MicroBurstParallelism)
	if cfg.MicroBurstPacketCount <= 0 {
		cfg.MicroBurstPacketCount = 6
	}
	cfg.MicroBurstPacketCount = max(2, cfg.MicroBurstPacketCount)
	if cfg.MicroBurstTimeout <= 0 {
		cfg.MicroBurstTimeout = 3 * time.Second
	}
	return &DiscoveryEngine{
		cfg:      cfg,
		prober:   prober,
		pool:     pool,
		log:      log,
		counters: &mtuScanCounters{},
	}
}

// Run probes candidates, qualifies batches, and finalizes startup admission.
func (e *DiscoveryEngine) Run(ctx context.Context, candidateSets ...[]Connection) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if e.pool == nil || e.pool.TotalCount() == 0 {
		return ErrNoValidConnections
	}

	// Phase 1: Candidate Enumeration & Quota Initialization
	var scanConnections []Connection
	if len(candidateSets) > 0 && len(candidateSets[0]) > 0 {
		scanConnections = candidateSets[0]
	} else {
		scanConnections = e.pool.AllConnections()
	}
	if len(scanConnections) == 0 {
		return ErrNoValidConnections
	}

	uniqueEndpoints := make(map[string]struct{}, len(scanConnections))
	for _, conn := range scanConnections {
		uniqueEndpoints[conn.ResolverLabel] = struct{}{}
	}
	totalUniqueResolvers := len(uniqueEndpoints)

	fastStart := e.cfg.FastStart
	targetValidResolvers := totalUniqueResolvers
	if fastStart {
		targetValidResolvers = min(totalUniqueResolvers, e.cfg.TargetResolvers)
	}

	effectiveMaxActive := e.cfg.MaxActiveResolvers
	if effectiveMaxActive > 0 {
		e.pool.SetMaxActive(effectiveMaxActive)
		if targetValidResolvers > effectiveMaxActive {
			targetValidResolvers = effectiveMaxActive
		}
	}

	workerCount := min(e.cfg.Parallelism, len(scanConnections))

	testedKeys := make(map[string]bool, len(scanConnections))
	qualifiedKeys := make(map[string]struct{})
	qualifiedEndpoints := make(map[string]struct{}, targetValidResolvers)

	// Phase 2: Candidate Batching Loop (Outer Replenishment Loop)
	for {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
		}

		if fastStart && len(qualifiedEndpoints) >= targetValidResolvers {
			break
		}

		allTested := true
		for _, conn := range scanConnections {
			if !testedKeys[conn.Key] {
				allTested = false
			}
		}
		if allTested {
			break
		}

		needed := targetValidResolvers - len(qualifiedEndpoints)
		if !fastStart || needed < 1 {
			needed = totalUniqueResolvers
		}

		batchCtx, cancelBatch := context.WithCancel(ctx)
		batchUniqueValid := &atomic.Int32{}
		var batchMu sync.Mutex
		batchEndpoints := make(map[string]struct{})
		var batchValidConns []Connection

		recordBatchValid := func(conn Connection) {
			batchMu.Lock()
			defer batchMu.Unlock()
			batchValidConns = append(batchValidConns, conn)
			if _, alreadyQual := qualifiedEndpoints[conn.ResolverLabel]; !alreadyQual {
				if _, exists := batchEndpoints[conn.ResolverLabel]; !exists {
					batchEndpoints[conn.ResolverLabel] = struct{}{}
					if batchUniqueValid.Add(1) >= int32(needed) && fastStart {
						cancelBatch()
					}
				}
			}
		}

		// Phase 3: Parallel Worker Pool Probing
		if workerCount <= 1 {
			for idx := range scanConnections {
				if batchCtx.Err() != nil {
					break
				}
				conn := scanConnections[idx]
				if testedKeys[conn.Key] {
					continue
				}

				result, completed := e.probeCandidateMTU(batchCtx, conn, idx+1, len(scanConnections))
				if !completed || batchCtx.Err() != nil {
					break
				}
				testedKeys[conn.Key] = true
				if acceptedConn, ok := e.pool.GetConnectionByKey(conn.Key); ok && result.Success {
					recordBatchValid(acceptedConn)
				}
			}
		} else {
			jobs := make(chan int)
			var wg sync.WaitGroup
			var testedMu sync.Mutex

			for range workerCount {
				wg.Go(func() {
					for idx := range jobs {
						if batchCtx.Err() != nil {
							continue // Drain safely on early exit
						}
						conn := scanConnections[idx]
						result, completed := e.probeCandidateMTU(batchCtx, conn, idx+1, len(scanConnections))
						if !completed || batchCtx.Err() != nil {
							// If probe was interrupted by batch cancellation, do NOT mark as tested
							continue
						}
						testedMu.Lock()
						testedKeys[conn.Key] = true
						testedMu.Unlock()

						if acceptedConn, ok := e.pool.GetConnectionByKey(conn.Key); ok && result.Success {
							recordBatchValid(acceptedConn)
						}
					}
				})
			}

		dispatchLoop:
			for idx := range scanConnections {
				if fastStart && batchUniqueValid.Load() >= int32(needed) {
					cancelBatch()
					break dispatchLoop
				}
				conn := scanConnections[idx]
				testedMu.Lock()
				alreadyTested := testedKeys[conn.Key]
				testedMu.Unlock()
				if alreadyTested {
					continue
				}

				select {
				case <-batchCtx.Done():
					break dispatchLoop
				case jobs <- idx:
				}
			}
			close(jobs)
			wg.Wait()
		}
		cancelBatch()

		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
		}

		if len(batchValidConns) == 0 {
			continue // Replenish next batch
		}

		// Phase 4: Micro-Burst Qualification (using score.EvaluateResolver)
		if !e.cfg.MicroBurstEnabled {
			for _, conn := range batchValidConns {
				qualifiedEndpoints[conn.ResolverLabel] = struct{}{}
				qualifiedKeys[conn.Key] = struct{}{}
			}
			continue
		}

		neededUnique := targetValidResolvers - len(qualifiedEndpoints)
		if neededUnique < 0 {
			neededUnique = 0
		}
		domainCount := max(1, len(e.cfg.Domains))
		maxBurstActive := neededUnique * domainCount
		effectiveMaxActive := e.cfg.MaxActiveResolvers
		if effectiveMaxActive > 0 && maxBurstActive > effectiveMaxActive {
			maxBurstActive = effectiveMaxActive
		}

		burstQualified, _ := e.runMicroBurstQualification(ctx, batchValidConns, maxBurstActive)

		// Phase 5: Batch Admission into ResolverPool
		for _, q := range burstQualified {
			qualifiedKeys[q.Key] = struct{}{}
			qualifiedEndpoints[q.ResolverLabel] = struct{}{}
		}

		// Phase 6: Replenishment check occurs at top of Phase 2 loop
	}

	// Fill qualified vacancies before applying the startup endpoint quota.
	_ = e.pool.Optimize()

	// Phase 7: FastStart Finalization
	finalCap := targetValidResolvers
	if effectiveMaxActive > 0 && (finalCap <= 0 || finalCap > effectiveMaxActive) {
		finalCap = effectiveMaxActive
	}
	if fastStart || (effectiveMaxActive > 0 && e.pool.ActiveCount() > effectiveMaxActive) {
		var requiredKeys map[string]struct{}
		if e.cfg.MicroBurstEnabled {
			requiredKeys = qualifiedKeys
		}
		e.pool.FinalizeFastStart(requiredKeys, finalCap)
	}

	if e.pool.ActiveCount() == 0 {
		if e.log != nil {
			e.log.Errorf("<red>No valid connections found after MTU testing!</red>")
		}
		return ErrNoValidConnections
	}

	return nil
}

func (e *DiscoveryEngine) probeCandidateMTU(ctx context.Context, conn Connection, serverID, total int) (result MTUProbeResult, completed bool) {
	if conn.Key == "" {
		return MTUProbeResult{}, true
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			result = MTUProbeResult{}
			completed = true
			e.pool.ApplyMTUProbeResult(conn.Key, 0, 0, 0, 0, false)
			if e.log != nil {
				e.log.Errorf("💥 <red>MTU Probe Worker Panic: <cyan>%v</cyan> (Resolver: <cyan>%s</cyan>)</red>", recovered, conn.ResolverLabel)
			}
			if e.counters != nil {
				completed := e.counters.completed.Add(1)
				rejected := e.counters.rejectUpload.Add(1) + e.counters.rejectDownload.Load()
				if e.log != nil && e.log.Enabled(logger.LevelWarn) {
					e.log.Warnf("<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>PANIC</yellow> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
						completed, total, conn.Domain, conn.ResolverLabel, e.counters.valid.Load(), rejected)
				}
			}
		}
	}()

	maxUploadPayload := 0
	if e.cfg.UploadCaps != nil {
		maxUploadPayload = e.cfg.UploadCaps[conn.Domain]
	}

	res, err := e.prober.ProbeMTU(ctx, conn, maxUploadPayload)
	if ctx != nil && ctx.Err() != nil {
		return MTUProbeResult{}, false
	}

	if err != nil || !res.Success {
		res.Success = false
		e.pool.ApplyMTUProbeResult(conn.Key, res.UploadBytes, res.UploadChars, res.DownloadBytes, 0, false)
		if e.counters != nil {
			completed := e.counters.completed.Add(1)
			var rejected int32
			if res.RejectReason == "upload mtu probe rejected" {
				rejected = e.counters.rejectUpload.Add(1) + e.counters.rejectDownload.Load()
			} else {
				rejected = e.counters.rejectUpload.Load() + e.counters.rejectDownload.Add(1)
			}
			if e.log != nil && e.log.Enabled(logger.LevelWarn) {
				e.log.Warnf("<red>❌ Rejected (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | reason=<yellow>%s</yellow> | totals: valid=<green>%d</green>, rejected=<red>%d</red></red>",
					completed, total, conn.Domain, conn.ResolverLabel, res.RejectReason, e.counters.valid.Load(), rejected)
			}
		}
		return res, true
	}

	// MTU success alone is not admission when burst qualification is required.
	e.pool.ApplyMTUProbeResult(conn.Key, res.UploadBytes, res.UploadChars, res.DownloadBytes, res.ResolveTime, !e.cfg.MicroBurstEnabled)
	if e.counters != nil {
		completed := e.counters.completed.Add(1)
		validNow := e.counters.recordValid(conn.ResolverLabel)
		rejected := e.counters.rejectUpload.Load() + e.counters.rejectDownload.Load()
		if e.log != nil && e.log.Enabled(logger.LevelInfo) {
			e.log.Infof("<green>✅ Accepted (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | upload=<cyan>%d</cyan> | download=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></green>",
				completed, total, conn.Domain, conn.ResolverLabel, res.UploadBytes, res.DownloadBytes, validNow, rejected)
		}
	}
	return res, true
}

func (e *DiscoveryEngine) runMicroBurstQualification(
	ctx context.Context,
	validConns []Connection,
	maxActiveLimit int,
) ([]Connection, []QualifiedResolver) {
	if len(validConns) == 0 {
		return nil, nil
	}

	parallelism := min(e.cfg.MicroBurstParallelism, len(validConns))
	packetCount := e.cfg.MicroBurstPacketCount
	timeout := e.cfg.MicroBurstTimeout

	results := make([]QualifiedResolver, len(validConns))
	jobs := make(chan int, len(validConns))
	var wg sync.WaitGroup

	syncedUp, syncedDown := e.pool.SessionMTU()

	for range parallelism {
		wg.Go(func() {
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				conn := validConns[idx]
				effectiveDown := syncedDown
				effectiveUp := syncedUp
				if effectiveDown <= 0 || effectiveDown > conn.DownloadMTUBytes {
					effectiveDown = conn.DownloadMTUBytes
				}
				if effectiveUp <= 0 || effectiveUp > conn.UploadMTUBytes {
					effectiveUp = conn.UploadMTUBytes
				}

				burstResult := e.prober.ProbeBurst(ctx, conn, packetCount, effectiveDown, effectiveUp, timeout)

				score := 0.0
				if burstResult.ReceivedCount > 0 {
					score = calculateBurstScore(burstResult)
				}

				results[idx] = QualifiedResolver{
					Connection:  conn,
					BurstResult: burstResult,
					Score:       score,
				}
			}
		})
	}

	for i := range validConns {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		if results[i].BurstResult.LossRatio != results[j].BurstResult.LossRatio {
			return results[i].BurstResult.LossRatio < results[j].BurstResult.LossRatio
		}
		return results[i].BurstResult.AverageRTT < results[j].BurstResult.AverageRTT
	})

	for i := range results {
		results[i].Rank = i + 1
	}

	qualifiedConns := make([]Connection, 0, len(results))
	for _, r := range results {
		if r.BurstResult.Qualified {
			qualifiedConns = append(qualifiedConns, r.Connection)
		}
	}

	maxActive := e.cfg.MaxActiveResolvers
	if maxActiveLimit > 0 && (maxActive <= 0 || maxActiveLimit < maxActive) {
		maxActive = maxActiveLimit
	}
	selected := qualifiedConns
	if maxActive > 0 && len(selected) > maxActive {
		selected = selected[:maxActive]
	}

	e.pool.AdmitStartupBatch(results, selected)
	return selected, results
}
