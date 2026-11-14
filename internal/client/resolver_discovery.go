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
	"fmt"
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

	// OnMTUSuccess is an optional callback invoked when a candidate connection successfully passes MTU probing.
	OnMTUSuccess func(conn Connection)
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
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return fmt.Errorf("run discovery: %w", ctx.Err())
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

	uniqueEndpoints := make(map[EndpointKey]struct{}, len(scanConnections))
	for _, conn := range scanConnections {
		uniqueEndpoints[connectionEndpointKey(conn)] = struct{}{}
	}
	totalUniqueResolvers := len(uniqueEndpoints)

	fastStart := e.cfg.FastStart
	targetValidResolvers := min(totalUniqueResolvers, e.cfg.TargetResolvers)

	effectiveMaxActive := e.cfg.MaxActiveResolvers
	if effectiveMaxActive > 0 {
		e.pool.SetMaxActive(effectiveMaxActive)
		if targetValidResolvers > effectiveMaxActive {
			targetValidResolvers = effectiveMaxActive
		}
	}

	// Install continuing coverage before the first admission, regardless of scan mode.
	e.pool.SetTargetEndpoints(targetValidResolvers)

	workerCount := min(e.cfg.Parallelism, len(scanConnections))

	testedKeys := make(map[string]bool, len(scanConnections))
	qualifiedKeys := make(map[string]struct{})
	qualifiedEndpoints := make(map[EndpointKey]struct{}, targetValidResolvers)
	// Existing Active Paths are already qualified. Preserve them when discovery
	// resumes, while excluding any that became incompatible with the Session.
	e.pool.Optimize(targetValidResolvers)
	for _, conn := range e.pool.ActiveResolvers() {
		qualifiedKeys[conn.Key] = struct{}{}
		qualifiedEndpoints[connectionEndpointKey(conn)] = struct{}{}
	}

	// Phase 2: Candidate Batching Loop (Outer Replenishment Loop)
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("run discovery: %w", err)
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

		testedBefore := len(testedKeys)
		needed := targetValidResolvers - len(qualifiedEndpoints)
		if !fastStart || needed < 1 {
			needed = totalUniqueResolvers
		}

		batchCtx, cancelBatch := context.WithCancel(ctx)
		batchUniqueValid := &atomic.Int32{}
		var batchMu sync.Mutex
		batchEndpoints := make(map[EndpointKey]struct{})
		var batchValidConns []Connection

		recordBatchValid := func(conn Connection) {
			batchMu.Lock()
			defer batchMu.Unlock()
			batchValidConns = append(batchValidConns, conn)
			epKey := connectionEndpointKey(conn)
			if _, alreadyQual := qualifiedEndpoints[epKey]; !alreadyQual {
				if _, exists := batchEndpoints[epKey]; !exists {
					batchEndpoints[epKey] = struct{}{}
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
				if !completed {
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
						if !completed {
							// Interrupted probes release their leases and remain untested.
							continue
						}
						// A completed probe still owns its result when another worker
						// cancels the batch. Preserve it for burst qualification or
						// parent-cancellation cleanup below.
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

		if err := ctx.Err(); err != nil {
			for _, c := range batchValidConns {
				if state, ok := e.pool.CandidateState(c.Key); ok && state == StateChecking {
					e.pool.CancelChecking(c)
				}
			}
			return fmt.Errorf("run discovery: %w", err)
		}

		// No batch should spin indefinitely without consuming candidates or
		// producing qualification work. Parent cancellation was handled above.
		if len(testedKeys) == testedBefore && len(batchValidConns) == 0 {
			break
		}
		if len(batchValidConns) == 0 {
			continue // Replenish next batch
		}

		// Phase 4: Micro-Burst Qualification (using score.EvaluateResolver)
		if !e.cfg.MicroBurstEnabled {
			for _, conn := range batchValidConns {
				qualifiedKeys[conn.Key] = struct{}{}
			}
			_ = e.pool.Optimize(targetValidResolvers)
			qualifiedEndpoints = make(map[EndpointKey]struct{})
			for _, conn := range e.pool.ActiveResolvers() {
				qualifiedEndpoints[connectionEndpointKey(conn)] = struct{}{}
			}
			continue
		}

		results := e.runMicroBurstQualification(ctx, batchValidConns)
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("run discovery: %w", err)
		}

		// Phase 5: Batch Admission into ResolverPool
		for _, r := range results {
			if r.BurstResult.Qualified {
				qualifiedKeys[r.Connection.Key] = struct{}{}
			}
		}
		_ = e.pool.Optimize(targetValidResolvers)
		qualifiedEndpoints = make(map[EndpointKey]struct{})
		for _, conn := range e.pool.ActiveResolvers() {
			qualifiedEndpoints[connectionEndpointKey(conn)] = struct{}{}
		}

		// Phase 6: Replenishment check occurs at top of Phase 2 loop
	}

	// Fill qualified vacancies before applying the startup endpoint quota.
	_ = e.pool.Optimize(targetValidResolvers)

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
	if e.pool != nil {
		leased, ok := e.pool.AcquireCandidateForChecking(conn.Key)
		if !ok {
			// Active or leased elsewhere: skip this candidate for this run.
			return MTUProbeResult{}, true
		}
		conn = leased
	}
	var probeDone bool
	defer func() {
		if !probeDone && e.pool != nil {
			e.pool.CancelChecking(conn)
		}
	}()

	defer func() {
		if recovered := recover(); recovered != nil {
			probeDone = true
			result = MTUProbeResult{}
			completed = true
			if e.pool != nil {
				e.pool.CommitCandidateOutcome(conn, false, 0, 0, 0, 0)
			}
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
		probeDone = true
		res.Success = false
		if e.pool != nil {
			e.pool.CommitCandidateOutcome(conn, false, res.UploadBytes, res.UploadChars, res.DownloadBytes, 0)
		}
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

	probeDone = true
	if !e.cfg.MicroBurstEnabled {
		if e.pool != nil {
			e.pool.CommitCandidateOutcome(conn, true, res.UploadBytes, res.UploadChars, res.DownloadBytes, res.ResolveTime)
		}
	} else {
		// MTU success alone is not admission when burst qualification is required;
		// candidate remains in StateChecking for subsequent micro-burst evaluation.
		if e.pool != nil {
			e.pool.SetCheckingMTU(conn, CandidateMTUParams{UploadBytes: res.UploadBytes, UploadChars: res.UploadChars, DownloadBytes: res.DownloadBytes, ResolveTime: res.ResolveTime})
		}
	}
	if e.counters != nil {
		completed := e.counters.completed.Add(1)
		validNow := e.counters.recordValid(connectionEndpointKey(conn))
		rejected := e.counters.rejectUpload.Load() + e.counters.rejectDownload.Load()
		if e.log != nil && e.log.Enabled(logger.LevelInfo) {
			e.log.Infof("<green>✅ Accepted (%d/%d): <cyan>%s</cyan> via <cyan>%s</cyan> | upload=<cyan>%d</cyan> | download=<cyan>%d</cyan> | totals: valid=<green>%d</green>, rejected=<red>%d</red></green>",
				completed, total, conn.Domain, conn.ResolverLabel, res.UploadBytes, res.DownloadBytes, validNow, rejected)
		}
	}
	if accepted, ok := e.pool.GetConnectionByKey(conn.Key); ok && e.cfg.OnMTUSuccess != nil {
		e.cfg.OnMTUSuccess(accepted)
	}
	return res, true
}

func (e *DiscoveryEngine) runMicroBurstQualification(
	ctx context.Context,
	validConns []Connection,
) []QualifiedResolver {
	if len(validConns) == 0 {
		return nil
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
				conn := validConns[idx]
				if ctx.Err() != nil {
					e.pool.CancelChecking(conn)
					continue
				}
				effectiveDown := syncedDown
				effectiveUp := syncedUp
				if effectiveDown <= 0 || effectiveDown > conn.DownloadMTUBytes {
					effectiveDown = conn.DownloadMTUBytes
				}
				if effectiveUp <= 0 || effectiveUp > conn.UploadMTUBytes {
					effectiveUp = conn.UploadMTUBytes
				}

				burstResult := e.prober.ProbeBurst(ctx, conn, packetCount, effectiveDown, effectiveUp, timeout)
				if ctx.Err() != nil {
					e.pool.CancelChecking(conn)
					continue
				}

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

	e.pool.AdmitStartupBatch(results)
	return results
}
