package client

import (
	"context"
	"errors"
	"fmt"
	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
	"sync"
	"testing"
	"time"
)

// completedMTURaceProber holds the late worker at the end of its successful
// probe until the ready worker cancels the foreground batch.
type completedMTURaceProber struct {
	*FakeResolverProber
	lateAtCompletion chan struct{}
	lateContext      context.Context
}

func (p *completedMTURaceProber) ProbeMTU(ctx context.Context, conn Connection, cap int) (MTUProbeResult, error) {
	if conn.Key == "late" {
		p.lateContext = ctx
	} else {
		select {
		case <-p.lateAtCompletion:
		case <-ctx.Done():
			return MTUProbeResult{}, ctx.Err()
		}
	}
	return p.FakeResolverProber.ProbeMTU(ctx, conn, cap)
}

func TestDiscoveryPreservesCompletedMTUAfterBatchCancellation(t *testing.T) {
	p := NewResolverPool(2, nil)
	p.SetConnections([]*Connection{{Key: "late", ResolverLabel: "A"}, {Key: "ready", ResolverLabel: "B"}})
	prober := &completedMTURaceProber{FakeResolverProber: NewFakeResolverProber(), lateAtCompletion: make(chan struct{})}
	prober.SetBurstResponse("ready", BurstProbeResult{Qualified: false})
	e := NewDiscoveryEngine(DiscoveryConfig{
		FastStart: true, TargetResolvers: 1, Parallelism: 2,
		MicroBurstEnabled: true, MicroBurstParallelism: 1,
		OnMTUSuccess: func(conn Connection) {
			if conn.Key == "late" {
				close(prober.lateAtCompletion)
				<-prober.lateContext.Done()
			}
		},
	}, prober, p, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := e.Run(ctx); err != nil {
		t.Fatalf("completed MTU result was discarded after quota cancellation: %v", err)
	}
	if state, _ := p.CandidateState("late"); state != StateActive {
		t.Fatalf("late successful candidate is %v, want Active", state)
	}
	if state, _ := p.CandidateState("ready"); state != StateRejected {
		t.Fatalf("failed burst candidate is %v, want Rejected", state)
	}
}

func TestDiscoveryReleasesCompletedMTUOnParentCancellation(t *testing.T) {
	for _, parallelism := range []int{1, 2} {
		t.Run(fmt.Sprint(parallelism), func(t *testing.T) {
			p := NewResolverPool(1, nil)
			p.SetConnections([]*Connection{{Key: "candidate", ResolverLabel: "A"}, {Key: "other", ResolverLabel: "B"}})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			e := NewDiscoveryEngine(DiscoveryConfig{
				FastStart: true, TargetResolvers: 1, Parallelism: parallelism,
				MicroBurstEnabled: true,
				OnMTUSuccess:      func(Connection) { cancel() },
			}, NewFakeResolverProber(), p, nil)
			if err := e.Run(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("got %v, want parent cancellation", err)
			}
			for _, key := range []string{"candidate", "other"} {
				if state, _ := p.CandidateState(key); state != StateUntested {
					t.Fatalf("cancelled initial candidate %s is %v, want Untested", key, state)
				}
			}
		})
	}
}

func TestSnapshotReadersDoNotMutatePool(t *testing.T) {
	p := NewResolverPool(1, nil)
	p.SetConnections([]*Connection{{Key: "candidate"}})
	p.SetConnectionValidity("candidate", true)
	// Stale compatibility fields must be derived on copies, never repaired by readers.
	p.candidates[0].conn.IsValid = false
	for _, read := range []func(){
		func() { p.AllConnections() }, func() { p.ActiveResolvers() },
		func() { p.GetConnectionByKey("candidate") }, func() { p.GetStatsSnapshot() },
	} {
		read()
		if p.candidates[0].conn.IsValid {
			t.Fatal("snapshot reader mutated stored compatibility flags")
		}
	}
	if conn, _ := p.GetConnectionByKey("candidate"); !conn.IsValid {
		t.Fatal("snapshot did not derive Active eligibility")
	}
}

func TestBurstCancellationReleasesAllCheckingCandidates(t *testing.T) {
	p := NewResolverPool(2, nil)
	p.SetConnections([]*Connection{{Key: "a"}, {Key: "b"}})
	a, _ := p.AcquireCandidateForChecking("a")
	b, _ := p.AcquireCandidateForChecking("b")
	ctx, cancel := context.WithCancel(context.Background())
	fake := NewFakeResolverProber()
	fake.SetOnProbeBurst(func(Connection) { cancel() })
	e := NewDiscoveryEngine(DiscoveryConfig{MicroBurstParallelism: 1, MicroBurstPacketCount: 4, MicroBurstTimeout: time.Second}, fake, p, nil)
	e.runMicroBurstQualification(ctx, []Connection{a, b})
	for _, key := range []string{"a", "b"} {
		if state, _ := p.CandidateState(key); state != StateUntested {
			t.Errorf("cancelled candidate %s is %v, want Untested", key, state)
		}
	}
	if p.CoverageStats().CompletedInitialAttempts != 0 {
		t.Fatal("cancelled work counted as completed initial coverage")
	}
}

func TestStartupAdmissionPreservesSatisfiedCoverage(t *testing.T) {
	p := NewResolverPool(3, nil)
	p.SetTargetEndpoints(2)
	conns := []*Connection{
		{Key: "a1", ResolverLabel: "A"}, {Key: "a2", ResolverLabel: "A"},
		{Key: "b", ResolverLabel: "B"}, {Key: "c", ResolverLabel: "C"},
	}
	p.SetConnections(conns)
	for _, key := range []string{"a1", "a2", "b"} {
		p.ApplyMTUProbeResult(key, 100, 100, 500, 10*time.Millisecond, true)
	}
	c, _ := p.AcquireCandidateForChecking("c")
	p.SetConnectionMTU("c", 100, 100, 500, time.Second)
	p.AdmitStartupBatch([]QualifiedResolver{{Connection: c, BurstResult: BurstProbeResult{Qualified: true, SentCount: 4, ReceivedCount: 4, AverageRTT: time.Second}}})
	if state, _ := p.CandidateState("c"); state != StateStandby {
		t.Fatalf("slow distinct candidate became %v after coverage was met", state)
	}
}

// candidateSnapshotForTest obtains the current lease for synchronous fixture setup.
func candidateSnapshotForTest(p *ResolverPool, key string) Connection {
	conn, _ := p.GetConnectionByKey(key)
	return conn
}

func TestCheckingLeaseRejectsStaleCompletionAfterReacquisition(t *testing.T) {
	p := NewResolverPool(1, nil)
	p.SetConnections([]*Connection{{Key: "candidate"}})
	first, _ := p.AcquireCandidateForChecking("candidate")
	p.CancelChecking(first)
	second, _ := p.AcquireCandidateForChecking("candidate")
	if p.CommitCandidateOutcome(first, true, 100, 100, 500, time.Millisecond) {
		t.Fatal("stale initial completion accepted against newer lease")
	}
	if _, ok := p.CompleteRecheck(ResolverRecheckResult{Connection: first, MTUVerified: true}); ok {
		t.Fatal("stale recheck completion accepted against newer lease")
	}
	p.CancelChecking(first)
	p.ReleaseRecheck(first)
	if st, _ := p.CandidateState("candidate"); st != StateChecking {
		t.Fatal("stale cleanup released newer lease")
	}
	if !p.CommitCandidateOutcome(second, true, 100, 100, 500, time.Millisecond) {
		t.Fatal("current lease completion rejected")
	}
}

func admitPoolTestBatch(p *ResolverPool, results []QualifiedResolver) {
	leasedResults := append([]QualifiedResolver(nil), results...)
	for i := range leasedResults {
		result := &leasedResults[i]
		original := result.Connection
		lease, ok := p.AcquireCandidateForChecking(original.Key)
		if !ok {
			lease, _ = p.GetConnectionByKey(original.Key)
		}
		if original.UploadMTUBytes > 0 || original.DownloadMTUBytes > 0 {
			p.SetCheckingMTU(lease, CandidateMTUParams{UploadBytes: original.UploadMTUBytes, UploadChars: original.UploadMTUChars, DownloadBytes: original.DownloadMTUBytes, ResolveTime: original.MTUResolveTime})
		}
		result.Connection = candidateSnapshotForTest(p, original.Key)
	}
	p.AdmitStartupBatch(leasedResults)
}

func checkingCandidatesForTest(p *ResolverPool, conns []Connection, up, down int) []Connection {
	leased := make([]Connection, 0, len(conns))
	for _, conn := range conns {
		c, ok := p.AcquireCandidateForChecking(conn.Key)
		if !ok {
			panic("fixture could not acquire qualification lease")
		}
		if conn.UploadMTUBytes > 0 {
			up = conn.UploadMTUBytes
		}
		if conn.DownloadMTUBytes > 0 {
			down = conn.DownloadMTUBytes
		}
		p.SetCheckingMTU(c, CandidateMTUParams{UploadBytes: up, UploadChars: up, DownloadBytes: down})
		leased = append(leased, candidateSnapshotForTest(p, conn.Key))
	}
	return leased
}

func TestBackgroundBurstLimitsActualQueryStarts(t *testing.T) {
	listener, port, count := startMockMTUDNSListener(t, "v.example.com")
	defer listener.Close()
	cfg := config.DefaultClientConfig()
	cfg.DataEncryptionMethod = 0
	cfg.Domains = []string{"v.example.com"}
	cfg.Resolvers = []config.ResolverAddress{{IP: "127.0.0.1", Port: port}}
	c := createTestFastStartClient(t, cfg)
	conn := c.pool.AllConnections()[0]
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	transport, err := c.newUDPQueryTransport(ctx, conn.ResolverLabel)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.conn.Close()
	limiter := NewBackgroundQueryLimiter(10, 1)
	started := time.Now()
	result := c.sendPipelinedMicroBurst(ctx, conn, transport, 32, 400, 100, 350*time.Millisecond, limiter)
	if result.SentCount != int(count.Load()) || result.LossRatio != 0 || !result.Incomplete || result.Qualified {
		t.Fatalf("budget interruption fabricated network loss or qualification: %+v", result)
	}
	elapsed := time.Since(started)
	// Bound all actual sends, including a train larger than the bucket capacity.
	maxStarts := int32(1 + int(elapsed.Seconds()*10))
	if got := count.Load(); got == 0 || got > maxStarts {
		t.Fatalf("actual background query starts=%d, budget=%d over %s", got, maxStarts, elapsed)
	}
	if elapsed >= time.Second {
		t.Fatalf("sender outlived bounded probe: %s", elapsed)
	}
}

func TestRateLimitedRecoveryFinishesConfiguredBurst(t *testing.T) {
	listener, port, queries := startMockMTUDNSListener(t, "v.example.com")
	defer listener.Close()
	cfg := config.DefaultClientConfig()
	cfg.DataEncryptionMethod = 0
	cfg.Domains = []string{"v.example.com"}
	cfg.Resolvers = []config.ResolverAddress{{IP: "127.0.0.1", Port: port}}
	cfg.RecheckBurstTestEnabled, cfg.RecheckBurstPacketCount = true, 32
	// Exercise completion through the budget, not a tight wall-clock deadline:
	// coarse host timers can consume the old 350ms response allowance while
	// pacing 32 queries. The exact query count and token budget remain asserted.
	cfg.MTUTestTimeout, cfg.MTUTestRetries = 1, 1
	c := createTestFastStartClient(t, cfg)
	c.syncedUploadMTU, c.syncedDownloadMTU = 100, 400
	c.pool.SetSessionMTU(100, 400)
	c.SetBackgroundQueryLimiter(NewBackgroundQueryLimiter(10, 1))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _ := c.pool.AcquireNextInactiveForRecheck(time.Now(), 0)
	started := time.Now()
	c.recheckInactiveResolver(ctx, conn)
	state, _ := c.pool.CandidateState(conn.Key)
	if state != StateActive || queries.Load() != 34 {
		t.Fatalf("healthy rate-limited recovery state=%v, queries=%d", state, queries.Load())
	}
	if int(queries.Load()) > 1+int(time.Since(started).Seconds()*10) {
		t.Fatal("query starts exceeded token budget")
	}
	if c.pool.GetStatsSnapshot()[0].BurstThroughputKBps != 0 {
		t.Fatal("scheduler-paced throughput reported as measured capacity")
	}
}

func TestFullScanKeepsContinuingCoveragePolicy(t *testing.T) {
	for _, burst := range []bool{false, true} {
		t.Run(fmt.Sprintf("burst=%t", burst), func(t *testing.T) {
			p := NewResolverPool(2, nil)
			p.SetConnections([]*Connection{
				{Key: "a1", ResolverLabel: "A"}, {Key: "a2", ResolverLabel: "A"},
				{Key: "b", ResolverLabel: "B"},
			})
			fake := NewFakeResolverProber()
			fake.SetMTUResponse("b", MTUProbeResult{Success: true, UploadBytes: 100, DownloadBytes: 500, ResolveTime: time.Second})
			fake.SetBurstResponse("b", BurstProbeResult{Qualified: true, SentCount: 4, ReceivedCount: 4, AverageRTT: time.Second})
			e := NewDiscoveryEngine(DiscoveryConfig{FastStart: false, TargetResolvers: 1, Parallelism: 1, MicroBurstEnabled: burst}, fake, p, nil)
			if err := e.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !p.IsFirstPassComplete() || p.TargetEndpoints() != 1 {
				t.Fatalf("full scan changed continuing policy: %+v target=%d", p.CoverageStats(), p.TargetEndpoints())
			}
			if state, _ := p.CandidateState("b"); state != StateStandby {
				t.Fatalf("slow distinct endpoint displaced a qualified path: %v", state)
			}
		})
	}
}

func TestRecoveryFairnessUsesDistinctActiveEndpoints(t *testing.T) {
	p := NewResolverPool(2, nil)
	p.SetTargetEndpoints(2)
	p.SetConnections([]*Connection{
		{Key: "a1", ResolverLabel: "A"}, {Key: "a2", ResolverLabel: "A"},
		{Key: "b", ResolverLabel: "B"}, {Key: "new1", ResolverLabel: "C"}, {Key: "new2", ResolverLabel: "D"},
	})
	for _, key := range []string{"a1", "a2"} {
		p.ApplyMTUProbeResult(key, 100, 100, 500, time.Millisecond, true)
	}
	b, _ := p.AcquireCandidateForChecking("b")
	p.CommitCandidateOutcome(b, false, 0, 0, 0, 0)
	lease, ok := p.AcquireNextInactiveForRecheck(time.Now(), 0)
	if !ok || lease.Key != "b" {
		t.Fatalf("duplicate Active Paths hid missing endpoint coverage: lease=%+v ok=%t", lease, ok)
	}
	p.ReleaseRecheck(lease)
	lease, ok = p.AcquireNextInactiveForRecheck(time.Now(), 0)
	if !ok || (lease.Key != "new1" && lease.Key != "new2") {
		t.Fatalf("recovery scheduling starved untested paths: %+v", lease)
	}
}

func TestPoolEvaluationSeparatesQualificationAndLiveEvidence(t *testing.T) {
	p := NewResolverPool(1, nil)
	p.SetConnections([]*Connection{{Key: "a", ResolverLabel: "A"}})
	lease, _ := p.AcquireCandidateForChecking("a")
	p.SetCheckingMTU(lease, CandidateMTUParams{UploadBytes: 100, DownloadBytes: 500, ResolveTime: 80 * time.Millisecond})
	// The health scheduling timestamp is deliberately unrelated to observation time.
	p.candidates[0].conn.LastHealthCheckAt = time.Unix(1, 0)
	p.AdmitStartupBatch([]QualifiedResolver{{Connection: lease, BurstResult: BurstProbeResult{
		Qualified: true, SentCount: 4, ReceivedCount: 3, AverageRTT: 40 * time.Millisecond, BurstThroughputKBps: 100,
	}}})
	qualification := *p.GetStatsSnapshot()[0].Evaluation
	if qualification.RTTSource != SourceQualification || qualification.LossSource != SourceQualification || qualification.SampleCount != 4 || qualification.LossRatio != 0.25 {
		t.Fatalf("qualification incorrectly labeled as live: %+v", qualification)
	}
	if qualification.RTTObservedAt.IsZero() || qualification.LossObservedAt.IsZero() || qualification.ThroughputObservedAt.IsZero() || qualification.RTTObservedAt.Equal(time.Unix(1, 0)) {
		t.Fatalf("qualification age uses lease scheduling timestamp: %+v", qualification)
	}
	b := NewBalancer(BalancingCommonScore, nil, p)
	b.ReportSend("a")
	b.ReportSuccess("a", 10*time.Millisecond)
	liveSnapshot := p.GetStatsSnapshot()[0]
	live := *liveSnapshot.Evaluation
	if live.RTTSource != SourceLiveTraffic || live.LossSource != SourceQualification || live.RTT != 10*time.Millisecond || live.SampleCount != 4 || live.LossRatio != 0.25 {
		t.Fatalf("seeded samples contaminated live evaluation: %+v", live)
	}
	if live.RTTObservedAt.Before(qualification.RTTObservedAt) || !live.ThroughputObservedAt.Equal(qualification.ThroughputObservedAt) {
		t.Fatalf("per-measurement ages were lost: qualification=%+v live=%+v", qualification, live)
	}
	_, displayedScore, _ := calculateResolverRuntimeSpeedAndScore(liveSnapshot)
	if displayedScore != formatScoreString(p.CalculateConnectionScore("a")) {
		t.Fatalf("diagnostics and pool evaluation disagree: %s", displayedScore)
	}
	// An isolated live timeout must not erase a larger qualification sample.
	b.ReportTimeout("a", time.Now(), time.Second, 1)
	if ev := p.GetStatsSnapshot()[0].Evaluation; ev.CompositeScore == 0 || ev.LossSource != SourceQualification {
		t.Fatalf("one timeout overrode qualification evidence: %+v", ev)
	}
	b.RetractTimeout("a", time.Now(), time.Second)
	// A qualification-sized live window takes over, including sustained loss.
	for range 3 {
		b.ReportSend("a")
	}
	for range 4 {
		b.ReportTimeout("a", time.Now(), time.Second, 1)
	}
	if ev := p.GetStatsSnapshot()[0].Evaluation; ev.CompositeScore != 0 || ev.LostCount != 4 || ev.LossSource != SourceLiveTraffic {
		t.Fatalf("sustained live loss not included: %+v", ev)
	}
	b.RetractTimeout("a", time.Now(), time.Second)
	if ev := p.GetStatsSnapshot()[0].Evaluation; ev.LostCount != 3 {
		t.Fatalf("retracted timeout remained in evaluation: %+v", ev)
	}
}

func TestDiscoverySkipsCandidatesOwnedElsewhere(t *testing.T) {
	for _, parallelism := range []int{1, 2} {
		for _, fastStart := range []bool{false, true} {
			t.Run(fmt.Sprintf("workers=%d/fast=%t", parallelism, fastStart), func(t *testing.T) {
				p := NewResolverPool(3, nil)
				p.SetConnections([]*Connection{
					{Key: "active", ResolverLabel: "A"}, {Key: "checking", ResolverLabel: "B"},
					{Key: "new", ResolverLabel: "C"},
				})
				p.ApplyMTUProbeResult("active", 200, 250, 500, time.Millisecond, true)
				otherLease, _ := p.AcquireCandidateForChecking("checking")
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				fake := NewFakeResolverProber()
				e := NewDiscoveryEngine(DiscoveryConfig{FastStart: fastStart, TargetResolvers: 3, Parallelism: parallelism, MicroBurstEnabled: true}, fake, p, nil)
				if err := e.Run(ctx); err != nil {
					t.Fatalf("discovery did not skip unavailable leases: %v", err)
				}
				if p.ActiveCount() != 2 || fake.MTUProbedCount() != 1 {
					t.Fatalf("existing Active Path lost or available candidate skipped: active=%d probes=%v", p.ActiveCount(), fake.ProbedMTUKeys())
				}
				if state, _ := p.CandidateState("checking"); state != StateChecking {
					t.Fatalf("discovery changed another owner's lease: %v", state)
				}
				p.CancelChecking(otherLease)
			})
		}
	}
}

func TestLiveOnlyLossNeedsNoQualificationWarmup(t *testing.T) {
	ev := EvaluateCandidateObservation(CandidateObservationInput{MTUResolveTime: time.Millisecond, LiveSentCount: 1, LiveLostCount: 1})
	if ev.CompositeScore != 0 || ev.LossSource != SourceLiveTraffic || ev.LossRatio != 1 {
		t.Fatalf("live-only loss was ignored: %+v", ev)
	}
}

func TestBalancerStrategyChangesDuringSelection(t *testing.T) {
	b := NewBalancer(BalancingCommonScore, nil)
	b.SetConnections([]*Connection{{Key: "a", ResolverLabel: "A"}, {Key: "b", ResolverLabel: "B"}})
	b.ApplyMTUProbeResult("a", 100, 100, 500, time.Millisecond, true)
	b.ApplyMTUProbeResult("b", 100, 100, 500, 2*time.Millisecond, true)
	b.EnsureStream(1)
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := range 1000 {
			b.SetStrategy(i % (BalancingCommonScore + 1))
		}
	}()
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 1000 {
				if _, ok := b.GetBestConnection(); !ok {
					t.Error("strategy update lost the Active working set")
					return
				}
				if _, ok := b.GetBestConnectionExcluding("a"); !ok {
					t.Error("strategy update lost the alternate endpoint")
					return
				}
				if targets, err := b.SelectTargets(uint8(Enums.PACKET_STREAM_DATA), 1, 2); err != nil || len(targets) != 2 {
					t.Errorf("strategy update broke Stream selection: %+v %v", targets, err)
					return
				}
				if len(b.GetUniqueConnections(2)) != 2 {
					t.Error("strategy update lost Duplication capacity")
					return
				}
				_ = b.Strategy()
			}
		}()
	}
	close(start)
	wg.Wait()
}

func TestStreamFailoverPrefersAnotherEndpoint(t *testing.T) {
	b := NewBalancer(BalancingCommonScore, nil)
	b.SetStreamFailoverConfig(1, 0)
	b.SetConnections([]*Connection{
		{Key: "a1", ResolverLabel: "A", Domain: "one"}, {Key: "a2", ResolverLabel: "A", Domain: "two"},
		{Key: "b", ResolverLabel: "B", Domain: "one"},
	})
	for i, key := range []string{"a1", "a2", "b"} {
		b.ApplyMTUProbeResult(key, 100, 100, 500, time.Duration(i+1)*time.Millisecond, true)
	}
	b.EnsureStream(1)
	initial, err := b.SelectTargets(uint8(Enums.PACKET_STREAM_DATA), 1, 2)
	if err != nil || len(initial) == 0 || initial[0].Key != "a1" {
		t.Fatalf("initial preference: %+v %v", initial, err)
	}
	failedOver, err := b.SelectTargets(uint8(Enums.PACKET_STREAM_RESEND), 1, 2)
	if err != nil || len(failedOver) == 0 || failedOver[0].Key != "b" {
		t.Fatalf("failover retried the same endpoint: %+v %v", failedOver, err)
	}
	b.SetConnectionValidity("b", false)
	if fallback, ok := b.selectAlternateConnectionLocked(b.pool.ActiveResolvers(), "a1"); !ok || fallback.Key != "a2" {
		t.Fatalf("single-endpoint fallback lost: %+v ok=%t", fallback, ok)
	}
}
