package client

import (
	"math"
	"testing"
	"time"

	"masterdnsvpn-go/internal/logger"
)

// TestScore_SharedEvaluation_ConsistentQuality verifies that the same observations
// produce identical scores regardless of caller (diagnostics, pool comparison, ranking).
func TestScore_SharedEvaluation_ConsistentQuality(t *testing.T) {
	log := logger.New("TestLogger", "debug")
	pool := NewResolverPool(2, log)
	pool.SetSessionMTU(1000, 1000)

	conn := &Connection{
		Domain:           "tunnel.example.com",
		Resolver:         "1.1.1.1",
		ResolverPort:     53,
		ResolverLabel:    "1.1.1.1:53",
		Key:              "1.1.1.1:53#tunnel.example.com",
		DownloadMTUBytes: 1200,
		UploadMTUBytes:   1200,
		MTUResolveTime:   50 * time.Millisecond,
	}
	pool.SetConnections([]*Connection{conn})
	pool.AcquireCandidateForChecking(conn.Key)
	pool.CommitCandidateOutcome(candidateSnapshotForTest(pool, conn.Key), true, 1200, 1200, 1200, 50*time.Millisecond)

	// 1. Direct evaluation from shared function
	obs := CandidateObservationInput{
		UploadMTUBytes:   1200,
		DownloadMTUBytes: 1200,
		MTUResolveTime:   50 * time.Millisecond,
	}
	ev := EvaluateCandidateObservation(obs)
	if ev.CompositeScore <= 0 {
		t.Fatalf("expected positive score, got %v", ev.CompositeScore)
	}

	// 2. Score reported by pool comparison
	poolScore := pool.CalculateConnectionScore(conn.Key)
	if math.Abs(poolScore-ev.CompositeScore) > 1e-6 {
		t.Fatalf("pool score (%v) does not match shared evaluation (%v)", poolScore, ev.CompositeScore)
	}

	// 3. No artificial active bonus in score
	if poolScore >= 1000.0 {
		t.Fatalf("score should not include artificial 1000.0 bonus; got %v", poolScore)
	}

	// 4. Runtime stats diagnostic produces matching score
	snap := ResolverStatsSnapshot{
		Connection: *conn,
		AverageRTT: 50 * time.Millisecond,
		Sent:       10,
		Acked:      10,
		Lost:       0,
	}
	_, scoreStr, _ := calculateResolverRuntimeSpeedAndScore(snap)
	expectedScoreStr := formatScoreString(ev.CompositeScore)
	if scoreStr != expectedScoreStr {
		t.Fatalf("runtime stats score string (%s) did not match expected (%s)", scoreStr, expectedScoreStr)
	}
}

// TestScore_Throughput_MeasuredVsEstimatedFallback verifies that measured burst throughput
// is used when available, and download-MTU/RTT throughput estimate is used as fallback.
func TestScore_Throughput_MeasuredVsEstimatedFallback(t *testing.T) {
	// Baseline: 1200 bytes download MTU, 50ms RTT -> (1200/1024)/0.05 = ~23.4375 KB/s
	obsEstimated := CandidateObservationInput{
		DownloadMTUBytes: 1200,
		MTUResolveTime:   50 * time.Millisecond,
	}
	evEstimated := EvaluateCandidateObservation(obsEstimated)
	if evEstimated.ThroughputIsMeasured {
		t.Fatalf("expected estimated throughput, but ThroughputIsMeasured was true")
	}
	expectedEstimate := (1200.0 / 1024.0) / 0.05
	if math.Abs(evEstimated.ThroughputKBps-expectedEstimate) > 0.01 {
		t.Fatalf("expected estimated throughput ~%v, got %v", expectedEstimate, evEstimated.ThroughputKBps)
	}

	// Override with empirical burst throughput (e.g. 150 KB/s)
	obsMeasured := CandidateObservationInput{
		DownloadMTUBytes:    1200,
		MTUResolveTime:      50 * time.Millisecond,
		BurstThroughputKBps: 150.0,
	}
	evMeasured := EvaluateCandidateObservation(obsMeasured)
	if !evMeasured.ThroughputIsMeasured {
		t.Fatalf("expected measured burst throughput, but ThroughputIsMeasured was false")
	}
	if math.Abs(evMeasured.ThroughputKBps-150.0) > 1e-6 {
		t.Fatalf("expected measured throughput 150.0, got %v", evMeasured.ThroughputKBps)
	}
	if evMeasured.CompositeScore <= evEstimated.CompositeScore {
		t.Fatalf("higher measured throughput should produce higher composite score")
	}
}

// TestScore_EdgeCases_FullLossAndInvalidNumbers verifies that 100% loss yields 0 score,
// and NaN/Inf inputs are sanitized safely.
func TestScore_EdgeCases_FullLossAndInvalidNumbers(t *testing.T) {
	// Full loss
	obsFullLoss := CandidateObservationInput{
		DownloadMTUBytes: 1200,
		MTUResolveTime:   50 * time.Millisecond,
		LiveSentCount:    10,
		LiveLostCount:    10,
		LiveLossRatio:    1.0,
	}
	evFullLoss := EvaluateCandidateObservation(obsFullLoss)
	if evFullLoss.CompositeScore != 0.0 {
		t.Fatalf("expected 0 score on 100%% loss, got %v", evFullLoss.CompositeScore)
	}

	// NaN/Inf sanitization
	obsInvalid := CandidateObservationInput{
		DownloadMTUBytes:    -5,
		MTUResolveTime:      -10 * time.Millisecond,
		BurstThroughputKBps: math.NaN(),
		LiveLossRatio:       math.Inf(1),
	}
	evInvalid := EvaluateCandidateObservation(obsInvalid)
	if math.IsNaN(evInvalid.CompositeScore) || math.IsInf(evInvalid.CompositeScore, 0) || evInvalid.CompositeScore < 0 {
		t.Fatalf("invalid input produced unsanitized composite score: %v", evInvalid.CompositeScore)
	}
}
