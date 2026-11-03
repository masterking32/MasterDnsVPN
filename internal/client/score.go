// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (score.go) centralizes candidate evaluation across startup ranking,
// pool comparison, saved endpoint ordering, and runtime diagnostics.
//
// Scoring distinctions:
//   - Shared Evaluation: Computes an immutable snapshot of candidate quality from
//     available observations (RTT, loss, throughput). Missing or invalid data is
//     safely bounded and never produces an artificial perfect score.
//   - Throughput: Empirical micro-burst throughput is used when measured; otherwise
//     baseline estimated throughput derived from (DownloadMTU / RTT) is labeled as estimated.
//   - Saved Ordering: Prioritizes Active over Standby members without altering or boosting
//     the underlying composite quality scores.
//   - Traffic Policies: Independent routing algorithms (e.g. Round Robin, Lowest Latency)
//     operate on active pool members without altering admission, qualification, or evaluation.
package client

import (
	"fmt"
	"math"
	"time"
)

// MeasurementSource identifies where a performance measurement was obtained.
type MeasurementSource int

const (
	SourceUnknown MeasurementSource = iota
	SourceQualification
	SourceLiveTraffic
	SourceBurstProbe
	SourceEstimate
)

func (s MeasurementSource) String() string {
	switch s {
	case SourceQualification:
		return "Qualification"
	case SourceLiveTraffic:
		return "LiveTraffic"
	case SourceBurstProbe:
		return "MeasuredBurst"
	case SourceEstimate:
		return "Estimated"
	default:
		return "Unknown"
	}
}

// CandidateObservationInput supplies raw observations from qualification or live runtime.
type CandidateObservationInput struct {
	UploadMTUBytes      int
	DownloadMTUBytes    int
	MTUResolveTime      time.Duration
	BurstThroughputKBps float64
	LiveRTT             time.Duration
	LiveLossRatio       float64
	LiveSentCount       uint64
	LiveLostCount       uint64
	ObservedAt          time.Time // Compatibility timestamp for direct callers.
	MTUObservedAt       time.Time
	MTURTTObservedAt    time.Time
	BurstObservedAt     time.Time
	QualificationRTT    time.Duration
	QualificationSent   uint64
	QualificationLost   uint64
	QualificationAt     time.Time
	LiveRTTAt           time.Time
	LiveLossAt          time.Time
}

// ResolverEvaluationSnapshot encapsulates an immutable standardized explanation of candidate quality.
type ResolverEvaluationSnapshot struct {
	UploadMTUBytes       int
	DownloadMTUBytes     int
	RTT                  time.Duration
	RTTSource            MeasurementSource
	LossRatio            float64
	LossSource           MeasurementSource
	ThroughputKBps       float64
	ThroughputIsMeasured bool
	ThroughputSource     MeasurementSource
	CompositeScore       float64
	Tier                 string
	ColoredBadge         string
	ObservedAt           time.Time
	RTTObservedAt        time.Time
	LossObservedAt       time.Time
	ThroughputObservedAt time.Time
	SampleCount          uint64
	LostCount            uint64
}

// EvaluateCandidateObservation centralizes input selection and score calculation into
// one immutable evaluation snapshot consumed by diagnostics, pool comparison, and ranking.
func EvaluateCandidateObservation(obs CandidateObservationInput) ResolverEvaluationSnapshot {
	downloadMTU := obs.DownloadMTUBytes
	if downloadMTU <= 0 {
		downloadMTU = 500
	}

	// 1. Select RTT and source
	var rtt time.Duration
	var rttSource MeasurementSource
	rttAt := obs.ObservedAt
	if obs.LiveSentCount > 0 && obs.LiveRTT > 0 {
		rtt = obs.LiveRTT
		rttSource = SourceLiveTraffic
		rttAt = obs.LiveRTTAt
	} else if obs.QualificationRTT > 0 {
		rtt = obs.QualificationRTT
		rttSource = SourceQualification
		rttAt = obs.QualificationAt
	} else if obs.MTUResolveTime > 0 {
		rtt = obs.MTUResolveTime
		rttSource = SourceQualification
		rttAt = obs.MTURTTObservedAt
		if rttAt.IsZero() {
			rttAt = obs.MTUObservedAt
		}
	} else {
		rtt = 0
		rttSource = SourceUnknown
	}

	// 2. Select LossRatio and source
	var lossRatio float64
	var lossSource MeasurementSource
	lossAt := obs.ObservedAt
	sampleCount, lostCount := obs.LiveSentCount, obs.LiveLostCount
	// Match the qualification sample size before replacing its loss evidence.
	// This uses the existing probe count rather than adding a tuning threshold;
	// live-only paths can still score immediately when no qualification exists.
	if obs.LiveSentCount > 0 && (obs.QualificationSent == 0 || obs.LiveSentCount >= obs.QualificationSent) {
		lossRatio = obs.LiveLossRatio
		lossSource = SourceLiveTraffic
		lossAt = obs.LiveLossAt
		if obs.LiveLostCount >= obs.LiveSentCount {
			lossRatio = 1.0
		}
	} else if obs.QualificationSent > 0 {
		sampleCount, lostCount = obs.QualificationSent, obs.QualificationLost
		lossRatio = float64(lostCount) / float64(sampleCount)
		lossSource = SourceQualification
		lossAt = obs.QualificationAt
	} else {
		lossSource = SourceUnknown
	}

	if math.IsNaN(lossRatio) || lossRatio > 1.0 {
		lossRatio = 1.0
	} else if lossRatio < 0.0 {
		lossRatio = 0.0
	}

	// 3. Select Throughput and source
	var speedKBps float64
	var isMeasured bool
	var speedSource MeasurementSource
	speedAt := obs.ObservedAt

	burst := obs.BurstThroughputKBps
	if !math.IsNaN(burst) && !math.IsInf(burst, 0) && burst > 0.0 {
		speedKBps = burst
		isMeasured = true
		speedSource = SourceBurstProbe
		speedAt = obs.BurstObservedAt
	} else if rtt > 0 {
		rttSec := rtt.Seconds()
		if rttSec > 0.0 {
			speedKBps = (float64(downloadMTU) / 1024.0) / rttSec
		}
		isMeasured = false
		speedSource = SourceEstimate
		speedAt = rttAt
		if !obs.MTUObservedAt.IsZero() && (speedAt.IsZero() || obs.MTUObservedAt.Before(speedAt)) {
			speedAt = obs.MTUObservedAt
		}
	} else {
		speedKBps = 0.0
		isMeasured = false
		speedSource = SourceUnknown
	}
	if math.IsNaN(speedKBps) || math.IsInf(speedKBps, 0) || speedKBps < 0.0 {
		speedKBps = 0.0
	}

	// 4. Calculate Composite Score
	var compositeScore float64
	if rtt <= 0 || lossRatio >= 1.0 {
		compositeScore = 0.0
	} else {
		rttMillis := float64(rtt.Milliseconds())
		latencyPenalty := 1.0 + (rttMillis / 500.0)
		if latencyPenalty < 1.0 || math.IsNaN(latencyPenalty) {
			latencyPenalty = 1.0
		}

		effectiveThroughput := speedKBps * (1.0 - lossRatio)
		if math.IsNaN(effectiveThroughput) || effectiveThroughput < 0.0 {
			effectiveThroughput = 0.0
		}

		compositeScore = effectiveThroughput / latencyPenalty
		if math.IsNaN(compositeScore) || math.IsInf(compositeScore, 0) || compositeScore < 0.0 {
			compositeScore = 0.0
		}
	}

	tier, badge := ResolverQualityTier(compositeScore)

	return ResolverEvaluationSnapshot{
		UploadMTUBytes:       obs.UploadMTUBytes,
		DownloadMTUBytes:     downloadMTU,
		RTT:                  rtt,
		RTTSource:            rttSource,
		LossRatio:            lossRatio,
		LossSource:           lossSource,
		ThroughputKBps:       speedKBps,
		ThroughputIsMeasured: isMeasured,
		ThroughputSource:     speedSource,
		CompositeScore:       compositeScore,
		Tier:                 tier,
		ColoredBadge:         badge,
		ObservedAt:           rttAt,
		RTTObservedAt:        rttAt,
		LossObservedAt:       lossAt,
		ThroughputObservedAt: speedAt,
		SampleCount:          sampleCount,
		LostCount:            lostCount,
	}
}

func formatScoreString(score float64) string {
	if math.IsNaN(score) || math.IsInf(score, 0) || score <= 0.0 {
		return "0.0"
	}
	return fmt.Sprintf("%.1f", score)
}

// ResolverMetrics encapsulates all observable performance inputs for a resolver.
type ResolverMetrics struct {
	// DownloadMTUBytes is the confirmed downstream payload capacity in bytes.
	// Defaults to 500 if <= 0.
	DownloadMTUBytes int

	// RTT is the round-trip latency measured for DNS transactions.
	RTT time.Duration

	// LossRatio is the packet drop rate, bounded within [0.0, 1.0].
	LossRatio float64

	// ThroughputKBps is the optional empirical throughput in KB/s (e.g. from micro-bursts).
	// If <= 0, baseline throughput is computed from DownloadMTUBytes and RTT.
	ThroughputKBps float64
}

// ResolverEvaluation contains the standardized evaluation results.
type ResolverEvaluation struct {
	// CompositeScore is the latency-penalized, loss-adjusted performance rating.
	CompositeScore float64

	// ThroughputKBps is the effective throughput in KB/s.
	ThroughputKBps float64

	// Tier is the qualitative tier ("Excellent", "Good", "Fair", "Poor").
	Tier string

	// ColoredBadge is the ANSI/log-formatted badge string.
	ColoredBadge string
}

// EvaluateResolver computes the unified performance metrics, composite score,
// and quality tier classification for a resolver without side effects.
func EvaluateResolver(m ResolverMetrics) ResolverEvaluation {
	ev := EvaluateCandidateObservation(CandidateObservationInput{
		DownloadMTUBytes:    m.DownloadMTUBytes,
		MTUResolveTime:      m.RTT,
		BurstThroughputKBps: m.ThroughputKBps,
		LiveRTT:             m.RTT,
		LiveLossRatio:       m.LossRatio,
		LiveSentCount:       1,
	})
	return ResolverEvaluation{
		CompositeScore: ev.CompositeScore,
		ThroughputKBps: ev.ThroughputKBps,
		Tier:           ev.Tier,
		ColoredBadge:   ev.ColoredBadge,
	}
}

// CalculateResolverScore provides backward compatibility by delegating to EvaluateResolver.
// Speed represents the theoretical single-request baseline throughput capacity:
//
//	Speed (KB/s) = (DownloadMTU / 1024) / RTT_seconds
//	Score        = Speed * (1 - LossRatio) / (1 + RTT_ms / 500)
func CalculateResolverScore(downloadMTU int, rtt time.Duration, lossRatio float64) (speedKBps float64, score float64) {
	ev := EvaluateResolver(ResolverMetrics{
		DownloadMTUBytes: downloadMTU,
		RTT:              rtt,
		LossRatio:        lossRatio,
	})
	return ev.ThroughputKBps, ev.CompositeScore
}

// FormatResolverSpeed formats speed in KB/s or MB/s consistently.
func FormatResolverSpeed(speedKBps float64) string {
	if math.IsNaN(speedKBps) || math.IsInf(speedKBps, 0) || speedKBps <= 0 {
		return "n/a"
	}
	if speedKBps >= 1000.0 {
		return fmt.Sprintf("%.2f MB/s", speedKBps/1024.0)
	}
	return fmt.Sprintf("%.1f KB/s", speedKBps)
}

// ResolverQualityTier returns the quality tier label and colored badge for a score.
func ResolverQualityTier(score float64) (tier string, coloredBadge string) {
	switch {
	case score >= 15.0:
		return "Excellent", "<green>[EXCELLENT]</green>"
	case score >= 8.0:
		return "Good", "<cyan>[GOOD]</cyan>"
	case score >= 4.0:
		return "Fair", "<yellow>[FAIR]</yellow>"
	default:
		return "Poor", "<red>[POOR]</red>"
	}
}
