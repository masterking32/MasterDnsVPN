// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"fmt"
	"math"
	"time"
)

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
	downloadMTU := m.DownloadMTUBytes
	if downloadMTU <= 0 {
		downloadMTU = 500
	}

	lossRatio := m.LossRatio
	if math.IsNaN(lossRatio) || lossRatio > 1.0 {
		lossRatio = 1.0
	} else if lossRatio < 0.0 {
		lossRatio = 0.0
	}

	speedKBps := m.ThroughputKBps
	if math.IsNaN(speedKBps) || math.IsInf(speedKBps, 0) || speedKBps <= 0.0 {
		speedKBps = 0.0
		if m.RTT > 0 {
			rttSec := m.RTT.Seconds()
			if rttSec > 0.0 {
				speedKBps = (float64(downloadMTU) / 1024.0) / rttSec
			}
		}
	}
	if math.IsNaN(speedKBps) || math.IsInf(speedKBps, 0) || speedKBps < 0.0 {
		speedKBps = 0.0
	}

	if m.RTT <= 0 {
		tier, badge := ResolverQualityTier(0.0)
		return ResolverEvaluation{
			CompositeScore: 0.0,
			ThroughputKBps: speedKBps,
			Tier:           tier,
			ColoredBadge:   badge,
		}
	}

	rttMillis := float64(m.RTT.Milliseconds())
	latencyPenalty := 1.0 + (rttMillis / 500.0)
	if latencyPenalty < 1.0 || math.IsNaN(latencyPenalty) {
		latencyPenalty = 1.0
	}

	effectiveThroughput := speedKBps * (1.0 - lossRatio)
	if math.IsNaN(effectiveThroughput) || effectiveThroughput < 0.0 {
		effectiveThroughput = 0.0
	}

	compositeScore := effectiveThroughput / latencyPenalty
	if math.IsNaN(compositeScore) || math.IsInf(compositeScore, 0) || compositeScore < 0.0 {
		compositeScore = 0.0
	}
	tier, badge := ResolverQualityTier(compositeScore)

	return ResolverEvaluation{
		CompositeScore: compositeScore,
		ThroughputKBps: speedKBps,
		Tier:           tier,
		ColoredBadge:   badge,
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
