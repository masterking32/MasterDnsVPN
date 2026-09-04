// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"fmt"
	"time"
)

// CalculateResolverScore computes the unified baseline speed and composite score
// for a resolver based on its download MTU, RTT, and packet loss ratio.
// Speed represents the theoretical single-request baseline throughput capacity:
//
//	Speed (KB/s) = (DownloadMTU / 1024) / RTT_seconds
//	Score        = Speed * (1 - LossRatio) / (1 + RTT_ms / 500)
func CalculateResolverScore(downloadMTU int, rtt time.Duration, lossRatio float64) (speedKBps float64, score float64) {
	if downloadMTU <= 0 {
		downloadMTU = 500
	}
	if lossRatio < 0 {
		lossRatio = 0
	} else if lossRatio > 1.0 {
		lossRatio = 1.0
	}
	if rtt <= 0 {
		return 0, 0
	}
	rttSec := rtt.Seconds()
	if rttSec <= 0 {
		return 0, 0
	}

	speedKBps = (float64(downloadMTU) / 1024.0) / rttSec
	rttMillis := float64(rtt.Milliseconds())
	latencyPenalty := 1.0 + (rttMillis / 500.0)
	effectiveThroughput := speedKBps * (1.0 - lossRatio)
	if effectiveThroughput < 0 {
		effectiveThroughput = 0
	}
	score = effectiveThroughput / latencyPenalty
	return speedKBps, score
}

// FormatResolverSpeed formats speed in KB/s or MB/s consistently.
func FormatResolverSpeed(speedKBps float64) string {
	if speedKBps <= 0 {
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
