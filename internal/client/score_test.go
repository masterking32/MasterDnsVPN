// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"math"
	"testing"
	"time"
)

func TestScore_EvaluateResolver_MTUDefaults(t *testing.T) {
	// Baseline with default MTU (500) and 100ms RTT
	rtt := 100 * time.Millisecond
	expectedBaseline := (500.0 / 1024.0) / rtt.Seconds()

	testCases := []struct {
		name        string
		downloadMTU int
		expectSpeed float64
	}{
		{
			name:        "Zero MTU defaults to 500",
			downloadMTU: 0,
			expectSpeed: expectedBaseline,
		},
		{
			name:        "Negative MTU defaults to 500",
			downloadMTU: -100,
			expectSpeed: expectedBaseline,
		},
		{
			name:        "Explicit 1200 MTU is respected",
			downloadMTU: 1200,
			expectSpeed: (1200.0 / 1024.0) / rtt.Seconds(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ev := EvaluateResolver(ResolverMetrics{
				DownloadMTUBytes: tc.downloadMTU,
				RTT:              rtt,
				LossRatio:        0.0,
			})
			if math.Abs(ev.ThroughputKBps-tc.expectSpeed) > 0.001 {
				t.Fatalf("expected ThroughputKBps %f, got %f", tc.expectSpeed, ev.ThroughputKBps)
			}
		})
	}
}

func TestScore_EvaluateResolver_LossRatioClamping(t *testing.T) {
	rtt := 100 * time.Millisecond
	// Baseline throughput with 1024 bytes and 100ms = (1024/1024)/0.1 = 10.0 KB/s
	// Latency penalty for 100ms = 1.0 + 100/500 = 1.2
	// For 0% loss: score = 10.0 / 1.2 = 8.333333

	testCases := []struct {
		name          string
		lossRatio     float64
		expectedScore float64
	}{
		{
			name:          "Negative loss ratio clamped to 0.0",
			lossRatio:     -0.5,
			expectedScore: 10.0 / 1.2,
		},
		{
			name:          "Loss ratio exceeding 1.0 clamped to 1.0 (zero score)",
			lossRatio:     1.5,
			expectedScore: 0.0,
		},
		{
			name:          "Exact 1.0 loss yields zero score",
			lossRatio:     1.0,
			expectedScore: 0.0,
		},
		{
			name:          "Valid 20% loss ratio applied correctly",
			lossRatio:     0.2,
			expectedScore: (10.0 * 0.8) / 1.2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ev := EvaluateResolver(ResolverMetrics{
				DownloadMTUBytes: 1024,
				RTT:              rtt,
				LossRatio:        tc.lossRatio,
			})
			if math.Abs(ev.CompositeScore-tc.expectedScore) > 0.001 {
				t.Fatalf("expected CompositeScore %f, got %f", tc.expectedScore, ev.CompositeScore)
			}
		})
	}
}

func TestScore_EvaluateResolver_ZeroNegativeRTT(t *testing.T) {
	testCases := []struct {
		name string
		rtt  time.Duration
	}{
		{
			name: "Zero RTT yields zero score and Poor tier",
			rtt:  0,
		},
		{
			name: "Negative RTT yields zero score and Poor tier",
			rtt:  -50 * time.Millisecond,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ev := EvaluateResolver(ResolverMetrics{
				DownloadMTUBytes: 1000,
				RTT:              tc.rtt,
				LossRatio:        0.0,
			})
			if ev.CompositeScore != 0.0 {
				t.Fatalf("expected CompositeScore 0.0, got %f", ev.CompositeScore)
			}
			if ev.Tier != "Poor" {
				t.Fatalf("expected Tier 'Poor', got '%s'", ev.Tier)
			}
			if ev.ColoredBadge != "<red>[POOR]</red>" {
				t.Fatalf("expected ColoredBadge '<red>[POOR]</red>', got '%s'", ev.ColoredBadge)
			}
		})
	}
}

func TestScore_EvaluateResolver_EmpiricalThroughputOverride(t *testing.T) {
	rtt := 100 * time.Millisecond
	baselineSpeed := (1024.0 / 1024.0) / rtt.Seconds() // 10.0 KB/s

	// Case 1: When empirical throughput is provided (>0), it overrides baseline
	empiricalSpeed := 250.0
	evEmpirical := EvaluateResolver(ResolverMetrics{
		DownloadMTUBytes: 1024,
		RTT:              rtt,
		LossRatio:        0.0,
		ThroughputKBps:   empiricalSpeed,
	})
	if math.Abs(evEmpirical.ThroughputKBps-empiricalSpeed) > 0.001 {
		t.Fatalf("expected empirical ThroughputKBps %f, got %f", empiricalSpeed, evEmpirical.ThroughputKBps)
	}
	expectedEmpiricalScore := 250.0 / 1.2
	if math.Abs(evEmpirical.CompositeScore-expectedEmpiricalScore) > 0.001 {
		t.Fatalf("expected CompositeScore %f, got %f", expectedEmpiricalScore, evEmpirical.CompositeScore)
	}

	// Case 2: When empirical throughput is 0 or negative, falls back to theoretical baseline
	evFallback := EvaluateResolver(ResolverMetrics{
		DownloadMTUBytes: 1024,
		RTT:              rtt,
		LossRatio:        0.0,
		ThroughputKBps:   0.0,
	})
	if math.Abs(evFallback.ThroughputKBps-baselineSpeed) > 0.001 {
		t.Fatalf("expected fallback ThroughputKBps %f, got %f", baselineSpeed, evFallback.ThroughputKBps)
	}

	evNegative := EvaluateResolver(ResolverMetrics{
		DownloadMTUBytes: 1024,
		RTT:              rtt,
		LossRatio:        0.0,
		ThroughputKBps:   -10.0,
	})
	if math.Abs(evNegative.ThroughputKBps-baselineSpeed) > 0.001 {
		t.Fatalf("expected fallback ThroughputKBps %f, got %f", baselineSpeed, evNegative.ThroughputKBps)
	}
}

func TestScore_EvaluateResolver_LatencyPenalty(t *testing.T) {
	// Fixed throughput = 300.0 KB/s, LossRatio = 0.0
	throughput := 300.0

	testCases := []struct {
		name            string
		rtt             time.Duration
		expectedPenalty float64
		expectedScore   float64
	}{
		{
			name:            "500ms RTT yields 2.0x penalty",
			rtt:             500 * time.Millisecond,
			expectedPenalty: 2.0, // 1.0 + 500/500
			expectedScore:   throughput / 2.0,
		},
		{
			name:            "1000ms RTT yields 3.0x penalty",
			rtt:             1000 * time.Millisecond,
			expectedPenalty: 3.0, // 1.0 + 1000/500
			expectedScore:   throughput / 3.0,
		},
		{
			name:            "250ms RTT yields 1.5x penalty",
			rtt:             250 * time.Millisecond,
			expectedPenalty: 1.5, // 1.0 + 250/500
			expectedScore:   throughput / 1.5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ev := EvaluateResolver(ResolverMetrics{
				RTT:            tc.rtt,
				LossRatio:      0.0,
				ThroughputKBps: throughput,
			})
			if math.Abs(ev.CompositeScore-tc.expectedScore) > 0.001 {
				t.Fatalf("expected CompositeScore %f, got %f", tc.expectedScore, ev.CompositeScore)
			}
		})
	}
}

func TestScore_QualityTierAndBadges(t *testing.T) {
	testCases := []struct {
		score        float64
		expectedTier string
		expectedBadg string
	}{
		{score: 25.0, expectedTier: "Excellent", expectedBadg: "<green>[EXCELLENT]</green>"},
		{score: 15.0, expectedTier: "Excellent", expectedBadg: "<green>[EXCELLENT]</green>"},
		{score: 14.99, expectedTier: "Good", expectedBadg: "<cyan>[GOOD]</cyan>"},
		{score: 8.0, expectedTier: "Good", expectedBadg: "<cyan>[GOOD]</cyan>"},
		{score: 7.99, expectedTier: "Fair", expectedBadg: "<yellow>[FAIR]</yellow>"},
		{score: 4.0, expectedTier: "Fair", expectedBadg: "<yellow>[FAIR]</yellow>"},
		{score: 3.99, expectedTier: "Poor", expectedBadg: "<red>[POOR]</red>"},
		{score: 0.0, expectedTier: "Poor", expectedBadg: "<red>[POOR]</red>"},
		{score: -5.0, expectedTier: "Poor", expectedBadg: "<red>[POOR]</red>"},
	}

	for _, tc := range testCases {
		tier, badge := ResolverQualityTier(tc.score)
		if tier != tc.expectedTier {
			t.Errorf("for score %f: expected tier %s, got %s", tc.score, tc.expectedTier, tier)
		}
		if badge != tc.expectedBadg {
			t.Errorf("for score %f: expected badge %s, got %s", tc.score, tc.expectedBadg, badge)
		}
	}
}

func TestScore_FormatResolverSpeed(t *testing.T) {
	testCases := []struct {
		speed    float64
		expected string
	}{
		{speed: 0.0, expected: "n/a"},
		{speed: -10.0, expected: "n/a"},
		{speed: math.NaN(), expected: "n/a"},
		{speed: math.Inf(1), expected: "n/a"},
		{speed: math.Inf(-1), expected: "n/a"},
		{speed: 512.4, expected: "512.4 KB/s"},
		{speed: 999.9, expected: "999.9 KB/s"},
		{speed: 1000.0, expected: "0.98 MB/s"}, // 1000 / 1024 = 0.9765625 -> 0.98
		{speed: 1024.0, expected: "1.00 MB/s"},
		{speed: 2048.0, expected: "2.00 MB/s"},
		{speed: 10240.0, expected: "10.00 MB/s"},
	}

	for _, tc := range testCases {
		formatted := FormatResolverSpeed(tc.speed)
		if formatted != tc.expected {
			t.Errorf("for speed %f: expected %s, got %s", tc.speed, tc.expected, formatted)
		}
	}
}

func TestScore_CalculateResolverScore_BackwardCompatibility(t *testing.T) {
	downloadMTU := 1200
	rtt := 80 * time.Millisecond
	lossRatio := 0.05

	speedKBps, score := CalculateResolverScore(downloadMTU, rtt, lossRatio)

	ev := EvaluateResolver(ResolverMetrics{
		DownloadMTUBytes: downloadMTU,
		RTT:              rtt,
		LossRatio:        lossRatio,
	})

	if speedKBps != ev.ThroughputKBps {
		t.Fatalf("expected speedKBps %f == ev.ThroughputKBps %f", speedKBps, ev.ThroughputKBps)
	}
	if score != ev.CompositeScore {
		t.Fatalf("expected score %f == ev.CompositeScore %f", score, ev.CompositeScore)
	}
}

func TestCalculateBurstScoreRanking(t *testing.T) {
	fastBurst := BurstProbeResult{
		Qualified:           true,
		SentCount:           10,
		ReceivedCount:       10,
		LossRatio:           0.0,
		BurstThroughputKBps: 500.0,
		AverageRTT:          20 * time.Millisecond,
	}

	mediumBurst := BurstProbeResult{
		Qualified:           true,
		SentCount:           10,
		ReceivedCount:       10,
		LossRatio:           0.0,
		BurstThroughputKBps: 200.0,
		AverageRTT:          50 * time.Millisecond,
	}

	lossyBurst := BurstProbeResult{
		Qualified:           true,
		SentCount:           10,
		ReceivedCount:       8,
		LossRatio:           0.2,
		BurstThroughputKBps: 200.0,
		AverageRTT:          50 * time.Millisecond,
	}

	unqualifiedBurst := BurstProbeResult{
		Qualified:     false,
		SentCount:     10,
		ReceivedCount: 0,
		LossRatio:     1.0,
	}

	scoreFast := calculateBurstScore(fastBurst)
	scoreMedium := calculateBurstScore(mediumBurst)
	scoreLossy := calculateBurstScore(lossyBurst)
	scoreUnqualified := calculateBurstScore(unqualifiedBurst)

	if scoreFast <= scoreMedium {
		t.Fatalf("expected scoreFast (%f) > scoreMedium (%f)", scoreFast, scoreMedium)
	}
	if scoreMedium <= scoreLossy {
		t.Fatalf("expected scoreMedium (%f) > scoreLossy (%f)", scoreMedium, scoreLossy)
	}
	if scoreLossy <= scoreUnqualified {
		t.Fatalf("expected scoreLossy (%f) > scoreUnqualified (%f)", scoreLossy, scoreUnqualified)
	}
	if scoreUnqualified != 0.0 {
		t.Fatalf("expected scoreUnqualified == 0.0, got %f", scoreUnqualified)
	}
}

func TestScore_EvaluateResolver_NaNInfRobustness(t *testing.T) {
	testCases := []struct {
		name    string
		metrics ResolverMetrics
	}{
		{
			name: "NaN LossRatio treated as 100% loss (zero score)",
			metrics: ResolverMetrics{
				DownloadMTUBytes: 1200,
				RTT:              50 * time.Millisecond,
				LossRatio:        math.NaN(),
				ThroughputKBps:   100.0,
			},
		},
		{
			name: "NaN ThroughputKBps falls back cleanly to baseline",
			metrics: ResolverMetrics{
				DownloadMTUBytes: 1200,
				RTT:              50 * time.Millisecond,
				LossRatio:        0.0,
				ThroughputKBps:   math.NaN(),
			},
		},
		{
			name: "+Inf ThroughputKBps sanitized without producing Inf score",
			metrics: ResolverMetrics{
				DownloadMTUBytes: 1200,
				RTT:              50 * time.Millisecond,
				LossRatio:        0.0,
				ThroughputKBps:   math.Inf(1),
			},
		},
		{
			name: "-Inf ThroughputKBps sanitized without producing negative score",
			metrics: ResolverMetrics{
				DownloadMTUBytes: 1200,
				RTT:              50 * time.Millisecond,
				LossRatio:        0.0,
				ThroughputKBps:   math.Inf(-1),
			},
		},
		{
			name: "NaN LossRatio and NaN ThroughputKBps simultaneously",
			metrics: ResolverMetrics{
				DownloadMTUBytes: 1200,
				RTT:              50 * time.Millisecond,
				LossRatio:        math.NaN(),
				ThroughputKBps:   math.NaN(),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ev := EvaluateResolver(tc.metrics)
			if math.IsNaN(ev.CompositeScore) || math.IsInf(ev.CompositeScore, 0) {
				t.Fatalf("EvaluateResolver produced invalid CompositeScore: %v", ev.CompositeScore)
			}
			if math.IsNaN(ev.ThroughputKBps) || math.IsInf(ev.ThroughputKBps, 0) {
				t.Fatalf("EvaluateResolver produced invalid ThroughputKBps: %v", ev.ThroughputKBps)
			}
			if ev.CompositeScore < 0.0 {
				t.Fatalf("EvaluateResolver produced negative CompositeScore: %v", ev.CompositeScore)
			}
			if ev.ThroughputKBps < 0.0 {
				t.Fatalf("EvaluateResolver produced negative ThroughputKBps: %v", ev.ThroughputKBps)
			}
		})
	}
}

