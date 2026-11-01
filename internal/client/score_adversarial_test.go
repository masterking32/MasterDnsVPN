// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"math"
	"math/rand"
	"sort"
	"testing"
	"time"
)

// TestScore_NumericalStability_NaNAndInfSanitization tests that EvaluateResolver
// strictly avoids returning NaN or Inf in CompositeScore and ThroughputKBps under all conditions.
// Per PR #205 R1 requirements, the pure evaluation module must enforce numerical stability.
func TestScore_NumericalStability_NaNAndInfSanitization(t *testing.T) {
	testCases := []struct {
		name    string
		metrics ResolverMetrics
	}{
		{
			name: "LossRatio is NaN",
			metrics: ResolverMetrics{
				DownloadMTUBytes: 1200,
				RTT:              100 * time.Millisecond,
				LossRatio:        math.NaN(),
			},
		},
		{
			name: "ThroughputKBps is NaN",
			metrics: ResolverMetrics{
				DownloadMTUBytes: 1200,
				RTT:              100 * time.Millisecond,
				ThroughputKBps:   math.NaN(),
			},
		},
		{
			name: "ThroughputKBps is +Inf and LossRatio is 1.0 (Inf * 0 = NaN hazard)",
			metrics: ResolverMetrics{
				DownloadMTUBytes: 1200,
				RTT:              100 * time.Millisecond,
				LossRatio:        1.0,
				ThroughputKBps:   math.Inf(1),
			},
		},
		{
			name: "ThroughputKBps is +Inf and LossRatio is 0.0",
			metrics: ResolverMetrics{
				DownloadMTUBytes: 1200,
				RTT:              100 * time.Millisecond,
				LossRatio:        0.0,
				ThroughputKBps:   math.Inf(1),
			},
		},
		{
			name: "Both LossRatio and ThroughputKBps are NaN",
			metrics: ResolverMetrics{
				DownloadMTUBytes: 1200,
				RTT:              100 * time.Millisecond,
				LossRatio:        math.NaN(),
				ThroughputKBps:   math.NaN(),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ev := EvaluateResolver(tc.metrics)
			if math.IsNaN(ev.CompositeScore) {
				t.Fatalf("NUMERICAL STABILITY FAILURE: CompositeScore is NaN for input: %+v", tc.metrics)
			}
			if math.IsInf(ev.CompositeScore, 0) {
				t.Fatalf("NUMERICAL STABILITY FAILURE: CompositeScore is Inf for input: %+v", tc.metrics)
			}
			if math.IsNaN(ev.ThroughputKBps) {
				t.Fatalf("NUMERICAL STABILITY FAILURE: ThroughputKBps is NaN for input: %+v", tc.metrics)
			}
			if math.IsInf(ev.ThroughputKBps, 0) {
				t.Fatalf("NUMERICAL STABILITY FAILURE: ThroughputKBps is Inf for input: %+v", tc.metrics)
			}
		})
	}
}

// TestScore_Adversarial_FormatResolverSpeedSpecialFloats verifies speed formatting for special values.
func TestScore_Adversarial_FormatResolverSpeedSpecialFloats(t *testing.T) {
	testCases := []struct {
		name     string
		speed    float64
		expected string
	}{
		{"NaN speed should return n/a", math.NaN(), "n/a"},
		{"+Inf speed should return n/a", math.Inf(1), "n/a"},
		{"-Inf speed should return n/a", math.Inf(-1), "n/a"},
		{"Zero speed", 0.0, "n/a"},
		{"Negative speed", -10.0, "n/a"},
		{"Normal speed", 512.4, "512.4 KB/s"},
		{"Just below MB threshold 999.94", 999.94, "999.9 KB/s"},
		{"Exact MB threshold 1000.0", 1000.0, "0.98 MB/s"},
		{"High MB speed", 2048.0, "2.00 MB/s"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatResolverSpeed(tc.speed)
			if got != tc.expected {
				t.Errorf("[%s] FormatResolverSpeed(%v) = %q, expected %q", tc.name, tc.speed, got, tc.expected)
			}
		})
	}
}

// TestScore_Adversarial_BurstScoreNaNPropagation demonstrates how unhandled NaN inputs
// propagate through calculateBurstScore and corrupt candidate ranking in micro-burst qualification.
func TestScore_Adversarial_BurstScoreNaNPropagation(t *testing.T) {
	// Case 1: Burst probe with NaN LossRatio
	burstWithNaN := BurstProbeResult{
		Qualified:           true,
		SentCount:           10,
		ReceivedCount:       8,
		LossRatio:           math.NaN(),
		BurstThroughputKBps: 200.0,
		AverageRTT:          50 * time.Millisecond,
	}

	scoreNaN := calculateBurstScore(burstWithNaN)
	if math.IsNaN(scoreNaN) {
		t.Fatalf("NUMERICAL STABILITY FAILURE: calculateBurstScore returned NaN: %v", scoreNaN)
	}

	// Case 2: Candidate slice ordering must not be corrupted by invalid scores
	results := []QualifiedResolver{
		{
			Connection: Connection{Key: "res-invalid"},
			Score:      scoreNaN,
		},
		{
			Connection: Connection{Key: "res-fast"},
			Score:      25.0,
		},
		{
			Connection: Connection{Key: "res-medium"},
			Score:      15.0,
		},
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		return false
	})

	if results[0].Connection.Key != "res-fast" {
		t.Fatalf("ORDERING FAILURE: expected res-fast at rank 1, got %s (score=%v)", results[0].Connection.Key, results[0].Score)
	}
}

// TestScore_Adversarial_TierBoundaryPrecision tests exact mathematical boundary conditions
// including epsilon differentials around 15.0, 8.0, and 4.0.
func TestScore_Adversarial_TierBoundaryPrecision(t *testing.T) {
	const eps = 1e-12

	testCases := []struct {
		score        float64
		expectedTier string
	}{
		// Boundary 15.0
		{15.0 + eps, "Excellent"},
		{15.0, "Excellent"},
		{15.0 - eps, "Good"},

		// Boundary 8.0
		{8.0 + eps, "Good"},
		{8.0, "Good"},
		{8.0 - eps, "Fair"},

		// Boundary 4.0
		{4.0 + eps, "Fair"},
		{4.0, "Fair"},
		{4.0 - eps, "Poor"},

		// Zero and negative boundaries
		{0.0 + eps, "Poor"},
		{0.0, "Poor"},
		{-0.0, "Poor"},
		{-eps, "Poor"},
		{-100.0, "Poor"},

		// IEEE 754 specials in Tier mapping
		{math.NaN(), "Poor"},
		{math.Inf(1), "Excellent"},
		{math.Inf(-1), "Poor"},
	}

	for _, tc := range testCases {
		tier, badge := ResolverQualityTier(tc.score)
		if tier != tc.expectedTier {
			t.Errorf("score %v: expected tier %q, got %q", tc.score, tc.expectedTier, tier)
		}
		if badge == "" {
			t.Errorf("score %v: badge should not be empty", tc.score)
		}
	}
}

// TestScore_Adversarial_ExtremeMetrics tests extreme integer and duration metrics.
func TestScore_Adversarial_ExtremeMetrics(t *testing.T) {
	testCases := []struct {
		name    string
		metrics ResolverMetrics
	}{
		{
			name: "Gigantic MTU (MaxInt32)",
			metrics: ResolverMetrics{
				DownloadMTUBytes: math.MaxInt32,
				RTT:              100 * time.Millisecond,
				LossRatio:        0.0,
			},
		},
		{
			name: "Sub-microsecond RTT (1 nanosecond)",
			metrics: ResolverMetrics{
				DownloadMTUBytes: 1200,
				RTT:              1 * time.Nanosecond,
				LossRatio:        0.0,
			},
		},
		{
			name: "Sub-millisecond RTT (500 microseconds)",
			metrics: ResolverMetrics{
				DownloadMTUBytes: 1200,
				RTT:              500 * time.Microsecond,
				LossRatio:        0.0,
			},
		},
		{
			name: "Extreme long RTT (MaxInt64 / ~292 years)",
			metrics: ResolverMetrics{
				DownloadMTUBytes: 1200,
				RTT:              time.Duration(math.MaxInt64),
				LossRatio:        0.0,
			},
		},
		{
			name: "Negative RTT (-1 nanosecond)",
			metrics: ResolverMetrics{
				DownloadMTUBytes: 1200,
				RTT:              -1 * time.Nanosecond,
				LossRatio:        0.0,
			},
		},
		{
			name: "Extremely negative RTT (MinInt64)",
			metrics: ResolverMetrics{
				DownloadMTUBytes: 1200,
				RTT:              time.Duration(math.MinInt64),
				LossRatio:        0.0,
			},
		},
		{
			name: "Extremely negative MTU (MinInt)",
			metrics: ResolverMetrics{
				DownloadMTUBytes: math.MinInt,
				RTT:              100 * time.Millisecond,
				LossRatio:        0.0,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ev := EvaluateResolver(tc.metrics)
			if math.IsNaN(ev.CompositeScore) {
				t.Fatalf("unexpected NaN CompositeScore for %s", tc.name)
			}
			if math.IsInf(ev.CompositeScore, 0) {
				t.Fatalf("unexpected Inf CompositeScore for %s", tc.name)
			}
			if ev.CompositeScore < 0.0 {
				t.Fatalf("unexpected negative CompositeScore %v for %s", ev.CompositeScore, tc.name)
			}
		})
	}
}

// TestScore_Adversarial_MonotonicityInvariants tests fundamental physical and mathematical invariants:
// 1. Monotonicity in Download MTU: higher MTU -> score does not decrease.
// 2. Monotonicity in RTT: higher RTT -> score does not increase.
// 3. Monotonicity in Loss Ratio: higher loss -> score does not increase.
// 4. Non-negativity: score is always >= 0.0.
func TestScore_Adversarial_MonotonicityInvariants(t *testing.T) {
	// Invariant 1: Monotonicity in MTU
	rtt := 50 * time.Millisecond
	loss := 0.05
	var prevScore float64 = -1.0
	for mtu := 500; mtu <= 4000; mtu += 100 {
		ev := EvaluateResolver(ResolverMetrics{
			DownloadMTUBytes: mtu,
			RTT:              rtt,
			LossRatio:        loss,
		})
		if ev.CompositeScore < prevScore {
			t.Fatalf("MTU monotonicity violation: MTU %d score %v < previous MTU score %v", mtu, ev.CompositeScore, prevScore)
		}
		prevScore = ev.CompositeScore
	}

	// Invariant 2: Monotonicity in RTT (baseline)
	mtu := 1200
	var prevRTTScore float64 = math.MaxFloat64
	for rttMs := 1; rttMs <= 2000; rttMs += 10 {
		ev := EvaluateResolver(ResolverMetrics{
			DownloadMTUBytes: mtu,
			RTT:              time.Duration(rttMs) * time.Millisecond,
			LossRatio:        loss,
		})
		if ev.CompositeScore > prevRTTScore {
			t.Fatalf("RTT monotonicity violation: RTT %dms score %v > previous RTT score %v", rttMs, ev.CompositeScore, prevRTTScore)
		}
		prevRTTScore = ev.CompositeScore
	}

	// Invariant 3: Monotonicity in RTT (with fixed empirical throughput)
	fixedThroughput := 300.0
	prevRTTScore = math.MaxFloat64
	for rttMs := 1; rttMs <= 2000; rttMs += 10 {
		ev := EvaluateResolver(ResolverMetrics{
			DownloadMTUBytes: mtu,
			RTT:              time.Duration(rttMs) * time.Millisecond,
			LossRatio:        loss,
			ThroughputKBps:   fixedThroughput,
		})
		if ev.CompositeScore > prevRTTScore {
			t.Fatalf("RTT empirical throughput monotonicity violation: RTT %dms score %v > previous RTT score %v", rttMs, ev.CompositeScore, prevRTTScore)
		}
		prevRTTScore = ev.CompositeScore
	}

	// Invariant 4: Monotonicity in LossRatio
	rtt = 80 * time.Millisecond
	var prevLossScore float64 = math.MaxFloat64
	for lossStep := 0; lossStep <= 100; lossStep++ {
		curLoss := float64(lossStep) / 100.0
		ev := EvaluateResolver(ResolverMetrics{
			DownloadMTUBytes: mtu,
			RTT:              rtt,
			LossRatio:        curLoss,
		})
		if ev.CompositeScore > prevLossScore {
			t.Fatalf("Loss monotonicity violation: Loss %v score %v > previous loss score %v", curLoss, ev.CompositeScore, prevLossScore)
		}
		prevLossScore = ev.CompositeScore
	}
}

// TestScore_Adversarial_FuzzingStress runs 50,000 randomized permutations of ResolverMetrics
// checking for panics, negative scores, and invariant breaks.
func TestScore_Adversarial_FuzzingStress(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	const iterations = 50000

	mtuChoices := []int{
		math.MinInt, -1000, -1, 0, 1, 100, 500, 1024, 1200, 1400, 1500, 4096, 65535, math.MaxInt32,
	}

	rttChoices := []time.Duration{
		time.Duration(math.MinInt64), -100 * time.Millisecond, -1 * time.Nanosecond,
		0, 1 * time.Nanosecond, 1 * time.Microsecond, 500 * time.Microsecond,
		1 * time.Millisecond, 10 * time.Millisecond, 100 * time.Millisecond,
		500 * time.Millisecond, 1 * time.Second, 10 * time.Second,
		time.Duration(math.MaxInt64),
	}

	lossChoices := []float64{
		-100.0, -1.0, -0.01, -0.0, 0.0, 0.05, 0.2, 0.5, 0.99, 1.0, 1.001, 2.0, 100.0,
	}

	throughputChoices := []float64{
		-1e6, -100.0, -1.0, -1e-9, -0.0, 0.0, 1e-9, 1.0, 50.0, 500.0, 10000.0, 1e9,
	}

	validTiers := map[string]bool{
		"Excellent": true,
		"Good":      true,
		"Fair":      true,
		"Poor":      true,
	}

	for i := 0; i < iterations; i++ {
		mtu := mtuChoices[rng.Intn(len(mtuChoices))]
		rtt := rttChoices[rng.Intn(len(rttChoices))]
		loss := lossChoices[rng.Intn(len(lossChoices))]
		tp := throughputChoices[rng.Intn(len(throughputChoices))]

		m := ResolverMetrics{
			DownloadMTUBytes: mtu,
			RTT:              rtt,
			LossRatio:        loss,
			ThroughputKBps:   tp,
		}

		ev := EvaluateResolver(m)

		if ev.CompositeScore < 0.0 {
			t.Fatalf("iteration %d: CompositeScore < 0.0: %v for %+v", i, ev.CompositeScore, m)
		}

		if ev.ThroughputKBps < 0.0 {
			t.Fatalf("iteration %d: ThroughputKBps < 0.0: %v for %+v", i, ev.ThroughputKBps, m)
		}

		if !validTiers[ev.Tier] {
			t.Fatalf("iteration %d: invalid tier %q for %+v", i, ev.Tier, m)
		}

		if ev.ColoredBadge == "" {
			t.Fatalf("iteration %d: empty ColoredBadge for %+v", i, m)
		}

		expectedTier, expectedBadge := ResolverQualityTier(ev.CompositeScore)
		if ev.Tier != expectedTier || ev.ColoredBadge != expectedBadge {
			t.Fatalf("iteration %d: tier mismatch ev.Tier=%q expected=%q for score %v", i, ev.Tier, expectedTier, ev.CompositeScore)
		}
	}
}
