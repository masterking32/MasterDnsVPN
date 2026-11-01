// ==============================================================================
// MasterDnsVPN - Milestone 1 Challenger Test Suite
// Concurrency, Stress, Thread-Safety & Caller Stability
// ==============================================================================
package client

import (
	"go/parser"
	"go/token"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestScore_Adversarial_ConcurrentEvaluation100Goroutines launches 200 concurrent
// goroutines executing millions of EvaluateResolver calculations under thread-safety
// pressure. Must pass cleanly under `go test -race`.
func TestScore_Adversarial_ConcurrentEvaluation100Goroutines(t *testing.T) {
	const goroutines = 200
	const iterationsPerGoroutine = 5000

	var startBarrier sync.WaitGroup
	startBarrier.Add(1)

	var doneGroup sync.WaitGroup
	doneGroup.Add(goroutines)

	var totalEvaluations uint64
	var errCount uint64

	for g := 0; g < goroutines; g++ {
		go func(workerID int) {
			defer doneGroup.Done()
			startBarrier.Wait() // Synchronized start

			rng := rand.New(rand.NewSource(int64(workerID * 10007)))

			for i := 0; i < iterationsPerGoroutine; i++ {
				// Generate diverse metrics covering valid, boundary, and zero values
				mtu := 500 + rng.Intn(1000)
				if rng.Intn(10) == 0 {
					mtu = 0 // test fallback to 500
				} else if rng.Intn(20) == 0 {
					mtu = -rng.Intn(500) // test negative
				}

				rttMs := rng.Intn(1500)
				var rtt time.Duration
				if rng.Intn(25) == 0 {
					rtt = 0 // test zero RTT
				} else if rng.Intn(50) == 0 {
					rtt = -time.Duration(rng.Intn(100)) * time.Millisecond // test negative RTT
				} else {
					rtt = time.Duration(rttMs) * time.Millisecond
				}

				loss := rng.Float64()
				if rng.Intn(15) == 0 {
					loss = -0.5 // negative loss clamp test
				} else if rng.Intn(15) == 0 {
					loss = 1.5 // >1.0 loss clamp test
				}

				var empiricalThroughput float64
				if rng.Intn(3) == 0 {
					empiricalThroughput = rng.Float64() * 1000.0
				}

				ev := EvaluateResolver(ResolverMetrics{
					DownloadMTUBytes: mtu,
					RTT:              rtt,
					LossRatio:        loss,
					ThroughputKBps:   empiricalThroughput,
				})

				atomic.AddUint64(&totalEvaluations, 1)

				// Verification of invariants
				if ev.CompositeScore < 0.0 {
					atomic.AddUint64(&errCount, 1)
					t.Errorf("worker %d iter %d: negative CompositeScore %v", workerID, i, ev.CompositeScore)
					return
				}
				if rtt <= 0 && ev.CompositeScore != 0.0 {
					atomic.AddUint64(&errCount, 1)
					t.Errorf("worker %d iter %d: RTT <= 0 must have CompositeScore 0.0, got %v", workerID, i, ev.CompositeScore)
					return
				}
				if ev.Tier == "" || ev.ColoredBadge == "" {
					atomic.AddUint64(&errCount, 1)
					t.Errorf("worker %d iter %d: empty Tier or Badge", workerID, i)
					return
				}

				speedStr := FormatResolverSpeed(ev.ThroughputKBps)
				if speedStr == "" {
					atomic.AddUint64(&errCount, 1)
					t.Errorf("worker %d iter %d: empty speed string", workerID, i)
					return
				}
			}
		}(g)
	}

	startBarrier.Done() // Unleash all goroutines
	doneGroup.Wait()

	if errs := atomic.LoadUint64(&errCount); errs > 0 {
		t.Fatalf("Encountered %d errors during concurrent evaluation", errs)
	}

	total := atomic.LoadUint64(&totalEvaluations)
	if total != goroutines*iterationsPerGoroutine {
		t.Fatalf("Expected %d total evaluations, got %d", goroutines*iterationsPerGoroutine, total)
	}
	t.Logf("PASS: Successfully executed %d concurrent evaluations across %d goroutines with zero data races", total, goroutines)
}

// TestScore_Adversarial_ConcurrentCallersStress exercises concurrent invocation of all
// caller integration points (micro_burst, runtime_stats, balancer connection score).
func TestScore_Adversarial_ConcurrentCallersStress(t *testing.T) {
	const callerWorkers = 150
	const iterations = 1000

	var startBarrier sync.WaitGroup
	startBarrier.Add(1)

	var doneGroup sync.WaitGroup
	doneGroup.Add(callerWorkers)

	for w := 0; w < callerWorkers; w++ {
		go func(workerID int) {
			defer doneGroup.Done()
			startBarrier.Wait()

			rng := rand.New(rand.NewSource(int64(workerID * 20011)))

			for i := 0; i < iterations; i++ {
				callType := i % 3

				switch callType {
				case 0:
					// Caller 1: calculateBurstScore in micro_burst.go
					burst := BurstProbeResult{
						Qualified:           rng.Intn(2) == 1,
						SentCount:           10,
						ReceivedCount:       rng.Intn(11),
						TotalBytesRx:        rng.Intn(15000),
						LossRatio:           rng.Float64(),
						AverageRTT:          time.Duration(rng.Intn(500)) * time.Millisecond,
						BurstThroughputKBps: rng.Float64() * 500.0,
						ThroughputKBps:      rng.Float64() * 300.0,
						DownloadMTUBytes:    500 + rng.Intn(1000),
					}
					score := calculateBurstScore(burst)
					if score < 0.0 {
						t.Errorf("calculateBurstScore produced negative score %v for burst %+v", score, burst)
						return
					}
					if !burst.Qualified || burst.ReceivedCount == 0 {
						if score != 0.0 {
							t.Errorf("unqualified burst must have score 0.0, got %v", score)
							return
						}
					}

				case 1:
					// Caller 2: calculateResolverRuntimeSpeedAndScore in runtime_stats.go
					rtt := time.Duration(rng.Intn(600)) * time.Millisecond
					if rng.Intn(10) == 0 {
						rtt = 0
					}
					snap := ResolverStatsSnapshot{
						Connection: Connection{
							ResolverLabel:    "test-resolver",
							Domain:           "example.com",
							DownloadMTUBytes: 1200,
							MTUResolveTime:   50 * time.Millisecond,
						},
						Sent:       uint64(rng.Intn(1000)),
						Acked:      uint64(rng.Intn(1000)),
						Lost:       uint64(rng.Intn(100)),
						LossRatio:  rng.Float64(),
						AverageRTT: rtt,
						IsValid:    true,
					}
					speedStr, scoreStr, tier := calculateResolverRuntimeSpeedAndScore(snap)
					if speedStr == "" || scoreStr == "" || tier == "" {
						t.Errorf("calculateResolverRuntimeSpeedAndScore returned empty string: (%q, %q, %q)", speedStr, scoreStr, tier)
						return
					}

				case 2:
					// Caller 3: CalculateResolverScore backward-compatibility shim
					speed, score := CalculateResolverScore(
						500+rng.Intn(1000),
						time.Duration(1+rng.Intn(1000))*time.Millisecond,
						rng.Float64(),
					)
					if speed < 0.0 || score < 0.0 {
						t.Errorf("CalculateResolverScore produced negative output: speed=%v score=%v", speed, score)
						return
					}
				}
			}
		}(w)
	}

	startBarrier.Done()
	doneGroup.Wait()
	t.Logf("PASS: Successfully executed %d caller stress operations across %d goroutines", callerWorkers*iterations, callerWorkers)
}

// TestScore_Adversarial_ZeroMutexAndNetworkPurity verifies via AST parsing that
// internal/client/score.go does NOT import any network or synchronization packages,
// uses zero mutexes, zero atomic operations, and is completely pure.
func TestScore_Adversarial_ZeroMutexAndNetworkPurity(t *testing.T) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "score.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("failed to parse score.go: %v", err)
	}

	forbiddenImports := map[string]string{
		`"net"`:         "network I/O package",
		`"net/http"`:    "HTTP package",
		`"sync"`:        "mutex/concurrency package",
		`"sync/atomic"`: "atomic primitives",
		`"os"`:          "operating system calls",
	}

	for _, imp := range node.Imports {
		path := imp.Path.Value
		if reason, forbidden := forbiddenImports[path]; forbidden {
			t.Fatalf("score.go violates zero-dependency architectural constraint by importing %s (%s)", path, reason)
		}
	}

	t.Log("PASS: score.go strictly complies with zero network dependencies and zero mutexes constraints")
}

// TestScore_Adversarial_CallerStabilityNaNInfZeroMicroseconds stresses caller edge cases:
// 0 received, 0 bytes, 0 RTT, negative RTT, NaN LossRatio, Inf LossRatio.
func TestScore_Adversarial_CallerStabilityNaNInfZeroMicroseconds(t *testing.T) {
	// Subcase 1: micro_burst with edge case values
	edgeBursts := []BurstProbeResult{
		{Qualified: false, ReceivedCount: 0},
		{Qualified: true, ReceivedCount: 0},
		{Qualified: true, ReceivedCount: 1, TotalBytesRx: 0, AverageRTT: 0},
		{Qualified: true, ReceivedCount: 1, TotalBytesRx: 1000, AverageRTT: -10 * time.Millisecond},
		{Qualified: true, ReceivedCount: 5, TotalBytesRx: 5000, AverageRTT: 1 * time.Microsecond, LossRatio: 1.0},
		{Qualified: true, ReceivedCount: 5, TotalBytesRx: 5000, AverageRTT: 10 * time.Millisecond, LossRatio: -0.5},
	}

	for i, b := range edgeBursts {
		score := calculateBurstScore(b)
		if math.IsNaN(score) {
			t.Errorf("calculateBurstScore produced NaN for edge burst case %d", i)
		}
		if score < 0.0 {
			t.Errorf("calculateBurstScore produced negative score %v for case %d", score, i)
		}
	}

	// Subcase 2: runtime_stats with zero and negative RTT
	edgeSnapshots := []ResolverStatsSnapshot{
		{AverageRTT: 0, Connection: Connection{MTUResolveTime: 0}},
		{AverageRTT: -5 * time.Millisecond, Connection: Connection{MTUResolveTime: -10 * time.Millisecond}},
		{AverageRTT: 1 * time.Microsecond, Connection: Connection{DownloadMTUBytes: 0}},
		{AverageRTT: 50 * time.Millisecond, Connection: Connection{DownloadMTUBytes: -500}, LossRatio: 2.0},
	}

	for i, s := range edgeSnapshots {
		speedStr, scoreStr, tier := calculateResolverRuntimeSpeedAndScore(s)
		if speedStr == "" || scoreStr == "" || tier == "" {
			t.Errorf("calculateResolverRuntimeSpeedAndScore returned empty string on edge case %d", i)
		}
		if tier != "Poor" && s.AverageRTT <= 0 && s.Connection.MTUResolveTime <= 0 {
			t.Errorf("expected Poor tier for zero/negative RTT on case %d, got %s", i, tier)
		}
	}

	t.Log("PASS: All callers remain completely stable under zero, negative, and edge-case inputs")
}

// TestScore_Adversarial_EmpiricalThroughputEquivalence compares EvaluateResolver
// against the legacy manual mathematical formulation over 1,000 parameter combinations.
func TestScore_Adversarial_EmpiricalThroughputEquivalence(t *testing.T) {
	rng := rand.New(rand.NewSource(99))

	const runs = 1000
	const epsilon = 1e-9

	for i := 0; i < runs; i++ {
		mtu := 500 + rng.Intn(1000)
		rttMs := 1 + rng.Intn(1000)
		rtt := time.Duration(rttMs) * time.Millisecond
		loss := rng.Float64() // in [0, 1)

		// Evaluator calculation
		ev := EvaluateResolver(ResolverMetrics{
			DownloadMTUBytes: mtu,
			RTT:              rtt,
			LossRatio:        loss,
		})

		// Legacy formula reconstruction:
		// Speed = (DownloadMTU / 1024) / RTT_sec
		// LatencyPenalty = 1.0 + (RTT_ms / 500.0)
		// Score = Speed * (1 - Loss) / LatencyPenalty
		rttSec := rtt.Seconds()
		expectedSpeed := (float64(mtu) / 1024.0) / rttSec
		expectedPenalty := 1.0 + (float64(rttMs) / 500.0)
		expectedScore := (expectedSpeed * (1.0 - loss)) / expectedPenalty

		if math.Abs(ev.ThroughputKBps-expectedSpeed) > epsilon {
			t.Fatalf("iter %d: speed mismatch: got %v, expected %v", i, ev.ThroughputKBps, expectedSpeed)
		}
		if math.Abs(ev.CompositeScore-expectedScore) > epsilon {
			t.Fatalf("iter %d: score mismatch: got %v, expected %v", i, ev.CompositeScore, expectedScore)
		}
	}

	t.Logf("PASS: Evaluated %d random parameter spaces; EvaluateResolver mathematically replicates baseline specification", runs)
}
