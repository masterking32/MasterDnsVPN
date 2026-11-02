# Handoff Report: Milestone 1 — Adversarial Challenge & Stress Testing

**Author:** teamwork_challenger instance 1 (challenger_m1_1)  
**Milestone:** Milestone 1 — Consolidated Resolver Evaluation  
**Date:** 2026-10-31T17:11:00Z  
**Branch:** `feat/fast-start-resolvers`  
**Working Directory:** `c:\Dev\Projects\DNStunnel\.agents\teamwork\challenger_m1_1`  
**Verdict:** **`REQUEST_CHANGES`**

---

## 1. Observation

### 1.1 Source Code Observations

1. **`internal/client/score.go` (Lines 48–104)**:
   ```go
   func EvaluateResolver(m ResolverMetrics) ResolverEvaluation {
       downloadMTU := m.DownloadMTUBytes
       if downloadMTU <= 0 {
           downloadMTU = 500
       }

       lossRatio := m.LossRatio
       if lossRatio < 0.0 {
           lossRatio = 0.0
       } else if lossRatio > 1.0 {
           lossRatio = 1.0
       }

       speedKBps := m.ThroughputKBps
       if speedKBps <= 0.0 {
           if m.RTT > 0 {
               rttSec := m.RTT.Seconds()
               if rttSec > 0.0 {
                   speedKBps = (float64(downloadMTU) / 1024.0) / rttSec
               }
           }
       }
       if speedKBps < 0.0 {
           speedKBps = 0.0
       }
       ...
       effectiveThroughput := speedKBps * (1.0 - lossRatio)
       if effectiveThroughput < 0.0 {
           effectiveThroughput = 0.0
       }

       compositeScore := effectiveThroughput / latencyPenalty
       tier, badge := ResolverQualityTier(compositeScore)
       ...
   }
   ```
   - Neither `math.IsNaN` nor `math.IsInf` is checked anywhere in `score.go`. `math` is not imported.
   - When `m.LossRatio = math.NaN()`: In IEEE 754, `lossRatio < 0.0` is `false`, and `lossRatio > 1.0` is `false`. `lossRatio` remains `NaN`.
   - `effectiveThroughput := speedKBps * (1.0 - NaN)` produces `NaN`. `effectiveThroughput < 0.0` is `false`.
   - `compositeScore := NaN / latencyPenalty` evaluates to `NaN`.
   - When `m.ThroughputKBps = math.NaN()`: `speedKBps <= 0.0` is `false`. The theoretical baseline fallback is bypassed. `speedKBps` remains `NaN`. `compositeScore` evaluates to `NaN`.
   - When `m.ThroughputKBps = math.Inf(1)` and `m.LossRatio = 1.0`: `1.0 - lossRatio = 0.0`. In IEEE 754, `+Inf * 0.0` evaluates to `NaN`. `compositeScore` evaluates to `NaN`.

2. **`internal/client/score.go` (Lines 121–129)**:
   ```go
   func FormatResolverSpeed(speedKBps float64) string {
       if speedKBps <= 0 {
           return "n/a"
       }
       if speedKBps >= 1000.0 {
           return fmt.Sprintf("%.2f MB/s", speedKBps/1024.0)
       }
       return fmt.Sprintf("%.1f KB/s", speedKBps)
   }
   ```
   - When `speedKBps = math.NaN()`: `speedKBps <= 0` is `false`, `speedKBps >= 1000.0` is `false`. The function formats `fmt.Sprintf("%.1f KB/s", NaN)` and verbatim returns `"NaN KB/s"`.
   - When `speedKBps = math.Inf(1)`: The function verbatim returns `"+Inf MB/s"`.

3. **`internal/client/micro_burst.go` (Lines 287–308 and 389–398)**:
   ```go
   func calculateBurstScore(result BurstProbeResult) float64 {
       if !result.Qualified || result.ReceivedCount == 0 {
           return 0.0
       }
       ...
       ev := EvaluateResolver(ResolverMetrics{
           DownloadMTUBytes: downloadMTU,
           RTT:              result.AverageRTT,
           LossRatio:        result.LossRatio,
           ThroughputKBps:   speedKBps,
       })
       return ev.CompositeScore
   }
   ```
   And in sorting candidates:
   ```go
   // Sort by Score descending, with Loss and RTT tie-breaking
   sort.Slice(results, func(i, j int) bool {
       if results[i].Score != results[j].Score {
           return results[i].Score > results[j].Score
       }
       if results[i].BurstResult.LossRatio != results[j].BurstResult.LossRatio {
           return results[i].BurstResult.LossRatio < results[j].BurstResult.LossRatio
       }
       return results[i].BurstResult.AverageRTT < results[j].BurstResult.AverageRTT
   })
   ```
   - In Go, `NaN != X` evaluates to `true` for any `X` (including `NaN != NaN`).
   - However, `NaN > X` evaluates to `false` and `X > NaN` evaluates to `false`.
   - Therefore, `sortFunc(nan, fast)` returns `false` AND `sortFunc(fast, nan)` returns `false`.
   - This violates the strict weak ordering required by `sort.Slice`.

4. **`internal/client/balancer.go` (Lines 1446–1454)**:
   ```go
   ev := EvaluateResolver(ResolverMetrics{
       DownloadMTUBytes: downloadMTU,
       RTT:              avgRTT,
       LossRatio:        lossRatio,
   })
   if ev.CompositeScore <= 0 {
       return 1.0
   }
   return ev.CompositeScore
   ```
   - In Go, `NaN <= 0` evaluates to `false`.
   - When `ev.CompositeScore` is `NaN`, `calculateConnectionScoreLocked` bypasses the `1.0` fallback clamp and returns `NaN` as the connection score, storing `b.connections[idx].Score = NaN`.

### 1.2 Empirical Reproduction Tool Commands & Results

We authored and executed the empirical test harness in `internal/client/score_adversarial_test.go`:

- **Command:** `go test -v ./internal/client -run "TestScore_NumericalStability_NaNAndInfSanitization"`
  ```
  === RUN   TestScore_NumericalStability_NaNAndInfSanitization
  === RUN   TestScore_NumericalStability_NaNAndInfSanitization/LossRatio_is_NaN
      score_adversarial_test.go:74: NUMERICAL STABILITY FAILURE: CompositeScore is NaN for input: {DownloadMTUBytes:1200 RTT:100ms LossRatio:NaN ThroughputKBps:0}
  === RUN   TestScore_NumericalStability_NaNAndInfSanitization/ThroughputKBps_is_NaN
      score_adversarial_test.go:74: NUMERICAL STABILITY FAILURE: CompositeScore is NaN for input: {DownloadMTUBytes:1200 RTT:100ms LossRatio:0 ThroughputKBps:NaN}
  === RUN   TestScore_NumericalStability_NaNAndInfSanitization/ThroughputKBps_is_+Inf_and_LossRatio_is_1.0_(Inf_*_0_=_NaN_hazard)
      score_adversarial_test.go:74: NUMERICAL STABILITY FAILURE: CompositeScore is NaN for input: {DownloadMTUBytes:1200 RTT:100ms LossRatio:1 ThroughputKBps:+Inf}
  === RUN   TestScore_NumericalStability_NaNAndInfSanitization/ThroughputKBps_is_+Inf_and_LossRatio_is_0.0
      score_adversarial_test.go:77: NUMERICAL STABILITY FAILURE: CompositeScore is Inf for input: {DownloadMTUBytes:1200 RTT:100ms LossRatio:0 ThroughputKBps:+Inf}
  === RUN   TestScore_NumericalStability_NaNAndInfSanitization/Both_LossRatio_and_ThroughputKBps_are_NaN
      score_adversarial_test.go:74: NUMERICAL STABILITY FAILURE: CompositeScore is NaN for input: {DownloadMTUBytes:1200 RTT:100ms LossRatio:NaN ThroughputKBps:NaN}
  --- FAIL: TestScore_NumericalStability_NaNAndInfSanitization (0.00s)
  ```

- **Command:** `go test -v ./internal/client -run "TestScore_Adversarial_BurstScoreNaNPropagation"`
  ```
  === RUN   TestScore_Adversarial_BurstScoreNaNPropagation
      score_adversarial_test.go:132: NUMERICAL STABILITY FAILURE: calculateBurstScore returned NaN: NaN
      score_adversarial_test.go:500: sortFunc(nan, fast) = false, sortFunc(fast, nan) = false
      score_adversarial_test.go:505: Rank 1: res-fast (score=25)
      score_adversarial_test.go:505: Rank 2: res-nan (score=NaN)
      score_adversarial_test.go:505: Rank 3: res-medium (score=15)
      score_adversarial_test.go:505: Rank 4: res-slow (score=5)
      score_adversarial_test.go:521: Results2 Rank 1: res-nan (score=NaN)
      score_adversarial_test.go:521: Results2 Rank 2: res-fast (score=25)
      score_adversarial_test.go:521: Results2 Rank 3: res-medium (score=15)
      score_adversarial_test.go:524: VULNERABILITY CONFIRMED: res-nan with NaN score was ranked #1 ahead of 25.0 score fast resolver!
  --- FAIL: TestScore_Adversarial_BurstScoreNaNPropagation (0.00s)
  ```

- **Command:** `go test -v ./internal/client -run "TestScore_Adversarial_FormatResolverSpeedSpecialFloats"`
  ```
  === RUN   TestScore_Adversarial_FormatResolverSpeedSpecialFloats
  === RUN   TestScore_Adversarial_FormatResolverSpeedSpecialFloats/NaN_speed_should_return_n/a
      score_adversarial_test.go:111: [NaN speed should return n/a] FormatResolverSpeed(NaN) = "NaN KB/s", expected "n/a"
  === RUN   TestScore_Adversarial_FormatResolverSpeedSpecialFloats/+Inf_speed_should_return_n/a
      score_adversarial_test.go:111: [+Inf speed should return n/a] FormatResolverSpeed(+Inf) = "+Inf MB/s", expected "n/a"
  --- FAIL: TestScore_Adversarial_FormatResolverSpeedSpecialFloats (0.00s)
  ```

---

## 2. Logic Chain

1. **Unsanitized Inputs in `EvaluateResolver`:** Observation 1.1.1 shows that `EvaluateResolver` performs comparisons `lossRatio < 0.0` and `lossRatio > 1.0` and `speedKBps <= 0.0`. In IEEE 754, all relational comparisons against `NaN` evaluate to `false`. Consequently, input `NaN` values bypass all clamping and fallback guards.
2. **`NaN` Generation via Floating Multiplications:** Observation 1.1.1 and test output in 1.2 demonstrate that `+Inf * 0.0` and `speed * (1.0 - NaN)` both compute to `NaN`, setting `ev.CompositeScore = NaN`.
3. **Propagation to Burst Scoring:** Observation 1.1.3 shows `calculateBurstScore` returns `ev.CompositeScore`. When fed a probe result with `NaN` loss or throughput, `calculateBurstScore` returns `NaN`.
4. **Sorting Corruption in MicroBurst:** Observation 1.1.3 and empirical verification in 1.2 demonstrate that `sort.Slice`'s comparator evaluates to `false` in both directions for `NaN` vs finite numbers. In `Results2` of the test, an invalid resolver with score `NaN` was sorted to Rank #1, ahead of a high-performance resolver with score `25.0`. In production, this causes degraded/unusable candidates to be selected for the active pool.
5. **Balancer Fallback Bypass:** Observation 1.1.4 shows `if ev.CompositeScore <= 0` in `balancer.go`. Because `NaN <= 0` is `false`, the fallback to `1.0` is skipped, polluting `balancer.connections[idx].Score` with `NaN`.
6. **Violations of Requirements:** ORIGINAL_REQUEST.md R1 and DISPATCH.md mandate: "Verify numerical stability (avoid divide-by-zero, NaN, Inf)." The current implementation directly violates this requirement.

---

## 3. Caveats

- **Passing Features:** Mathematical monotonicity (in MTU, RTT, and loss ratio), quality tier boundaries (15.0, 8.0, 4.0, eps), sub-microsecond RTT handling (1 ns), extreme MTUs (`math.MaxInt32`), and 50,000 randomized permutations all passed without crashes or unexpected negative values.
- **Scope of Defect:** The defect is strictly confined to IEEE 754 floating-point special value sanitization (`math.IsNaN`, `math.IsInf`) in `score.go`, `micro_burst.go`, and `balancer.go`.

---

## 4. Conclusion & Required Changes

**Verdict: `REQUEST_CHANGES`**

Milestone 1 cannot be approved in its current state because `EvaluateResolver` fails to sanitize IEEE 754 floating point specials (`NaN` and `Inf`). This causes `CompositeScore` to become `NaN`, which corrupts `micro_burst.go` ranking and allows invalid resolvers to be ranked #1 and promoted into the active pool.

### Actionable Remediation Required:

1. **In `internal/client/score.go`**:
   - Import `"math"`.
   - In `EvaluateResolver(m ResolverMetrics)`:
     - Sanitize `lossRatio`:
       ```go
       lossRatio := m.LossRatio
       if math.IsNaN(lossRatio) || lossRatio > 1.0 {
           lossRatio = 1.0
       } else if lossRatio < 0.0 {
           lossRatio = 0.0
       }
       ```
     - Sanitize `speedKBps`:
       ```go
       speedKBps := m.ThroughputKBps
       if math.IsNaN(speedKBps) || math.IsInf(speedKBps, 0) || speedKBps <= 0.0 {
           if m.RTT > 0 {
               rttSec := m.RTT.Seconds()
               if rttSec > 0.0 {
                   speedKBps = (float64(downloadMTU) / 1024.0) / rttSec
               }
           }
       }
       if math.IsNaN(speedKBps) || speedKBps < 0.0 {
           speedKBps = 0.0
       }
       ```
     - Guard `latencyPenalty`:
       ```go
       if latencyPenalty < 1.0 || math.IsNaN(latencyPenalty) {
           latencyPenalty = 1.0
       }
       ```
     - Guard `effectiveThroughput`:
       ```go
       effectiveThroughput := speedKBps * (1.0 - lossRatio)
       if math.IsNaN(effectiveThroughput) || effectiveThroughput < 0.0 {
           effectiveThroughput = 0.0
       }
       ```
     - Guard `compositeScore`:
       ```go
       compositeScore := effectiveThroughput / latencyPenalty
       if math.IsNaN(compositeScore) || math.IsInf(compositeScore, 0) || compositeScore < 0.0 {
           compositeScore = 0.0
       }
       ```
   - In `FormatResolverSpeed(speedKBps float64)`:
     ```go
     if math.IsNaN(speedKBps) || math.IsInf(speedKBps, 0) || speedKBps <= 0 {
         return "n/a"
     }
     ```

2. **In `internal/client/micro_burst.go`**:
   - In `calculateBurstScore`:
     ```go
     if math.IsNaN(ev.CompositeScore) || ev.CompositeScore <= 0 {
         return 0.0
     }
     ```

3. **In `internal/client/balancer.go`**:
   - In `calculateConnectionScoreLocked`:
     ```go
     if math.IsNaN(ev.CompositeScore) || ev.CompositeScore <= 0 {
         return 1.0
     }
     ```

---

## 5. Verification Method

To verify the remediation:

1. Run the adversarial numerical stability and burst ranking suite in `internal/client/score_adversarial_test.go`:
   ```bash
   go test -v ./internal/client -run "TestScore_NumericalStability_.*|TestScore_Adversarial_.*"
   ```
2. Run all score tests:
   ```bash
   go test -v ./internal/client -run "TestScore.*|TestCalculateBurstScore.*"
   ```
3. Run the full client package test suite:
   ```bash
   go test ./internal/client
   ```
4. Build both binaries:
   ```bash
   go build ./cmd/client
   go build ./cmd/server
   ```
5. Confirm no changes outside allowed scope:
   ```bash
   git diff -- go.mod go.sum
   ```
