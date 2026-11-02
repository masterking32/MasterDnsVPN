# Architectural Survey & Design: R1 (Consolidated Resolver Evaluation) & R4 (Event-Driven Persistence & Maintenance Cleanup)

**Author:** teamwork_explorer instance 1  
**Target Branch:** `feat/fast-start-resolvers`  
**Repository:** `MasterDnsVPN` (`c:\Dev\Projects\DNStunnel`)  
**Scope:** R1 (Consolidated Resolver Evaluation) & R4 (Event-Driven Persistence & Maintenance Cleanup)  
**Status:** Complete Technical Blueprint  

---

## 1. Executive Summary

This investigation maps out the architectural consolidation required for **R1 (Consolidated Resolver Evaluation)** and **R4 (Event-Driven Persistence & Maintenance Cleanup)** as part of PR #205.

- **R1** consolidates performance evaluation, speed metrics, latency penalties, packet loss weighting, and tier badge generation currently fragmented and duplicated across `score.go`, `micro_burst.go`, `balancer.go`, `runtime_stats.go`, and `mtu_logging.go`. It establishes a pure, zero-dependency, zero-mutex functional core in `internal/client/score.go` centered on `EvaluateResolver(m ResolverMetrics) ResolverEvaluation`.
- **R4** eliminates the legacy 60-second polling maintenance loop (`internal/client/resolver_maintenance.go`), deletes `resolver_maintenance.go` and its tests, strips the `resolverMaintenanceStarted` flag from `Client`, hooks ranked resolver persistence directly to `pool.SetOnPoolChanged(...)`, and queries `pool.RankedEndpoints(50)` directly from `SaveRankedResolversToFile()`.

---

## 2. R1: Consolidated Resolver Evaluation

### 2.1 Current Implementation & Codebase Fragmentation Map

Currently, resolver scoring and quality tier categorization are fragmented across multiple files with duplicated formulas and awkward data conversions:

| File | Lines | Existing Role / Logic | Mutex Usage | Issues / Duplication |
|---|---|---|---|---|
| `internal/client/score.go` | 20–46 | `CalculateResolverScore(downloadMTU int, rtt time.Duration, lossRatio float64) (speedKBps, score float64)` | None | Calculates theoretical baseline speed `(MTU/1024)/RTT` and score. Cannot ingest empirical measured throughput. Has 0 unit tests. |
| `internal/client/score.go` | 48–57 | `FormatResolverSpeed(speedKBps float64) string` | None | Formats speed to KB/s or MB/s. Clean and reusable. |
| `internal/client/score.go` | 59–71 | `ResolverQualityTier(score float64) (tier string, coloredBadge string)` | None | Maps composite score to 4 tiers ("Excellent", "Good", "Fair", "Poor"). |
| `internal/client/micro_burst.go` | 252–257 | Empirical throughput calculation from byte counter and elapsed duration. | None | Computes `result.BurstThroughputKBps = (TotalBytesRx / 1024) / seconds`, then calls `CalculateResolverScore` to set baseline `result.ThroughputKBps`. |
| `internal/client/micro_burst.go` | 287–326 | `calculateBurstScore(result BurstProbeResult) float64` | None | **Duplicated scoring math**: Re-implements `effectiveThroughput = speed * (1 - lossRatio)` and `latencyPenalty = 1.0 + (rttMillis / 500.0)` because `CalculateResolverScore` did not allow passing measured throughput. |
| `internal/client/balancer.go` | 1415–1451 | `calculateConnectionScoreLocked(idx int) float64` | Executed under `b.mu` | Extracts MTU and loss/rtt snapshot from `b.stats[idx]`, calls `CalculateResolverScore(downloadMTU, avgRTT, lossRatio)`, and floor-clamps non-positive scores to `1.0`. |
| `internal/client/balancer.go` | 484–487 | Active member bonus in `GetRankedEndpoints` | Executed under `b.mu` | Adds arbitrary `+1000.0` score bump to active connections so active resolvers sort ahead of standby candidates. |
| `internal/client/runtime_stats.go` | 195–210 | `calculateResolverRuntimeSpeedAndScore(s ResolverStatsSnapshot) (string, string)` | None | Calls `CalculateResolverScore`, formats speed and score into strings. |
| `internal/client/runtime_stats.go` | 114–121, 158–165 | Runtime stats table printing in `DumpRuntimeStats` | None | **Anti-pattern**: Calls `calculateResolverRuntimeSpeedAndScore` to get `scoreStr`, then uses `fmt.Sscanf(scoreStr, "%f", &scoreVal)` to convert back to float to call `ResolverQualityTier(scoreVal)`. |
| `internal/client/mtu_logging.go` | 419, 493–496 | Formats completion table and reactivated resolver log | None | Calls `CalculateResolverScore` and `ResolverQualityTier`. |

### 2.2 Mathematical Model, Weights, and Edge Cases

#### 1. Baseline Throughput Capacity ($Speed$)
$$Speed\ (\text{KB/s}) = \frac{DownloadMTU / 1024.0}{RTT_{seconds}}$$
- If empirical measured throughput ($ThroughputKBps$) is already known (e.g. from micro-burst testing), empirical throughput takes precedence over the theoretical single-request baseline.
- If $DownloadMTU \le 0$, it defaults to the standard DNS minimum floor of `500` bytes.
- If $RTT \le 0$, throughput defaults to `0.0` KB/s.

#### 2. Loss Penalty ($Effective Throughput$)
$$EffectiveThroughput = Speed \times (1.0 - LossRatio)$$
- $LossRatio$ is clamped to the range $[0.0, 1.0]$.
- If $EffectiveThroughput < 0.0$, it is clamped to `0.0`.

#### 3. Latency Penalty
$$LatencyPenalty = 1.0 + \frac{RTT_{milliseconds}}{500.0}$$
- A resolver with $RTT = 0\text{ms}$ has penalty $1.0$.
- A resolver with $RTT = 500\text{ms}$ has penalty $2.0$ (halving its composite score).
- A resolver with $RTT = 1000\text{ms}$ has penalty $3.0$ (dividing its composite score by 3).
- $LatencyPenalty$ is floor-clamped to $\ge 1.0$.

#### 4. Composite Score
$$CompositeScore = \frac{EffectiveThroughput}{LatencyPenalty}$$
- If $RTT \le 0$ or $LossRatio \ge 1.0$, $CompositeScore = 0.0$.

#### 5. Quality Tier and Badge Mapping
| Composite Score Range | Tier Label | Terminal Colored Badge |
|---|---|---|
| $Score \ge 15.0$ | `Excellent` | `<green>[EXCELLENT]</green>` |
| $8.0 \le Score < 15.0$ | `Good` | `<cyan>[GOOD]</cyan>` |
| $4.0 \le Score < 8.0$ | `Fair` | `<yellow>[FAIR]</yellow>` |
| $Score < 4.0$ | `Poor` | `<red>[POOR]</red>` |

### 2.3 Proposed Target Design in `internal/client/score.go`

`internal/client/score.go` will be a pure mathematical module with **zero network dependencies** (`net` package must NOT be imported) and **zero mutexes**.

```go
package client

import (
	"fmt"
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
	if latencyPenalty <= 0.0 {
		latencyPenalty = 1.0
	}

	effectiveThroughput := speedKBps * (1.0 - lossRatio)
	if effectiveThroughput < 0.0 {
		effectiveThroughput = 0.0
	}

	compositeScore := effectiveThroughput / latencyPenalty
	tier, badge := ResolverQualityTier(compositeScore)

	return ResolverEvaluation{
		CompositeScore: compositeScore,
		ThroughputKBps: speedKBps,
		Tier:           tier,
		ColoredBadge:   badge,
	}
}

// CalculateResolverScore provides backward compatibility by delegating to EvaluateResolver.
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
```

### 2.4 Call-Site Migration Matrix

#### Call-Site 1: `internal/client/micro_burst.go`
- **Current** (lines 287–326):
  ```go
  func calculateBurstScore(result BurstProbeResult) float64 {
      if !result.Qualified || result.ReceivedCount == 0 {
          return 0.0
      }
      speedKBps := result.BurstThroughputKBps
      if speedKBps <= 0 { speedKBps = result.ThroughputKBps }
      ...
      effectiveThroughput := speedKBps * (1.0 - lossRatio)
      ...
      return effectiveThroughput / latencyPenalty
  }
  ```
- **Refactored**:
  ```go
  func calculateBurstScore(result BurstProbeResult) float64 {
      if !result.Qualified || result.ReceivedCount == 0 {
          return 0.0
      }
      speedKBps := result.BurstThroughputKBps
      if speedKBps <= 0 {
          speedKBps = result.ThroughputKBps
      }
      downloadMTU := result.DownloadMTUBytes
      if downloadMTU <= 0 && result.ReceivedCount > 0 && result.TotalBytesRx > 0 {
          downloadMTU = result.TotalBytesRx / result.ReceivedCount
      }
      ev := EvaluateResolver(ResolverMetrics{
          DownloadMTUBytes: downloadMTU,
          RTT:              result.AverageRTT,
          LossRatio:        result.LossRatio,
          ThroughputKBps:   speedKBps,
      })
      return ev.CompositeScore
  }
  ```
- **Benefit**: Eliminates 30+ lines of duplicated math and handles `BurstThroughputKBps` natively through `ResolverMetrics`.

#### Call-Site 2: `internal/client/balancer.go`
- **Current** (lines 1446–1450):
  ```go
  _, score := CalculateResolverScore(downloadMTU, avgRTT, lossRatio)
  if score <= 0 {
      return 1.0
  }
  return score
  ```
- **Refactored**:
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
  *(Note: In R2, this scoring logic transitions into `ResolverPool.calculateScoreLocked`)*

#### Call-Site 3: `internal/client/runtime_stats.go`
- **Current** (lines 114–121 & 195–210):
  ```go
  func calculateResolverRuntimeSpeedAndScore(s ResolverStatsSnapshot) (string, string) {
      ...
      speedKBps, score := CalculateResolverScore(s.Connection.DownloadMTUBytes, rtt, s.LossRatio)
      speedStr := FormatResolverSpeed(speedKBps)
      scoreStr := fmt.Sprintf("%.1f", score)
      return speedStr, scoreStr
  }
  // Inside DumpRuntimeStats:
  speedStr, scoreStr := calculateResolverRuntimeSpeedAndScore(s)
  scoreVal := 0.0
  if scoreStr != "n/a" {
      _, _ = fmt.Sscanf(scoreStr, "%f", &scoreVal)
  }
  tier, _ := ResolverQualityTier(scoreVal)
  statusStr := fmt.Sprintf("ACTIVE (%s)", tier)
  ```
- **Refactored**:
  ```go
  rtt := s.AverageRTT
  if rtt <= 0 {
      rtt = s.Connection.MTUResolveTime
  }
  ev := EvaluateResolver(ResolverMetrics{
      DownloadMTUBytes: s.Connection.DownloadMTUBytes,
      RTT:              rtt,
      LossRatio:        s.LossRatio,
  })
  speedStr := FormatResolverSpeed(ev.ThroughputKBps)
  scoreStr := "n/a"
  if rtt > 0 {
      scoreStr = fmt.Sprintf("%.1f", ev.CompositeScore)
  }
  statusStr := fmt.Sprintf("ACTIVE (%s)", ev.Tier)
  ```
- **Benefit**: Eliminates the `fmt.Sscanf` parsing anti-pattern and directly uses `ev.Tier` and `ev.ThroughputKBps`.

---

## 3. R4: Event-Driven Persistence & Maintenance Cleanup

### 3.1 Flaws in the Current Polling Implementation

Currently, `internal/client/resolver_maintenance.go` contains:
```go
const resolverMaintenanceInterval = time.Minute

func (c *Client) ensureResolverMaintenance(ctx context.Context) {
	if c == nil || !c.resolverMaintenanceStarted.CompareAndSwap(false, true) {
		return
	}
	go c.runResolverMaintenance(ctx)
}

func (c *Client) runResolverMaintenance(ctx context.Context) {
	ticker := time.NewTicker(resolverMaintenanceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if ctx.Err() != nil {
				return
			}
			if c.balancer != nil && c.balancer.OptimizeActivePool() {
				c.SaveRankedResolversToFile()
			}
		}
	}
}
```

**Architectural Deficiencies:**
1. **Unnecessary Goroutine & Polling:** Wakes up every 60 seconds even when no traffic or rechecks have occurred.
2. **Lag in Persistence:** If an inactive resolver recheck discovers a superior candidate at second 5, the updated ranking is not persisted until second 60.
3. **Session Reset Complications:** Requires atomic flag tracking (`c.resolverMaintenanceStarted`) and special handling in `client.go` and `resolver_maintenance_test.go` to avoid duplicate background loops across session restarts.
4. **Testing Overhead:** Requires synctest mocking with virtual time steps of 59s and 60s in `resolver_maintenance_test.go`.

### 3.2 Mechanism of `SaveRankedResolversToFile()`

Currently located in `internal/client/client_utils.go` (lines 654–686):
```go
func (c *Client) SaveRankedResolversToFile() {
	if c == nil || c.balancer == nil || !c.cfg.AutoSaveRankedResolvers {
		return
	}

	resolversPath := c.cfg.ResolversPath()
	if resolversPath == "" {
		return
	}

	maxRanked := c.cfg.MaxActiveResolvers * 2
	if maxRanked < 32 {
		maxRanked = 32
	}

	ranked := c.balancer.GetRankedEndpoints(maxRanked)
	if len(ranked) == 0 {
		return
	}

	if err := config.UpdateResolversFileWithRanked(resolversPath, ranked); err != nil {
		if c.log != nil && c.log.Enabled(logger.LevelWarn) {
			c.log.Warnf("<yellow>[Resolvers]</yellow> Failed to auto-save ranked resolvers to <cyan>%s</cyan>: %v", resolversPath, err)
		}
		return
	}

	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf("<green>[Resolvers]</green> Saved %d ranked resolvers to <cyan>%s</cyan>", len(ranked), resolversPath)
	}
}
```

How it works:
1. Checks preconditions: `AutoSaveRankedResolvers` must be true and `ResolversPath` must be non-empty.
2. Requests ranked endpoints.
3. Calls `config.UpdateResolversFileWithRanked(resolversPath, ranked)`.
4. `config.UpdateResolversFileWithRanked` updates the auto-ranked header block (`# Auto-Ranked Best Resolvers`) while preserving all custom user lines, comments, and subnets below.

### 3.3 Target Event-Driven Architecture

In the unified design, `ResolverPool` (from R2) manages candidate state transitions and notifies listeners whenever the pool composition changes.

#### 1. Registration via `pool.SetOnPoolChanged`
In `Client` initialization (`client.go:New` or session startup):
```go
c.pool.SetOnPoolChanged(func() {
    c.SaveRankedResolversToFile()
})
```

#### 2. Pool Events That Trigger `onPoolChanged`
In `ResolverPool`:
- `AdmitStartupBatch`: When the initial startup batch is admitted.
- `FinalizeFastStart`: When excess resolvers are demoted back to standby after FastStart target is reached.
- `ReleaseRecheck`: When an inactive candidate finishes health recheck and is promoted or ranked.
- `Optimize`: When periodic optimization swaps a degraded active resolver for a superior standby.

#### 3. Update to `SaveRankedResolversToFile()` in `client_utils.go`
Directly connects to `c.pool.RankedEndpoints(50)`:
```go
// SaveRankedResolversToFile persists the top-ranked resolver endpoints to the resolvers file
// under an auto-ranked header block, preserving all custom user lines below.
func (c *Client) SaveRankedResolversToFile() {
	if c == nil || c.pool == nil || !c.cfg.AutoSaveRankedResolvers {
		return
	}

	resolversPath := c.cfg.ResolversPath()
	if resolversPath == "" {
		return
	}

	ranked := c.pool.RankedEndpoints(50)
	if len(ranked) == 0 {
		return
	}

	if err := config.UpdateResolversFileWithRanked(resolversPath, ranked); err != nil {
		if c.log != nil && c.log.Enabled(logger.LevelWarn) {
			c.log.Warnf("<yellow>[Resolvers]</yellow> Failed to auto-save ranked resolvers to <cyan>%s</cyan>: %v", resolversPath, err)
		}
		return
	}

	if c.log != nil && c.log.Enabled(logger.LevelDebug) {
		c.log.Debugf("<green>[Resolvers]</green> Saved %d ranked resolvers to <cyan>%s</cyan>", len(ranked), resolversPath)
	}
}
```

#### 4. File Deletions and Cleanup
- **DELETE** `internal/client/resolver_maintenance.go`
- **DELETE** `internal/client/resolver_maintenance_test.go`
- In `internal/client/client.go`:
  - Delete `resolverMaintenanceStarted atomic.Bool` field from `struct Client` (line 90).
  - Delete `c.ensureResolverMaintenance(ctx)` call (line 439).

---

## 4. Test Impact & Verification Plan

### 4.1 Existing Tests Touching Score, Evaluation, and Maintenance

| Test File | Existing Test Function | Impact / Required Changes |
|---|---|---|
| `internal/client/score.go` | *None* | Create `internal/client/score_test.go` to test `EvaluateResolver`, MTU defaults, loss clamping, latency penalties, tiers, and speed formatting. |
| `internal/client/micro_burst_test.go` | `TestCalculateBurstScoreRanking` (lines 28–92) | Will automatically verify that `calculateBurstScore` delegating to `EvaluateResolver` produces identical ranking behavior. |
| `internal/client/runtime_stats_test.go` | `TestClientSaveRankedResolversToFile` (lines 166–218) | Update from `c.balancer.SetConnections(...)` to initialize `c.pool` and verify `pool.RankedEndpoints(50)`. |
| `internal/client/balancer_test.go` | `TestBalancerGetRankedEndpoints` (lines 624–671) | Balancer retains packet dispatching; ranking moves to `ResolverPool.RankedEndpoints`. |
| `internal/client/resolver_maintenance_test.go` | `TestResolverMaintenance*` | Entire file is deleted. The event-driven callback will be tested in `internal/client/resolver_pool_test.go` (`TestResolverPool_OnPoolChanged`). |
| `internal/client/empirical_challenge_test.go` | `TestEmpirical_MicroBurst_ActivePoolFullPromotion` | Tests active pool displacement and ranking; passes without regressions. |

### 4.2 New Unit Test Suite: `internal/client/score_test.go`

A comprehensive test suite should be created to verify:
1. **Zero / Negative MTU Defaulting**: Confirms that non-positive MTU defaults to 500 bytes.
2. **Loss Ratio Clamping**: Confirms that negative loss is clamped to 0.0 and loss > 1.0 is clamped to 1.0.
3. **Zero / Negative RTT Handling**: Confirms that RTT <= 0 yields CompositeScore = 0.0 and Tier = "Poor".
4. **Empirical Throughput Override**: Confirms that when `ThroughputKBps > 0`, it overrides the theoretical baseline.
5. **Latency Penalty Calculation**: Confirms that RTT = 500ms applies a 2.0x divisor, and RTT = 1000ms applies a 3.0x divisor.
6. **Tier Badge Classifications**:
   - Score >= 15.0 -> "Excellent", `[EXCELLENT]`
   - Score 8.0 -> "Good", `[GOOD]`
   - Score 4.0 -> "Fair", `[FAIR]`
   - Score < 4.0 -> "Poor", `[POOR]`
7. **Speed Formatting**: Formats < 1000 KB/s as `%.1f KB/s` and >= 1000 KB/s as `%.2f MB/s`.

---

## 5. File Modification Checklist

| Action | Path | Description |
|---|---|---|
| **Modify** | `internal/client/score.go` | Add `ResolverMetrics`, `ResolverEvaluation`, and `EvaluateResolver`. Delegate `CalculateResolverScore`. Retain `ResolverQualityTier` and `FormatResolverSpeed`. |
| **Create** | `internal/client/score_test.go` | Unit test suite for `EvaluateResolver`, metrics handling, and tier assignments. |
| **Modify** | `internal/client/micro_burst.go` | Refactor `calculateBurstScore` to delegate to `EvaluateResolver`. |
| **Modify** | `internal/client/balancer.go` | Refactor `calculateConnectionScoreLocked` to use `EvaluateResolver`. |
| **Modify** | `internal/client/runtime_stats.go` | Refactor `calculateResolverRuntimeSpeedAndScore` and `DumpRuntimeStats` to use `EvaluateResolver` directly, eliminating `fmt.Sscanf`. |
| **Modify** | `internal/client/client_utils.go` | Update `SaveRankedResolversToFile()` to query `c.pool.RankedEndpoints(50)`. |
| **Modify** | `internal/client/client.go` | Remove `resolverMaintenanceStarted` atomic flag; remove `ensureResolverMaintenance(ctx)`. Register `pool.SetOnPoolChanged(func() { c.SaveRankedResolversToFile() })`. |
| **Delete** | `internal/client/resolver_maintenance.go` | Remove obsolete 60-second polling maintenance loop. |
| **Delete** | `internal/client/resolver_maintenance_test.go` | Remove obsolete polling tests. |
| **Modify** | `internal/client/runtime_stats_test.go` | Adapt `TestClientSaveRankedResolversToFile` to use `c.pool`. |
