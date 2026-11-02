# Handoff Report: R1 & R4 Codebase Survey

**Agent:** `teamwork_explorer_1`  
**Working Directory:** `c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_1`  
**Report Path:** `c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_1\report.md`  
**Handoff Type:** Hard  

---

## 1. Observation

1. **`internal/client/score.go` (lines 20–46):**
   `CalculateResolverScore(downloadMTU int, rtt time.Duration, lossRatio float64) (speedKBps float64, score float64)` computes:
   ```go
   speedKBps = (float64(downloadMTU) / 1024.0) / rttSec
   rttMillis := float64(rtt.Milliseconds())
   latencyPenalty := 1.0 + (rttMillis / 500.0)
   effectiveThroughput := speedKBps * (1.0 - lossRatio)
   score = effectiveThroughput / latencyPenalty
   ```
   Lines 59–71 define `ResolverQualityTier(score float64)` with thresholds 15.0 ("Excellent"), 8.0 ("Good"), 4.0 ("Fair"), and default "Poor".
   Zero network dependencies and zero mutexes exist in this file.

2. **`internal/client/micro_burst.go` (lines 287–326):**
   `calculateBurstScore(result BurstProbeResult) float64` duplicates the exact latency penalty and effective throughput calculations:
   ```go
   effectiveThroughput := speedKBps * (1.0 - lossRatio)
   rttMillis := float64(result.AverageRTT.Milliseconds())
   latencyPenalty := 1.0 + (rttMillis / 500.0)
   return effectiveThroughput / latencyPenalty
   ```
   This duplication exists because `CalculateResolverScore` does not accept empirical measured throughput (`ThroughputKBps` or `BurstThroughputKBps`).

3. **`internal/client/balancer.go` (lines 1415–1451):**
   `calculateConnectionScoreLocked(idx int) float64` acquires stats from `b.stats[idx].snapshot()`, calls `CalculateResolverScore(downloadMTU, avgRTT, lossRatio)`, and floor-clamps non-positive scores to `1.0`.

4. **`internal/client/runtime_stats.go` (lines 114–121, 158–165, 195–210):**
   `calculateResolverRuntimeSpeedAndScore` calls `CalculateResolverScore`, converts to `speedStr` and `scoreStr = fmt.Sprintf("%.1f", score)`.
   In `DumpRuntimeStats`, lines 118 and 162 re-parse this formatted string with `fmt.Sscanf(scoreStr, "%f", &scoreVal)` solely to call `ResolverQualityTier(scoreVal)`.

5. **`internal/client/resolver_maintenance.go` (lines 8–38):**
   Implements a 1-minute ticker:
   ```go
   const resolverMaintenanceInterval = time.Minute
   func (c *Client) runResolverMaintenance(ctx context.Context) {
       ticker := time.NewTicker(resolverMaintenanceInterval)
       defer ticker.Stop()
       for {
           select {
           case <-ctx.Done(): return
           case <-ticker.C:
               if c.balancer != nil && c.balancer.OptimizeActivePool() {
                   c.SaveRankedResolversToFile()
               }
           }
       }
   }
   ```
   In `internal/client/client.go` line 90, `resolverMaintenanceStarted atomic.Bool` guards this loop, and line 439 calls `c.ensureResolverMaintenance(ctx)`.

6. **`internal/client/client_utils.go` (lines 654–686):**
   `SaveRankedResolversToFile()` queries `c.balancer.GetRankedEndpoints(maxRanked)` and writes out the file using `config.UpdateResolversFileWithRanked(resolversPath, ranked)`.

7. **Test execution:**
   Running `go test ./internal/client` succeeded in 52.773s with zero failures.

---

## 2. Logic Chain

1. From Observation 1 and 2, `score.go`'s `CalculateResolverScore` lacks an empirical throughput field, causing `micro_burst.go` to re-implement the entire scoring pipeline in `calculateBurstScore`. Introducing `ResolverMetrics{DownloadMTUBytes, RTT, LossRatio, ThroughputKBps}` and `ResolverEvaluation{CompositeScore, ThroughputKBps, Tier, ColoredBadge}` via `EvaluateResolver(m ResolverMetrics) ResolverEvaluation` provides a single unified entry point that naturally handles both theoretical baseline MTU/RTT calculation and measured burst throughput.
2. From Observation 4, `runtime_stats.go` currently executes an inefficient round-trip (`score float64` -> `string` via `Sprintf` -> `scoreVal float64` via `Sscanf` -> `tier` via `ResolverQualityTier`). Consolidating this into `EvaluateResolver` allows `DumpRuntimeStats` to read `ev.Tier` and `ev.ThroughputKBps` directly, eliminating `fmt.Sscanf`.
3. From Observation 5, `resolver_maintenance.go` polls active pool optimization on an arbitrary 60-second ticker solely to call `SaveRankedResolversToFile()` when a replacement occurs. This polling delays persistence of rank changes discovered during rechecks, requires background goroutine lifecycle management in `client.go`, and introduces synctest fragility.
4. From Observation 5 and 6, when `ResolverPool` (R2) introduces `SetOnPoolChanged(func())`, every meaningful state transition (startup batch admission, FastStart finalization, recheck completion via `ReleaseRecheck`, and pool optimization via `Optimize`) can directly invoke `SaveRankedResolversToFile()`.
5. Therefore, `resolver_maintenance.go` and `resolver_maintenance_test.go` can be completely deleted, `resolverMaintenanceStarted` removed from `Client`, and `SaveRankedResolversToFile` updated to query `c.pool.RankedEndpoints(50)`.

---

## 3. Caveats

1. **Implementation dependency on R2 (`ResolverPool`):** R4 connects `SaveRankedResolversToFile` to `c.pool.RankedEndpoints(50)` and registers the callback via `c.pool.SetOnPoolChanged(...)`. The implementer must ensure `c.pool` is initialized and exposed before wiring the callback in `client.go`.
2. **Backward Compatibility:** `CalculateResolverScore`, `FormatResolverSpeed`, and `ResolverQualityTier` must remain exported in `score.go` as compatibility shims so unmigrated tests or packages outside `internal/client` continue compiling cleanly.
3. **Scope Constraint:** Zero modifications were made to code during this turn in accordance with read-only investigation rules.

---

## 4. Conclusion

The blueprints for R1 and R4 are complete, verified against existing tests, and documented in detail in `report.md`:
1. **R1:** `internal/client/score.go` will export `ResolverMetrics`, `ResolverEvaluation`, and `EvaluateResolver`. `micro_burst.go`, `balancer.go`, and `runtime_stats.go` will be refactored to consume `EvaluateResolver`, deleting 30+ lines of duplicate math in `micro_burst.go` and removing the string parsing roundtrip in `runtime_stats.go`. A dedicated `score_test.go` will be added.
2. **R4:** `internal/client/resolver_maintenance.go` and `resolver_maintenance_test.go` will be deleted. `client.go` will remove `resolverMaintenanceStarted` and `c.ensureResolverMaintenance(ctx)`. `client_utils.go`'s `SaveRankedResolversToFile()` will directly call `c.pool.RankedEndpoints(50)` and be triggered reactively via `pool.SetOnPoolChanged(...)`.

---

## 5. Verification Method

To verify these findings independently:
1. **Inspect Survey Report:**
   Read `c:\Dev\Projects\DNStunnel\.agents\teamwork\explorer_survey_1\report.md` for exact line numbers, formulas, and refactoring diff designs.
2. **Verify Duplicated Scoring Math:**
   Compare `micro_burst.go:314-325` with `score.go:37-45` using `view_file`.
3. **Verify Polling Maintenance Loop:**
   Inspect `resolver_maintenance.go:21-37` and `client.go:90,439` using `view_file`.
4. **Run Unit Tests:**
   Execute `go test -v ./internal/client -run "TestCalculateBurstScoreRanking|TestClientSaveRankedResolversToFile"` to verify existing tests touching scoring and persistence.
