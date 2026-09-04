// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (runtime_stats.go) handles live resolver performance monitoring,
// periodic table dumps, and interactive console hotkey inspection.
// ==============================================================================
package client

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/logger"
)

var (
	consoleListenerOnce sync.Once
	statsHintOnce       sync.Once
)

// DumpRuntimeStats prints a formatted diagnostic summary table of all active
// and standby resolvers with their traffic, loss %, latency, and assigned streams.
func (c *Client) DumpRuntimeStats(reason string) {
	if c == nil || c.balancer == nil || c.log == nil {
		return
	}

	snapshots := c.balancer.GetStatsSnapshot()
	if len(snapshots) == 0 {
		return
	}

	// Partition into active and standby
	activeSnapshots := make([]ResolverStatsSnapshot, 0, len(snapshots))
	standbySnapshots := make([]ResolverStatsSnapshot, 0, len(snapshots))

	var totalSent, totalAcked, totalLost uint64
	var totalActiveStreams int

	for _, s := range snapshots {
		totalSent += s.Sent
		totalAcked += s.Acked
		totalLost += s.Lost
		totalActiveStreams += s.ActiveStreams

		if s.IsValid {
			activeSnapshots = append(activeSnapshots, s)
		} else {
			standbySnapshots = append(standbySnapshots, s)
		}
	}

	// Sort active resolvers by Sent descending, then by Loss ascending, then by RTT ascending
	sort.Slice(activeSnapshots, func(i, j int) bool {
		if activeSnapshots[i].Sent != activeSnapshots[j].Sent {
			return activeSnapshots[i].Sent > activeSnapshots[j].Sent
		}
		if activeSnapshots[i].LossRatio != activeSnapshots[j].LossRatio {
			return activeSnapshots[i].LossRatio < activeSnapshots[j].LossRatio
		}
		return activeSnapshots[i].AverageRTT < activeSnapshots[j].AverageRTT
	})

	overallLossRatio := 0.0
	if totalSent > 0 {
		overallLossRatio = float64(totalLost) / float64(totalSent)
	}

	reasonStr := ""
	if reason != "" {
		reasonStr = fmt.Sprintf(" [%s]", reason)
	}

	separator := strings.Repeat("=", 106)
	subSeparator := strings.Repeat("-", 106)

	c.log.Infof("%s", separator)
	c.log.Infof("<green>📊 Live Resolver Performance & Usage%s (Active: <cyan>%d</cyan> | Total: <cyan>%d</cyan>):</green>",
		reasonStr, len(activeSnapshots), len(snapshots))
	c.log.Infof("%s", separator)
	c.log.Infof(
		"%-20s %-16s %-8s %-8s %-8s %-9s %-11s %-8s %-8s %-16s",
		"Resolver",
		"Domain",
		"Sent",
		"Acked",
		"Loss %",
		"Avg RTT",
		"Speed",
		"Score",
		"Streams",
		"Status",
	)
	c.log.Infof("%s", subSeparator)

	// Print active resolvers
	for _, s := range activeSnapshots {
		lossStr := fmt.Sprintf("%.1f%%", s.LossRatio*100)
		rttStr := "n/a"
		if s.AverageRTT > 0 {
			rttStr = formatResolverRTT(s.AverageRTT)
		}
		speedStr, scoreStr := calculateResolverRuntimeSpeedAndScore(s)

		scoreVal := 0.0
		if scoreStr != "n/a" {
			_, _ = fmt.Sscanf(scoreStr, "%f", &scoreVal)
		}
		tier, _ := ResolverQualityTier(scoreVal)
		statusStr := fmt.Sprintf("ACTIVE (%s)", tier)

		c.log.Infof(
			"<cyan>%-20s</cyan> <blue>%-16s</blue> %-8d %-8d <yellow>%-8s</yellow> <yellow>%-9s</yellow> <green>%-11s</green> <cyan>%-8s</cyan> <cyan>%-8d</cyan> <green>%-16s</green>",
			s.Connection.ResolverLabel,
			s.Connection.Domain,
			s.Sent,
			s.Acked,
			lossStr,
			rttStr,
			speedStr,
			scoreStr,
			s.ActiveStreams,
			statusStr,
		)
	}

	// Print top 3 standby resolvers if any have activity
	standbyWithActivity := 0
	for _, s := range standbySnapshots {
		if s.Sent > 0 {
			standbyWithActivity++
		}
	}
	if standbyWithActivity > 0 {
		sort.Slice(standbySnapshots, func(i, j int) bool {
			return standbySnapshots[i].Sent > standbySnapshots[j].Sent
		})
		c.log.Infof("%s", subSeparator)
		maxShow := min(3, len(standbySnapshots))
		for i := 0; i < maxShow; i++ {
			s := standbySnapshots[i]
			lossStr := fmt.Sprintf("%.1f%%", s.LossRatio*100)
			rttStr := "n/a"
			if s.AverageRTT > 0 {
				rttStr = formatResolverRTT(s.AverageRTT)
			}
			speedStr, scoreStr := calculateResolverRuntimeSpeedAndScore(s)

			scoreVal := 0.0
			if scoreStr != "n/a" {
				_, _ = fmt.Sscanf(scoreStr, "%f", &scoreVal)
			}
			tier, _ := ResolverQualityTier(scoreVal)
			statusStr := fmt.Sprintf("STANDBY (%s)", tier)

			c.log.Infof(
				"<cyan>%-20s</cyan> <blue>%-16s</blue> %-8d %-8d <yellow>%-8s</yellow> <yellow>%-9s</yellow> <green>%-11s</green> <cyan>%-8s</cyan> <cyan>%-8d</cyan> <yellow>%-16s</yellow>",
				s.Connection.ResolverLabel,
				s.Connection.Domain,
				s.Sent,
				s.Acked,
				lossStr,
				rttStr,
				speedStr,
				scoreStr,
				s.ActiveStreams,
				statusStr,
			)
		}
	}

	c.log.Infof("%s", separator)
	c.log.Infof(
		"<blue>Total Tunnel Traffic: Sent <cyan>%d</cyan> pkts | Acked <green>%d</green> | Lost <yellow>%d</yellow> (<yellow>%.1f%%</yellow>) | Active Streams: <cyan>%d</cyan></blue>",
		totalSent,
		totalAcked,
		totalLost,
		overallLossRatio*100,
		totalActiveStreams,
	)
	c.log.Infof("%s", separator)
}

func calculateResolverRuntimeSpeedAndScore(s ResolverStatsSnapshot) (string, string) {
	rtt := s.AverageRTT
	if rtt <= 0 {
		rtt = s.Connection.MTUResolveTime
	}

	if rtt <= 0 {
		return "n/a", "n/a"
	}

	speedKBps, score := CalculateResolverScore(s.Connection.DownloadMTUBytes, rtt, s.LossRatio)
	speedStr := FormatResolverSpeed(speedKBps)
	scoreStr := fmt.Sprintf("%.1f", score)

	return speedStr, scoreStr
}

// runRuntimeStatsLoop runs a periodic background checker that logs performance
// stats whenever tunnel traffic has been processed.
func (c *Client) runRuntimeStatsLoop(ctx context.Context) {
	if c == nil || c.cfg.RuntimeStatsIntervalSeconds <= 0 {
		return
	}

	interval := time.Duration(c.cfg.RuntimeStatsIntervalSeconds * float64(time.Second))
	if interval < time.Second {
		interval = 60 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastSentTotal uint64

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Periodically evaluate and optimize the active pool (swap degraded resolvers with better standbys)
			if c.balancer != nil {
				if c.balancer.OptimizeActivePool() {
					c.SaveRankedResolversToFile()
				}
			}

			currentSentTotal := c.calculateTotalSentPackets()
			if currentSentTotal > lastSentTotal {
				lastSentTotal = currentSentTotal
				if c.log != nil && c.log.Enabled(logger.LevelInfo) {
					c.DumpRuntimeStats("Periodic")
				}
			}
		}
	}
}

// calculateTotalSentPackets sums the sent packet count across all resolvers.
func (c *Client) calculateTotalSentPackets() uint64 {
	if c == nil || c.balancer == nil {
		return 0
	}
	snapshots := c.balancer.GetStatsSnapshot()
	var total uint64
	for _, s := range snapshots {
		total += s.Sent
	}
	return total
}

// printRuntimeStatsHint prints a startup reminder on how to view live stats.
func (c *Client) printRuntimeStatsHint() {
	if c == nil || c.log == nil {
		return
	}
	statsHintOnce.Do(func() {
		c.log.Infof("<yellow>💡 Tip: Press <green>'s'</green> + <green>Enter</green> at any time to view live resolver performance and traffic statistics.</yellow>")
	})
}

// startInteractiveConsoleListener starts a background listener on standard input
// that triggers an on-demand performance dump when the user presses 's' or Enter.
func (c *Client) startInteractiveConsoleListener(ctx context.Context) {
	if c == nil {
		return
	}

	consoleListenerOnce.Do(func() {
		go func() {
			scanner := bufio.NewScanner(os.Stdin)
			var lastTrigger atomic.Int64

			for scanner.Scan() {
				if ctx.Err() != nil {
					return
				}

				text := strings.TrimSpace(scanner.Text())
				if text == "s" || text == "S" || text == "stats" || text == "" {
					now := time.Now().UnixNano()
					prev := lastTrigger.Load()
					// Debounce keypresses within 500ms
					if now-prev > int64(500*time.Millisecond) {
						lastTrigger.Store(now)
						c.DumpRuntimeStats("Keypress")
					}
				}
			}
		}()
	})
}
