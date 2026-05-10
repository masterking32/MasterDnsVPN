// ==============================================================================
// MasterDnsVPN — Innovation: Hot-Reload Config
// Listens for SIGHUP and reloads the resolver list and selected config fields
// without restarting the process. The VPN session stays up; only the balancer
// connection list is updated atomically.
// ==============================================================================
package configwatcher

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// ReloadFunc is called when SIGHUP is received. It should reload and apply
// only the fields that are safe to change at runtime (resolvers, log level).
type ReloadFunc func() error

// Watch blocks until ctx is cancelled, reloading config on every SIGHUP.
// Call this in a background goroutine:
//
//	go configwatcher.Watch(ctx, func() error { return reloadResolvers() })
func Watch(ctx context.Context, reload ReloadFunc, logf func(format string, args ...any)) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			if logf != nil {
				logf("🔄 SIGHUP received — reloading configuration...")
			}
			if err := reload(); err != nil {
				if logf != nil {
					logf("❌ Config reload failed: %v", err)
				}
			} else {
				if logf != nil {
					logf("✅ Configuration reloaded successfully")
				}
			}
		}
	}
}
