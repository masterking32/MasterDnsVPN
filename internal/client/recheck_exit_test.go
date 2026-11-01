package client

import (
	"context"
	"net"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
)

func TestRecheckInactiveResolver_EarlyExitsCompleteCandidate(t *testing.T) {
	for _, reason := range []string{"dial-error", "cancelled-before-dial", "cancelled-during-probe"} {
		t.Run(reason, func(t *testing.T) {
			listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			cfg := config.DefaultClientConfig()
			cfg.Domains = []string{"v.example.com"}
			cfg.Resolvers = []config.ResolverAddress{{IP: "127.0.0.1", Port: listener.LocalAddr().(*net.UDPAddr).Port}}
			cfg.DataEncryptionMethod = 0
			cfg.MTUTestTimeout = 10
			cfg.MTUTestRetries = 1
			c := createTestFastStartClient(t, cfg)
			c.pool.SetOnPoolChanged(nil)
			c.syncedUploadMTU, c.syncedDownloadMTU = 100, 500
			key := c.pool.AllConnections()[0].Key
			c.pool.SetConnectionStandbyEligible(key, true)
			candidate, ok := c.pool.AcquireNextInactiveForRecheck(time.Now(), time.Second)
			if !ok {
				t.Fatal("expected scheduled recheck candidate")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch reason {
			case "dial-error":
				candidate.ResolverLabel = "127.0.0.1:invalid-port"
			case "cancelled-before-dial":
				cancel()
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				c.recheckInactiveResolver(ctx, candidate)
			}()
			if reason == "cancelled-during-probe" {
				_ = listener.SetReadDeadline(time.Now().Add(2 * time.Second))
				if _, _, err := listener.ReadFromUDP(make([]byte, 4096)); err != nil {
					cancel()
					t.Fatalf("wait for probe: %v", err)
				}
				cancel()
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				// Let the old implementation finish before releasing the fixture.
				listener.Close()
				<-done
				t.Fatal("recheck did not exit promptly after cancellation")
			}
			c.pool.mu.RLock()
			state := c.pool.candidates[c.pool.indexByKey[key]].state
			c.pool.mu.RUnlock()
			got, _ := c.pool.GetConnectionByKey(key)
			if state != StateInactive || got.IsValid || got.StandbyEligible {
				t.Fatalf("unfinished recheck: state=%v active=%v standby=%v", state, got.IsValid, got.StandbyEligible)
			}
		})
	}
}
