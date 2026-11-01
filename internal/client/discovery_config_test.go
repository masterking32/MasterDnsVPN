package client

import (
	"context"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
)

type observedBurstConfig struct {
	packets int
	timeout time.Duration
}

type configRecordingProber struct {
	*FakeResolverProber
	bursts chan observedBurstConfig
}

func (p *configRecordingProber) ProbeBurst(ctx context.Context, conn Connection, packets, downloadMTU, uploadMTU int, timeout time.Duration) BurstProbeResult {
	p.bursts <- observedBurstConfig{packets, timeout}
	return p.FakeResolverProber.ProbeBurst(ctx, conn, packets, downloadMTU, uploadMTU, timeout)
}

// Direct engine defaults intentionally differ from Client configuration defaults.
// Verify the actual arguments reaching the probe, not just configuration storage.
func TestDiscoveryEngine_ProbeConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name        string
		packets     int
		timeout     time.Duration
		wantPackets int
		wantTimeout time.Duration
	}{
		{"defaults", 0, 0, 6, 3 * time.Second},
		{"negative", -1, -time.Second, 6, 3 * time.Second},
		{"minimum", 1, time.Second, 2, time.Second},
		{"explicit", 9, 200 * time.Millisecond, 9, 200 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pool, _ := createTestDiscoverySetup(2)
			prober := &configRecordingProber{NewFakeResolverProber(), make(chan observedBurstConfig, 2)}
			cfg := DiscoveryConfig{
				MicroBurstEnabled: true, MicroBurstPacketCount: tc.packets,
				MicroBurstTimeout: tc.timeout,
			}
			if err := NewDiscoveryEngine(cfg, prober, pool, nil).Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			if pool.ActiveCount() != 2 || len(prober.bursts) != 2 {
				t.Fatalf("default full scan must qualify both candidates: active=%d bursts=%d", pool.ActiveCount(), len(prober.bursts))
			}
			for range 2 {
				got := <-prober.bursts
				if got.packets != tc.wantPackets || got.timeout != tc.wantTimeout {
					t.Fatalf("probe config=%+v; want packets=%d timeout=%v", got, tc.wantPackets, tc.wantTimeout)
				}
			}
		})
	}
}

func TestClientDiscoveryConfig_PreservesDefaultsAndOverrides(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		name := "fallbacks"
		if explicit {
			name = "overrides"
		}
		t.Run(name, func(t *testing.T) {
			cfg := config.DefaultClientConfig()
			cfg.Domains = []string{"example.com"}
			cfg.Resolvers = []config.ResolverAddress{{IP: "127.0.0.1", Port: 53}}
			cfg.DataEncryptionMethod = 0
			cfg.AutoSaveRankedResolvers = false
			cfg.MicroBurstPacketCount = 1
			cfg.MicroBurstParallelism = 0
			cfg.RecheckInactiveServersEnabled = true
			if explicit {
				cfg.MicroBurstPacketCount = 9
				cfg.MicroBurstParallelism = 3
				cfg.RecheckInactiveServersEnabled = false
			}
			client := createTestFastStartClient(t, cfg)
			got := client.newDiscoveryConfig()
			wantPackets, wantWorkers := 6, 8
			if explicit {
				wantPackets, wantWorkers = 9, 3
			}
			if got.MicroBurstPacketCount != wantPackets || got.MicroBurstParallelism != wantWorkers || got.FastStart != !explicit {
				t.Fatalf("unexpected translated discovery config: %+v", got)
			}
			if got.TargetResolvers != 1 || got.Parallelism != 1 || got.MaxActiveResolvers != cfg.MaxActiveResolvers {
				t.Fatalf("quota, worker bound or capacity changed: %+v", got)
			}
		})
	}
}
