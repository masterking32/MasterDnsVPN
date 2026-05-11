// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const profileTestResolversLine = "8.8.8.8\n"

// updateProfileGoldenEnv lets developers regenerate snapshots when a preset
// definition or a default value changes. Set the env var to "1" to overwrite
// every golden file driven by this test suite.
const updateProfileGoldenEnv = "MASTERDNSVPN_UPDATE_PROFILE_GOLDEN"

func writeProfileTestConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client_config.toml")
	resolversPath := filepath.Join(dir, "client_resolvers.txt")
	if err := os.WriteFile(configPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(resolversPath, []byte(profileTestResolversLine), 0o644); err != nil {
		t.Fatalf("write resolvers: %v", err)
	}
	return configPath
}

// stripVolatile clears fields that depend on the test temp directory so two
// configs loaded from different directories can be compared semantically.
func stripVolatile(cfg *ClientConfig) {
	cfg.ConfigPath = ""
	cfg.ConfigDir = ""
	cfg.ResolversFilePath = ""
	cfg.Resolvers = nil
	cfg.ResolverMap = nil
}

// snapshotConfig serializes the resolved ClientConfig to deterministic JSON
// after stripping out fields that depend on the test temp directory or on
// runtime-derived data unrelated to profile semantics.
func snapshotConfig(t *testing.T, cfg ClientConfig) []byte {
	t.Helper()
	stripVolatile(&cfg)

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	return append(out, '\n')
}

func assertGoldenSnapshot(t *testing.T, goldenPath string, got []byte) {
	t.Helper()
	if os.Getenv(updateProfileGoldenEnv) == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("mkdir golden: %v", err)
		}
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with %s=1 to regenerate)", goldenPath, err, updateProfileGoldenEnv)
	}
	if string(got) != string(want) {
		t.Fatalf("snapshot mismatch for %s\n--- got ---\n%s\n--- want ---\n%s", goldenPath, got, want)
	}
}

func loadConfigForProfile(t *testing.T, body string) ClientConfig {
	t.Helper()
	configPath := writeProfileTestConfig(t, body)
	cfg, err := LoadClientConfig(configPath)
	if err != nil {
		t.Fatalf("LoadClientConfig: %v", err)
	}
	return cfg
}

func TestProfileStableMatchesOmittedProfile(t *testing.T) {
	const baseTOML = `
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
`
	omitted := loadConfigForProfile(t, baseTOML)
	stable := loadConfigForProfile(t, baseTOML+"PROFILE = \"stable\"\n")

	stripVolatile(&omitted)
	stripVolatile(&stable)
	stable.Profile = omitted.Profile

	if !reflect.DeepEqual(omitted, stable) {
		omittedSnap := snapshotConfig(t, omitted)
		stableSnap := snapshotConfig(t, stable)
		t.Fatalf("PROFILE=stable should match omitted PROFILE\n--- omitted ---\n%s\n--- stable ---\n%s", omittedSnap, stableSnap)
	}
}

func TestProfileStableSnapshot(t *testing.T) {
	cfg := loadConfigForProfile(t, `
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
PROFILE = "stable"
`)
	got := snapshotConfig(t, cfg)
	assertGoldenSnapshot(t, filepath.Join("testdata", "profile_stable.golden.json"), got)
}

func TestProfileUnknownReturnsError(t *testing.T) {
	configPath := writeProfileTestConfig(t, `
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
PROFILE = "no-such-profile"
`)
	if _, err := LoadClientConfig(configPath); err == nil {
		t.Fatal("expected error for unknown PROFILE")
	} else if !strings.Contains(err.Error(), "PROFILE") {
		t.Fatalf("error should mention PROFILE, got: %v", err)
	}
}

func TestProfilePrecedenceExplicitKeyWinsOverPreset(t *testing.T) {
	cfg := loadConfigForProfile(t, `
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
PROFILE = "stable"
PACKET_DUPLICATION_COUNT = 5
`)
	if cfg.PacketDuplicationCount != 5 {
		t.Fatalf("explicit PACKET_DUPLICATION_COUNT should win: got=%d want=5", cfg.PacketDuplicationCount)
	}
}

func TestProfileMobileSnapshot(t *testing.T) {
	cfg := loadConfigForProfile(t, `
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
PROFILE = "mobile"
`)
	got := snapshotConfig(t, cfg)
	assertGoldenSnapshot(t, filepath.Join("testdata", "profile_mobile.golden.json"), got)
}

func TestProfileMobileAppliesExpectedFields(t *testing.T) {
	cfg := loadConfigForProfile(t, `
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
PROFILE = "mobile"
`)

	if cfg.PingCooldownIntervalSeconds != 4.0 {
		t.Errorf("PingCooldownIntervalSeconds: got=%v want=4.0", cfg.PingCooldownIntervalSeconds)
	}
	if cfg.PingColdIntervalSeconds != 30.0 {
		t.Errorf("PingColdIntervalSeconds: got=%v want=30.0", cfg.PingColdIntervalSeconds)
	}
	if cfg.PingWarmThresholdSeconds != 16.0 {
		t.Errorf("PingWarmThresholdSeconds: got=%v want=16.0", cfg.PingWarmThresholdSeconds)
	}
	if cfg.PingCoolThresholdSeconds != 40.0 {
		t.Errorf("PingCoolThresholdSeconds: got=%v want=40.0", cfg.PingCoolThresholdSeconds)
	}
	if cfg.PingColdThresholdSeconds != 60.0 {
		t.Errorf("PingColdThresholdSeconds: got=%v want=60.0", cfg.PingColdThresholdSeconds)
	}
	if cfg.PacketDuplicationCount != 1 {
		t.Errorf("PacketDuplicationCount: got=%d want=1", cfg.PacketDuplicationCount)
	}
	if cfg.ARQDataNackInitialDelaySeconds != 0.6 {
		t.Errorf("ARQDataNackInitialDelaySeconds: got=%v want=0.6", cfg.ARQDataNackInitialDelaySeconds)
	}
	if cfg.LocalDNSCacheMaxRecords != 5000 {
		t.Errorf("LocalDNSCacheMaxRecords: got=%d want=5000", cfg.LocalDNSCacheMaxRecords)
	}
}

func TestProfileMobileExplicitKeyOverridesPreset(t *testing.T) {
	cfg := loadConfigForProfile(t, `
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
PROFILE = "mobile"
PACKET_DUPLICATION_COUNT = 4
PING_COOLDOWN_INTERVAL_SECONDS = 1.5
`)
	if cfg.PacketDuplicationCount != 4 {
		t.Errorf("explicit PACKET_DUPLICATION_COUNT should win: got=%d want=4", cfg.PacketDuplicationCount)
	}
	if cfg.PingCooldownIntervalSeconds != 1.5 {
		t.Errorf("explicit PING_COOLDOWN_INTERVAL_SECONDS should win: got=%v want=1.5", cfg.PingCooldownIntervalSeconds)
	}
	if cfg.PingColdIntervalSeconds != 30.0 {
		t.Errorf("untouched mobile knob should still apply: got=%v want=30.0", cfg.PingColdIntervalSeconds)
	}
}

func TestProfileCensoredSnapshot(t *testing.T) {
	cfg := loadConfigForProfile(t, `
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
PROFILE = "censored"
`)
	got := snapshotConfig(t, cfg)
	assertGoldenSnapshot(t, filepath.Join("testdata", "profile_censored.golden.json"), got)
}

func TestProfileCensoredAppliesExpectedFields(t *testing.T) {
	cfg := loadConfigForProfile(t, `
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
PROFILE = "censored"
`)

	if cfg.PacketDuplicationCount != 4 {
		t.Errorf("PacketDuplicationCount: got=%d want=4", cfg.PacketDuplicationCount)
	}
	if cfg.PingAggressiveIntervalSeconds != 0.050 {
		t.Errorf("PingAggressiveIntervalSeconds: got=%v want=0.050", cfg.PingAggressiveIntervalSeconds)
	}
	if cfg.PingLazyIntervalSeconds != 0.500 {
		t.Errorf("PingLazyIntervalSeconds: got=%v want=0.500", cfg.PingLazyIntervalSeconds)
	}
	if cfg.MinUploadMTU != 28 {
		t.Errorf("MinUploadMTU: got=%d want=28", cfg.MinUploadMTU)
	}
	if cfg.MinDownloadMTU != 60 {
		t.Errorf("MinDownloadMTU: got=%d want=60", cfg.MinDownloadMTU)
	}
	if cfg.MaxUploadMTU != 200 {
		t.Errorf("MaxUploadMTU: got=%d want=200", cfg.MaxUploadMTU)
	}
	if cfg.MaxDownloadMTU != 900 {
		t.Errorf("MaxDownloadMTU: got=%d want=900", cfg.MaxDownloadMTU)
	}
	if cfg.ARQInitialRTOSeconds != 2.0 {
		t.Errorf("ARQInitialRTOSeconds: got=%v want=2.0", cfg.ARQInitialRTOSeconds)
	}
	if cfg.ARQMaxDataRetries != 2400 {
		t.Errorf("ARQMaxDataRetries: got=%d want=2400", cfg.ARQMaxDataRetries)
	}
	if !cfg.BaseEncodeData {
		t.Errorf("BaseEncodeData: got=false want=true")
	}
}

func TestProfileCensoredExplicitKeyOverridesPreset(t *testing.T) {
	cfg := loadConfigForProfile(t, `
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
PROFILE = "censored"
PACKET_DUPLICATION_COUNT = 2
BASE_ENCODE_DATA = false
`)
	if cfg.PacketDuplicationCount != 2 {
		t.Errorf("explicit PACKET_DUPLICATION_COUNT should win: got=%d want=2", cfg.PacketDuplicationCount)
	}
	if cfg.BaseEncodeData {
		t.Errorf("explicit BASE_ENCODE_DATA=false should win over preset true")
	}
	if cfg.MinUploadMTU != 28 {
		t.Errorf("untouched censored knob should still apply: got=%d want=28", cfg.MinUploadMTU)
	}
}

func TestApplyProfileUnknownFieldNamesAreCaught(t *testing.T) {
	cfgType := reflect.TypeOf(ClientConfig{})
	overrideType := reflect.TypeOf(profileOverrides{})
	for i := 0; i < overrideType.NumField(); i++ {
		name := overrideType.Field(i).Name
		if _, ok := cfgType.FieldByName(name); !ok {
			t.Errorf("profileOverrides field %q has no matching ClientConfig field", name)
		}
	}
}

// TestProfileRegistryIsSorted is a tiny safety-net: ensures preset names are
// lowercase ASCII and don't collide with the reserved no-op tokens.
func TestProfileRegistryNamesAreNormalized(t *testing.T) {
	names := make([]string, 0, len(profilePresets))
	for name := range profilePresets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name != strings.ToLower(strings.TrimSpace(name)) {
			t.Errorf("preset name %q must be lowercased and trimmed", name)
		}
		if name == "" || name == "custom" {
			t.Errorf("preset name %q collides with a reserved no-op token", name)
		}
	}
}
