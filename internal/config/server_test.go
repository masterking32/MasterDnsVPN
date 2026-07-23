// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package config

import (
	"encoding/base64"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestServerConfigAddress(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "family-neutral wildcard", host: "", want: ":53"},
		{name: "IPv4", host: "0.0.0.0", want: "0.0.0.0:53"},
		{name: "IPv6", host: "::", want: "[::]:53"},
		{name: "concrete IPv6", host: "2001:db8::1", want: "[2001:db8::1]:53"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ServerConfig{UDPHost: tt.host, UDPPort: 53}
			if got := cfg.Address(); got != tt.want {
				t.Fatalf("Address()=%q want=%q", got, tt.want)
			}
		})
	}
}

func TestServerConfigUDPHostValidation(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		want    string
		wantErr bool
	}{
		{name: "empty uses family-neutral wildcard", want: ""},
		{name: "IPv4 literal", host: "0.0.0.0", want: "0.0.0.0"},
		{name: "IPv6 literal", host: "2001:db8::1", want: "2001:db8::1"},
		{name: "non-IP value", host: "not-an-ip", wantErr: true},
		{name: "bracketed IPv6 literal", host: "[::]", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultServerConfig()
			cfg.UDPHost = tt.host
			got, err := finalizeServerConfig(cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("finalizeServerConfig(%q) unexpectedly succeeded", tt.host)
				}
				return
			}
			if err != nil {
				t.Fatalf("finalizeServerConfig(%q) returned error: %v", tt.host, err)
			}
			if got.UDPHost != tt.want {
				t.Fatalf("UDPHost=%q want=%q", got.UDPHost, tt.want)
			}
		})
	}
}

func TestLoadServerConfigWithOverridesAppliesFlagPrecedence(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server_config.toml")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
UDP_PORT = 53
DOMAIN = ["config.example.com"]
DATA_ENCRYPTION_METHOD = 1
SUPPORTED_UPLOAD_COMPRESSION_TYPES = [0, 3]
SUPPORTED_DOWNLOAD_COMPRESSION_TYPES = [0, 3]
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}

	cfg, err := LoadServerConfigWithOverrides(configPath, ServerConfigOverrides{
		Values: map[string]any{
			"UDPPort":                           5300,
			"Domain":                            []string{"flag.example.com", "alt.example.com"},
			"DataEncryptionMethod":              2,
			"SupportedUploadCompressionTypes":   []int{0, 1},
			"SupportedDownloadCompressionTypes": []int{0, 1, 3},
		},
	})
	if err != nil {
		t.Fatalf("LoadServerConfigWithOverrides returned error: %v", err)
	}

	if cfg.UDPPort != 5300 {
		t.Fatalf("unexpected udp port override: got=%d want=%d", cfg.UDPPort, 5300)
	}
	if len(cfg.Domain) != 2 || cfg.Domain[0] != "flag.example.com" || cfg.Domain[1] != "alt.example.com" {
		t.Fatalf("unexpected domain override: %+v", cfg.Domain)
	}
	if cfg.DataEncryptionMethod != 2 {
		t.Fatalf("unexpected data encryption override: got=%d want=%d", cfg.DataEncryptionMethod, 2)
	}
	if len(cfg.SupportedUploadCompressionTypes) != 2 || cfg.SupportedUploadCompressionTypes[0] != 0 || cfg.SupportedUploadCompressionTypes[1] != 1 {
		t.Fatalf("unexpected upload compression override: %+v", cfg.SupportedUploadCompressionTypes)
	}
	if len(cfg.SupportedDownloadCompressionTypes) != 3 {
		t.Fatalf("unexpected download compression override: %+v", cfg.SupportedDownloadCompressionTypes)
	}
}

func TestServerConfigFlagBinderBuildsOverridesForSetFlagsOnly(t *testing.T) {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	binder, err := NewServerConfigFlagBinder(fs)
	if err != nil {
		t.Fatalf("NewServerConfigFlagBinder returned error: %v", err)
	}

	if err := fs.Parse([]string{
		"-udp-port=5300",
		"-domain=a.example.com,b.example.com",
		"-use-external-socks5",
		"-supported-upload-compression-types=0,1",
		"-data-encryption-method=2",
	}); err != nil {
		t.Fatalf("flag parse failed: %v", err)
	}

	overrides := binder.Overrides()
	if got, ok := overrides.Values["UDPPort"].(int); !ok || got != 5300 {
		t.Fatalf("unexpected udp port override: %#v", overrides.Values["UDPPort"])
	}
	if got, ok := overrides.Values["UseExternalSOCKS5"].(bool); !ok || !got {
		t.Fatalf("unexpected socks5 override: %#v", overrides.Values["UseExternalSOCKS5"])
	}
	if got, ok := overrides.Values["DataEncryptionMethod"].(int); !ok || got != 2 {
		t.Fatalf("unexpected encryption method override: %#v", overrides.Values["DataEncryptionMethod"])
	}
	gotDomains, ok := overrides.Values["Domain"].([]string)
	if !ok || len(gotDomains) != 2 || gotDomains[0] != "a.example.com" || gotDomains[1] != "b.example.com" {
		t.Fatalf("unexpected domains override: %#v", overrides.Values["Domain"])
	}
	gotCompressions, ok := overrides.Values["SupportedUploadCompressionTypes"].([]int)
	if !ok || len(gotCompressions) != 2 || gotCompressions[0] != 0 || gotCompressions[1] != 1 {
		t.Fatalf("unexpected compression override: %#v", overrides.Values["SupportedUploadCompressionTypes"])
	}
	if _, exists := overrides.Values["UDPHost"]; exists {
		t.Fatalf("did not expect unset flag to appear in overrides: %#v", overrides.Values["UDPHost"])
	}
}

func TestServerConfigEffectiveSizingUsesSmartFloorsAndDerivedCapacities(t *testing.T) {
	cfg := defaultServerConfig()
	cfg.ProtocolType = "SOCKS5"
	cfg.UDPReaders = 1
	cfg.DNSRequestWorkers = 1
	cfg.DeferredSessionWorkers = 1
	cfg.DeferredSessionQueueLimit = 64
	cfg.MaxConcurrentRequests = 512
	cfg.MaxPacketsPerBatch = 1
	cfg.DNSCacheMaxRecords = 100
	cfg.ARQWindowSize = 2000

	if got := cfg.EffectiveUDPReaders(); got < 1 {
		t.Fatalf("expected effective udp readers floor, got=%d", got)
	}
	if got := cfg.EffectiveDNSRequestWorkers(); got < cfg.EffectiveUDPReaders()+1 {
		t.Fatalf("expected dns workers to track reader pressure, got=%d readers=%d", got, cfg.EffectiveUDPReaders())
	}
	if got := cfg.EffectiveDeferredSessionQueueLimit(); got < 256 {
		t.Fatalf("expected deferred queue smart floor, got=%d", got)
	}
	if got := cfg.EffectiveMaxConcurrentRequests(); got < 4096 {
		t.Fatalf("expected max concurrent requests smart floor, got=%d", got)
	}
	if got := cfg.EffectiveMaxPacketsPerBatch(); got < 10 {
		t.Fatalf("expected max packets per batch smart floor, got=%d", got)
	}
	if got := cfg.EffectiveDNSCacheMaxRecords(); got < cfg.EffectiveMaxConcurrentRequests()*2 {
		t.Fatalf("expected dns cache smart floor, got=%d concurrent=%d", got, cfg.EffectiveMaxConcurrentRequests())
	}
	if got := cfg.EffectiveSessionOrphanQueueInitialCap(); got < 32 {
		t.Fatalf("expected derived orphan queue cap, got=%d", got)
	}
	if got := cfg.EffectiveStreamQueueInitialCapacity(); got < 32 {
		t.Fatalf("expected derived stream queue cap, got=%d", got)
	}
	if got := cfg.EffectiveDNSFragmentStoreCapacity(); got < 64 {
		t.Fatalf("expected derived dns fragment store cap, got=%d", got)
	}
	if got := cfg.EffectiveSOCKS5FragmentStoreCapacity(); got < 64 {
		t.Fatalf("expected derived socks5 fragment store cap, got=%d", got)
	}
}

func TestServerConfigClientPolicyLimitsAreSafelyClamped(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server_config.toml")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
UDP_PORT = 53
DOMAIN = ["config.example.com"]
DATA_ENCRYPTION_METHOD = 1
SUPPORTED_UPLOAD_COMPRESSION_TYPES = [0, 3]
SUPPORTED_DOWNLOAD_COMPRESSION_TYPES = [0, 3]
MAX_ALLOWED_CLIENT_PACKET_DUPLICATION_COUNT = 999
MAX_ALLOWED_CLIENT_SETUP_PACKET_DUPLICATION_COUNT = 999
MAX_ALLOWED_CLIENT_ACTIVE_SESSION = 999
MAX_ALLOWED_CLIENT_ACTIVE_STREAMS_PER_SESSION = 999999
MAX_ALLOWED_CLIENT_UPLOAD_MTU = 999
MAX_ALLOWED_CLIENT_DOWNLOAD_MTU = 999999
MAX_ALLOWED_CLIENT_RX_TX_WORKERS = 999
MIN_ALLOWED_CLIENT_PING_AGGRESSIVE_INTERVAL_SECONDS = 0.001
MAX_ALLOWED_CLIENT_PACKETS_PER_BATCH = 999
MAX_ALLOWED_CLIENT_ARQ_WINDOW_SIZE = 999999
MAX_ALLOWED_CLIENT_ARQ_DATA_NACK_MAX_GAP = 999
MIN_ALLOWED_CLIENT_COMPRESSION_MIN_SIZE = 999999
MIN_ALLOWED_CLIENT_ARQ_INITIAL_RTO_SECONDS = 0.001
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}

	cfg, err := LoadServerConfig(configPath)
	if err != nil {
		t.Fatalf("LoadServerConfig returned error: %v", err)
	}

	if cfg.ClientMaxPacketDuplicationCount != 15 {
		t.Fatalf("unexpected packet duplication clamp: got=%d want=%d", cfg.ClientMaxPacketDuplicationCount, 15)
	}
	if cfg.ClientMaxSetupDuplicationCount != 15 {
		t.Fatalf("unexpected setup duplication clamp: got=%d want=%d", cfg.ClientMaxSetupDuplicationCount, 15)
	}
	if cfg.MaxAllowedClientActiveSessions != 255 {
		t.Fatalf("unexpected active session clamp: got=%d want=%d", cfg.MaxAllowedClientActiveSessions, 255)
	}
	if cfg.MaxAllowedClientActiveStreams != 65535 {
		t.Fatalf("unexpected active streams clamp: got=%d want=%d", cfg.MaxAllowedClientActiveStreams, 65535)
	}
	if cfg.ClientMaxUploadMTU != 255 {
		t.Fatalf("unexpected upload mtu clamp: got=%d want=%d", cfg.ClientMaxUploadMTU, 255)
	}
	if cfg.ClientMaxDownloadMTU != 65535 {
		t.Fatalf("unexpected download mtu clamp: got=%d want=%d", cfg.ClientMaxDownloadMTU, 65535)
	}
	if cfg.ClientMaxRxTxWorkers != 255 {
		t.Fatalf("unexpected worker clamp: got=%d want=%d", cfg.ClientMaxRxTxWorkers, 255)
	}
	if cfg.ClientMinPingAggressiveInterval != 0.05 {
		t.Fatalf("unexpected ping interval clamp: got=%f want=%f", cfg.ClientMinPingAggressiveInterval, 0.05)
	}
	if cfg.ClientMaxPacketsPerBatch != 255 {
		t.Fatalf("unexpected packets per batch clamp: got=%d want=%d", cfg.ClientMaxPacketsPerBatch, 255)
	}
	if cfg.ClientMaxARQWindowSize != 8000 {
		t.Fatalf("unexpected arq window clamp: got=%d want=%d", cfg.ClientMaxARQWindowSize, 8000)
	}
	if cfg.ClientMaxARQDataNackMaxGap != 255 {
		t.Fatalf("unexpected arq nack gap clamp: got=%d want=%d", cfg.ClientMaxARQDataNackMaxGap, 255)
	}
	if cfg.ClientMinCompressionMinSize != 65535 {
		t.Fatalf("unexpected compression min size clamp: got=%d want=%d", cfg.ClientMinCompressionMinSize, 65535)
	}
	if cfg.ClientMinARQInitialRTOSeconds != 0.05 {
		t.Fatalf("unexpected arq initial rto clamp: got=%f want=%f", cfg.ClientMinARQInitialRTOSeconds, 0.05)
	}
}

func TestLoadServerConfigFallsBackToJSONWhenTOMLIsMissing(t *testing.T) {
	dir := t.TempDir()

	configPath := filepath.Join(dir, "server_config.toml")
	jsonPath := filepath.Join(dir, "server_config.json")

	if err := os.WriteFile(jsonPath, []byte(`{
  "PROTOCOL_TYPE": "SOCKS5",
  "UDP_PORT": 5300,
  "DOMAIN": ["json.example.com"],
  "DATA_ENCRYPTION_METHOD": 1,
  "SUPPORTED_UPLOAD_COMPRESSION_TYPES": [0, 3],
  "SUPPORTED_DOWNLOAD_COMPRESSION_TYPES": [0, 3]
}`), 0o644); err != nil {
		t.Fatalf("WriteFile JSON config failed: %v", err)
	}

	cfg, err := LoadServerConfig(configPath)
	if err != nil {
		t.Fatalf("LoadServerConfig returned error: %v", err)
	}

	if cfg.ConfigPath != jsonPath {
		t.Fatalf("expected JSON fallback path: got=%q want=%q", cfg.ConfigPath, jsonPath)
	}
	if cfg.UDPPort != 5300 {
		t.Fatalf("unexpected JSON UDP port: got=%d want=%d", cfg.UDPPort, 5300)
	}
}

func TestLoadServerConfigFromJSONBase64AppliesDefaults(t *testing.T) {
	rawJSON := `{
  "PROTOCOL_TYPE": "SOCKS5",
  "UDP_PORT": 5301,
  "DOMAIN": ["base64.example.com"],
  "DATA_ENCRYPTION_METHOD": 1,
  "SUPPORTED_UPLOAD_COMPRESSION_TYPES": [0, 3],
  "SUPPORTED_DOWNLOAD_COMPRESSION_TYPES": [0, 3]
}`
	encoded := base64.StdEncoding.EncodeToString([]byte(rawJSON))

	cfg, err := LoadServerConfigFromJSONBase64(encoded)
	if err != nil {
		t.Fatalf("LoadServerConfigFromJSONBase64 returned error: %v", err)
	}

	if cfg.ConfigPath != "<json_base64>" {
		t.Fatalf("unexpected config path: got=%q want=%q", cfg.ConfigPath, "<json_base64>")
	}
	if cfg.UDPPort != 5301 {
		t.Fatalf("unexpected JSON base64 UDP port: got=%d want=%d", cfg.UDPPort, 5301)
	}
	if cfg.UDPHost != "" {
		t.Fatalf("unexpected default UDP host: got=%q want empty", cfg.UDPHost)
	}
	if cfg.MaxPacketsPerBatch != defaultServerConfig().MaxPacketsPerBatch {
		t.Fatalf("expected default max packets per batch to apply: got=%d want=%d", cfg.MaxPacketsPerBatch, defaultServerConfig().MaxPacketsPerBatch)
	}
}

func TestLoadServerConfigFromJSONBase64WithOverridesAppliesBeforeFinalize(t *testing.T) {
	rawJSON := `{
  "PROTOCOL_TYPE": "SOCKS5",
  "UDP_PORT": 5301,
  "DATA_ENCRYPTION_METHOD": 1,
  "SUPPORTED_UPLOAD_COMPRESSION_TYPES": [0, 3],
  "SUPPORTED_DOWNLOAD_COMPRESSION_TYPES": [0, 3]
}`
	encoded := base64.StdEncoding.EncodeToString([]byte(rawJSON))

	cfg, err := LoadServerConfigFromJSONBase64WithOverrides(encoded, ServerConfigOverrides{
		Values: map[string]any{
			"Domain": []string{"override.example.com"},
		},
	})
	if err != nil {
		t.Fatalf("LoadServerConfigFromJSONBase64WithOverrides returned error: %v", err)
	}

	if len(cfg.Domain) != 1 || cfg.Domain[0] != "override.example.com" {
		t.Fatalf("unexpected override domain: %+v", cfg.Domain)
	}
}
