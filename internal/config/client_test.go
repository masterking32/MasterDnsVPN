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

	"masterdnsvpn-go/internal/compression"
)

func TestLoadClientConfigNormalizesAndLoadsResolvers(t *testing.T) {
	dir := t.TempDir()

	configPath := filepath.Join(dir, "client_config.toml")
	resolversPath := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "socks5"
DOMAINS = ["V.Domain.com", "v.domain.com."]
RESOLVER_BALANCING_STRATEGY = 2
BASE_ENCODE_DATA = true
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
MIN_UPLOAD_MTU = 70
MIN_DOWNLOAD_MTU = 150
MAX_UPLOAD_MTU = 150
MAX_DOWNLOAD_MTU = 200
MTU_TEST_RETRIES = 2
MTU_TEST_TIMEOUT = 1.5
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}

	if err := os.WriteFile(resolversPath, []byte(`
# comment
8.8.8.8
1.1.1.1:5353
`), 0o644); err != nil {
		t.Fatalf("WriteFile resolvers failed: %v", err)
	}

	cfg, err := LoadClientConfig(configPath)
	if err != nil {
		t.Fatalf("LoadClientConfig returned error: %v", err)
	}

	if cfg.ProtocolType != "SOCKS5" {
		t.Fatalf("unexpected protocol type: got=%q want=%q", cfg.ProtocolType, "SOCKS5")
	}
	if len(cfg.Domains) != 1 || cfg.Domains[0] != "v.domain.com" {
		t.Fatalf("unexpected domains: %+v", cfg.Domains)
	}
	if cfg.ResolverBalancingStrategy != 2 {
		t.Fatalf("unexpected resolver balancing strategy: got=%d want=%d", cfg.ResolverBalancingStrategy, 2)
	}
	if !cfg.BaseEncodeData {
		t.Fatalf("unexpected base encode flag: got=%v want=%v", cfg.BaseEncodeData, true)
	}
	if cfg.MTUTestTimeout != 1.5 {
		t.Fatalf("unexpected mtu timeout: got=%v want=%v", cfg.MTUTestTimeout, 1.5)
	}
	if cfg.ResolverMap["8.8.8.8"] != 53 {
		t.Fatalf("unexpected resolver port for 8.8.8.8: got=%d want=%d", cfg.ResolverMap["8.8.8.8"], 53)
	}
	if cfg.ResolverMap["1.1.1.1"] != 5353 {
		t.Fatalf("unexpected resolver port for 1.1.1.1: got=%d want=%d", cfg.ResolverMap["1.1.1.1"], 5353)
	}
}

func TestLoadClientConfigLoadsFDControlUnixSocket(t *testing.T) {
	t.Setenv("MASTERDNSVPN_PROTECT_PATH", "")
	dir := t.TempDir()

	configPath := filepath.Join(dir, "client_config.toml")
	resolversPath := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
FD_CONTROL_UNIX_SOCKET = " /tmp/masterdnsvpn-protect.sock "
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}
	if err := os.WriteFile(resolversPath, []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile resolvers failed: %v", err)
	}

	cfg, err := LoadClientConfig(configPath)
	if err != nil {
		t.Fatalf("LoadClientConfig returned error: %v", err)
	}

	if cfg.FDControlUnixSocket != "/tmp/masterdnsvpn-protect.sock" {
		t.Fatalf("unexpected fd control path: got=%q", cfg.FDControlUnixSocket)
	}
}

func TestLoadClientConfigFDControlEnvOverridesTOML(t *testing.T) {
	t.Setenv("MASTERDNSVPN_PROTECT_PATH", "/tmp/env-protect.sock")
	dir := t.TempDir()

	configPath := filepath.Join(dir, "client_config.toml")
	resolversPath := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
FD_CONTROL_UNIX_SOCKET = "/tmp/toml-protect.sock"
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}
	if err := os.WriteFile(resolversPath, []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile resolvers failed: %v", err)
	}

	cfg, err := LoadClientConfig(configPath)
	if err != nil {
		t.Fatalf("LoadClientConfig returned error: %v", err)
	}

	if cfg.FDControlUnixSocket != "/tmp/env-protect.sock" {
		t.Fatalf("expected env protect path override, got=%q", cfg.FDControlUnixSocket)
	}
}

func TestLoadClientConfigFDControlDefaultEmpty(t *testing.T) {
	t.Setenv("MASTERDNSVPN_PROTECT_PATH", "")
	dir := t.TempDir()

	configPath := filepath.Join(dir, "client_config.toml")
	resolversPath := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}
	if err := os.WriteFile(resolversPath, []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile resolvers failed: %v", err)
	}

	cfg, err := LoadClientConfig(configPath)
	if err != nil {
		t.Fatalf("LoadClientConfig returned error: %v", err)
	}

	if cfg.FDControlUnixSocket != "" {
		t.Fatalf("expected empty fd control path, got=%q", cfg.FDControlUnixSocket)
	}
}

func TestLoadClientConfigRejectsInvalidProtocol(t *testing.T) {
	dir := t.TempDir()

	configPath := filepath.Join(dir, "client_config.toml")
	resolversPath := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "udp"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}
	if err := os.WriteFile(resolversPath, []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile resolvers failed: %v", err)
	}

	if _, err := LoadClientConfig(configPath); err == nil {
		t.Fatal("LoadClientConfig should reject an invalid PROTOCOL_TYPE")
	}
}

func TestLoadClientConfigRejectsInvalidResolverBalancingStrategy(t *testing.T) {
	dir := t.TempDir()

	configPath := filepath.Join(dir, "client_config.toml")
	resolversPath := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
RESOLVER_BALANCING_STRATEGY = 9
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}
	if err := os.WriteFile(resolversPath, []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile resolvers failed: %v", err)
	}

	if _, err := LoadClientConfig(configPath); err == nil {
		t.Fatal("LoadClientConfig should reject an invalid RESOLVER_BALANCING_STRATEGY")
	}
}

func TestLoadClientConfigAppliesDefaultsAndClamps(t *testing.T) {
	dir := t.TempDir()

	configPath := filepath.Join(dir, "client_config.toml")
	resolversPath := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "tcp"
DOMAINS = ["v.domain.com"]
LISTEN_IP = "  "
LOCAL_DNS_IP = ""
LOCAL_DNS_CACHE_MAX_RECORDS = 0
LOCAL_DNS_CACHE_TTL_SECONDS = 0
LOCAL_DNS_PENDING_TIMEOUT_SECONDS = 0
LOCAL_DNS_CACHE_FLUSH_INTERVAL_SECONDS = 0
COMPRESSION_MIN_SIZE = 0
MTU_TEST_RETRIES = 0
MTU_TEST_TIMEOUT = 0
MTU_TEST_PARALLELISM = 0
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}
	if err := os.WriteFile(resolversPath, []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile resolvers failed: %v", err)
	}

	cfg, err := LoadClientConfig(configPath)
	if err != nil {
		t.Fatalf("LoadClientConfig returned error: %v", err)
	}

	if cfg.LocalDNSCacheMaxRecords != 10000 {
		t.Fatalf("unexpected local dns records default: got=%d want=%d", cfg.LocalDNSCacheMaxRecords, 10000)
	}
	if cfg.ARQInitialRTOSeconds != 1.0 || cfg.ARQMaxRTOSeconds != 5.0 {
		t.Fatalf("unexpected arq rto defaults: initial=%v max=%v", cfg.ARQInitialRTOSeconds, cfg.ARQMaxRTOSeconds)
	}
	if cfg.ARQDataNackMaxGap != 16 {
		t.Fatalf("unexpected ARQ data NACK gap default: got=%d want=16", cfg.ARQDataNackMaxGap)
	}
	if cfg.ARQDataNackRepeatSeconds != 1.0 {
		t.Fatalf("unexpected ARQ data NACK repeat default: got=%v want=%v", cfg.ARQDataNackRepeatSeconds, 1.0)
	}
	if cfg.ARQMaxControlRetries != 400 || cfg.ARQMaxDataRetries != 1200 {
		t.Fatalf("unexpected arq retry defaults: control=%d data=%d", cfg.ARQMaxControlRetries, cfg.ARQMaxDataRetries)
	}
	if cfg.CompressionMinSize != compression.DefaultMinSize {
		t.Fatalf("unexpected compression min size default: got=%d want=%d", cfg.CompressionMinSize, compression.DefaultMinSize)
	}
	if cfg.MTUTestRetries != 1 || cfg.MTUTestTimeout != 2.0 || cfg.MTUTestParallelism != 1 {
		t.Fatalf("unexpected mtu defaults: retries=%d timeout=%v parallelism=%d", cfg.MTUTestRetries, cfg.MTUTestTimeout, cfg.MTUTestParallelism)
	}
	if cfg.MTUServersFileName != "masterdnsvpn_success_test_{time}.log" || cfg.MTUServersFileFormat != "{IP} ({DOMAIN}) - UP: {UP_MTU} DOWN: {DOWN-MTU}" {
		t.Fatalf("unexpected mtu file defaults: file=%q format=%q", cfg.MTUServersFileName, cfg.MTUServersFileFormat)
	}
	if cfg.ProtocolType != "TCP" {
		t.Fatal("tcp mode should be loaded")
	}
}

func TestLoadClientConfigAllowsUsernameOnlySocksAuth(t *testing.T) {
	dir := t.TempDir()

	configPath := filepath.Join(dir, "client_config.toml")
	resolversPath := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
SOCKS5_AUTH = true
SOCKS5_USER = "user_only"
SOCKS5_PASS = ""
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}
	if err := os.WriteFile(resolversPath, []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile resolvers failed: %v", err)
	}

	cfg, err := LoadClientConfig(configPath)
	if err != nil {
		t.Fatalf("LoadClientConfig returned error: %v", err)
	}

	if !cfg.SOCKS5Auth || cfg.SOCKS5User != "user_only" || cfg.SOCKS5Pass != "" {
		t.Fatalf("unexpected socks auth config: auth=%v user=%q pass=%q", cfg.SOCKS5Auth, cfg.SOCKS5User, cfg.SOCKS5Pass)
	}
}

func TestLoadClientConfigAllowsShortAutoDisableWindowForQuickTesting(t *testing.T) {
	dir := t.TempDir()

	configPath := filepath.Join(dir, "client_config.toml")
	resolversPath := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
AUTO_DISABLE_TIMEOUT_SERVERS = true
AUTO_DISABLE_TIMEOUT_WINDOW_SECONDS = 3.0
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}
	if err := os.WriteFile(resolversPath, []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile resolvers failed: %v", err)
	}

	cfg, err := LoadClientConfig(configPath)
	if err != nil {
		t.Fatalf("LoadClientConfig returned error: %v", err)
	}

	if cfg.AutoDisableTimeoutWindowSeconds != 3.0 {
		t.Fatalf("unexpected auto-disable timeout window: got=%v want=%v", cfg.AutoDisableTimeoutWindowSeconds, 3.0)
	}
}

func TestLoadClientConfigUsesMergedRX_TX_Workers(t *testing.T) {
	dir := t.TempDir()

	configPath := filepath.Join(dir, "client_config.toml")
	resolversPath := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
RX_TX_WORKERS = 9
TUNNEL_PROCESS_WORKERS = 2
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}
	if err := os.WriteFile(resolversPath, []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile resolvers failed: %v", err)
	}

	cfg, err := LoadClientConfig(configPath)
	if err != nil {
		t.Fatalf("LoadClientConfig returned error: %v", err)
	}

	if cfg.RX_TX_Workers != 9 {
		t.Fatalf("unexpected merged RX/TX workers: got=%d want=%d", cfg.RX_TX_Workers, 9)
	}
	if cfg.TunnelProcessWorkers != 9 {
		t.Fatalf("expected process workers to be raised to RX/TX count: got=%d want=%d", cfg.TunnelProcessWorkers, 9)
	}
}

func TestLoadClientConfigFallsBackToLegacyReaderWriterWorkers(t *testing.T) {
	dir := t.TempDir()

	configPath := filepath.Join(dir, "client_config.toml")
	resolversPath := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
TUNNEL_READER_WORKERS = 3
TUNNEL_WRITER_WORKERS = 9
TUNNEL_PROCESS_WORKERS = 2
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}
	if err := os.WriteFile(resolversPath, []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile resolvers failed: %v", err)
	}

	cfg, err := LoadClientConfig(configPath)
	if err != nil {
		t.Fatalf("LoadClientConfig returned error: %v", err)
	}

	if cfg.RX_TX_Workers != 9 {
		t.Fatalf("expected legacy reader/writer workers to map into merged RX/TX workers: got=%d want=%d", cfg.RX_TX_Workers, 9)
	}
	if cfg.TunnelProcessWorkers != 9 {
		t.Fatalf("expected process workers to be raised to merged RX/TX count: got=%d want=%d", cfg.TunnelProcessWorkers, 9)
	}
}

func TestLoadClientConfigAutoDerivesTunnelProcessWorkersAboveRXTX(t *testing.T) {
	dir := t.TempDir()

	configPath := filepath.Join(dir, "client_config.toml")
	resolversPath := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["v.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
RX_TX_WORKERS = 6
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}
	if err := os.WriteFile(resolversPath, []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile resolvers failed: %v", err)
	}

	cfg, err := LoadClientConfig(configPath)
	if err != nil {
		t.Fatalf("LoadClientConfig returned error: %v", err)
	}

	if cfg.TunnelProcessWorkers != 7 {
		t.Fatalf("expected process workers to be auto-derived above RX/TX count: got=%d want=%d", cfg.TunnelProcessWorkers, 7)
	}
}

func TestLoadClientConfigWithOverridesReplacesResolversDomainsAndMTURange(t *testing.T) {
	dir := t.TempDir()

	configPath := filepath.Join(dir, "client_config.toml")
	defaultResolversPath := filepath.Join(dir, "client_resolvers.txt")
	overrideResolversPath := filepath.Join(dir, "custom_resolvers.txt")

	if err := os.WriteFile(configPath, []byte(`
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["config.domain.com"]
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
MIN_UPLOAD_MTU = 40
MAX_UPLOAD_MTU = 64
MIN_DOWNLOAD_MTU = 100
MAX_DOWNLOAD_MTU = 140
`), 0o644); err != nil {
		t.Fatalf("WriteFile config failed: %v", err)
	}
	if err := os.WriteFile(defaultResolversPath, []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile default resolvers failed: %v", err)
	}
	if err := os.WriteFile(overrideResolversPath, []byte("1.1.1.1:5353\n"), 0o644); err != nil {
		t.Fatalf("WriteFile override resolvers failed: %v", err)
	}

	minUp := 70
	maxUp := 90
	minDown := 180
	maxDown := 220
	cfg, err := LoadClientConfigWithOverrides(configPath, ClientConfigOverrides{
		ResolversFilePath: &overrideResolversPath,
		Values: map[string]any{
			"Domains":        []string{"a.example.com", "b.example.com."},
			"MinUploadMTU":   minUp,
			"MaxUploadMTU":   maxUp,
			"MinDownloadMTU": minDown,
			"MaxDownloadMTU": maxDown,
		},
	})
	if err != nil {
		t.Fatalf("LoadClientConfigWithOverrides returned error: %v", err)
	}

	if cfg.ResolversPath() != overrideResolversPath {
		t.Fatalf("unexpected overridden resolvers path: got=%q want=%q", cfg.ResolversPath(), overrideResolversPath)
	}
	if len(cfg.Domains) != 2 || cfg.Domains[0] != "a.example.com" || cfg.Domains[1] != "b.example.com" {
		t.Fatalf("unexpected overridden domains: %+v", cfg.Domains)
	}
	if cfg.ResolverMap["1.1.1.1"] != 5353 {
		t.Fatalf("unexpected override resolver map entry: got=%d want=%d", cfg.ResolverMap["1.1.1.1"], 5353)
	}
	if cfg.MinUploadMTU != minUp || cfg.MaxUploadMTU != maxUp || cfg.MinDownloadMTU != minDown || cfg.MaxDownloadMTU != maxDown {
		t.Fatalf("unexpected overridden MTU range: up=%d..%d down=%d..%d", cfg.MinUploadMTU, cfg.MaxUploadMTU, cfg.MinDownloadMTU, cfg.MaxDownloadMTU)
	}
}

func TestClientConfigFlagBinderBuildsOverridesForSetFlagsOnly(t *testing.T) {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	binder, err := NewClientConfigFlagBinder(fs)
	if err != nil {
		t.Fatalf("NewClientConfigFlagBinder returned error: %v", err)
	}

	if err := fs.Parse([]string{
		"-domains=a.example.com,b.example.com",
		"-min-upload-mtu=70",
		"-max-download-mtu=220",
		"-encryption-key=override-secret",
		"-base-encode-data",
	}); err != nil {
		t.Fatalf("flag parse failed: %v", err)
	}

	overrides := binder.Overrides()
	if got, ok := overrides.Values["MinUploadMTU"].(int); !ok || got != 70 {
		t.Fatalf("unexpected min upload mtu override: %#v", overrides.Values["MinUploadMTU"])
	}
	if got, ok := overrides.Values["MaxDownloadMTU"].(int); !ok || got != 220 {
		t.Fatalf("unexpected max download mtu override: %#v", overrides.Values["MaxDownloadMTU"])
	}
	if got, ok := overrides.Values["EncryptionKey"].(string); !ok || got != "override-secret" {
		t.Fatalf("unexpected encryption key override: %#v", overrides.Values["EncryptionKey"])
	}
	if got, ok := overrides.Values["BaseEncodeData"].(bool); !ok || !got {
		t.Fatalf("unexpected base encode override: %#v", overrides.Values["BaseEncodeData"])
	}
	gotDomains, ok := overrides.Values["Domains"].([]string)
	if !ok || len(gotDomains) != 2 || gotDomains[0] != "a.example.com" || gotDomains[1] != "b.example.com" {
		t.Fatalf("unexpected domains override: %#v", overrides.Values["Domains"])
	}
	if _, exists := overrides.Values["MaxUploadMTU"]; exists {
		t.Fatalf("did not expect unset flag to appear in overrides: %#v", overrides.Values["MaxUploadMTU"])
	}
}

func TestLoadClientConfigFallsBackToJSONWhenTOMLIsMissing(t *testing.T) {
	dir := t.TempDir()

	configPath := filepath.Join(dir, "client_config.toml")
	jsonPath := filepath.Join(dir, "client_config.json")
	resolversPath := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(jsonPath, []byte(`{
  "PROTOCOL_TYPE": "SOCKS5",
  "DOMAINS": ["json.example.com"],
  "DATA_ENCRYPTION_METHOD": 1,
  "ENCRYPTION_KEY": "json-secret",
  "MAX_UPLOAD_MTU": 140
}`), 0o644); err != nil {
		t.Fatalf("WriteFile JSON config failed: %v", err)
	}
	if err := os.WriteFile(resolversPath, []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("WriteFile resolvers failed: %v", err)
	}

	cfg, err := LoadClientConfig(configPath)
	if err != nil {
		t.Fatalf("LoadClientConfig returned error: %v", err)
	}

	if cfg.ConfigPath != jsonPath {
		t.Fatalf("expected JSON fallback path: got=%q want=%q", cfg.ConfigPath, jsonPath)
	}
	if cfg.MaxUploadMTU != 140 {
		t.Fatalf("unexpected JSON MTU value: got=%d want=%d", cfg.MaxUploadMTU, 140)
	}
	if len(cfg.Domains) != 1 || cfg.Domains[0] != "json.example.com" {
		t.Fatalf("unexpected JSON domains: %+v", cfg.Domains)
	}
}

func TestLoadClientConfigFromJSONBase64AppliesDefaultsAndLoadsResolvers(t *testing.T) {
	dir := t.TempDir()
	resolversPath := filepath.Join(dir, "client_resolvers.txt")

	if err := os.WriteFile(resolversPath, []byte("1.1.1.1\n"), 0o644); err != nil {
		t.Fatalf("WriteFile resolvers failed: %v", err)
	}

	previousWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	defer func() {
		_ = os.Chdir(previousWD)
	}()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	rawJSON := `{
  "PROTOCOL_TYPE": "SOCKS5",
  "DOMAINS": ["base64.example.com"],
  "DATA_ENCRYPTION_METHOD": 1,
  "ENCRYPTION_KEY": "base64-secret"
}`
	encoded := base64.StdEncoding.EncodeToString([]byte(rawJSON))

	cfg, err := LoadClientConfigFromJSONBase64(encoded)
	if err != nil {
		t.Fatalf("LoadClientConfigFromJSONBase64 returned error: %v", err)
	}

	if cfg.ConfigPath != "<json_base64>" {
		t.Fatalf("unexpected config path: got=%q want=%q", cfg.ConfigPath, "<json_base64>")
	}
	if cfg.MaxUploadMTU != defaultClientConfig().MaxUploadMTU {
		t.Fatalf("expected default upload mtu to apply: got=%d want=%d", cfg.MaxUploadMTU, defaultClientConfig().MaxUploadMTU)
	}
	if cfg.ResolverMap["1.1.1.1"] != 53 {
		t.Fatalf("expected resolvers file from cwd to be loaded, got=%d", cfg.ResolverMap["1.1.1.1"])
	}
}

func TestLoadClientConfigFromJSONBase64WithOverridesAppliesBeforeFinalize(t *testing.T) {
	dir := t.TempDir()
	overrideResolversPath := filepath.Join(dir, "override_resolvers.txt")

	if err := os.WriteFile(overrideResolversPath, []byte("9.9.9.9\n"), 0o644); err != nil {
		t.Fatalf("WriteFile override resolvers failed: %v", err)
	}

	rawJSON := `{
  "PROTOCOL_TYPE": "SOCKS5",
  "DATA_ENCRYPTION_METHOD": 1
}`
	encoded := base64.StdEncoding.EncodeToString([]byte(rawJSON))

	cfg, err := LoadClientConfigFromJSONBase64WithOverrides(encoded, ClientConfigOverrides{
		ResolversFilePath: &overrideResolversPath,
		Values: map[string]any{
			"Domains":       []string{"override.example.com"},
			"EncryptionKey": "override-secret",
		},
	})
	if err != nil {
		t.Fatalf("LoadClientConfigFromJSONBase64WithOverrides returned error: %v", err)
	}

	if len(cfg.Domains) != 1 || cfg.Domains[0] != "override.example.com" {
		t.Fatalf("unexpected override domains: %+v", cfg.Domains)
	}
	if cfg.EncryptionKey != "override-secret" {
		t.Fatalf("unexpected override encryption key: got=%q", cfg.EncryptionKey)
	}
	if cfg.ResolverMap["9.9.9.9"] != 53 {
		t.Fatalf("expected override resolvers to be loaded, got=%d", cfg.ResolverMap["9.9.9.9"])
	}
}
