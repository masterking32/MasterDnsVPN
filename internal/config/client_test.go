// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package config

import (
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
RESOLVER_BALANCING_STRATEGY = 8
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

	if cfg.LocalDNSCacheMaxRecords != 2000 {
		t.Fatalf("unexpected local dns records default: got=%d want=%d", cfg.LocalDNSCacheMaxRecords, 2000)
	}
	if cfg.CompressionMinSize != compression.DefaultMinSize {
		t.Fatalf("unexpected compression min size default: got=%d want=%d", cfg.CompressionMinSize, compression.DefaultMinSize)
	}
	if cfg.MTUTestRetries != 1 || cfg.MTUTestTimeout != 1.0 || cfg.MTUTestParallelism != 1 {
		t.Fatalf("unexpected mtu defaults: retries=%d timeout=%v parallelism=%d", cfg.MTUTestRetries, cfg.MTUTestTimeout, cfg.MTUTestParallelism)
	}
	if cfg.MTUServersFileName != "masterdnsvpn_success_test_{time}.log" || cfg.MTUServersFileFormat != "{IP} - UP: {UP_MTU} DOWN: {DOWN-MTU}" {
		t.Fatalf("unexpected mtu file defaults: file=%q format=%q", cfg.MTUServersFileName, cfg.MTUServersFileFormat)
	}
	if cfg.ProtocolType != "TCP" {
		t.Fatal("tcp mode should be loaded")
	}
}
