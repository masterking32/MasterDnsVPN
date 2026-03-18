// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"masterdnsvpn-go/internal/compression"
)

type ClientConfig struct {
	ConfigDir                 string            `toml:"-"`
	ConfigPath                string            `toml:"-"`
	ProtocolType              string            `toml:"PROTOCOL_TYPE"`
	Domains                   []string          `toml:"DOMAINS"`
	LocalDNSEnabled           bool              `toml:"LOCAL_DNS_ENABLED"`
	LocalDNSIP                string            `toml:"LOCAL_DNS_IP"`
	LocalDNSPort              int               `toml:"LOCAL_DNS_PORT"`
	LocalDNSWorkers           int               `toml:"LOCAL_DNS_WORKERS"`
	LocalDNSQueueSize         int               `toml:"LOCAL_DNS_QUEUE_SIZE"`
	LocalDNSCacheMaxRecords   int               `toml:"LOCAL_DNS_CACHE_MAX_RECORDS"`
	LocalDNSCacheTTLSeconds   float64           `toml:"LOCAL_DNS_CACHE_TTL_SECONDS"`
	LocalDNSPendingTimeoutSec float64           `toml:"LOCAL_DNS_PENDING_TIMEOUT_SECONDS"`
	LocalDNSCachePersist      bool              `toml:"LOCAL_DNS_CACHE_PERSIST_TO_FILE"`
	LocalDNSCacheFlushSec     float64           `toml:"LOCAL_DNS_CACHE_FLUSH_INTERVAL_SECONDS"`
	ResolverBalancingStrategy int               `toml:"RESOLVER_BALANCING_STRATEGY"`
	MaxPacketsPerBatch        int               `toml:"MAX_PACKETS_PER_BATCH"`
	BaseEncodeData            bool              `toml:"BASE_ENCODE_DATA"`
	UploadCompressionType     int               `toml:"UPLOAD_COMPRESSION_TYPE"`
	DownloadCompressionType   int               `toml:"DOWNLOAD_COMPRESSION_TYPE"`
	CompressionMinSize        int               `toml:"COMPRESSION_MIN_SIZE"`
	DataEncryptionMethod      int               `toml:"DATA_ENCRYPTION_METHOD"`
	EncryptionKey             string            `toml:"ENCRYPTION_KEY"`
	MinUploadMTU              int               `toml:"MIN_UPLOAD_MTU"`
	MinDownloadMTU            int               `toml:"MIN_DOWNLOAD_MTU"`
	MaxUploadMTU              int               `toml:"MAX_UPLOAD_MTU"`
	MaxDownloadMTU            int               `toml:"MAX_DOWNLOAD_MTU"`
	MTUTestRetries            int               `toml:"MTU_TEST_RETRIES"`
	MTUTestTimeout            float64           `toml:"MTU_TEST_TIMEOUT"`
	MTUTestParallelism        int               `toml:"MTU_TEST_PARALLELISM"`
	LogLevel                  string            `toml:"LOG_LEVEL"`
	Resolvers                 []ResolverAddress `toml:"-"`
	ResolverMap               map[string]int    `toml:"-"`
}

func defaultClientConfig() ClientConfig {
	return ClientConfig{
		ProtocolType:              "SOCKS5",
		Domains:                   nil,
		LocalDNSEnabled:           false,
		LocalDNSIP:                "127.0.0.1",
		LocalDNSPort:              5353,
		LocalDNSWorkers:           2,
		LocalDNSQueueSize:         512,
		LocalDNSCacheMaxRecords:   2000,
		LocalDNSCacheTTLSeconds:   3600.0,
		LocalDNSPendingTimeoutSec: 30.0,
		LocalDNSCachePersist:      true,
		LocalDNSCacheFlushSec:     60.0,
		ResolverBalancingStrategy: 0,
		MaxPacketsPerBatch:        5,
		BaseEncodeData:            false,
		UploadCompressionType:     compression.TypeOff,
		DownloadCompressionType:   compression.TypeOff,
		CompressionMinSize:        compression.DefaultMinSize,
		DataEncryptionMethod:      1,
		EncryptionKey:             "",
		MinUploadMTU:              70,
		MinDownloadMTU:            150,
		MaxUploadMTU:              150,
		MaxDownloadMTU:            200,
		MTUTestRetries:            2,
		MTUTestTimeout:            2.0,
		MTUTestParallelism:        6,
		LogLevel:                  "INFO",
	}
}

func LoadClientConfig(filename string) (ClientConfig, error) {
	cfg := defaultClientConfig()
	path, err := filepath.Abs(filename)
	if err != nil {
		return cfg, err
	}

	if _, err := os.Stat(path); err != nil {
		return cfg, fmt.Errorf("config file not found: %s", path)
	}

	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, fmt.Errorf("parse TOML failed for %s: %w", path, err)
	}

	cfg.ConfigPath = path
	cfg.ConfigDir = filepath.Dir(path)
	cfg.ProtocolType = strings.ToUpper(strings.TrimSpace(cfg.ProtocolType))
	cfg.LogLevel = strings.TrimSpace(cfg.LogLevel)
	if cfg.LogLevel == "" {
		cfg.LogLevel = "INFO"
	}

	switch cfg.ProtocolType {
	case "", "SOCKS5":
		cfg.ProtocolType = "SOCKS5"
	case "TCP":
	default:
		return cfg, fmt.Errorf("invalid PROTOCOL_TYPE: %q", cfg.ProtocolType)
	}

	if cfg.DataEncryptionMethod < 0 || cfg.DataEncryptionMethod > 5 {
		return cfg, fmt.Errorf("invalid DATA_ENCRYPTION_METHOD: %d", cfg.DataEncryptionMethod)
	}
	cfg.LocalDNSIP = strings.TrimSpace(cfg.LocalDNSIP)
	if cfg.LocalDNSIP == "" {
		cfg.LocalDNSIP = "127.0.0.1"
	}
	if cfg.LocalDNSPort < 0 || cfg.LocalDNSPort > 65535 {
		return cfg, fmt.Errorf("invalid LOCAL_DNS_PORT: %d", cfg.LocalDNSPort)
	}
	if cfg.LocalDNSWorkers < 1 {
		cfg.LocalDNSWorkers = 1
	}
	if cfg.LocalDNSQueueSize < 1 {
		cfg.LocalDNSQueueSize = 512
	}
	if cfg.LocalDNSCacheMaxRecords < 1 {
		cfg.LocalDNSCacheMaxRecords = 2000
	}
	if cfg.LocalDNSCacheTTLSeconds <= 0 {
		cfg.LocalDNSCacheTTLSeconds = 3600.0
	}
	if cfg.LocalDNSPendingTimeoutSec <= 0 {
		cfg.LocalDNSPendingTimeoutSec = 30.0
	}
	if cfg.LocalDNSCacheFlushSec <= 0 {
		cfg.LocalDNSCacheFlushSec = 60.0
	}
	if cfg.MaxPacketsPerBatch < 1 {
		cfg.MaxPacketsPerBatch = 5
	}
	if cfg.UploadCompressionType < compression.TypeOff || cfg.UploadCompressionType > compression.TypeZLIB {
		return cfg, fmt.Errorf("invalid UPLOAD_COMPRESSION_TYPE: %d", cfg.UploadCompressionType)
	}
	if cfg.DownloadCompressionType < compression.TypeOff || cfg.DownloadCompressionType > compression.TypeZLIB {
		return cfg, fmt.Errorf("invalid DOWNLOAD_COMPRESSION_TYPE: %d", cfg.DownloadCompressionType)
	}
	if cfg.CompressionMinSize <= 0 {
		cfg.CompressionMinSize = compression.DefaultMinSize
	}
	if cfg.ResolverBalancingStrategy < 0 || cfg.ResolverBalancingStrategy > 4 {
		return cfg, fmt.Errorf("invalid RESOLVER_BALANCING_STRATEGY: %d", cfg.ResolverBalancingStrategy)
	}
	if cfg.MinUploadMTU < 0 || cfg.MinDownloadMTU < 0 || cfg.MaxUploadMTU < 0 || cfg.MaxDownloadMTU < 0 {
		return cfg, fmt.Errorf("mtu values cannot be negative")
	}
	if cfg.MaxUploadMTU > 0 && cfg.MinUploadMTU > cfg.MaxUploadMTU {
		return cfg, fmt.Errorf("MIN_UPLOAD_MTU cannot be greater than MAX_UPLOAD_MTU")
	}
	if cfg.MaxDownloadMTU > 0 && cfg.MinDownloadMTU > cfg.MaxDownloadMTU {
		return cfg, fmt.Errorf("MIN_DOWNLOAD_MTU cannot be greater than MAX_DOWNLOAD_MTU")
	}
	if cfg.MTUTestRetries < 1 {
		cfg.MTUTestRetries = 1
	}
	if cfg.MTUTestTimeout <= 0 {
		cfg.MTUTestTimeout = 1.0
	}
	if cfg.MTUTestParallelism < 1 {
		cfg.MTUTestParallelism = 1
	}

	cfg.EncryptionKey = strings.TrimSpace(cfg.EncryptionKey)
	if cfg.EncryptionKey == "" {
		return cfg, fmt.Errorf("ENCRYPTION_KEY is required in client config")
	}

	cfg.Domains = normalizeClientDomains(cfg.Domains)
	if len(cfg.Domains) == 0 {
		return cfg, fmt.Errorf("DOMAINS must contain at least one domain")
	}

	resolvers, resolverMap, err := LoadClientResolvers(cfg.ResolversPath())
	if err != nil {
		return cfg, err
	}
	cfg.Resolvers = resolvers
	cfg.ResolverMap = resolverMap
	return cfg, nil
}

func (c ClientConfig) ResolversPath() string {
	return filepath.Join(c.ConfigDir, "client_resolvers.txt")
}

func (c ClientConfig) LocalDNSCachePath() string {
	return filepath.Join(c.ConfigDir, "local_dns_cache.json")
}

func normalizeClientDomains(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}

	unique := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
		if normalized == "" || normalized == "." {
			continue
		}
		unique[normalized] = struct{}{}
	}

	if len(unique) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(unique))
	for domain := range unique {
		normalized = append(normalized, domain)
	}

	sort.Slice(normalized, func(i, j int) bool {
		if len(normalized[i]) == len(normalized[j]) {
			return normalized[i] < normalized[j]
		}
		return len(normalized[i]) > len(normalized[j])
	})

	return normalized
}
