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
	ConfigDir                   string            `toml:"-"`
	ConfigPath                  string            `toml:"-"`
	ProtocolType                string            `toml:"PROTOCOL_TYPE"`
	Domains                     []string          `toml:"DOMAINS"`
	ListenIP                    string            `toml:"LISTEN_IP"`
	ListenPort                  int               `toml:"LISTEN_PORT"`
	SOCKS5Auth                  bool              `toml:"SOCKS5_AUTH"`
	SOCKS5User                  string            `toml:"SOCKS5_USER"`
	SOCKS5Pass                  string            `toml:"SOCKS5_PASS"`
	LocalDNSEnabled             bool              `toml:"LOCAL_DNS_ENABLED"`
	LocalDNSIP                  string            `toml:"LOCAL_DNS_IP"`
	LocalDNSPort                int               `toml:"LOCAL_DNS_PORT"`
	LocalDNSCacheMaxRecords     int               `toml:"LOCAL_DNS_CACHE_MAX_RECORDS"`
	LocalDNSCacheTTLSeconds     float64           `toml:"LOCAL_DNS_CACHE_TTL_SECONDS"`
	LocalDNSPendingTimeoutSec   float64           `toml:"LOCAL_DNS_PENDING_TIMEOUT_SECONDS"`
	LocalDNSCachePersist        bool              `toml:"LOCAL_DNS_CACHE_PERSIST_TO_FILE"`
	LocalDNSCacheFlushSec       float64           `toml:"LOCAL_DNS_CACHE_FLUSH_INTERVAL_SECONDS"`
	ResolverBalancingStrategy   int               `toml:"RESOLVER_BALANCING_STRATEGY"`
	PacketDuplicationCount      int               `toml:"PACKET_DUPLICATION_COUNT"`
	SetupPacketDuplicationCount int               `toml:"SETUP_PACKET_DUPLICATION_COUNT"`
	BaseEncodeData              bool              `toml:"BASE_ENCODE_DATA"`
	UploadCompressionType       int               `toml:"UPLOAD_COMPRESSION_TYPE"`
	DownloadCompressionType     int               `toml:"DOWNLOAD_COMPRESSION_TYPE"`
	CompressionMinSize          int               `toml:"COMPRESSION_MIN_SIZE"`
	DataEncryptionMethod        int               `toml:"DATA_ENCRYPTION_METHOD"`
	EncryptionKey               string            `toml:"ENCRYPTION_KEY"`
	MinUploadMTU                int               `toml:"MIN_UPLOAD_MTU"`
	MinDownloadMTU              int               `toml:"MIN_DOWNLOAD_MTU"`
	MaxUploadMTU                int               `toml:"MAX_UPLOAD_MTU"`
	MaxDownloadMTU              int               `toml:"MAX_DOWNLOAD_MTU"`
	MTUTestRetries              int               `toml:"MTU_TEST_RETRIES"`
	MTUTestTimeout              float64           `toml:"MTU_TEST_TIMEOUT"`
	MTUTestParallelism          int               `toml:"MTU_TEST_PARALLELISM"`
	SaveMTUServersToFile        bool              `toml:"SAVE_MTU_SERVERS_TO_FILE"`
	MTUServersFileName          string            `toml:"MTU_SERVERS_FILE_NAME"`
	MTUServersFileFormat        string            `toml:"MTU_SERVERS_FILE_FORMAT"`
	MTUUsingSeparatorText       string            `toml:"MTU_USING_SECTION_SEPARATOR_TEXT"`
	MTURemovedServerLogFormat   string            `toml:"MTU_REMOVED_SERVER_LOG_FORMAT"`
	MTUAddedServerLogFormat     string            `toml:"MTU_ADDED_SERVER_LOG_FORMAT"`
	LogLevel                    string            `toml:"LOG_LEVEL"`
	MaxPacketsPerBatch          int               `toml:"MAX_PACKETS_PER_BATCH"`
	ARQWindowSize               int               `toml:"ARQ_WINDOW_SIZE"`
	Resolvers                   []ResolverAddress `toml:"-"`
	ResolverMap                 map[string]int    `toml:"-"`
}

func defaultClientConfig() ClientConfig {
	return ClientConfig{
		ProtocolType:                "SOCKS5",
		Domains:                     nil,
		ListenIP:                    "127.0.0.1",
		ListenPort:                  18000,
		SOCKS5Auth:                  false,
		SOCKS5User:                  "master_dns_vpn",
		SOCKS5Pass:                  "master_dns_vpn",
		LocalDNSEnabled:             false,
		LocalDNSIP:                  "127.0.0.1",
		LocalDNSPort:                53,
		LocalDNSCacheMaxRecords:     5000,
		LocalDNSCacheTTLSeconds:     28800.0,
		LocalDNSPendingTimeoutSec:   300.0,
		LocalDNSCachePersist:        true,
		LocalDNSCacheFlushSec:       60.0,
		ResolverBalancingStrategy:   0,
		PacketDuplicationCount:      2,
		SetupPacketDuplicationCount: 3,
		BaseEncodeData:              false,
		UploadCompressionType:       compression.TypeOff,
		DownloadCompressionType:     compression.TypeOff,
		CompressionMinSize:          compression.DefaultMinSize,
		DataEncryptionMethod:        1,
		EncryptionKey:               "",
		MinUploadMTU:                70,
		MinDownloadMTU:              150,
		MaxUploadMTU:                150,
		MaxDownloadMTU:              200,
		MTUTestRetries:              2,
		MTUTestTimeout:              2.0,
		MTUTestParallelism:          6,
		SaveMTUServersToFile:        false,
		MTUServersFileName:          "masterdnsvpn_success_test_{time}.log",
		MTUServersFileFormat:        "{IP} - UP: {UP_MTU} DOWN: {DOWN-MTU}",
		MTUUsingSeparatorText:       "",
		MTURemovedServerLogFormat:   "",
		MTUAddedServerLogFormat:     "",
		LogLevel:                    "INFO",
		MaxPacketsPerBatch:          5,
		ARQWindowSize:               2000,
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

	cfg.ListenIP = defaultString(strings.TrimSpace(cfg.ListenIP), "127.0.0.1")

	if cfg.ListenPort < 0 || cfg.ListenPort > 65535 {
		return cfg, fmt.Errorf("invalid LISTEN_PORT: %d", cfg.ListenPort)
	}

	if len(cfg.SOCKS5User) > 255 {
		return cfg, fmt.Errorf("SOCKS5_USER cannot exceed 255 bytes")
	}

	if len(cfg.SOCKS5Pass) > 255 {
		return cfg, fmt.Errorf("SOCKS5_PASS cannot exceed 255 bytes")
	}

	if cfg.SOCKS5Auth && (cfg.SOCKS5User == "" || cfg.SOCKS5Pass == "") {
		return cfg, fmt.Errorf("SOCKS5_AUTH requires both SOCKS5_USER and SOCKS5_PASS")
	}

	cfg.LocalDNSIP = defaultString(strings.TrimSpace(cfg.LocalDNSIP), "127.0.0.1")

	if cfg.LocalDNSPort < 0 || cfg.LocalDNSPort > 65535 {
		return cfg, fmt.Errorf("invalid LOCAL_DNS_PORT: %d", cfg.LocalDNSPort)
	}

	cfg.LocalDNSCacheMaxRecords = defaultIntBelow(cfg.LocalDNSCacheMaxRecords, 1, 2000)
	cfg.LocalDNSCacheTTLSeconds = defaultFloatAtMostZero(cfg.LocalDNSCacheTTLSeconds, 3600.0)
	cfg.LocalDNSPendingTimeoutSec = defaultFloatAtMostZero(cfg.LocalDNSPendingTimeoutSec, 600.0)
	cfg.LocalDNSCacheFlushSec = defaultFloatAtMostZero(cfg.LocalDNSCacheFlushSec, 60.0)

	if cfg.UploadCompressionType < compression.TypeOff || cfg.UploadCompressionType > compression.TypeZLIB {
		return cfg, fmt.Errorf("invalid UPLOAD_COMPRESSION_TYPE: %d", cfg.UploadCompressionType)
	}

	if cfg.DownloadCompressionType < compression.TypeOff || cfg.DownloadCompressionType > compression.TypeZLIB {
		return cfg, fmt.Errorf("invalid DOWNLOAD_COMPRESSION_TYPE: %d", cfg.DownloadCompressionType)
	}

	cfg.CompressionMinSize = defaultIntBelow(cfg.CompressionMinSize, 1, compression.DefaultMinSize)

	if cfg.ResolverBalancingStrategy < 0 || cfg.ResolverBalancingStrategy > 4 {
		return cfg, fmt.Errorf("invalid RESOLVER_BALANCING_STRATEGY: %d", cfg.ResolverBalancingStrategy)
	}

	cfg.PacketDuplicationCount = clampInt(defaultIntBelow(cfg.PacketDuplicationCount, 1, 1), 1, 8)
	cfg.SetupPacketDuplicationCount = clampInt(defaultIntBelow(cfg.SetupPacketDuplicationCount, 1, max(2, cfg.PacketDuplicationCount)), cfg.PacketDuplicationCount, 8)
	cfg.MaxPacketsPerBatch = clampInt(defaultIntBelow(cfg.MaxPacketsPerBatch, 1, 5), 1, 64)
	cfg.ARQWindowSize = clampInt(defaultIntBelow(cfg.ARQWindowSize, 1, 600), 1, 4096)

	if cfg.MinUploadMTU < 0 || cfg.MinDownloadMTU < 0 || cfg.MaxUploadMTU < 0 || cfg.MaxDownloadMTU < 0 {
		return cfg, fmt.Errorf("mtu values cannot be negative")
	}

	if cfg.MaxUploadMTU > 0 && cfg.MinUploadMTU > cfg.MaxUploadMTU {
		return cfg, fmt.Errorf("MIN_UPLOAD_MTU cannot be greater than MAX_UPLOAD_MTU")
	}

	if cfg.MaxDownloadMTU > 0 && cfg.MinDownloadMTU > cfg.MaxDownloadMTU {
		return cfg, fmt.Errorf("MIN_DOWNLOAD_MTU cannot be greater than MAX_DOWNLOAD_MTU")
	}

	cfg.MTUTestRetries = defaultIntBelow(cfg.MTUTestRetries, 1, 1)
	cfg.MTUTestTimeout = defaultFloatAtMostZero(cfg.MTUTestTimeout, 1.0)
	cfg.MTUTestParallelism = defaultIntBelow(cfg.MTUTestParallelism, 1, 1)
	cfg.MTUServersFileName = strings.TrimSpace(cfg.MTUServersFileName)
	cfg.MTUServersFileFormat = strings.TrimSpace(cfg.MTUServersFileFormat)
	cfg.MTUUsingSeparatorText = strings.TrimSpace(cfg.MTUUsingSeparatorText)
	cfg.MTURemovedServerLogFormat = strings.TrimSpace(cfg.MTURemovedServerLogFormat)
	cfg.MTUAddedServerLogFormat = strings.TrimSpace(cfg.MTUAddedServerLogFormat)

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
	return filepath.Join(c.ConfigDir, "local_dns_cache.bin")
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

func defaultString(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func defaultIntBelow(value int, minValue int, fallback int) int {
	if value < minValue {
		return fallback
	}
	return value
}

func clampInt(value int, minValue int, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func defaultFloatAtMostZero(value float64, fallback float64) float64 {
	if value <= 0 {
		return fallback
	}
	return value
}

func defaultFloatBelow(value float64, minValue float64, fallback float64) float64 {
	if value < minValue {
		return fallback
	}
	return value
}
