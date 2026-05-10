// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"masterdnsvpn-go/internal/compression"
)

type ClientConfig struct {
	ConfigDir                             string            `toml:"-"`
	ConfigPath                            string            `toml:"-"`
	ResolversFilePath                     string            `toml:"-"`
	explicitRX_TX_Workers                 bool              `toml:"-"`
	explicitTunnelProcessWorkers          bool              `toml:"-"`
	ProtocolType                          string            `toml:"PROTOCOL_TYPE"`
	Domains                               []string          `toml:"DOMAINS"`
	ListenIP                              string            `toml:"LISTEN_IP"`
	ListenPort                            int               `toml:"LISTEN_PORT"`
	SOCKS5Auth                            bool              `toml:"SOCKS5_AUTH"`
	SOCKS5User                            string            `toml:"SOCKS5_USER"`
	SOCKS5Pass                            string            `toml:"SOCKS5_PASS"`
	LocalDNSEnabled                       bool              `toml:"LOCAL_DNS_ENABLED"`
	LocalDNSIP                            string            `toml:"LOCAL_DNS_IP"`
	LocalDNSPort                          int               `toml:"LOCAL_DNS_PORT"`
	LocalDNSCacheMaxRecords               int               `toml:"LOCAL_DNS_CACHE_MAX_RECORDS"`
	LocalDNSCacheTTLSeconds               float64           `toml:"LOCAL_DNS_CACHE_TTL_SECONDS"`
	LocalDNSPendingTimeoutSec             float64           `toml:"LOCAL_DNS_PENDING_TIMEOUT_SECONDS"`
	LocalDNSCachePersist                  bool              `toml:"LOCAL_DNS_CACHE_PERSIST_TO_FILE"`
	LocalDNSCacheFlushSec                 float64           `toml:"LOCAL_DNS_CACHE_FLUSH_INTERVAL_SECONDS"`
	ResolverBalancingStrategy             int               `toml:"RESOLVER_BALANCING_STRATEGY"`
	PacketDuplicationCount                int               `toml:"PACKET_DUPLICATION_COUNT"`
	SetupPacketDuplicationCount           int               `toml:"SETUP_PACKET_DUPLICATION_COUNT"`
	StreamResolverFailoverResendThreshold int               `toml:"STREAM_RESOLVER_FAILOVER_RESEND_THRESHOLD"`
	StreamResolverFailoverCooldownSec     float64           `toml:"STREAM_RESOLVER_FAILOVER_COOLDOWN"`
	RecheckInactiveServersEnabled         bool              `toml:"RECHECK_INACTIVE_SERVERS_ENABLED"`
	AutoDisableTimeoutServers             bool              `toml:"AUTO_DISABLE_TIMEOUT_SERVERS"`
	AutoDisableTimeoutWindowSeconds       float64           `toml:"AUTO_DISABLE_TIMEOUT_WINDOW_SECONDS"`
	BaseEncodeData                        bool              `toml:"BASE_ENCODE_DATA"`
	UploadCompressionType                 int               `toml:"UPLOAD_COMPRESSION_TYPE"`
	DownloadCompressionType               int               `toml:"DOWNLOAD_COMPRESSION_TYPE"`
	CompressionMinSize                    int               `toml:"COMPRESSION_MIN_SIZE"`
	DataEncryptionMethod                  int               `toml:"DATA_ENCRYPTION_METHOD"`
	EncryptionKey                         string            `toml:"ENCRYPTION_KEY"`
	MinUploadMTU                          int               `toml:"MIN_UPLOAD_MTU"`
	MinDownloadMTU                        int               `toml:"MIN_DOWNLOAD_MTU"`
	MaxUploadMTU                          int               `toml:"MAX_UPLOAD_MTU"`
	MaxDownloadMTU                        int               `toml:"MAX_DOWNLOAD_MTU"`
	MTUTestRetries                        int               `toml:"MTU_TEST_RETRIES"`
	MTUTestTimeout                        float64           `toml:"MTU_TEST_TIMEOUT"`
	MTUTestParallelism                    int               `toml:"MTU_TEST_PARALLELISM"`
	RX_TX_Workers                         int               `toml:"RX_TX_WORKERS"`
	LegacyTunnelReaderWorkers             int               `toml:"TUNNEL_READER_WORKERS"`
	LegacyTunnelWriterWorkers             int               `toml:"TUNNEL_WRITER_WORKERS"`
	TunnelProcessWorkers                  int               `toml:"TUNNEL_PROCESS_WORKERS"`
	TunnelPacketTimeoutSec                float64           `toml:"TUNNEL_PACKET_TIMEOUT_SECONDS"`
	DispatcherIdlePollIntervalSeconds     float64           `toml:"DISPATCHER_IDLE_POLL_INTERVAL_SECONDS"`
	PingAggressiveIntervalSeconds         float64           `toml:"PING_AGGRESSIVE_INTERVAL_SECONDS"`
	PingLazyIntervalSeconds               float64           `toml:"PING_LAZY_INTERVAL_SECONDS"`
	PingCooldownIntervalSeconds           float64           `toml:"PING_COOLDOWN_INTERVAL_SECONDS"`
	PingColdIntervalSeconds               float64           `toml:"PING_COLD_INTERVAL_SECONDS"`
	PingWarmThresholdSeconds              float64           `toml:"PING_WARM_THRESHOLD_SECONDS"`
	PingCoolThresholdSeconds              float64           `toml:"PING_COOL_THRESHOLD_SECONDS"`
	PingColdThresholdSeconds              float64           `toml:"PING_COLD_THRESHOLD_SECONDS"`
	RXChannelSize                         int               `toml:"RX_CHANNEL_SIZE"`
	DNSResponseFragmentTimeoutSeconds     float64           `toml:"DNS_RESPONSE_FRAGMENT_TIMEOUT_SECONDS"`
	SOCKSUDPAssociateReadTimeoutSeconds   float64           `toml:"SOCKS_UDP_ASSOCIATE_READ_TIMEOUT_SECONDS"`
	ClientTerminalStreamRetentionSeconds  float64           `toml:"CLIENT_TERMINAL_STREAM_RETENTION_SECONDS"`
	ClientCancelledSetupRetentionSeconds  float64           `toml:"CLIENT_CANCELLED_SETUP_RETENTION_SECONDS"`
	SessionInitRetryBaseSeconds           float64           `toml:"SESSION_INIT_RETRY_BASE_SECONDS"`
	SessionInitRetryStepSeconds           float64           `toml:"SESSION_INIT_RETRY_STEP_SECONDS"`
	SessionInitRetryLinearAfter           int               `toml:"SESSION_INIT_RETRY_LINEAR_AFTER"`
	SessionInitRetryMaxSeconds            float64           `toml:"SESSION_INIT_RETRY_MAX_SECONDS"`
	SessionInitBusyRetryIntervalSeconds   float64           `toml:"SESSION_INIT_BUSY_RETRY_INTERVAL_SECONDS"`
	SessionInitRacingCount                int               `toml:"SESSION_INIT_RACING_COUNT"`
	SaveMTUServersToFile                  bool              `toml:"SAVE_MTU_SERVERS_TO_FILE"`
	MTUServersFileName                    string            `toml:"MTU_SERVERS_FILE_NAME"`
	MTUServersFileFormat                  string            `toml:"MTU_SERVERS_FILE_FORMAT"`
	MTUUsingSeparatorText                 string            `toml:"MTU_USING_SECTION_SEPARATOR_TEXT"`
	MTURemovedServerLogFormat             string            `toml:"MTU_REMOVED_SERVER_LOG_FORMAT"`
	MTUAddedServerLogFormat               string            `toml:"MTU_ADDED_SERVER_LOG_FORMAT"`
	MTUReactiveAddedServerLogFormat       string            `toml:"MTU_REACTIVE_ADDED_SERVER_LOG_FORMAT"`
	LogLevel                              string            `toml:"LOG_LEVEL"`
	MaxPacketsPerBatch                    int               `toml:"MAX_PACKETS_PER_BATCH"`
	ARQWindowSize                         int               `toml:"ARQ_WINDOW_SIZE"`
	ARQInitialRTOSeconds                  float64           `toml:"ARQ_INITIAL_RTO_SECONDS"`
	ARQMaxRTOSeconds                      float64           `toml:"ARQ_MAX_RTO_SECONDS"`
	ARQControlInitialRTOSeconds           float64           `toml:"ARQ_CONTROL_INITIAL_RTO_SECONDS"`
	ARQControlMaxRTOSeconds               float64           `toml:"ARQ_CONTROL_MAX_RTO_SECONDS"`
	ARQMaxControlRetries                  int               `toml:"ARQ_MAX_CONTROL_RETRIES"`
	ARQInactivityTimeoutSeconds           float64           `toml:"ARQ_INACTIVITY_TIMEOUT_SECONDS"`
	ARQDataPacketTTLSeconds               float64           `toml:"ARQ_DATA_PACKET_TTL_SECONDS"`
	ARQControlPacketTTLSeconds            float64           `toml:"ARQ_CONTROL_PACKET_TTL_SECONDS"`
	ARQMaxDataRetries                     int               `toml:"ARQ_MAX_DATA_RETRIES"`
	ARQDataNackMaxGap                     int               `toml:"ARQ_DATA_NACK_MAX_GAP"`
	ARQDataNackInitialDelaySeconds        float64           `toml:"ARQ_DATA_NACK_INITIAL_DELAY_SECONDS"`
	ARQDataNackRepeatSeconds              float64           `toml:"ARQ_DATA_NACK_REPEAT_SECONDS"`
	ARQTerminalDrainTimeoutSec            float64           `toml:"ARQ_TERMINAL_DRAIN_TIMEOUT_SECONDS"`
	ARQTerminalAckWaitTimeoutSec          float64           `toml:"ARQ_TERMINAL_ACK_WAIT_TIMEOUT_SECONDS"`
	Resolvers                             []ResolverAddress `toml:"-"`
	ResolverMap                           map[string]int    `toml:"-"`
}

type ClientConfigOverrides struct {
	ResolversFilePath *string
	Values            map[string]any
}

type ClientConfigFlagBinder struct {
	values      ClientConfig
	setFields   map[string]struct{}
	flagToField map[string]string
}

func defaultClientConfig() ClientConfig {
	return ClientConfig{
		ProtocolType:                          "SOCKS5",
		Domains:                               nil,
		ListenIP:                              "127.0.0.1",
		ListenPort:                            18000,
		SOCKS5Auth:                            false,
		SOCKS5User:                            "master_dns_vpn",
		SOCKS5Pass:                            "master_dns_vpn",
		LocalDNSEnabled:                       false,
		LocalDNSIP:                            "127.0.0.1",
		LocalDNSPort:                          53,
		LocalDNSCacheMaxRecords:               10000,
		LocalDNSCacheTTLSeconds:               14400.0,
		LocalDNSPendingTimeoutSec:             300.0,
		LocalDNSCachePersist:                  true,
		LocalDNSCacheFlushSec:                 60.0,
		ResolverBalancingStrategy:             2,
		PacketDuplicationCount:                2,
		SetupPacketDuplicationCount:           2,
		StreamResolverFailoverResendThreshold: 2,
		StreamResolverFailoverCooldownSec:     2.5,
		RecheckInactiveServersEnabled:         true,
		AutoDisableTimeoutServers:             true,
		AutoDisableTimeoutWindowSeconds:       30.0,
		BaseEncodeData:                        false,
		UploadCompressionType:                 compression.TypeOff,
		DownloadCompressionType:               compression.TypeOff,
		CompressionMinSize:                    compression.DefaultMinSize,
		DataEncryptionMethod:                  1,
		EncryptionKey:                         "",
		MinUploadMTU:                          38,
		MinDownloadMTU:                        100,
		MaxUploadMTU:                          150,
		MaxDownloadMTU:                        500,
		MTUTestRetries:                        2,
		MTUTestTimeout:                        2.0,
		MTUTestParallelism:                    16,
		RX_TX_Workers:                         4,
		TunnelProcessWorkers:                  0,
		TunnelPacketTimeoutSec:                10.0,
		DispatcherIdlePollIntervalSeconds:     0.020,
		PingAggressiveIntervalSeconds:         0.100,
		PingLazyIntervalSeconds:               0.750,
		PingCooldownIntervalSeconds:           2.0,
		PingColdIntervalSeconds:               15.0,
		PingWarmThresholdSeconds:              8.0,
		PingCoolThresholdSeconds:              20.0,
		PingColdThresholdSeconds:              30.0,
		RXChannelSize:                         4096,
		DNSResponseFragmentTimeoutSeconds:     60.0,
		SOCKSUDPAssociateReadTimeoutSeconds:   30.0,
		ClientTerminalStreamRetentionSeconds:  45.0,
		ClientCancelledSetupRetentionSeconds:  120.0,
		SessionInitRetryBaseSeconds:           1.0,
		SessionInitRetryStepSeconds:           1.0,
		SessionInitRetryLinearAfter:           5,
		SessionInitRetryMaxSeconds:            60.0,
		SessionInitBusyRetryIntervalSeconds:   60.0,
		SessionInitRacingCount:                3,
		SaveMTUServersToFile:                  false,
		MTUServersFileName:                    "masterdnsvpn_success_test_{time}.log",
		MTUServersFileFormat:                  "{IP} ({DOMAIN}) - UP: {UP_MTU} DOWN: {DOWN-MTU}",
		MTUUsingSeparatorText:                 "",
		MTURemovedServerLogFormat:             "Resolver {IP} ({DOMAIN}) removed at {TIME} due to {CAUSE}",
		MTUAddedServerLogFormat:               "Resolver {IP} ({DOMAIN}) added back at {TIME} (UP {UP_MTU}, DOWN {DOWN_MTU})",
		MTUReactiveAddedServerLogFormat:       "Resolver {IP} ({DOMAIN}) added back at {TIME} after reactive recheck (UP {UP_MTU}, DOWN {DOWN_MTU})",
		LogLevel:                              "INFO",
		MaxPacketsPerBatch:                    8,
		ARQWindowSize:                         600,
		ARQInitialRTOSeconds:                  1.0,
		ARQMaxRTOSeconds:                      5.0,
		ARQControlInitialRTOSeconds:           0.5,
		ARQControlMaxRTOSeconds:               3.0,
		ARQMaxControlRetries:                  400,
		ARQInactivityTimeoutSeconds:           1800.0,
		ARQDataPacketTTLSeconds:               2400.0,
		ARQControlPacketTTLSeconds:            1200.0,
		ARQMaxDataRetries:                     1200,
		ARQDataNackMaxGap:                     16,
		ARQDataNackInitialDelaySeconds:        0.1,
		ARQDataNackRepeatSeconds:              1.0,
		ARQTerminalDrainTimeoutSec:            120.0,
		ARQTerminalAckWaitTimeoutSec:          90.0,
	}
}

func LoadClientConfig(filename string) (ClientConfig, error) {
	cfg, err := loadClientConfigFile(filename)
	if err != nil {
		return cfg, err
	}
	return finalizeClientConfig(cfg)
}

func loadClientConfigFile(filename string) (ClientConfig, error) {
	cfg := defaultClientConfig()
	path, format, err := resolveConfigPathWithJSONFallback(filename)
	if err != nil {
		return cfg, err
	}

	cfg.ConfigPath = path
	cfg.ConfigDir = filepath.Dir(path)
	cfg.ResolversFilePath = ""

	switch format {
	case configSourceJSON:
		raw, err := os.ReadFile(path)
		if err != nil {
			return cfg, err
		}
		defined, err := decodeConfigJSONInto(&cfg, raw)
		if err != nil {
			return cfg, fmt.Errorf("parse JSON failed for %s: %w", path, err)
		}
		cfg.explicitRX_TX_Workers = defined["RX_TX_Workers"]
		cfg.explicitTunnelProcessWorkers = defined["TunnelProcessWorkers"]
	default:
		meta, err := toml.DecodeFile(path, &cfg)
		if err != nil {
			return cfg, fmt.Errorf("parse TOML failed for %s: %w", path, err)
		}
		cfg.explicitRX_TX_Workers = meta.IsDefined("RX_TX_WORKERS")
		cfg.explicitTunnelProcessWorkers = meta.IsDefined("TUNNEL_PROCESS_WORKERS")
	}

	return cfg, nil
}

func LoadClientConfigFromJSONBase64(encoded string) (ClientConfig, error) {
	cfg, err := loadClientConfigFromJSONBase64(encoded)
	if err != nil {
		return cfg, err
	}
	return finalizeClientConfig(cfg)
}

func loadClientConfigFromJSONBase64(encoded string) (ClientConfig, error) {
	cfg := defaultClientConfig()
	raw, err := decodeBase64ConfigJSON(encoded)
	if err != nil {
		return cfg, fmt.Errorf("decode client JSON base64 failed: %w", err)
	}
	defined, err := decodeConfigJSONInto(&cfg, raw)
	if err != nil {
		return cfg, fmt.Errorf("parse client JSON base64 failed: %w", err)
	}
	cfg.ConfigDir = currentWorkingConfigDir()
	cfg.ConfigPath = "<json_base64>"
	cfg.ResolversFilePath = ""
	cfg.explicitRX_TX_Workers = defined["RX_TX_Workers"]
	cfg.explicitTunnelProcessWorkers = defined["TunnelProcessWorkers"]
	return cfg, nil
}

func LoadClientConfigWithOverrides(filename string, overrides ClientConfigOverrides) (ClientConfig, error) {
	cfg, err := loadClientConfigFile(filename)
	if err != nil {
		return cfg, err
	}

	if overrides.ResolversFilePath != nil {
		cfg.ResolversFilePath = strings.TrimSpace(*overrides.ResolversFilePath)
	}
	if len(overrides.Values) > 0 {
		if err := applyClientConfigOverrideValues(&cfg, overrides.Values); err != nil {
			return cfg, err
		}
		if _, ok := overrides.Values["TunnelProcessWorkers"]; ok {
			cfg.explicitTunnelProcessWorkers = true
		}
	}

	return finalizeClientConfig(cfg)
}

func LoadClientConfigFromJSONBase64WithOverrides(encoded string, overrides ClientConfigOverrides) (ClientConfig, error) {
	cfg, err := loadClientConfigFromJSONBase64(encoded)
	if err != nil {
		return cfg, err
	}

	if overrides.ResolversFilePath != nil {
		cfg.ResolversFilePath = strings.TrimSpace(*overrides.ResolversFilePath)
	}
	if len(overrides.Values) > 0 {
		if err := applyClientConfigOverrideValues(&cfg, overrides.Values); err != nil {
			return cfg, err
		}
		if _, ok := overrides.Values["TunnelProcessWorkers"]; ok {
			cfg.explicitTunnelProcessWorkers = true
		}
	}

	return finalizeClientConfig(cfg)
}

func finalizeClientConfig(cfg ClientConfig) (ClientConfig, error) {
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

	if cfg.SOCKS5Auth && cfg.SOCKS5User == "" {
		return cfg, fmt.Errorf("SOCKS5_AUTH requires SOCKS5_USER")
	}

	cfg.LocalDNSIP = defaultString(strings.TrimSpace(cfg.LocalDNSIP), "127.0.0.1")

	if cfg.LocalDNSPort < 0 || cfg.LocalDNSPort > 65535 {
		return cfg, fmt.Errorf("invalid LOCAL_DNS_PORT: %d", cfg.LocalDNSPort)
	}

	cfg.LocalDNSCacheMaxRecords = defaultIntBelow(cfg.LocalDNSCacheMaxRecords, 1, 10000)
	cfg.LocalDNSCacheTTLSeconds = defaultFloatAtMostZero(cfg.LocalDNSCacheTTLSeconds, 14400.0)
	cfg.LocalDNSPendingTimeoutSec = defaultFloatAtMostZero(cfg.LocalDNSPendingTimeoutSec, 300.0)
	cfg.LocalDNSCacheFlushSec = defaultFloatAtMostZero(cfg.LocalDNSCacheFlushSec, 60.0)

	if cfg.UploadCompressionType < compression.TypeOff || cfg.UploadCompressionType > compression.TypeZLIB {
		return cfg, fmt.Errorf("invalid UPLOAD_COMPRESSION_TYPE: %d", cfg.UploadCompressionType)
	}

	if cfg.DownloadCompressionType < compression.TypeOff || cfg.DownloadCompressionType > compression.TypeZLIB {
		return cfg, fmt.Errorf("invalid DOWNLOAD_COMPRESSION_TYPE: %d", cfg.DownloadCompressionType)
	}

	cfg.CompressionMinSize = defaultIntBelow(cfg.CompressionMinSize, 100, compression.DefaultMinSize)

	if cfg.ResolverBalancingStrategy < 0 || cfg.ResolverBalancingStrategy > 8 {
		return cfg, fmt.Errorf("invalid RESOLVER_BALANCING_STRATEGY: %d", cfg.ResolverBalancingStrategy)
	}

	cfg.PacketDuplicationCount = clampInt(defaultIntBelow(cfg.PacketDuplicationCount, 1, 2), 1, 10)
	cfg.SetupPacketDuplicationCount = clampInt(defaultIntBelow(cfg.SetupPacketDuplicationCount, 1, max(2, cfg.PacketDuplicationCount)), cfg.PacketDuplicationCount, 12)
	cfg.StreamResolverFailoverResendThreshold = clampInt(defaultIntBelow(cfg.StreamResolverFailoverResendThreshold, 1, 2), 1, 256)
	cfg.StreamResolverFailoverCooldownSec = clampFloat(defaultFloatAtMostZero(cfg.StreamResolverFailoverCooldownSec, 2.5), 0.1, 120.0)
	cfg.AutoDisableTimeoutWindowSeconds = clampFloat(defaultFloatAtMostZero(cfg.AutoDisableTimeoutWindowSeconds, 30.0), 1.0, 86400.0)
	cfg.MaxPacketsPerBatch = clampInt(defaultIntBelow(cfg.MaxPacketsPerBatch, 1, 8), 1, 64)
	cfg.ARQWindowSize = clampInt(defaultIntBelow(cfg.ARQWindowSize, 1, 600), 1, 8000)
	cfg.ARQInitialRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQInitialRTOSeconds, 0.5), 0.01, 60.0)
	cfg.ARQMaxRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQMaxRTOSeconds, 3.0), cfg.ARQInitialRTOSeconds, 120.0)
	cfg.ARQControlInitialRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQControlInitialRTOSeconds, 0.5), 0.01, 60.0)
	cfg.ARQControlMaxRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQControlMaxRTOSeconds, 2.0), cfg.ARQControlInitialRTOSeconds, 120.0)
	cfg.ARQMaxControlRetries = clampInt(defaultIntBelow(cfg.ARQMaxControlRetries, 1, 128), 5, 5000)
	cfg.ARQInactivityTimeoutSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQInactivityTimeoutSeconds, 1800.0), 10.0, 86400.0)
	cfg.ARQDataPacketTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQDataPacketTTLSeconds, 2400.0), 10.0, 86400.0)
	cfg.ARQControlPacketTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQControlPacketTTLSeconds, 1200.0), 10.0, 86400.0)
	cfg.ARQMaxDataRetries = clampInt(defaultIntBelow(cfg.ARQMaxDataRetries, 1, 128), 5, 100000)
	dataNackGapCap := min(min(max(cfg.ARQWindowSize/8, 16), 128), cfg.ARQWindowSize-1)
	cfg.ARQDataNackMaxGap = clampInt(defaultIntBelow(cfg.ARQDataNackMaxGap, 0, 16), 0, dataNackGapCap)
	cfg.ARQDataNackInitialDelaySeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQDataNackInitialDelaySeconds, 0.1), 0.01, 60.0)
	cfg.ARQDataNackRepeatSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQDataNackRepeatSeconds, 1.0), 0.01, 60.0)
	cfg.ARQTerminalDrainTimeoutSec = clampFloat(defaultFloatAtMostZero(cfg.ARQTerminalDrainTimeoutSec, 120.0), 10.0, 3600.0)
	cfg.ARQTerminalAckWaitTimeoutSec = clampFloat(defaultFloatAtMostZero(cfg.ARQTerminalAckWaitTimeoutSec, 90.0), 5.0, 3600.0)

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
	cfg.MTUTestTimeout = defaultFloatAtMostZero(cfg.MTUTestTimeout, 2.0)
	cfg.MTUTestParallelism = defaultIntBelow(cfg.MTUTestParallelism, 1, 1)
	legacyRX_TX_Workers := max(cfg.LegacyTunnelReaderWorkers, cfg.LegacyTunnelWriterWorkers)
	if !cfg.explicitRX_TX_Workers && legacyRX_TX_Workers > 0 {
		cfg.RX_TX_Workers = legacyRX_TX_Workers
	}

	cfg.RX_TX_Workers = clampInt(defaultIntBelow(cfg.RX_TX_Workers, 1, 4), 1, 128)
	cfg.TunnelProcessWorkers = deriveConfiguredTunnelProcessWorkers(
		cfg.TunnelProcessWorkers,
		cfg.RX_TX_Workers,
		cfg.explicitTunnelProcessWorkers,
	)

	cfg.TunnelPacketTimeoutSec = clampFloat(defaultFloatAtMostZero(cfg.TunnelPacketTimeoutSec, 10.0), 0.5, 120.0)
	cfg.DispatcherIdlePollIntervalSeconds = clampFloat(defaultFloatAtMostZero(cfg.DispatcherIdlePollIntervalSeconds, 0.020), 0.001, 1.0)
	cfg.PingAggressiveIntervalSeconds = clampFloat(defaultFloatAtMostZero(cfg.PingAggressiveIntervalSeconds, 0.100), 0.01, 30.0)
	cfg.PingLazyIntervalSeconds = clampFloat(defaultFloatAtMostZero(cfg.PingLazyIntervalSeconds, 0.750), cfg.PingAggressiveIntervalSeconds, 60.0)
	cfg.PingCooldownIntervalSeconds = clampFloat(defaultFloatAtMostZero(cfg.PingCooldownIntervalSeconds, 2.0), cfg.PingLazyIntervalSeconds, 300.0)
	cfg.PingColdIntervalSeconds = clampFloat(defaultFloatAtMostZero(cfg.PingColdIntervalSeconds, 15.0), cfg.PingCooldownIntervalSeconds, 3600.0)
	cfg.PingWarmThresholdSeconds = clampFloat(defaultFloatAtMostZero(cfg.PingWarmThresholdSeconds, 8.0), 0.1, 600.0)
	cfg.PingCoolThresholdSeconds = clampFloat(defaultFloatAtMostZero(cfg.PingCoolThresholdSeconds, 20.0), cfg.PingWarmThresholdSeconds, 1800.0)
	cfg.PingColdThresholdSeconds = clampFloat(defaultFloatAtMostZero(cfg.PingColdThresholdSeconds, 30.0), cfg.PingCoolThresholdSeconds, 3600.0)
	cfg.RXChannelSize = clampInt(defaultIntBelow(cfg.RXChannelSize, 1, 4096), 64, 65536)
	cfg.DNSResponseFragmentTimeoutSeconds = clampFloat(defaultFloatAtMostZero(cfg.DNSResponseFragmentTimeoutSeconds, 60.0), 1.0, 600.0)
	cfg.SOCKSUDPAssociateReadTimeoutSeconds = clampFloat(defaultFloatAtMostZero(cfg.SOCKSUDPAssociateReadTimeoutSeconds, 30.0), 1.0, 3600.0)
	cfg.ClientTerminalStreamRetentionSeconds = clampFloat(defaultFloatAtMostZero(cfg.ClientTerminalStreamRetentionSeconds, 45.0), 1.0, 3600.0)
	cfg.ClientCancelledSetupRetentionSeconds = clampFloat(defaultFloatAtMostZero(cfg.ClientCancelledSetupRetentionSeconds, 120.0), 1.0, 3600.0)
	cfg.SessionInitRetryBaseSeconds = clampFloat(defaultFloatAtMostZero(cfg.SessionInitRetryBaseSeconds, 1.0), 0.1, 60.0)
	cfg.SessionInitRetryStepSeconds = clampFloat(defaultFloatAtMostZero(cfg.SessionInitRetryStepSeconds, 1.0), 0.0, 60.0)
	cfg.SessionInitRetryLinearAfter = clampInt(defaultIntBelow(cfg.SessionInitRetryLinearAfter, 0, 5), 0, 1000)
	cfg.SessionInitRetryMaxSeconds = clampFloat(defaultFloatAtMostZero(cfg.SessionInitRetryMaxSeconds, 60.0), cfg.SessionInitRetryBaseSeconds, 3600.0)
	cfg.SessionInitBusyRetryIntervalSeconds = clampFloat(defaultFloatAtMostZero(cfg.SessionInitBusyRetryIntervalSeconds, 60.0), 1.0, 3600.0)
	cfg.SessionInitRacingCount = clampInt(defaultIntBelow(cfg.SessionInitRacingCount, 1, 3), 1, 5)
	cfg.MTUServersFileName = strings.TrimSpace(cfg.MTUServersFileName)
	cfg.MTUServersFileFormat = strings.TrimSpace(cfg.MTUServersFileFormat)
	cfg.MTUUsingSeparatorText = strings.TrimSpace(cfg.MTUUsingSeparatorText)
	cfg.MTURemovedServerLogFormat = strings.TrimSpace(cfg.MTURemovedServerLogFormat)
	cfg.MTUAddedServerLogFormat = strings.TrimSpace(cfg.MTUAddedServerLogFormat)
	cfg.MTUReactiveAddedServerLogFormat = strings.TrimSpace(cfg.MTUReactiveAddedServerLogFormat)

	cfg.EncryptionKey = strings.TrimSpace(cfg.EncryptionKey)
	if cfg.EncryptionKey == "" {
		return cfg, fmt.Errorf("ENCRYPTION_KEY is required in client config")
	}

	cfg.Domains = normalizeClientDomains(cfg.Domains)
	if len(cfg.Domains) == 0 {
		return cfg, fmt.Errorf("DOMAINS must contain at least one domain")
	}

	cfg.ResolversFilePath = strings.TrimSpace(cfg.ResolversFilePath)

	resolvers, resolverMap, err := LoadClientResolvers(cfg.ResolversPath())
	if err != nil {
		return cfg, err
	}
	cfg.Resolvers = resolvers
	cfg.ResolverMap = resolverMap
	return cfg, nil
}

func (c ClientConfig) ResolversPath() string {
	if c.ResolversFilePath != "" {
		if filepath.IsAbs(c.ResolversFilePath) {
			return c.ResolversFilePath
		}
		if c.ConfigDir != "" {
			return filepath.Join(c.ConfigDir, c.ResolversFilePath)
		}
		return c.ResolversFilePath
	}
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

func (c ClientConfig) DispatcherIdlePollInterval() time.Duration {
	return time.Duration(c.DispatcherIdlePollIntervalSeconds * float64(time.Second))
}

func (c ClientConfig) PingAggressiveInterval() time.Duration {
	return time.Duration(c.PingAggressiveIntervalSeconds * float64(time.Second))
}

func (c ClientConfig) PingLazyInterval() time.Duration {
	return time.Duration(c.PingLazyIntervalSeconds * float64(time.Second))
}

func (c ClientConfig) PingCooldownInterval() time.Duration {
	return time.Duration(c.PingCooldownIntervalSeconds * float64(time.Second))
}

func (c ClientConfig) PingColdInterval() time.Duration {
	return time.Duration(c.PingColdIntervalSeconds * float64(time.Second))
}

func (c ClientConfig) PingWarmThreshold() time.Duration {
	return time.Duration(c.PingWarmThresholdSeconds * float64(time.Second))
}

func (c ClientConfig) PingCoolThreshold() time.Duration {
	return time.Duration(c.PingCoolThresholdSeconds * float64(time.Second))
}

func (c ClientConfig) PingColdThreshold() time.Duration {
	return time.Duration(c.PingColdThresholdSeconds * float64(time.Second))
}

func (c ClientConfig) DNSResponseFragmentTimeout() time.Duration {
	return time.Duration(c.DNSResponseFragmentTimeoutSeconds * float64(time.Second))
}

func (c ClientConfig) SOCKSUDPAssociateReadTimeout() time.Duration {
	return time.Duration(c.SOCKSUDPAssociateReadTimeoutSeconds * float64(time.Second))
}

func (c ClientConfig) ClientTerminalStreamRetention() time.Duration {
	return time.Duration(c.ClientTerminalStreamRetentionSeconds * float64(time.Second))
}

func (c ClientConfig) ClientCancelledSetupRetention() time.Duration {
	return time.Duration(c.ClientCancelledSetupRetentionSeconds * float64(time.Second))
}

func (c ClientConfig) SessionInitRetryBase() time.Duration {
	return time.Duration(c.SessionInitRetryBaseSeconds * float64(time.Second))
}

func (c ClientConfig) SessionInitRetryStep() time.Duration {
	return time.Duration(c.SessionInitRetryStepSeconds * float64(time.Second))
}

func (c ClientConfig) SessionInitRetryMax() time.Duration {
	return time.Duration(c.SessionInitRetryMaxSeconds * float64(time.Second))
}

func (c ClientConfig) SessionInitBusyRetryInterval() time.Duration {
	return time.Duration(c.SessionInitBusyRetryIntervalSeconds * float64(time.Second))
}

func (c ClientConfig) EffectiveResolverUDPConnectionPoolSize() int {
	maxDup := max(c.PacketDuplicationCount, c.SetupPacketDuplicationCount)
	if maxDup < 1 {
		maxDup = 1
	}
	resolverCount := len(c.Resolvers)
	if resolverCount < 1 {
		resolverCount = 1
	}

	size := max(8, c.RX_TX_Workers*maxDup*2)
	switch {
	case resolverCount <= 4:
		size *= 2
	case resolverCount <= 8:
		size = size * 3 / 2
	case resolverCount >= 64:
		size = max(8, size/2)
	case resolverCount >= 32:
		size = max(8, size*3/4)
	}

	return clampInt(size, 8, 128)
}

func (c ClientConfig) EffectiveStreamQueueInitialCapacity() int {
	size := max(c.ARQWindowSize/8, c.MaxPacketsPerBatch*8)
	if c.PacketDuplicationCount > 1 {
		size += c.PacketDuplicationCount * 4
	}
	return clampInt(size, 32, 512)
}

func (c ClientConfig) EffectiveOrphanQueueInitialCapacity() int {
	maxDup := max(c.PacketDuplicationCount, c.SetupPacketDuplicationCount)
	size := c.MaxPacketsPerBatch*4 + c.RX_TX_Workers*2 + maxDup*4
	return clampInt(size, 16, 128)
}

func (c ClientConfig) EffectiveDNSResponseFragmentStoreCap() int {
	size := (c.TunnelProcessWorkers + c.RX_TX_Workers) * c.MaxPacketsPerBatch * 2
	if c.PacketDuplicationCount > 1 {
		size += c.PacketDuplicationCount * c.MaxPacketsPerBatch * 4
	}
	return clampInt(size, 128, 2048)
}

func (c ClientConfig) EffectiveRXChannelSize() int {
	maxDup := max(max(c.PacketDuplicationCount, c.SetupPacketDuplicationCount), 1)
	workerBudget := max(c.RX_TX_Workers+c.TunnelProcessWorkers, 2)
	recommended := clampInt(workerBudget*c.MaxPacketsPerBatch*maxDup*16, 1024, 32768)
	return max(c.RXChannelSize, recommended)
}

func (c ClientConfig) EffectiveMTUTestParallelism() int {
	totalResolvers := len(c.Resolvers)
	if totalResolvers <= 1 {
		return max(1, c.MTUTestParallelism)
	}

	recommended := 2
	switch {
	case totalResolvers <= 4:
		recommended = 2
	case totalResolvers <= 8:
		recommended = 4
	case totalResolvers <= 16:
		recommended = 6
	case totalResolvers <= 32:
		recommended = 8
	case totalResolvers <= 64:
		recommended = 12
	case totalResolvers <= 128:
		recommended = 16
	default:
		recommended = 20
	}

	maxSafe := clampInt(max(c.RX_TX_Workers*2, 4), 4, 24)
	if recommended > maxSafe {
		recommended = maxSafe
	}

	return max(c.MTUTestParallelism, recommended)
}

func applyClientConfigOverrideValues(cfg *ClientConfig, values map[string]any) error {
	if cfg == nil || len(values) == 0 {
		return nil
	}

	elem := reflect.ValueOf(cfg).Elem()
	typ := elem.Type()
	for fieldName, rawValue := range values {
		field, ok := typ.FieldByName(fieldName)
		if !ok {
			return fmt.Errorf("unknown client config override field: %s", fieldName)
		}
		value := elem.FieldByName(fieldName)
		if !value.CanSet() {
			return fmt.Errorf("client config override field is not settable: %s", fieldName)
		}
		if err := assignClientConfigOverrideValue(value, rawValue, field.Name); err != nil {
			return err
		}
	}
	return nil
}

func assignClientConfigOverrideValue(target reflect.Value, rawValue any, fieldName string) error {
	if !target.IsValid() {
		return fmt.Errorf("invalid client config override target: %s", fieldName)
	}

	switch target.Kind() {
	case reflect.String:
		v, ok := rawValue.(string)
		if !ok {
			return fmt.Errorf("invalid string override for %s", fieldName)
		}
		target.SetString(v)
		return nil
	case reflect.Bool:
		v, ok := rawValue.(bool)
		if !ok {
			return fmt.Errorf("invalid bool override for %s", fieldName)
		}
		target.SetBool(v)
		return nil
	case reflect.Int:
		v, ok := rawValue.(int)
		if !ok {
			return fmt.Errorf("invalid int override for %s", fieldName)
		}
		target.SetInt(int64(v))
		return nil
	case reflect.Float64:
		v, ok := rawValue.(float64)
		if !ok {
			return fmt.Errorf("invalid float override for %s", fieldName)
		}
		target.SetFloat(v)
		return nil
	case reflect.Slice:
		if target.Type().Elem().Kind() == reflect.String {
			v, ok := rawValue.([]string)
			if !ok {
				return fmt.Errorf("invalid string slice override for %s", fieldName)
			}
			target.Set(reflect.ValueOf(append([]string(nil), v...)))
			return nil
		}
	}

	return fmt.Errorf("unsupported client config override type for %s", fieldName)
}

func NewClientConfigFlagBinder(fs *flag.FlagSet) (*ClientConfigFlagBinder, error) {
	if fs == nil {
		return nil, fmt.Errorf("flag set is required")
	}

	binder := &ClientConfigFlagBinder{
		values:      defaultClientConfig(),
		setFields:   make(map[string]struct{}),
		flagToField: make(map[string]string),
	}

	valueElem := reflect.ValueOf(&binder.values).Elem()
	valueType := valueElem.Type()
	for i := 0; i < valueType.NumField(); i++ {
		field := valueType.Field(i)
		tomlTag := field.Tag.Get("toml")
		if tomlTag == "" || tomlTag == "-" {
			continue
		}

		flagName := clientConfigFlagName(tomlTag)
		binder.flagToField[flagName] = field.Name
		target := valueElem.Field(i)
		usage := fmt.Sprintf("Override %s from config file", tomlTag)

		switch target.Kind() {
		case reflect.String:
			fs.Var(newClientConfigStringFlag(target.Addr().Interface().(*string), binder, field.Name), flagName, usage)
		case reflect.Bool:
			fs.Var(newClientConfigBoolFlag(target.Addr().Interface().(*bool), binder, field.Name), flagName, usage)
		case reflect.Int:
			fs.Var(newClientConfigIntFlag(target.Addr().Interface().(*int), binder, field.Name), flagName, usage)
		case reflect.Float64:
			fs.Var(newClientConfigFloatFlag(target.Addr().Interface().(*float64), binder, field.Name), flagName, usage)
		case reflect.Slice:
			if target.Type().Elem().Kind() != reflect.String {
				continue
			}
			fs.Var(newClientConfigStringSliceFlag(target.Addr().Interface().(*[]string), binder, field.Name), flagName, usage+" (comma-separated)")
		default:
			continue
		}
	}

	return binder, nil
}

func (b *ClientConfigFlagBinder) Overrides() ClientConfigOverrides {
	overrides := ClientConfigOverrides{
		Values: make(map[string]any, len(b.setFields)),
	}
	if b == nil {
		return overrides
	}

	valueElem := reflect.ValueOf(&b.values).Elem()
	for fieldName := range b.setFields {
		field := valueElem.FieldByName(fieldName)
		if !field.IsValid() {
			continue
		}
		switch field.Kind() {
		case reflect.String:
			overrides.Values[fieldName] = field.String()
		case reflect.Bool:
			overrides.Values[fieldName] = field.Bool()
		case reflect.Int:
			overrides.Values[fieldName] = int(field.Int())
		case reflect.Float64:
			overrides.Values[fieldName] = field.Float()
		case reflect.Slice:
			if field.Type().Elem().Kind() == reflect.String {
				src := field.Interface().([]string)
				overrides.Values[fieldName] = append([]string(nil), src...)
			}
		}
	}

	return overrides
}

func (b *ClientConfigFlagBinder) markSet(fieldName string) {
	if b == nil || fieldName == "" {
		return
	}
	b.setFields[fieldName] = struct{}{}
}

func clientConfigFlagName(tomlTag string) string {
	return strings.ToLower(strings.ReplaceAll(tomlTag, "_", "-"))
}

type clientConfigStringFlag struct {
	target    *string
	binder    *ClientConfigFlagBinder
	fieldName string
}

func newClientConfigStringFlag(target *string, binder *ClientConfigFlagBinder, fieldName string) *clientConfigStringFlag {
	return &clientConfigStringFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *clientConfigStringFlag) String() string {
	if f == nil || f.target == nil {
		return ""
	}
	return *f.target
}

func (f *clientConfigStringFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	*f.target = value
	f.binder.markSet(f.fieldName)
	return nil
}

type clientConfigBoolFlag struct {
	target    *bool
	binder    *ClientConfigFlagBinder
	fieldName string
}

func newClientConfigBoolFlag(target *bool, binder *ClientConfigFlagBinder, fieldName string) *clientConfigBoolFlag {
	return &clientConfigBoolFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *clientConfigBoolFlag) String() string {
	if f == nil || f.target == nil {
		return "false"
	}
	return strconv.FormatBool(*f.target)
}

func (f *clientConfigBoolFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return err
	}
	*f.target = parsed
	f.binder.markSet(f.fieldName)
	return nil
}

func (f *clientConfigBoolFlag) IsBoolFlag() bool { return true }

type clientConfigIntFlag struct {
	target    *int
	binder    *ClientConfigFlagBinder
	fieldName string
}

func newClientConfigIntFlag(target *int, binder *ClientConfigFlagBinder, fieldName string) *clientConfigIntFlag {
	return &clientConfigIntFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *clientConfigIntFlag) String() string {
	if f == nil || f.target == nil {
		return "0"
	}
	return strconv.Itoa(*f.target)
}

func (f *clientConfigIntFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return err
	}
	*f.target = parsed
	f.binder.markSet(f.fieldName)
	return nil
}

type clientConfigFloatFlag struct {
	target    *float64
	binder    *ClientConfigFlagBinder
	fieldName string
}

func newClientConfigFloatFlag(target *float64, binder *ClientConfigFlagBinder, fieldName string) *clientConfigFloatFlag {
	return &clientConfigFloatFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *clientConfigFloatFlag) String() string {
	if f == nil || f.target == nil {
		return "0"
	}
	return strconv.FormatFloat(*f.target, 'f', -1, 64)
}

func (f *clientConfigFloatFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return err
	}
	*f.target = parsed
	f.binder.markSet(f.fieldName)
	return nil
}

type clientConfigStringSliceFlag struct {
	target    *[]string
	binder    *ClientConfigFlagBinder
	fieldName string
}

func newClientConfigStringSliceFlag(target *[]string, binder *ClientConfigFlagBinder, fieldName string) *clientConfigStringSliceFlag {
	return &clientConfigStringSliceFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *clientConfigStringSliceFlag) String() string {
	if f == nil || f.target == nil {
		return ""
	}
	return strings.Join(*f.target, ",")
}

func (f *clientConfigStringSliceFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		items = append(items, part)
	}
	*f.target = items
	f.binder.markSet(f.fieldName)
	return nil
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

func clampFloat(value float64, minValue float64, maxValue float64) float64 {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func deriveConfiguredTunnelProcessWorkers(current int, rxWorkers int, explicit bool) int {
	recommended := deriveRecommendedTunnelProcessWorkers(rxWorkers)
	if explicit {
		current = clampInt(current, 1, 256)
		if current < rxWorkers {
			return rxWorkers
		}
		return current
	}
	return recommended
}

func deriveRecommendedTunnelProcessWorkers(rxWorkers int) int {
	if rxWorkers < 1 {
		rxWorkers = 1
	}
	return clampInt(max(4, rxWorkers+1), rxWorkers, 256)
}
