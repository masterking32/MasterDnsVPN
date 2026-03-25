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
	"time"

	"github.com/BurntSushi/toml"

	"masterdnsvpn-go/internal/compression"
)

type ClientConfig struct {
	ConfigDir                             string            `toml:"-"`
	ConfigPath                            string            `toml:"-"`
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
	RecheckInactiveIntervalSeconds        float64           `toml:"RECHECK_INACTIVE_INTERVAL_SECONDS"`
	RecheckServerIntervalSeconds          float64           `toml:"RECHECK_SERVER_INTERVAL_SECONDS"`
	RecheckBatchSize                      int               `toml:"RECHECK_BATCH_SIZE"`
	AutoDisableTimeoutServers             bool              `toml:"AUTO_DISABLE_TIMEOUT_SERVERS"`
	AutoDisableTimeoutWindowSeconds       float64           `toml:"AUTO_DISABLE_TIMEOUT_WINDOW_SECONDS"`
	AutoDisableMinObservations            int               `toml:"AUTO_DISABLE_MIN_OBSERVATIONS"`
	AutoDisableCheckIntervalSeconds       float64           `toml:"AUTO_DISABLE_CHECK_INTERVAL_SECONDS"`
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
	TunnelReaderWorkers                   int               `toml:"TUNNEL_READER_WORKERS"`
	TunnelWriterWorkers                   int               `toml:"TUNNEL_WRITER_WORKERS"`
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
	TXChannelSize                         int               `toml:"TX_CHANNEL_SIZE"`
	RXChannelSize                         int               `toml:"RX_CHANNEL_SIZE"`
	ResolverUDPConnectionPoolSize         int               `toml:"RESOLVER_UDP_CONNECTION_POOL_SIZE"`
	StreamQueueInitialCapacity            int               `toml:"STREAM_QUEUE_INITIAL_CAPACITY"`
	OrphanQueueInitialCapacity            int               `toml:"ORPHAN_QUEUE_INITIAL_CAPACITY"`
	DNSResponseFragmentStoreCap           int               `toml:"DNS_RESPONSE_FRAGMENT_STORE_CAPACITY"`
	DNSResponseFragmentTimeoutSeconds     float64           `toml:"DNS_RESPONSE_FRAGMENT_TIMEOUT_SECONDS"`
	SOCKSUDPAssociateReadTimeoutSeconds   float64           `toml:"SOCKS_UDP_ASSOCIATE_READ_TIMEOUT_SECONDS"`
	ClientTerminalStreamRetentionSeconds  float64           `toml:"CLIENT_TERMINAL_STREAM_RETENTION_SECONDS"`
	ClientCancelledSetupRetentionSeconds  float64           `toml:"CLIENT_CANCELLED_SETUP_RETENTION_SECONDS"`
	SessionInitRetryBaseSeconds           float64           `toml:"SESSION_INIT_RETRY_BASE_SECONDS"`
	SessionInitRetryStepSeconds           float64           `toml:"SESSION_INIT_RETRY_STEP_SECONDS"`
	SessionInitRetryLinearAfter           int               `toml:"SESSION_INIT_RETRY_LINEAR_AFTER"`
	SessionInitRetryMaxSeconds            float64           `toml:"SESSION_INIT_RETRY_MAX_SECONDS"`
	SessionInitBusyRetryIntervalSeconds   float64           `toml:"SESSION_INIT_BUSY_RETRY_INTERVAL_SECONDS"`
	SaveMTUServersToFile                  bool              `toml:"SAVE_MTU_SERVERS_TO_FILE"`
	MTUServersFileName                    string            `toml:"MTU_SERVERS_FILE_NAME"`
	MTUServersFileFormat                  string            `toml:"MTU_SERVERS_FILE_FORMAT"`
	MTUUsingSeparatorText                 string            `toml:"MTU_USING_SECTION_SEPARATOR_TEXT"`
	MTURemovedServerLogFormat             string            `toml:"MTU_REMOVED_SERVER_LOG_FORMAT"`
	MTUAddedServerLogFormat               string            `toml:"MTU_ADDED_SERVER_LOG_FORMAT"`
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
	ARQTerminalDrainTimeoutSec            float64           `toml:"ARQ_TERMINAL_DRAIN_TIMEOUT_SECONDS"`
	ARQTerminalAckWaitTimeoutSec          float64           `toml:"ARQ_TERMINAL_ACK_WAIT_TIMEOUT_SECONDS"`
	Resolvers                             []ResolverAddress `toml:"-"`
	ResolverMap                           map[string]int    `toml:"-"`
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
		LocalDNSCacheMaxRecords:               5000,
		LocalDNSCacheTTLSeconds:               28800.0,
		LocalDNSPendingTimeoutSec:             300.0,
		LocalDNSCachePersist:                  true,
		LocalDNSCacheFlushSec:                 60.0,
		ResolverBalancingStrategy:             0,
		PacketDuplicationCount:                5,
		SetupPacketDuplicationCount:           5,
		StreamResolverFailoverResendThreshold: 2,
		StreamResolverFailoverCooldownSec:     1.0,
		RecheckInactiveServersEnabled:         true,
		RecheckInactiveIntervalSeconds:        1800.0,
		RecheckServerIntervalSeconds:          3.0,
		RecheckBatchSize:                      5,
		AutoDisableTimeoutServers:             true,
		AutoDisableTimeoutWindowSeconds:       180.0,
		AutoDisableMinObservations:            6,
		AutoDisableCheckIntervalSeconds:       3.0,
		BaseEncodeData:                        false,
		UploadCompressionType:                 compression.TypeOff,
		DownloadCompressionType:               compression.TypeOff,
		CompressionMinSize:                    compression.DefaultMinSize,
		DataEncryptionMethod:                  1,
		EncryptionKey:                         "",
		MinUploadMTU:                          40,
		MinDownloadMTU:                        100,
		MaxUploadMTU:                          64,
		MaxDownloadMTU:                        140,
		MTUTestRetries:                        2,
		MTUTestTimeout:                        4.0,
		MTUTestParallelism:                    16,
		TunnelReaderWorkers:                   6,
		TunnelWriterWorkers:                   6,
		TunnelProcessWorkers:                  4,
		TunnelPacketTimeoutSec:                8.0,
		DispatcherIdlePollIntervalSeconds:     0.020,
		PingAggressiveIntervalSeconds:         0.300,
		PingLazyIntervalSeconds:               1.0,
		PingCooldownIntervalSeconds:           3.0,
		PingColdIntervalSeconds:               30.0,
		PingWarmThresholdSeconds:              5.0,
		PingCoolThresholdSeconds:              10.0,
		PingColdThresholdSeconds:              20.0,
		TXChannelSize:                         4096,
		RXChannelSize:                         4096,
		ResolverUDPConnectionPoolSize:         64,
		StreamQueueInitialCapacity:            128,
		OrphanQueueInitialCapacity:            32,
		DNSResponseFragmentStoreCap:           256,
		DNSResponseFragmentTimeoutSeconds:     10.0,
		SOCKSUDPAssociateReadTimeoutSeconds:   30.0,
		ClientTerminalStreamRetentionSeconds:  45.0,
		ClientCancelledSetupRetentionSeconds:  120.0,
		SessionInitRetryBaseSeconds:           1.0,
		SessionInitRetryStepSeconds:           1.0,
		SessionInitRetryLinearAfter:           5,
		SessionInitRetryMaxSeconds:            60.0,
		SessionInitBusyRetryIntervalSeconds:   60.0,
		SaveMTUServersToFile:                  false,
		MTUServersFileName:                    "masterdnsvpn_success_test_{time}.log",
		MTUServersFileFormat:                  "{IP} - UP: {UP_MTU} DOWN: {DOWN-MTU}",
		MTUUsingSeparatorText:                 "",
		MTURemovedServerLogFormat:             "Resolver {IP} removed at {TIME} due to {CAUSE}",
		MTUAddedServerLogFormat:               "Resolver {IP} added back at {TIME} (UP {UP_MTU}, DOWN {DOWN_MTU})",
		LogLevel:                              "INFO",
		MaxPacketsPerBatch:                    8,
		ARQWindowSize:                         2000,
		ARQInitialRTOSeconds:                  1.0,
		ARQMaxRTOSeconds:                      8.0,
		ARQControlInitialRTOSeconds:           1.0,
		ARQControlMaxRTOSeconds:               8.0,
		ARQMaxControlRetries:                  80,
		ARQInactivityTimeoutSeconds:           1800.0,
		ARQDataPacketTTLSeconds:               1800.0,
		ARQControlPacketTTLSeconds:            900.0,
		ARQMaxDataRetries:                     800,
		ARQTerminalDrainTimeoutSec:            90.0,
		ARQTerminalAckWaitTimeoutSec:          60.0,
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

	if cfg.SOCKS5Auth && cfg.SOCKS5User == "" {
		return cfg, fmt.Errorf("SOCKS5_AUTH requires SOCKS5_USER")
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
	cfg.StreamResolverFailoverResendThreshold = clampInt(defaultIntBelow(cfg.StreamResolverFailoverResendThreshold, 1, 2), 1, 128)
	cfg.StreamResolverFailoverCooldownSec = clampFloat(defaultFloatAtMostZero(cfg.StreamResolverFailoverCooldownSec, 1.0), 0.1, 120.0)
	cfg.RecheckInactiveIntervalSeconds = clampFloat(defaultFloatAtMostZero(cfg.RecheckInactiveIntervalSeconds, 1800.0), 60.0, 86400.0)
	cfg.RecheckServerIntervalSeconds = clampFloat(defaultFloatAtMostZero(cfg.RecheckServerIntervalSeconds, 3.0), 1.0, 600.0)
	cfg.RecheckBatchSize = clampInt(defaultIntBelow(cfg.RecheckBatchSize, 1, 5), 1, 1024)
	cfg.AutoDisableTimeoutWindowSeconds = clampFloat(defaultFloatAtMostZero(cfg.AutoDisableTimeoutWindowSeconds, 180.0), 1.0, 86400.0)
	cfg.AutoDisableMinObservations = clampInt(defaultIntBelow(cfg.AutoDisableMinObservations, 1, 6), 1, 10000)
	cfg.AutoDisableCheckIntervalSeconds = clampFloat(defaultFloatAtMostZero(cfg.AutoDisableCheckIntervalSeconds, 3.0), 0.25, 600.0)
	cfg.MaxPacketsPerBatch = clampInt(defaultIntBelow(cfg.MaxPacketsPerBatch, 1, 5), 1, 64)
	cfg.ARQWindowSize = clampInt(defaultIntBelow(cfg.ARQWindowSize, 1, 600), 1, 4096)
	cfg.ARQInitialRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQInitialRTOSeconds, 1.0), 0.05, 60.0)
	cfg.ARQMaxRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQMaxRTOSeconds, 8.0), cfg.ARQInitialRTOSeconds, 120.0)
	cfg.ARQControlInitialRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQControlInitialRTOSeconds, 1.0), 0.05, 60.0)
	cfg.ARQControlMaxRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQControlMaxRTOSeconds, 8.0), cfg.ARQControlInitialRTOSeconds, 120.0)
	cfg.ARQMaxControlRetries = clampInt(defaultIntBelow(cfg.ARQMaxControlRetries, 1, 80), 5, 5000)
	cfg.ARQInactivityTimeoutSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQInactivityTimeoutSeconds, 1800.0), 30.0, 86400.0)
	cfg.ARQDataPacketTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQDataPacketTTLSeconds, 1800.0), 30.0, 86400.0)
	cfg.ARQControlPacketTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQControlPacketTTLSeconds, 900.0), 30.0, 86400.0)
	cfg.ARQMaxDataRetries = clampInt(defaultIntBelow(cfg.ARQMaxDataRetries, 1, 800), 60, 100000)
	cfg.ARQTerminalDrainTimeoutSec = clampFloat(defaultFloatAtMostZero(cfg.ARQTerminalDrainTimeoutSec, 90.0), 10.0, 3600.0)
	cfg.ARQTerminalAckWaitTimeoutSec = clampFloat(defaultFloatAtMostZero(cfg.ARQTerminalAckWaitTimeoutSec, 60.0), 5.0, 3600.0)

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
	cfg.TunnelReaderWorkers = clampInt(defaultIntBelow(cfg.TunnelReaderWorkers, 1, 6), 1, 64)
	cfg.TunnelWriterWorkers = clampInt(defaultIntBelow(cfg.TunnelWriterWorkers, 1, 6), 1, 64)
	cfg.TunnelProcessWorkers = clampInt(defaultIntBelow(cfg.TunnelProcessWorkers, 1, 4), 1, 64)
	cfg.TunnelPacketTimeoutSec = clampFloat(defaultFloatAtMostZero(cfg.TunnelPacketTimeoutSec, 8.0), 0.5, 120.0)
	cfg.DispatcherIdlePollIntervalSeconds = clampFloat(defaultFloatAtMostZero(cfg.DispatcherIdlePollIntervalSeconds, 0.020), 0.001, 1.0)
	cfg.PingAggressiveIntervalSeconds = clampFloat(defaultFloatAtMostZero(cfg.PingAggressiveIntervalSeconds, 0.300), 0.05, 30.0)
	cfg.PingLazyIntervalSeconds = clampFloat(defaultFloatAtMostZero(cfg.PingLazyIntervalSeconds, 1.0), cfg.PingAggressiveIntervalSeconds, 60.0)
	cfg.PingCooldownIntervalSeconds = clampFloat(defaultFloatAtMostZero(cfg.PingCooldownIntervalSeconds, 3.0), cfg.PingLazyIntervalSeconds, 300.0)
	cfg.PingColdIntervalSeconds = clampFloat(defaultFloatAtMostZero(cfg.PingColdIntervalSeconds, 30.0), cfg.PingCooldownIntervalSeconds, 3600.0)
	cfg.PingWarmThresholdSeconds = clampFloat(defaultFloatAtMostZero(cfg.PingWarmThresholdSeconds, 5.0), 0.1, 600.0)
	cfg.PingCoolThresholdSeconds = clampFloat(defaultFloatAtMostZero(cfg.PingCoolThresholdSeconds, 10.0), cfg.PingWarmThresholdSeconds, 1800.0)
	cfg.PingColdThresholdSeconds = clampFloat(defaultFloatAtMostZero(cfg.PingColdThresholdSeconds, 20.0), cfg.PingCoolThresholdSeconds, 3600.0)
	cfg.TXChannelSize = clampInt(defaultIntBelow(cfg.TXChannelSize, 1, 4096), 64, 65536)
	cfg.RXChannelSize = clampInt(defaultIntBelow(cfg.RXChannelSize, 1, 4096), 64, 65536)
	cfg.ResolverUDPConnectionPoolSize = clampInt(defaultIntBelow(cfg.ResolverUDPConnectionPoolSize, 1, 64), 1, 1024)
	cfg.StreamQueueInitialCapacity = clampInt(defaultIntBelow(cfg.StreamQueueInitialCapacity, 1, 128), 8, 65536)
	cfg.OrphanQueueInitialCapacity = clampInt(defaultIntBelow(cfg.OrphanQueueInitialCapacity, 1, 32), 4, 4096)
	cfg.DNSResponseFragmentStoreCap = clampInt(defaultIntBelow(cfg.DNSResponseFragmentStoreCap, 1, 256), 16, 16384)
	cfg.DNSResponseFragmentTimeoutSeconds = clampFloat(defaultFloatAtMostZero(cfg.DNSResponseFragmentTimeoutSeconds, 10.0), 1.0, 600.0)
	cfg.SOCKSUDPAssociateReadTimeoutSeconds = clampFloat(defaultFloatAtMostZero(cfg.SOCKSUDPAssociateReadTimeoutSeconds, 30.0), 1.0, 3600.0)
	cfg.ClientTerminalStreamRetentionSeconds = clampFloat(defaultFloatAtMostZero(cfg.ClientTerminalStreamRetentionSeconds, 45.0), 1.0, 3600.0)
	cfg.ClientCancelledSetupRetentionSeconds = clampFloat(defaultFloatAtMostZero(cfg.ClientCancelledSetupRetentionSeconds, 120.0), 1.0, 3600.0)
	cfg.SessionInitRetryBaseSeconds = clampFloat(defaultFloatAtMostZero(cfg.SessionInitRetryBaseSeconds, 1.0), 0.1, 60.0)
	cfg.SessionInitRetryStepSeconds = clampFloat(defaultFloatAtMostZero(cfg.SessionInitRetryStepSeconds, 1.0), 0.0, 60.0)
	cfg.SessionInitRetryLinearAfter = clampInt(defaultIntBelow(cfg.SessionInitRetryLinearAfter, 0, 5), 0, 1000)
	cfg.SessionInitRetryMaxSeconds = clampFloat(defaultFloatAtMostZero(cfg.SessionInitRetryMaxSeconds, 60.0), cfg.SessionInitRetryBaseSeconds, 3600.0)
	cfg.SessionInitBusyRetryIntervalSeconds = clampFloat(defaultFloatAtMostZero(cfg.SessionInitBusyRetryIntervalSeconds, 60.0), 1.0, 3600.0)
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
