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
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"masterdnsvpn-go/internal/compression"
)

type ServerConfig struct {
	ConfigDir                         string   `toml:"-"`
	ConfigPath                        string   `toml:"-"`
	ProtocolType                      string   `toml:"PROTOCOL_TYPE"`
	UDPHost                           string   `toml:"UDP_HOST"`
	UDPPort                           int      `toml:"UDP_PORT"`
	UDPReaders                        int      `toml:"UDP_READERS"`
	SocketBufferSize                  int      `toml:"SOCKET_BUFFER_SIZE"`
	MaxConcurrentRequests             int      `toml:"MAX_CONCURRENT_REQUESTS"`
	DNSRequestWorkers                 int      `toml:"DNS_REQUEST_WORKERS"`
	DeferredSessionWorkers            int      `toml:"DEFERRED_SESSION_WORKERS"`
	DeferredSessionQueueLimit         int      `toml:"DEFERRED_SESSION_QUEUE_LIMIT"`
	MaxPacketSize                     int      `toml:"MAX_PACKET_SIZE"`
	DropLogIntervalSecs               float64  `toml:"DROP_LOG_INTERVAL_SECONDS"`
	InvalidCookieWindowSecs           float64  `toml:"INVALID_COOKIE_WINDOW_SECONDS"`
	InvalidCookieErrorThreshold       int      `toml:"INVALID_COOKIE_ERROR_THRESHOLD"`
	SessionTimeoutSecs                float64  `toml:"SESSION_TIMEOUT_SECONDS"`
	SessionCleanupIntervalSecs        float64  `toml:"SESSION_CLEANUP_INTERVAL_SECONDS"`
	ClosedSessionRetentionSecs        float64  `toml:"CLOSED_SESSION_RETENTION_SECONDS"`
	SessionInitReuseTTLSeconds        float64  `toml:"SESSION_INIT_REUSE_TTL_SECONDS"`
	RecentlyClosedStreamTTLSeconds    float64  `toml:"RECENTLY_CLOSED_STREAM_TTL_SECONDS"`
	RecentlyClosedStreamCap           int      `toml:"RECENTLY_CLOSED_STREAM_CAP"`
	TerminalStreamRetentionSeconds    float64  `toml:"TERMINAL_STREAM_RETENTION_SECONDS"`
	MaxPacketsPerBatch                int      `toml:"MAX_PACKETS_PER_BATCH"`
	PacketBlockControlDuplication     int      `toml:"PACKET_BLOCK_CONTROL_DUPLICATION"`
	DNSUpstreamServers                []string `toml:"DNS_UPSTREAM_SERVERS"`
	DNSUpstreamTimeoutSecs            float64  `toml:"DNS_UPSTREAM_TIMEOUT"`
	DNSInflightWaitTimeoutSecs        float64  `toml:"DNS_INFLIGHT_WAIT_TIMEOUT_SECONDS"`
	SOCKSConnectTimeoutSecs           float64  `toml:"SOCKS_CONNECT_TIMEOUT"`
	DNSFragmentAssemblyTimeoutSecs    float64  `toml:"DNS_FRAGMENT_ASSEMBLY_TIMEOUT"`
	StreamSetupAckTTLSeconds          float64  `toml:"STREAM_SETUP_ACK_TTL_SECONDS"`
	StreamResultPacketTTLSeconds      float64  `toml:"STREAM_RESULT_PACKET_TTL_SECONDS"`
	StreamFailurePacketTTLSeconds     float64  `toml:"STREAM_FAILURE_PACKET_TTL_SECONDS"`
	DNSCacheMaxRecords                int      `toml:"DNS_CACHE_MAX_RECORDS"`
	DNSCacheTTLSeconds                float64  `toml:"DNS_CACHE_TTL_SECONDS"`
	UseExternalSOCKS5                 bool     `toml:"USE_EXTERNAL_SOCKS5"`
	SOCKS5Auth                        bool     `toml:"SOCKS5_AUTH"`
	SOCKS5User                        string   `toml:"SOCKS5_USER"`
	SOCKS5Pass                        string   `toml:"SOCKS5_PASS"`
	ForwardIP                         string   `toml:"FORWARD_IP"`
	ForwardPort                       int      `toml:"FORWARD_PORT"`
	Domain                            []string `toml:"DOMAIN"`
	MinVPNLabelLength                 int      `toml:"MIN_VPN_LABEL_LENGTH"`
	SupportedUploadCompressionTypes   []int    `toml:"SUPPORTED_UPLOAD_COMPRESSION_TYPES"`
	SupportedDownloadCompressionTypes []int    `toml:"SUPPORTED_DOWNLOAD_COMPRESSION_TYPES"`
	DataEncryptionMethod              int      `toml:"DATA_ENCRYPTION_METHOD"`
	EncryptionKeyFile                 string   `toml:"ENCRYPTION_KEY_FILE"`
	LogLevel                          string   `toml:"LOG_LEVEL"`
	ARQWindowSize                     int      `toml:"ARQ_WINDOW_SIZE"`
	ARQInitialRTOSeconds              float64  `toml:"ARQ_INITIAL_RTO_SECONDS"`
	ARQMaxRTOSeconds                  float64  `toml:"ARQ_MAX_RTO_SECONDS"`
	ARQControlInitialRTOSeconds       float64  `toml:"ARQ_CONTROL_INITIAL_RTO_SECONDS"`
	ARQControlMaxRTOSeconds           float64  `toml:"ARQ_CONTROL_MAX_RTO_SECONDS"`
	ARQMaxControlRetries              int      `toml:"ARQ_MAX_CONTROL_RETRIES"`
	ARQInactivityTimeoutSeconds       float64  `toml:"ARQ_INACTIVITY_TIMEOUT_SECONDS"`
	ARQDataPacketTTLSeconds           float64  `toml:"ARQ_DATA_PACKET_TTL_SECONDS"`
	ARQControlPacketTTLSeconds        float64  `toml:"ARQ_CONTROL_PACKET_TTL_SECONDS"`
	ARQMaxDataRetries                 int      `toml:"ARQ_MAX_DATA_RETRIES"`
	ARQDataNackMaxGap                 int      `toml:"ARQ_DATA_NACK_MAX_GAP"`
	ARQDataNackInitialDelaySeconds    float64  `toml:"ARQ_DATA_NACK_INITIAL_DELAY_SECONDS"`
	ARQDataNackRepeatSeconds          float64  `toml:"ARQ_DATA_NACK_REPEAT_SECONDS"`
	ARQTerminalDrainTimeoutSec        float64  `toml:"ARQ_TERMINAL_DRAIN_TIMEOUT_SECONDS"`
	ARQTerminalAckWaitTimeoutSec      float64  `toml:"ARQ_TERMINAL_ACK_WAIT_TIMEOUT_SECONDS"`
	MaxAllowedClientActiveSessions    int      `toml:"MAX_ALLOWED_CLIENT_ACTIVE_SESSION"`
	MaxAllowedClientActiveStreams     int      `toml:"MAX_ALLOWED_CLIENT_ACTIVE_STREAMS_PER_SESSION"`
	ClientMaxPacketDuplicationCount   int      `toml:"MAX_ALLOWED_CLIENT_PACKET_DUPLICATION_COUNT"`
	ClientMaxSetupDuplicationCount    int      `toml:"MAX_ALLOWED_CLIENT_SETUP_PACKET_DUPLICATION_COUNT"`
	ClientMaxUploadMTU                int      `toml:"MAX_ALLOWED_CLIENT_UPLOAD_MTU"`
	ClientMaxDownloadMTU              int      `toml:"MAX_ALLOWED_CLIENT_DOWNLOAD_MTU"`
	ClientMaxRxTxWorkers              int      `toml:"MAX_ALLOWED_CLIENT_RX_TX_WORKERS"`
	ClientMinPingAggressiveInterval   float64  `toml:"MIN_ALLOWED_CLIENT_PING_AGGRESSIVE_INTERVAL_SECONDS"`
	ClientMaxPacketsPerBatch          int      `toml:"MAX_ALLOWED_CLIENT_PACKETS_PER_BATCH"`
	ClientMaxARQWindowSize            int      `toml:"MAX_ALLOWED_CLIENT_ARQ_WINDOW_SIZE"`
	ClientMaxARQDataNackMaxGap        int      `toml:"MAX_ALLOWED_CLIENT_ARQ_DATA_NACK_MAX_GAP"`
	ClientMinCompressionMinSize       int      `toml:"MIN_ALLOWED_CLIENT_COMPRESSION_MIN_SIZE"`
	ClientMinARQInitialRTOSeconds     float64  `toml:"MIN_ALLOWED_CLIENT_ARQ_INITIAL_RTO_SECONDS"`
}

type ServerConfigOverrides struct {
	Values map[string]any
}

type ServerConfigFlagBinder struct {
	values      ServerConfig
	setFields   map[string]struct{}
	flagToField map[string]string
}

func defaultServerConfig() ServerConfig {
	return ServerConfig{
		ProtocolType:                      "SOCKS5",
		UDPHost:                           "",
		UDPPort:                           53,
		UDPReaders:                        4,
		SocketBufferSize:                  8 * 1024 * 1024,
		MaxConcurrentRequests:             16384,
		DNSRequestWorkers:                 8,
		DeferredSessionWorkers:            4,
		DeferredSessionQueueLimit:         4096,
		MaxPacketSize:                     65535,
		DropLogIntervalSecs:               2.0,
		InvalidCookieWindowSecs:           2.0,
		InvalidCookieErrorThreshold:       10,
		SessionTimeoutSecs:                300.0,
		SessionCleanupIntervalSecs:        30.0,
		ClosedSessionRetentionSecs:        600.0,
		SessionInitReuseTTLSeconds:        600.0,
		RecentlyClosedStreamTTLSeconds:    600.0,
		RecentlyClosedStreamCap:           2000,
		TerminalStreamRetentionSeconds:    45.0,
		MaxPacketsPerBatch:                5,
		PacketBlockControlDuplication:     1,
		DNSUpstreamServers:                []string{"1.1.1.1:53", "1.0.0.1:53"},
		DNSUpstreamTimeoutSecs:            4.0,
		DNSInflightWaitTimeoutSecs:        15.0,
		SOCKSConnectTimeoutSecs:           120.0,
		DNSFragmentAssemblyTimeoutSecs:    300.0,
		StreamSetupAckTTLSeconds:          400.0,
		StreamResultPacketTTLSeconds:      300.0,
		StreamFailurePacketTTLSeconds:     120.0,
		DNSCacheMaxRecords:                50000,
		DNSCacheTTLSeconds:                300.0,
		UseExternalSOCKS5:                 false,
		SOCKS5Auth:                        false,
		SOCKS5User:                        "admin",
		SOCKS5Pass:                        "123456",
		ForwardIP:                         "",
		ForwardPort:                       1080,
		Domain:                            nil,
		MinVPNLabelLength:                 3,
		SupportedUploadCompressionTypes:   []int{0, 1, 2, 3},
		SupportedDownloadCompressionTypes: []int{0, 1, 2, 3},
		DataEncryptionMethod:              1,
		EncryptionKeyFile:                 "encrypt_key.txt",
		LogLevel:                          "INFO",
		ARQWindowSize:                     800,
		ARQInitialRTOSeconds:              1.0,
		ARQMaxRTOSeconds:                  5.0,
		ARQControlInitialRTOSeconds:       0.5,
		ARQControlMaxRTOSeconds:           3.0,
		ARQMaxControlRetries:              400,
		ARQInactivityTimeoutSeconds:       1800.0,
		ARQDataPacketTTLSeconds:           2400.0,
		ARQControlPacketTTLSeconds:        1200.0,
		ARQMaxDataRetries:                 1200,
		ARQDataNackMaxGap:                 16,
		ARQDataNackInitialDelaySeconds:    0.3,
		ARQDataNackRepeatSeconds:          1.0,
		ARQTerminalDrainTimeoutSec:        120.0,
		ARQTerminalAckWaitTimeoutSec:      90.0,
		MaxAllowedClientActiveSessions:    255,
		MaxAllowedClientActiveStreams:     2000,
		ClientMaxPacketDuplicationCount:   5,
		ClientMaxSetupDuplicationCount:    6,
		ClientMaxUploadMTU:                150,
		ClientMaxDownloadMTU:              4096,
		ClientMaxRxTxWorkers:              255,
		ClientMinPingAggressiveInterval:   0.05,
		ClientMaxPacketsPerBatch:          20,
		ClientMaxARQWindowSize:            8000,
		ClientMaxARQDataNackMaxGap:        255,
		ClientMinCompressionMinSize:       120,
		ClientMinARQInitialRTOSeconds:     0.05,
	}
}

func LoadServerConfig(filename string) (ServerConfig, error) {
	cfg, err := loadServerConfigFile(filename)
	if err != nil {
		return cfg, err
	}
	return finalizeServerConfig(cfg)
}

func loadServerConfigFile(filename string) (ServerConfig, error) {
	cfg := defaultServerConfig()
	path, format, err := resolveConfigPathWithJSONFallback(filename)
	if err != nil {
		return cfg, err
	}

	switch format {
	case configSourceJSON:
		raw, err := os.ReadFile(path)
		if err != nil {
			return cfg, err
		}
		if _, err := decodeConfigJSONInto(&cfg, raw); err != nil {
			return cfg, fmt.Errorf("parse JSON failed for %s: %w", path, err)
		}
	default:
		if _, err := toml.DecodeFile(path, &cfg); err != nil {
			return cfg, fmt.Errorf("parse TOML failed for %s: %w", path, err)
		}
	}

	cfg.ConfigPath = path
	cfg.ConfigDir = filepath.Dir(path)
	return cfg, nil
}

func LoadServerConfigFromJSONBase64(encoded string) (ServerConfig, error) {
	cfg, err := loadServerConfigFromJSONBase64(encoded)
	if err != nil {
		return cfg, err
	}
	return finalizeServerConfig(cfg)
}

func loadServerConfigFromJSONBase64(encoded string) (ServerConfig, error) {
	cfg := defaultServerConfig()
	raw, err := decodeBase64ConfigJSON(encoded)
	if err != nil {
		return cfg, fmt.Errorf("decode server JSON base64 failed: %w", err)
	}
	if _, err := decodeConfigJSONInto(&cfg, raw); err != nil {
		return cfg, fmt.Errorf("parse server JSON base64 failed: %w", err)
	}
	cfg.ConfigDir = currentWorkingConfigDir()
	cfg.ConfigPath = "<json_base64>"
	return cfg, nil
}

func LoadServerConfigWithOverrides(filename string, overrides ServerConfigOverrides) (ServerConfig, error) {
	cfg, err := loadServerConfigFile(filename)
	if err != nil {
		return cfg, err
	}
	if len(overrides.Values) > 0 {
		if err := applyServerConfigOverrideValues(&cfg, overrides.Values); err != nil {
			return cfg, err
		}
	}
	return finalizeServerConfig(cfg)
}

func LoadServerConfigFromJSONBase64WithOverrides(encoded string, overrides ServerConfigOverrides) (ServerConfig, error) {
	cfg, err := loadServerConfigFromJSONBase64(encoded)
	if err != nil {
		return cfg, err
	}
	if len(overrides.Values) > 0 {
		if err := applyServerConfigOverrideValues(&cfg, overrides.Values); err != nil {
			return cfg, err
		}
	}
	return finalizeServerConfig(cfg)
}

func finalizeServerConfig(cfg ServerConfig) (ServerConfig, error) {
	cfg.ProtocolType = defaultString(strings.ToUpper(strings.TrimSpace(cfg.ProtocolType)), "SOCKS5")

	switch cfg.ProtocolType {
	case "SOCKS5", "TCP":
	default:
		return cfg, fmt.Errorf("invalid PROTOCOL_TYPE: %q", cfg.ProtocolType)
	}

	if cfg.UDPHost != "" && net.ParseIP(cfg.UDPHost) == nil {
		return cfg, fmt.Errorf("invalid UDP_HOST %q: must be an unbracketed IP literal", cfg.UDPHost)
	}

	if cfg.UDPPort <= 0 || cfg.UDPPort > 65535 {
		return cfg, fmt.Errorf("invalid UDP_PORT: %d", cfg.UDPPort)
	}

	if cfg.UDPReaders <= 0 {
		cfg.UDPReaders = defaultServerConfig().UDPReaders
	}

	if cfg.SocketBufferSize <= 0 {
		cfg.SocketBufferSize = 8 * 1024 * 1024
	}

	if cfg.MaxConcurrentRequests <= 0 {
		cfg.MaxConcurrentRequests = 4096
	}

	if cfg.DNSRequestWorkers <= 0 {
		cfg.DNSRequestWorkers = defaultServerConfig().DNSRequestWorkers
	}
	if cfg.DeferredSessionWorkers < 0 {
		cfg.DeferredSessionWorkers = 0
	}

	if cfg.DeferredSessionWorkers > 128 {
		cfg.DeferredSessionWorkers = 128
	}

	if cfg.DeferredSessionQueueLimit < 1 {
		cfg.DeferredSessionQueueLimit = 256
	}

	if cfg.DeferredSessionQueueLimit > 14336 {
		cfg.DeferredSessionQueueLimit = 14336
	}

	if cfg.MaxPacketSize <= 0 {
		cfg.MaxPacketSize = 65535
	}

	if cfg.DropLogIntervalSecs <= 0 {
		cfg.DropLogIntervalSecs = 2.0
	}

	if cfg.InvalidCookieWindowSecs <= 0 {
		cfg.InvalidCookieWindowSecs = 2.0
	}

	if cfg.InvalidCookieErrorThreshold <= 0 {
		cfg.InvalidCookieErrorThreshold = 10
	}

	if cfg.SessionTimeoutSecs <= 0 {
		cfg.SessionTimeoutSecs = 300.0
	}

	if cfg.SessionCleanupIntervalSecs <= 0 {
		cfg.SessionCleanupIntervalSecs = 30.0
	}

	if cfg.ClosedSessionRetentionSecs <= 0 {
		cfg.ClosedSessionRetentionSecs = 600.0
	}

	cfg.SessionInitReuseTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.SessionInitReuseTTLSeconds, 600.0), 1.0, 86400.0)
	cfg.RecentlyClosedStreamTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.RecentlyClosedStreamTTLSeconds, 600.0), 1.0, 86400.0)
	cfg.RecentlyClosedStreamCap = clampInt(defaultIntBelow(cfg.RecentlyClosedStreamCap, 1, 2000), 1, 1000000)
	cfg.TerminalStreamRetentionSeconds = clampFloat(defaultFloatAtMostZero(cfg.TerminalStreamRetentionSeconds, 45.0), 1.0, 86400.0)

	if cfg.MaxPacketsPerBatch < 1 {
		cfg.MaxPacketsPerBatch = 20
	}

	if cfg.PacketBlockControlDuplication < 1 {
		cfg.PacketBlockControlDuplication = 1
	}

	if cfg.PacketBlockControlDuplication > 4 {
		cfg.PacketBlockControlDuplication = 4
	}

	if len(cfg.DNSUpstreamServers) == 0 {
		cfg.DNSUpstreamServers = []string{"1.1.1.1:53"}
	}

	if cfg.DNSUpstreamTimeoutSecs <= 0 {
		cfg.DNSUpstreamTimeoutSecs = 4.0
	}
	cfg.DNSInflightWaitTimeoutSecs = clampFloat(defaultFloatAtMostZero(cfg.DNSInflightWaitTimeoutSecs, 15.0), 0.1, 120.0)

	if cfg.SOCKSConnectTimeoutSecs <= 0 {
		cfg.SOCKSConnectTimeoutSecs = 120.0
	}

	if cfg.DNSFragmentAssemblyTimeoutSecs <= 0 {
		cfg.DNSFragmentAssemblyTimeoutSecs = 300.0
	}

	cfg.StreamSetupAckTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.StreamSetupAckTTLSeconds, 400.0), 1.0, 86400.0)
	cfg.StreamResultPacketTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.StreamResultPacketTTLSeconds, 300.0), 1.0, 86400.0)
	cfg.StreamFailurePacketTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.StreamFailurePacketTTLSeconds, 120.0), 1.0, 86400.0)

	if cfg.DNSCacheMaxRecords < 1 {
		cfg.DNSCacheMaxRecords = 50000
	}

	if cfg.DNSCacheTTLSeconds <= 0 {
		cfg.DNSCacheTTLSeconds = 3600.0
	}

	if cfg.ForwardPort < 0 || cfg.ForwardPort > 65535 {
		return cfg, fmt.Errorf("invalid FORWARD_PORT: %d", cfg.ForwardPort)
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

	if cfg.UseExternalSOCKS5 {
		if cfg.ForwardIP == "" {
			return cfg, fmt.Errorf("USE_EXTERNAL_SOCKS5 requires FORWARD_IP")
		}
		if cfg.ForwardPort <= 0 {
			return cfg, fmt.Errorf("USE_EXTERNAL_SOCKS5 requires a valid FORWARD_PORT")
		}
	}

	if cfg.MinVPNLabelLength <= 0 {
		cfg.MinVPNLabelLength = 3
	}

	cfg.SupportedUploadCompressionTypes = normalizeCompressionTypeList(cfg.SupportedUploadCompressionTypes)
	cfg.SupportedDownloadCompressionTypes = normalizeCompressionTypeList(cfg.SupportedDownloadCompressionTypes)

	if cfg.DataEncryptionMethod < 0 || cfg.DataEncryptionMethod > 5 {
		cfg.DataEncryptionMethod = 1
	}

	if cfg.EncryptionKeyFile == "" {
		cfg.EncryptionKeyFile = "encrypt_key.txt"
	}

	if cfg.LogLevel == "" {
		cfg.LogLevel = "INFO"
	}

	cfg.ARQWindowSize = clampInt(defaultIntBelow(cfg.ARQWindowSize, 1, 800), 1, 8000)
	cfg.ARQInitialRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQInitialRTOSeconds, 0.5), 0.01, 60.0)
	cfg.ARQMaxRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQMaxRTOSeconds, 3.0), cfg.ARQInitialRTOSeconds, 120.0)
	cfg.ARQControlInitialRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQControlInitialRTOSeconds, 0.5), 0.01, 60.0)
	cfg.ARQControlMaxRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQControlMaxRTOSeconds, 2.0), cfg.ARQControlInitialRTOSeconds, 120.0)
	cfg.ARQMaxControlRetries = clampInt(defaultIntBelow(cfg.ARQMaxControlRetries, 1, 128), 1, 5000)
	cfg.ARQInactivityTimeoutSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQInactivityTimeoutSeconds, 1800.0), 10.0, 86400.0)
	cfg.ARQDataPacketTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQDataPacketTTLSeconds, 2400.0), 10.0, 86400.0)
	cfg.ARQControlPacketTTLSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQControlPacketTTLSeconds, 1200.0), 10.0, 86400.0)
	cfg.ARQMaxDataRetries = clampInt(defaultIntBelow(cfg.ARQMaxDataRetries, 1, 128), 1, 5000)
	dataNackGapCap := min(min(max(cfg.ARQWindowSize/8, 16), 128), cfg.ARQWindowSize-1)
	cfg.ARQDataNackMaxGap = clampInt(defaultIntBelow(cfg.ARQDataNackMaxGap, 0, 16), 0, dataNackGapCap)
	cfg.ARQDataNackInitialDelaySeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQDataNackInitialDelaySeconds, 0.3), 0.01, 30.0)
	cfg.ARQDataNackRepeatSeconds = clampFloat(defaultFloatAtMostZero(cfg.ARQDataNackRepeatSeconds, 0.8), 0.01, 30.0)
	cfg.ARQTerminalDrainTimeoutSec = clampFloat(defaultFloatAtMostZero(cfg.ARQTerminalDrainTimeoutSec, 120.0), 10.0, 3600.0)
	cfg.ARQTerminalAckWaitTimeoutSec = clampFloat(defaultFloatAtMostZero(cfg.ARQTerminalAckWaitTimeoutSec, 90.0), 5.0, 3600.0)
	cfg.MaxAllowedClientActiveSessions = clampInt(defaultIntBelow(cfg.MaxAllowedClientActiveSessions, 1, defaultServerConfig().MaxAllowedClientActiveSessions), 1, 255)
	cfg.MaxAllowedClientActiveStreams = clampInt(defaultIntBelow(cfg.MaxAllowedClientActiveStreams, 1, defaultServerConfig().MaxAllowedClientActiveStreams), 1, int(^uint16(0)))
	cfg.ClientMaxPacketDuplicationCount = clampInt(defaultIntBelow(cfg.ClientMaxPacketDuplicationCount, 0, defaultServerConfig().ClientMaxPacketDuplicationCount), 0, min(15, int(^uint8(0))))
	cfg.ClientMaxSetupDuplicationCount = clampInt(defaultIntBelow(cfg.ClientMaxSetupDuplicationCount, 0, defaultServerConfig().ClientMaxSetupDuplicationCount), 0, min(15, int(^uint8(0))))
	cfg.ClientMaxUploadMTU = clampInt(defaultIntBelow(cfg.ClientMaxUploadMTU, 1, defaultServerConfig().ClientMaxUploadMTU), 1, int(^uint8(0)))
	cfg.ClientMaxDownloadMTU = clampInt(defaultIntBelow(cfg.ClientMaxDownloadMTU, 1, defaultServerConfig().ClientMaxDownloadMTU), 1, int(^uint16(0)))
	cfg.ClientMaxRxTxWorkers = clampInt(defaultIntBelow(cfg.ClientMaxRxTxWorkers, 1, defaultServerConfig().ClientMaxRxTxWorkers), 1, int(^uint8(0)))
	cfg.ClientMinPingAggressiveInterval = clampFloat(defaultFloatAtMostZero(cfg.ClientMinPingAggressiveInterval, defaultServerConfig().ClientMinPingAggressiveInterval), 0.05, 1.0)
	cfg.ClientMaxPacketsPerBatch = clampInt(defaultIntBelow(cfg.ClientMaxPacketsPerBatch, 1, defaultServerConfig().ClientMaxPacketsPerBatch), 1, int(^uint8(0)))
	cfg.ClientMaxARQWindowSize = clampInt(defaultIntBelow(cfg.ClientMaxARQWindowSize, 1, defaultServerConfig().ClientMaxARQWindowSize), 1, min(8000, int(^uint16(0))))
	cfg.ClientMaxARQDataNackMaxGap = clampInt(defaultIntBelow(cfg.ClientMaxARQDataNackMaxGap, 0, defaultServerConfig().ClientMaxARQDataNackMaxGap), 0, min(255, int(^uint8(0))))
	cfg.ClientMinCompressionMinSize = clampInt(defaultIntBelow(cfg.ClientMinCompressionMinSize, 1, defaultServerConfig().ClientMinCompressionMinSize), 1, int(^uint16(0)))
	cfg.ClientMinARQInitialRTOSeconds = clampFloat(defaultFloatAtMostZero(cfg.ClientMinARQInitialRTOSeconds, defaultServerConfig().ClientMinARQInitialRTOSeconds), 0.05, 1.0)

	return cfg, nil
}

func (c ServerConfig) Address() string {
	return net.JoinHostPort(c.UDPHost, strconv.Itoa(c.UDPPort))
}

func (c ServerConfig) DropLogInterval() time.Duration {
	return time.Duration(c.DropLogIntervalSecs * float64(time.Second))
}

func (c ServerConfig) InvalidCookieWindow() time.Duration {
	return time.Duration(c.InvalidCookieWindowSecs * float64(time.Second))
}

func (c ServerConfig) SessionTimeout() time.Duration {
	return time.Duration(c.SessionTimeoutSecs * float64(time.Second))
}

func (c ServerConfig) SessionCleanupInterval() time.Duration {
	return time.Duration(c.SessionCleanupIntervalSecs * float64(time.Second))
}

func (c ServerConfig) ClosedSessionRetention() time.Duration {
	return time.Duration(c.ClosedSessionRetentionSecs * float64(time.Second))
}

func (c ServerConfig) DNSUpstreamTimeout() time.Duration {
	return time.Duration(c.DNSUpstreamTimeoutSecs * float64(time.Second))
}

func (c ServerConfig) DNSInflightWaitTimeout() time.Duration {
	return time.Duration(c.DNSInflightWaitTimeoutSecs * float64(time.Second))
}

func (c ServerConfig) SOCKSConnectTimeout() time.Duration {
	return time.Duration(c.SOCKSConnectTimeoutSecs * float64(time.Second))
}

func (c ServerConfig) DNSFragmentAssemblyTimeout() time.Duration {
	return time.Duration(c.DNSFragmentAssemblyTimeoutSecs * float64(time.Second))
}

func (c ServerConfig) SessionInitReuseTTL() time.Duration {
	return time.Duration(c.SessionInitReuseTTLSeconds * float64(time.Second))
}

func (c ServerConfig) RecentlyClosedStreamTTL() time.Duration {
	return time.Duration(c.RecentlyClosedStreamTTLSeconds * float64(time.Second))
}

func (c ServerConfig) TerminalStreamRetention() time.Duration {
	return time.Duration(c.TerminalStreamRetentionSeconds * float64(time.Second))
}

func (c ServerConfig) StreamSetupAckTTL() time.Duration {
	return time.Duration(c.StreamSetupAckTTLSeconds * float64(time.Second))
}

func (c ServerConfig) StreamResultPacketTTL() time.Duration {
	return time.Duration(c.StreamResultPacketTTLSeconds * float64(time.Second))
}

func (c ServerConfig) StreamFailurePacketTTL() time.Duration {
	return time.Duration(c.StreamFailurePacketTTLSeconds * float64(time.Second))
}

func (c ServerConfig) EffectiveUDPReaders() int {
	recommended := min(max(runtime.NumCPU()/2, 1), 8)
	if c.ProtocolType == "SOCKS5" && runtime.NumCPU() >= 4 && recommended < 2 {
		recommended = 2
	}

	if c.MaxConcurrentRequests >= 32768 && runtime.NumCPU() >= 4 && recommended < 4 {
		recommended = 4
	}

	return clampInt(max(c.UDPReaders, recommended), 1, 32)
}

func (c ServerConfig) EffectiveDNSRequestWorkers() int {
	recommended := min(max(runtime.NumCPU(), 2), 24)
	if c.ProtocolType == "SOCKS5" && runtime.NumCPU() >= 4 && recommended < 4 {
		recommended = 4
	}

	readerTarget := c.EffectiveUDPReaders() + 1
	if runtime.NumCPU() >= 4 {
		readerTarget = c.EffectiveUDPReaders() * 2
	}

	if recommended < readerTarget {
		recommended = readerTarget
	}

	return clampInt(max(c.DNSRequestWorkers, recommended), 1, 256)
}

func (c ServerConfig) EffectiveDeferredSessionWorkers() int {
	recommended := min(max(runtime.NumCPU()/2, 2), 16)
	if c.ProtocolType == "SOCKS5" && recommended < 4 {
		recommended = 4
	}
	return clampInt(max(c.DeferredSessionWorkers, recommended), 0, 256)
}

func (c ServerConfig) EffectiveDeferredSessionQueueLimit() int {
	recommended := clampInt(max(c.EffectiveDeferredSessionWorkers()*512, c.EffectiveMaxPacketsPerBatch()*128), 256, 16384)
	return clampInt(max(c.DeferredSessionQueueLimit, recommended), 256, 32768)
}

func (c ServerConfig) EffectiveMaxConcurrentRequests() int {
	recommended := max(c.EffectiveUDPReaders()*c.EffectiveDNSRequestWorkers()*512, 4096)
	return clampInt(max(c.MaxConcurrentRequests, recommended), 1024, 131072)
}

func (c ServerConfig) EffectiveMaxPacketsPerBatch() int {
	recommended := 5
	switch {
	case c.ARQWindowSize > 3000:
		recommended = 14
	case c.ARQWindowSize > 1500:
		recommended = 12
	case c.ARQWindowSize > 1024:
		recommended = 10
	}
	return clampInt(max(c.MaxPacketsPerBatch, recommended), 1, 64)
}

func (c ServerConfig) EffectiveDNSCacheMaxRecords() int {
	recommended := clampInt(max(c.EffectiveMaxConcurrentRequests()*2, 2000), 2000, 200000)
	return clampInt(max(c.DNSCacheMaxRecords, recommended), 1, 500000)
}

func (c ServerConfig) EffectiveSessionOrphanQueueInitialCap() int {
	recommended := c.EffectiveMaxPacketsPerBatch()*4 + c.EffectiveDeferredSessionWorkers()*16 + c.PacketBlockControlDuplication*16
	return clampInt(recommended, 32, 2048)
}

func (c ServerConfig) EffectiveStreamQueueInitialCapacity() int {
	recommended := max(c.ARQWindowSize/8, c.EffectiveMaxPacketsPerBatch()*8)
	if c.PacketBlockControlDuplication > 1 {
		recommended += c.PacketBlockControlDuplication * 4
	}
	return clampInt(recommended, 32, 2048)
}

func (c ServerConfig) EffectiveDNSFragmentStoreCapacity() int {
	recommended := c.EffectiveMaxConcurrentRequests()/32 + c.EffectiveDNSRequestWorkers()*16
	return clampInt(recommended, 64, 8192)
}

func (c ServerConfig) EffectiveSOCKS5FragmentStoreCapacity() int {
	recommended := c.EffectiveMaxConcurrentRequests()/16 + c.EffectiveDeferredSessionWorkers()*32
	return clampInt(recommended, 64, 8192)
}

func (c ServerConfig) EncryptionKeyPath() string {
	if c.EncryptionKeyFile == "" {
		return filepath.Join(c.ConfigDir, "encrypt_key.txt")
	}
	if filepath.IsAbs(c.EncryptionKeyFile) {
		return c.EncryptionKeyFile
	}
	return filepath.Join(c.ConfigDir, c.EncryptionKeyFile)
}

func normalizeCompressionTypeList(values []int) []int {
	if len(values) == 0 {
		return []int{0}
	}

	seen := [4]bool{}
	out := make([]int, 0, len(values))
	for _, value := range values {
		if value < 0 || value > 3 || seen[value] || !compression.IsTypeAvailable(uint8(value)) {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	if len(out) == 0 {
		return []int{0}
	}
	return out
}

func applyServerConfigOverrideValues(cfg *ServerConfig, values map[string]any) error {
	if cfg == nil || len(values) == 0 {
		return nil
	}

	elem := reflect.ValueOf(cfg).Elem()
	typ := elem.Type()
	for fieldName, rawValue := range values {
		field, ok := typ.FieldByName(fieldName)
		if !ok {
			return fmt.Errorf("unknown server config override field: %s", fieldName)
		}
		value := elem.FieldByName(fieldName)
		if !value.CanSet() {
			return fmt.Errorf("server config override field is not settable: %s", field.Name)
		}
		if err := assignServerConfigOverrideValue(value, rawValue, field.Name); err != nil {
			return err
		}
	}
	return nil
}

func assignServerConfigOverrideValue(target reflect.Value, rawValue any, fieldName string) error {
	if !target.IsValid() {
		return fmt.Errorf("invalid server config override target: %s", fieldName)
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
		switch target.Type().Elem().Kind() {
		case reflect.String:
			v, ok := rawValue.([]string)
			if !ok {
				return fmt.Errorf("invalid string slice override for %s", fieldName)
			}
			target.Set(reflect.ValueOf(append([]string(nil), v...)))
			return nil
		case reflect.Int:
			v, ok := rawValue.([]int)
			if !ok {
				return fmt.Errorf("invalid int slice override for %s", fieldName)
			}
			target.Set(reflect.ValueOf(append([]int(nil), v...)))
			return nil
		}
	}

	return fmt.Errorf("unsupported server config override type for %s", fieldName)
}

func NewServerConfigFlagBinder(fs *flag.FlagSet) (*ServerConfigFlagBinder, error) {
	if fs == nil {
		return nil, fmt.Errorf("flag set is required")
	}

	binder := &ServerConfigFlagBinder{
		values:      defaultServerConfig(),
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
			fs.Var(newServerConfigStringFlag(target.Addr().Interface().(*string), binder, field.Name), flagName, usage)
		case reflect.Bool:
			fs.Var(newServerConfigBoolFlag(target.Addr().Interface().(*bool), binder, field.Name), flagName, usage)
		case reflect.Int:
			fs.Var(newServerConfigIntFlag(target.Addr().Interface().(*int), binder, field.Name), flagName, usage)
		case reflect.Float64:
			fs.Var(newServerConfigFloatFlag(target.Addr().Interface().(*float64), binder, field.Name), flagName, usage)
		case reflect.Slice:
			switch target.Type().Elem().Kind() {
			case reflect.String:
				fs.Var(newServerConfigStringSliceFlag(target.Addr().Interface().(*[]string), binder, field.Name), flagName, usage+" (comma-separated)")
			case reflect.Int:
				fs.Var(newServerConfigIntSliceFlag(target.Addr().Interface().(*[]int), binder, field.Name), flagName, usage+" (comma-separated)")
			}
		}
	}

	return binder, nil
}

func (b *ServerConfigFlagBinder) Overrides() ServerConfigOverrides {
	overrides := ServerConfigOverrides{
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
			switch field.Type().Elem().Kind() {
			case reflect.String:
				src := field.Interface().([]string)
				overrides.Values[fieldName] = append([]string(nil), src...)
			case reflect.Int:
				src := field.Interface().([]int)
				overrides.Values[fieldName] = append([]int(nil), src...)
			}
		}
	}

	return overrides
}

func (b *ServerConfigFlagBinder) markSet(fieldName string) {
	if b == nil || fieldName == "" {
		return
	}
	b.setFields[fieldName] = struct{}{}
}

type serverConfigStringFlag struct {
	target    *string
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigStringFlag(target *string, binder *ServerConfigFlagBinder, fieldName string) *serverConfigStringFlag {
	return &serverConfigStringFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigStringFlag) String() string {
	if f == nil || f.target == nil {
		return ""
	}
	return *f.target
}

func (f *serverConfigStringFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	*f.target = value
	f.binder.markSet(f.fieldName)
	return nil
}

type serverConfigBoolFlag struct {
	target    *bool
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigBoolFlag(target *bool, binder *ServerConfigFlagBinder, fieldName string) *serverConfigBoolFlag {
	return &serverConfigBoolFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigBoolFlag) String() string {
	if f == nil || f.target == nil {
		return "false"
	}
	return strconv.FormatBool(*f.target)
}

func (f *serverConfigBoolFlag) Set(value string) error {
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

func (f *serverConfigBoolFlag) IsBoolFlag() bool { return true }

type serverConfigIntFlag struct {
	target    *int
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigIntFlag(target *int, binder *ServerConfigFlagBinder, fieldName string) *serverConfigIntFlag {
	return &serverConfigIntFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigIntFlag) String() string {
	if f == nil || f.target == nil {
		return "0"
	}
	return strconv.Itoa(*f.target)
}

func (f *serverConfigIntFlag) Set(value string) error {
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

type serverConfigFloatFlag struct {
	target    *float64
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigFloatFlag(target *float64, binder *ServerConfigFlagBinder, fieldName string) *serverConfigFloatFlag {
	return &serverConfigFloatFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigFloatFlag) String() string {
	if f == nil || f.target == nil {
		return "0"
	}
	return strconv.FormatFloat(*f.target, 'f', -1, 64)
}

func (f *serverConfigFloatFlag) Set(value string) error {
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

type serverConfigStringSliceFlag struct {
	target    *[]string
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigStringSliceFlag(target *[]string, binder *ServerConfigFlagBinder, fieldName string) *serverConfigStringSliceFlag {
	return &serverConfigStringSliceFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigStringSliceFlag) String() string {
	if f == nil || f.target == nil {
		return ""
	}
	return strings.Join(*f.target, ",")
}

func (f *serverConfigStringSliceFlag) Set(value string) error {
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

type serverConfigIntSliceFlag struct {
	target    *[]int
	binder    *ServerConfigFlagBinder
	fieldName string
}

func newServerConfigIntSliceFlag(target *[]int, binder *ServerConfigFlagBinder, fieldName string) *serverConfigIntSliceFlag {
	return &serverConfigIntSliceFlag{target: target, binder: binder, fieldName: fieldName}
}

func (f *serverConfigIntSliceFlag) String() string {
	if f == nil || f.target == nil || len(*f.target) == 0 {
		return ""
	}
	parts := make([]string, 0, len(*f.target))
	for _, item := range *f.target {
		parts = append(parts, strconv.Itoa(item))
	}
	return strings.Join(parts, ",")
}

func (f *serverConfigIntSliceFlag) Set(value string) error {
	if f == nil || f.target == nil {
		return nil
	}
	parts := strings.Split(value, ",")
	items := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		parsed, err := strconv.Atoi(part)
		if err != nil {
			return err
		}
		items = append(items, parsed)
	}
	*f.target = items
	f.binder.markSet(f.fieldName)
	return nil
}
