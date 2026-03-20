// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/arq"
	"masterdnsvpn-go/internal/compression"
	"masterdnsvpn-go/internal/config"
	dnsCache "masterdnsvpn-go/internal/dnscache"
	Enums "masterdnsvpn-go/internal/enums"
	fragmentStore "masterdnsvpn-go/internal/fragmentstore"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

type Client struct {
	cfg      config.ClientConfig
	log      *logger.Logger
	codec    *security.Codec
	balancer *Balancer
	now      func() time.Time

	connections            []Connection
	connectionsByKey       map[string]int
	localDNSCache          *dnsCache.Store
	dnsResponses           *fragmentStore.Store[clientDNSFragmentKey]
	localDNSCachePath      string
	localDNSCachePersist   bool
	localDNSCacheFlushTick time.Duration
	localDNSFragTTL        time.Duration
	localDNSCacheLoadOnce  sync.Once
	localDNSCacheFlushOnce sync.Once

	successMTUChecks          bool
	sessionReady              bool
	sessionID                 uint8
	sessionCookie             uint8
	responseMode              uint8
	uploadCompression         uint8
	downloadCompression       uint8
	enqueueSeq                uint64
	mainSequence              uint16
	lastStreamID              uint16
	syncedUploadMTU           int
	syncedDownloadMTU         int
	syncedUploadChars         int
	safeUploadMTU             int
	maxPackedBlocks           int
	mtuCryptoOverhead         int
	mtuSuccessOutputPath      string
	mtuUsageSeparatorWritten  bool
	mtuSaveToFile             bool
	mtuServersFileName        string
	mtuServersFileFormat      string
	mtuUsingSeparatorText     string
	mtuRemovedServerLogFormat string
	mtuAddedServerLogFormat   string
	mtuOutputMu               sync.Mutex

	exchangeQueryFn                       func(Connection, []byte, time.Duration) ([]byte, error)
	sendOneWayPacketFn                    func(Connection, []byte, time.Time) error
	fragmentLimits                        sync.Map
	stream0Runtime                        *stream0Runtime
	streamsMu                             sync.RWMutex
	streams                               map[uint16]*clientStream
	closedStreams                         map[uint16]int64
	closedStreamsQueue                    []uint16
	mtuTestRetries                        int
	mtuTestTimeout                        time.Duration
	packetDuplicationCount                int
	setupPacketDuplicationCount           int
	streamResolverFailoverResendThreshold int
	streamResolverFailoverCooldown        time.Duration
	streamTXWindow                        int
	streamTXQueueLimit                    int
	streamTXMaxRetries                    int
	streamTXTTL                           time.Duration
	resolverHealthMu                      sync.Mutex
	resolverHealth                        map[string]*resolverHealthState
	resolverRecheck                       map[string]resolverRecheckState
	runtimeDisabled                       map[string]resolverDisabledState
	healthRuntimeRun                      bool
	recheckConnectionFn                   func(*Connection) bool

	reconnectSignal     chan struct{}
	reconnectPending    atomic.Bool
	initStateMu         sync.Mutex
	sessionInitPayload  []byte
	sessionInitVerify   [4]byte
	sessionInitBase64   bool
	sessionInitReady    bool
	sessionInitCursor   int
	sessionInitBusyUnix atomic.Int64

	resolverConnsMu sync.Mutex
	resolverConns   map[string]chan *net.UDPConn

	udpBufferPool sync.Pool
	mtuProbeCounter atomic.Uint64
}

const (
	clientClosedStreamRecordTTL = 45 * time.Second
	clientClosedStreamRecordCap = 2000
)

type Connection struct {
	Domain           string
	Resolver         string
	ResolverPort     int
	ResolverLabel    string
	Key              string
	IsValid          bool
	UploadMTUBytes   int
	UploadMTUChars   int
	DownloadMTUBytes int
}

type clientStream struct {
	mu                   sync.Mutex
	ID                   uint16
	Conn                 net.Conn
	NextSequence         uint16
	LocalFinSent         bool
	RemoteFinRecv        bool
	ResetSent            bool
	Closed               bool
	LastActivityAt       time.Time
	InboundDataSeq       uint16
	InboundDataSet       bool
	RemoteFinSeq         uint16
	RemoteFinSet         bool
	PreferredServerKey   string
	ResolverResendStreak int
	LastResolverFailover time.Time
	TXQueue              []clientStreamTXPacket
	TXInFlight           []clientStreamTXPacket
	TXWake               chan struct{}
	StopCh               chan struct{}
	stopOnce             sync.Once
	retryBase            time.Duration
	srtt                 time.Duration
	rttVar               time.Duration
}

type clientStreamTXPacket struct {
	PacketType  uint8
	SequenceNum uint16
	Payload     []byte
	CreatedAt   time.Time
	LastSentAt  time.Time
	RetryDelay  time.Duration
	RetryAt     time.Time
	RetryCount  int
	Scheduled   bool
}

func Bootstrap(configPath string) (*Client, error) {
	cfg, err := config.LoadClientConfig(configPath)
	if err != nil {
		return nil, err
	}

	log := logger.New("MasterDnsVPN Client", cfg.LogLevel)
	codec, err := security.NewCodec(cfg.DataEncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("client codec setup failed: %w", err)
	}

	c := New(cfg, log, codec)
	c.BuildConnectionMap()
	c.ensureLocalDNSCacheLoaded()
	return c, nil
}

func New(cfg config.ClientConfig, log *logger.Logger, codec *security.Codec) *Client {
	removedServerLogFormat := strings.TrimSpace(cfg.MTURemovedServerLogFormat)
	if removedServerLogFormat == "" {
		removedServerLogFormat = strings.TrimSpace(cfg.ResolverRemovedServerLogFormat)
	}
	addedServerLogFormat := strings.TrimSpace(cfg.MTUAddedServerLogFormat)
	if addedServerLogFormat == "" {
		addedServerLogFormat = strings.TrimSpace(cfg.ResolverAddedServerLogFormat)
	}

	c := &Client{
		cfg:              cfg,
		log:              log,
		codec:            codec,
		balancer:         NewBalancer(cfg.ResolverBalancingStrategy),
		connectionsByKey: make(map[string]int, len(cfg.Domains)*len(cfg.Resolvers)),
		now:              time.Now,
		localDNSCache: dnsCache.New(
			cfg.LocalDNSCacheMaxRecords,
			time.Duration(cfg.LocalDNSCacheTTLSeconds*float64(time.Second)),
			time.Duration(cfg.LocalDNSPendingTimeoutSec*float64(time.Second)),
		),
		dnsResponses:         fragmentStore.New[clientDNSFragmentKey](32),
		localDNSCachePath:    cfg.LocalDNSCachePath(),
		localDNSCachePersist: cfg.LocalDNSCachePersist,
		localDNSCacheFlushTick: time.Duration(
			cfg.LocalDNSCacheFlushSec * float64(time.Second),
		),
		localDNSFragTTL:                       time.Duration(cfg.LocalDNSFragmentTimeoutSec * float64(time.Second)),
		streams:                               make(map[uint16]*clientStream, 16),
		closedStreams:                         make(map[uint16]int64, 16),
		closedStreamsQueue:                    make([]uint16, 0, 16),
		mtuTestRetries:                        cfg.MTUTestRetries,
		mtuTestTimeout:                        time.Duration(cfg.MTUTestTimeout * float64(time.Second)),
		packetDuplicationCount:                cfg.PacketDuplicationCount,
		setupPacketDuplicationCount:           cfg.SetupPacketDuplicationCount,
		streamResolverFailoverResendThreshold: cfg.StreamResolverFailoverResendThreshold,
		streamResolverFailoverCooldown:        time.Duration(cfg.StreamResolverFailoverCooldownSec * float64(time.Second)),
		mtuCryptoOverhead:                     mtuCryptoOverhead(cfg.DataEncryptionMethod),
		mtuSaveToFile:                         cfg.SaveMTUServersToFile,
		mtuServersFileName:                    strings.TrimSpace(cfg.MTUServersFileName),
		mtuServersFileFormat: strings.TrimSpace(
			cfg.MTUServersFileFormat,
		),
		mtuUsingSeparatorText: strings.TrimSpace(
			cfg.MTUUsingSeparatorText,
		),
		mtuRemovedServerLogFormat: removedServerLogFormat,
		mtuAddedServerLogFormat:   addedServerLogFormat,
		streamTXWindow:            cfg.StreamTXWindow,
		streamTXQueueLimit:        cfg.StreamTXQueueLimit,
		streamTXMaxRetries:        cfg.StreamTXMaxRetries,
		streamTXTTL:               time.Duration(cfg.StreamTXTTLSeconds * float64(time.Second)),
		resolverHealth:            make(map[string]*resolverHealthState, len(cfg.Domains)*len(cfg.Resolvers)),
		resolverRecheck:           make(map[string]resolverRecheckState, len(cfg.Domains)*len(cfg.Resolvers)),
		runtimeDisabled:           make(map[string]resolverDisabledState, len(cfg.Domains)*len(cfg.Resolvers)),
		reconnectSignal:           make(chan struct{}, 1),
		resolverConns:             make(map[string]chan *net.UDPConn),
		udpBufferPool: sync.Pool{
			New: func() any {
				return make([]byte, EDnsSafeUDPSize)
			},
		},
	}

	if c.localDNSCacheFlushTick <= 0 {
		c.localDNSCacheFlushTick = time.Minute
	}

	if c.localDNSFragTTL <= 0 {
		c.localDNSFragTTL = 5 * time.Minute
	}

	if c.mtuTestRetries < 1 {
		c.mtuTestRetries = 1
	}

	if c.mtuTestTimeout <= 0 {
		c.mtuTestTimeout = time.Second
	}
	if c.packetDuplicationCount < 1 {
		c.packetDuplicationCount = 1
	}
	if c.setupPacketDuplicationCount < c.packetDuplicationCount {
		c.setupPacketDuplicationCount = c.packetDuplicationCount
	}
	if c.streamResolverFailoverResendThreshold < 1 {
		c.streamResolverFailoverResendThreshold = 1
	}
	if c.streamResolverFailoverCooldown <= 0 {
		c.streamResolverFailoverCooldown = time.Second
	}

	c.ResetRuntimeState(true)
	c.uploadCompression = uint8(cfg.UploadCompressionType)
	c.downloadCompression = uint8(cfg.DownloadCompressionType)
	c.maxPackedBlocks = 1
	c.stream0Runtime = newStream0Runtime(c)
	return c
}

func (c *Client) Config() config.ClientConfig {
	return c.cfg
}

func (c *Client) Logger() *logger.Logger {
	return c.log
}

func (c *Client) Codec() *security.Codec {
	return c.codec
}

func (c *Client) Balancer() *Balancer {
	return c.balancer
}

func (c *Client) LocalDNSCache() *dnsCache.Store {
	return c.localDNSCache
}

func (c *Client) Connections() []Connection {
	return c.connections
}

func (c *Client) SyncedUploadMTU() int {
	return c.syncedUploadMTU
}

func (c *Client) SyncedDownloadMTU() int {
	return c.syncedDownloadMTU
}

func (c *Client) SyncedUploadChars() int {
	return c.syncedUploadChars
}

func (c *Client) SafeUploadMTU() int {
	if c == nil {
		return 0
	}
	if c.safeUploadMTU > 0 {
		return c.safeUploadMTU
	}
	return c.syncedUploadMTU
}

func (c *Client) SessionID() uint8 {
	return c.sessionID
}

func (c *Client) SessionReady() bool {
	return c != nil && c.sessionReady
}

func (c *Client) SessionCookie() uint8 {
	return c.sessionCookie
}

func (c *Client) MaxPackedBlocks() int {
	if c.maxPackedBlocks < 1 {
		return 1
	}
	return c.maxPackedBlocks
}

func (c *Client) ResetRuntimeState(resetSessionCookie bool) {
	c.enqueueSeq = 0
	c.mainSequence = 0
	c.lastStreamID = 0
	c.sessionReady = false
	c.sessionID = 0
	if resetSessionCookie {
		c.sessionCookie = 0
	}
	c.responseMode = 0
	c.maxPackedBlocks = 1
	c.fragmentLimits = sync.Map{}
	c.dnsResponses = fragmentStore.New[clientDNSFragmentKey](32)
	if c.localDNSCache != nil {
		c.localDNSCache.ClearPending()
	}
	if c.stream0Runtime != nil {
		c.stream0Runtime.ResetForReconnect()
	}
	c.closeAllStreams()
	c.streamsMu.Lock()
	c.streams = make(map[uint16]*clientStream, 16)
	c.closedStreams = make(map[uint16]int64, 16)
	c.closedStreamsQueue = make([]uint16, 0, 16)
	c.streamsMu.Unlock()
	c.resolverHealthMu.Lock()
	c.resolverHealth = make(map[string]*resolverHealthState, len(c.connections))
	c.resolverRecheck = make(map[string]resolverRecheckState, len(c.connections))
	c.runtimeDisabled = make(map[string]resolverDisabledState, len(c.connections))
	c.healthRuntimeRun = false
	c.resolverHealthMu.Unlock()
	c.clearSessionInitBusyUntil()

	c.resolverConnsMu.Lock()
	for key, pool := range c.resolverConns {
		close(pool)
		for conn := range pool {
			if conn != nil {
				_ = conn.Close()
			}
		}
		delete(c.resolverConns, key)
	}
	c.resolverConnsMu.Unlock()
}

func (c *Client) updateMaxPackedBlocks() {
	c.maxPackedBlocks = arq.ComputeClientPackedControlBlockLimit(
		c.syncedUploadMTU,
		c.cfg.MaxPacketsPerBatch,
	)
	if c.stream0Runtime != nil {
		c.stream0Runtime.SetMaxPackedBlocks(c.maxPackedBlocks)
	}
}

func (c *Client) applySyncedMTUState(uploadMTU int, downloadMTU int, uploadChars int) {
	if c == nil {
		return
	}
	c.successMTUChecks = uploadMTU > 0 && downloadMTU > 0
	c.syncedUploadMTU = uploadMTU
	c.syncedDownloadMTU = downloadMTU
	c.syncedUploadChars = uploadChars
	c.safeUploadMTU = computeSafeUploadMTU(uploadMTU, c.mtuCryptoOverhead)
	c.updateMaxPackedBlocks()
}

func (c *Client) HasSuccessfulMTUChecks() bool {
	return c != nil && c.successMTUChecks
}

func (c *Client) MarkMTUChecksStale() {
	if c == nil {
		return
	}
	c.successMTUChecks = false
}

func (c *Client) applySessionCompressionPolicy() {
	if c == nil {
		return
	}

	minSize := c.cfg.CompressionMinSize
	if minSize <= 0 {
		minSize = compression.DefaultMinSize
	}

	uploadCompression := compression.NormalizeAvailableType(c.uploadCompression)
	downloadCompression := compression.NormalizeAvailableType(c.downloadCompression)

	if c.syncedUploadMTU > 0 && c.syncedUploadMTU <= minSize {
		if uploadCompression != compression.TypeOff && c.log != nil {
			c.log.Infof(
				"\U0001F5DC <green>Session Compression Upload: <cyan>%s</cyan> (Disabled due to MTU: <cyan>%d</cyan>)</green>",
				compression.TypeName(uploadCompression),
				c.syncedUploadMTU,
			)
		}
		uploadCompression = compression.TypeOff
	}

	if c.syncedDownloadMTU > 0 && c.syncedDownloadMTU <= minSize {
		if downloadCompression != compression.TypeOff && c.log != nil {
			c.log.Infof(
				"\U0001F5DC <green>Session Compression Download: <cyan>%s</cyan> (Disabled due to MTU: <cyan>%d</cyan>)</green>",
				compression.TypeName(downloadCompression),
				c.syncedDownloadMTU,
			)
		}
		downloadCompression = compression.TypeOff
	}

	c.uploadCompression = uploadCompression
	c.downloadCompression = downloadCompression

	if c.log != nil {
		c.log.Infof(
			"\U0001F9E9 <green>Effective Compression Upload: <cyan>%s</cyan> Download: <cyan>%s</cyan></green>",
			compression.TypeName(c.uploadCompression),
			compression.TypeName(c.downloadCompression),
		)
	}
}

func (c *Client) BuildConnectionMap() {
	domains := c.cfg.Domains
	resolvers := c.cfg.Resolvers

	total := len(domains) * len(resolvers)
	if total <= 0 {
		c.connections = nil
		c.connectionsByKey = make(map[string]int)
		c.balancer.SetConnections(nil)
		return
	}

	connections := make([]Connection, 0, total)
	indexByKey := make(map[string]int, total)

	for _, domain := range domains {
		for _, resolver := range resolvers {
			label := formatResolverEndpoint(resolver.IP, resolver.Port)
			key := makeConnectionKey(resolver.IP, resolver.Port, domain)
			if _, exists := indexByKey[key]; exists {
				continue
			}

			indexByKey[key] = len(connections)
			connections = append(connections, Connection{
				Domain:        domain,
				Resolver:      resolver.IP,
				ResolverPort:  resolver.Port,
				ResolverLabel: label,
				Key:           key,
				IsValid:       true,
			})
		}
	}

	c.connections = connections
	c.connectionsByKey = indexByKey
	c.initResolverRecheckMeta()
	c.rebuildBalancer()
}

func (c *Client) GetConnectionByKey(serverKey string) (Connection, bool) {
	idx, ok := c.connectionIndexByKey(serverKey)
	if !ok || idx < 0 || idx >= len(c.connections) {
		return Connection{}, false
	}
	return c.connections[idx], true
}

func (c *Client) SetConnectionValidity(serverKey string, valid bool) bool {
	key := strings.TrimSpace(serverKey)
	idx, ok := c.connectionIndexByKey(key)
	if !ok || idx < 0 || idx >= len(c.connections) {
		return false
	}
	if c.connections[idx].IsValid == valid {
		return true
	}
	if !c.balancer.SetConnectionValidity(key, valid) {
		return false
	}
	return true
}

func (c *Client) GetBestConnection() (Connection, bool) {
	return c.balancer.GetBestConnection()
}

func (c *Client) GetUniqueConnections(requiredCount int) []Connection {
	return c.balancer.GetUniqueConnections(requiredCount)
}

func (c *Client) rebuildBalancer() {
	ptrs := make([]*Connection, 0, len(c.connections))
	for idx := range c.connections {
		ptrs = append(ptrs, &c.connections[idx])
	}
	c.balancer.SetConnections(ptrs)
}

func formatResolverEndpoint(resolver string, port int) string {
	if strings.IndexByte(resolver, ':') >= 0 && !strings.HasPrefix(resolver, "[") {
		return fmt.Sprintf("[%s]:%d", resolver, port)
	}
	return fmt.Sprintf("%s:%d", resolver, port)
}

func makeConnectionKey(resolver string, port int, domain string) string {
	return resolver + "|" + strconv.Itoa(port) + "|" + domain
}

func (c *Client) storeStream(stream *clientStream) {
	if c == nil || stream == nil {
		return
	}
	c.streamsMu.Lock()
	c.streams[stream.ID] = stream
	c.streamsMu.Unlock()
}

func (c *Client) getStream(streamID uint16) (*clientStream, bool) {
	if c == nil || streamID == 0 {
		return nil, false
	}
	c.streamsMu.RLock()
	defer c.streamsMu.RUnlock()
	stream, ok := c.streams[streamID]
	return stream, ok
}

func (c *Client) deleteStream(streamID uint16) {
	if c == nil || streamID == 0 {
		return
	}
	c.streamsMu.Lock()
	stream := c.streams[streamID]
	delete(c.streams, streamID)
	c.noteClosedStreamLocked(streamID, time.Now())
	c.streamsMu.Unlock()
	if stream != nil && stream.Conn != nil {
		stream.stopOnce.Do(func() {
			close(stream.StopCh)
		})
		_ = stream.Conn.Close()
	}
}

func (c *Client) closeAllStreams() {
	if c == nil {
		return
	}
	c.streamsMu.Lock()
	streams := c.streams
	c.streams = make(map[uint16]*clientStream, 16)
	c.closedStreams = make(map[uint16]int64, 16)
	c.streamsMu.Unlock()
	for _, stream := range streams {
		if stream == nil {
			continue
		}
		stream.stopOnce.Do(func() {
			close(stream.StopCh)
		})
		if stream.Conn != nil {
			_ = stream.Conn.Close()
		}
	}
}

func (c *Client) handleClosedStreamPacket(packet VpnProto.Packet, timeout time.Duration) (VpnProto.Packet, bool, error) {
	if c == nil || packet.StreamID == 0 || !c.isRecentlyClosedStream(packet.StreamID, time.Now()) {
		return VpnProto.Packet{}, false, nil
	}

	responsePacket := VpnProto.Packet{
		StreamID:       packet.StreamID,
		HasStreamID:    true,
		SequenceNum:    packet.SequenceNum,
		HasSequenceNum: packet.SequenceNum != 0,
	}

	outgoingType := uint8(0)
	switch packet.PacketType {
	case Enums.PACKET_STREAM_FIN:
		outgoingType = Enums.PACKET_STREAM_FIN_ACK
		responsePacket.PacketType = outgoingType
	case Enums.PACKET_STREAM_RST:
		outgoingType = Enums.PACKET_STREAM_RST_ACK
		responsePacket.PacketType = outgoingType
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND, Enums.PACKET_STREAM_DATA_ACK:
		outgoingType = Enums.PACKET_STREAM_RST
		responsePacket.PacketType = outgoingType
		responsePacket.SequenceNum = 0
		responsePacket.HasSequenceNum = false
	default:
		return VpnProto.Packet{}, false, nil
	}

	_ = c.sendClosedStreamOneWayPacket(outgoingType, packet.StreamID, responsePacket.SequenceNum, timeout)
	return responsePacket, true, nil
}

func (c *Client) sendClosedStreamOneWayPacket(packetType uint8, streamID uint16, sequenceNum uint16, timeout time.Duration) error {
	if c == nil || !c.SessionReady() {
		return nil
	}

	connections, err := c.selectTargetConnectionsForPacket(packetType, streamID)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(normalizeTimeout(timeout, defaultRuntimeTimeout))
	var firstErr error
	for _, connection := range connections {
		query, buildErr := c.buildStreamQuery(connection.Domain, packetType, streamID, sequenceNum, 0, 1, nil)
		if buildErr != nil {
			if firstErr == nil {
				firstErr = buildErr
			}
			continue
		}
		c.sendOneWaySessionPacket(connection, query, deadline)
	}
	return firstErr
}

func (c *Client) isRecentlyClosedStream(streamID uint16, now time.Time) bool {
	if c == nil || streamID == 0 {
		return false
	}

	c.streamsMu.RLock()
	closedAt, ok := c.closedStreams[streamID]
	c.streamsMu.RUnlock()
	if !ok {
		return false
	}
	return now.UnixNano()-closedAt <= clientClosedStreamRecordTTL.Nanoseconds()
}

func (c *Client) noteClosedStreamLocked(streamID uint16, now time.Time) {
	if c == nil || streamID == 0 {
		return
	}
	if c.closedStreams == nil {
		c.closedStreams = make(map[uint16]int64, 16)
		c.closedStreamsQueue = make([]uint16, 0, 16)
	}

	nowUnix := now.UnixNano()
	expiredBefore := nowUnix - clientClosedStreamRecordTTL.Nanoseconds()

	// O(1) Amortized cleanup using the queue
	for len(c.closedStreamsQueue) > 0 {
		oldestID := c.closedStreamsQueue[0]
		oldestAt, ok := c.closedStreams[oldestID]
		if !ok || oldestAt < expiredBefore || len(c.closedStreams) > clientClosedStreamRecordCap {
			delete(c.closedStreams, oldestID)
			c.closedStreamsQueue = c.closedStreamsQueue[1:]
			continue
		}
		break
	}

	c.closedStreams[streamID] = nowUnix
	c.closedStreamsQueue = append(c.closedStreamsQueue, streamID)
}

func (c *Client) activeStreamCount() int {
	if c == nil {
		return 0
	}
	c.streamsMu.RLock()
	defer c.streamsMu.RUnlock()
	return len(c.streams)
}

func (c *Client) connectionPtrByKey(serverKey string) *Connection {
	if c == nil {
		return nil
	}
	idx, ok := c.connectionIndexByKey(serverKey)
	if !ok || idx < 0 || idx >= len(c.connections) {
		return nil
	}
	return &c.connections[idx]
}

func (c *Client) connectionIndexByKey(serverKey string) (int, bool) {
	if c == nil {
		return 0, false
	}
	idx, ok := c.connectionsByKey[serverKey]
	return idx, ok
}

func (c *Client) startResolverHealthRuntime(ctx context.Context) {
	if c == nil {
		return
	}

	c.resolverHealthMu.Lock()
	if c.healthRuntimeRun {
		c.resolverHealthMu.Unlock()
		return
	}
	c.healthRuntimeRun = true
	c.resolverHealthMu.Unlock()

	go c.runResolverHealthLoop(ctx)
}
