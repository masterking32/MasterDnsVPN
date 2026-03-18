// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"masterdnsvpn-go/internal/compression"
	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/dnscache"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func TestBuildConnectionMap(t *testing.T) {
	cfg := config.ClientConfig{
		ProtocolType: "SOCKS5",
		Domains: []string{
			"a.example.com",
			"b.example.com",
		},
		Resolvers: []config.ResolverAddress{
			{IP: "8.8.8.8", Port: 53},
			{IP: "2001:4860:4860::8888", Port: 5353},
		},
	}

	c := New(cfg, nil, nil)
	c.BuildConnectionMap()

	if got, want := len(c.Connections()), 4; got != want {
		t.Fatalf("unexpected connection count: got=%d want=%d", got, want)
	}

	first := c.Connections()[0]
	if first.Domain == "" || first.Resolver == "" || first.Key == "" {
		t.Fatalf("connection fields should be populated: %+v", first)
	}
	if !first.IsValid {
		t.Fatalf("connections should start valid")
	}
	if first.Resolver == "2001:4860:4860::8888" && first.ResolverLabel != "[2001:4860:4860::8888]:5353" {
		t.Fatalf("unexpected ipv6 resolver label: got=%q", first.ResolverLabel)
	}
	if c.Balancer().ValidCount() != 4 {
		t.Fatalf("unexpected valid connection count: got=%d want=%d", c.Balancer().ValidCount(), 4)
	}
}

func TestResetRuntimeState(t *testing.T) {
	c := New(config.ClientConfig{}, nil, nil)
	c.sessionID = 11
	c.sessionCookie = 22
	c.enqueueSeq = 33

	c.ResetRuntimeState(false)
	if c.sessionID != 0 || c.enqueueSeq != 0 {
		t.Fatalf("reset should clear session id and enqueue seq: sid=%d enqueue=%d", c.sessionID, c.enqueueSeq)
	}
	if c.sessionCookie != 22 {
		t.Fatalf("reset without cookie reset should preserve session cookie: got=%d", c.sessionCookie)
	}

	c.ResetRuntimeState(true)
	if c.sessionCookie != 0 {
		t.Fatalf("reset with cookie reset should clear session cookie: got=%d", c.sessionCookie)
	}
}

func TestSetConnectionValidityKeepsClientAndBalancerInSync(t *testing.T) {
	cfg := config.ClientConfig{
		Domains: []string{"a.example.com"},
		Resolvers: []config.ResolverAddress{
			{IP: "8.8.8.8", Port: 53},
		},
	}

	c := New(cfg, nil, nil)
	c.BuildConnectionMap()
	key := c.Connections()[0].Key

	if !c.SetConnectionValidity(key, false) {
		t.Fatal("SetConnectionValidity returned false")
	}
	if c.Connections()[0].IsValid {
		t.Fatal("client connection validity was not updated")
	}
	if got := c.Balancer().ValidCount(); got != 0 {
		t.Fatalf("unexpected valid count after disable: got=%d want=0", got)
	}

	if !c.SetConnectionValidity(key, true) {
		t.Fatal("SetConnectionValidity returned false when re-enabling")
	}
	if !c.Connections()[0].IsValid {
		t.Fatal("client connection validity was not restored")
	}
	if got := c.Balancer().ValidCount(); got != 1 {
		t.Fatalf("unexpected valid count after enable: got=%d want=1", got)
	}
}

func TestBuildSessionInitPayloadLayout(t *testing.T) {
	c := New(config.ClientConfig{
		BaseEncodeData:          true,
		UploadCompressionType:   2,
		DownloadCompressionType: 1,
	}, nil, nil)
	c.syncedUploadMTU = 150
	c.syncedDownloadMTU = 200

	payload, useBase64, verifyCode, err := c.buildSessionInitPayload()
	if err != nil {
		t.Fatalf("buildSessionInitPayload returned error: %v", err)
	}
	if !useBase64 {
		t.Fatal("expected base64 response mode")
	}
	if len(payload) != 10 {
		t.Fatalf("unexpected payload len: got=%d want=10", len(payload))
	}
	if payload[0] != 1 {
		t.Fatalf("unexpected response mode byte: got=%d want=1", payload[0])
	}
	if payload[1] != 0x21 {
		t.Fatalf("unexpected compression pair: got=%#x want=%#x", payload[1], 0x21)
	}
	if got := int(binary.BigEndian.Uint16(payload[2:4])); got != 150 {
		t.Fatalf("unexpected upload mtu: got=%d want=150", got)
	}
	if got := int(binary.BigEndian.Uint16(payload[4:6])); got != 200 {
		t.Fatalf("unexpected download mtu: got=%d want=200", got)
	}
	if string(payload[6:10]) != string(verifyCode[:]) {
		t.Fatalf("unexpected verify code bytes: got=%v want=%v", payload[6:10], verifyCode)
	}
}

func TestValidateServerPacketAllowsPreSessionResponses(t *testing.T) {
	c := New(config.ClientConfig{}, nil, nil)
	if !c.validateServerPacket(VpnProto.Packet{PacketType: Enums.PACKET_MTU_UP_RES}) {
		t.Fatal("pre-session mtu-up response should be accepted")
	}
	if !c.validateServerPacket(VpnProto.Packet{PacketType: Enums.PACKET_MTU_DOWN_RES}) {
		t.Fatal("pre-session mtu-down response should be accepted")
	}
	if !c.validateServerPacket(VpnProto.Packet{PacketType: Enums.PACKET_SESSION_ACCEPT}) {
		t.Fatal("pre-session session-accept should be accepted")
	}
}

func TestValidateServerPacketRequiresMatchingSessionCookie(t *testing.T) {
	c := New(config.ClientConfig{}, nil, nil)
	c.sessionID = 7
	c.sessionCookie = 55

	valid := VpnProto.Packet{
		SessionID:     7,
		SessionCookie: 55,
		PacketType:    Enums.PACKET_PONG,
	}
	if !c.validateServerPacket(valid) {
		t.Fatal("matching session packet should be accepted")
	}

	wrongCookie := valid
	wrongCookie.SessionCookie = 66
	if c.validateServerPacket(wrongCookie) {
		t.Fatal("packet with wrong session cookie should be rejected")
	}

	wrongSession := valid
	wrongSession.SessionID = 8
	if c.validateServerPacket(wrongSession) {
		t.Fatal("packet with wrong session id should be rejected")
	}
}

func TestApplySessionCompressionPolicyDisablesSmallMTUDirections(t *testing.T) {
	c := New(config.ClientConfig{
		CompressionMinSize: compression.DefaultMinSize,
	}, nil, nil)
	c.syncedUploadMTU = compression.DefaultMinSize
	c.syncedDownloadMTU = compression.DefaultMinSize - 1
	c.uploadCompression = compression.TypeZLIB
	c.downloadCompression = compression.TypeZLIB

	c.applySessionCompressionPolicy()

	if c.uploadCompression != compression.TypeOff {
		t.Fatalf("upload compression should be disabled, got=%d", c.uploadCompression)
	}
	if c.downloadCompression != compression.TypeOff {
		t.Fatalf("download compression should be disabled, got=%d", c.downloadCompression)
	}
}

func TestApplySessionCompressionPolicyKeepsLargeMTUDirections(t *testing.T) {
	c := New(config.ClientConfig{
		CompressionMinSize: compression.DefaultMinSize,
	}, nil, nil)
	c.syncedUploadMTU = compression.DefaultMinSize + 1
	c.syncedDownloadMTU = compression.DefaultMinSize + 50
	c.uploadCompression = compression.TypeZLIB
	c.downloadCompression = compression.TypeOff

	c.applySessionCompressionPolicy()

	if c.uploadCompression != compression.TypeZLIB {
		t.Fatalf("upload compression should stay enabled, got=%d", c.uploadCompression)
	}
	if c.downloadCompression != compression.TypeOff {
		t.Fatalf("download compression should stay off, got=%d", c.downloadCompression)
	}
}

func TestNewKeepsLocalDNSDefaults(t *testing.T) {
	c := New(config.ClientConfig{
		LocalDNSEnabled:   true,
		LocalDNSIP:        "127.0.0.1",
		LocalDNSPort:      5353,
		LocalDNSWorkers:   2,
		LocalDNSQueueSize: 512,
	}, nil, nil)

	if !c.cfg.LocalDNSEnabled {
		t.Fatal("expected local dns listener to stay enabled in config")
	}
	if c.cfg.LocalDNSIP != "127.0.0.1" || c.cfg.LocalDNSPort != 5353 {
		t.Fatalf("unexpected local dns bind config: %s:%d", c.cfg.LocalDNSIP, c.cfg.LocalDNSPort)
	}
}

func TestHandleDNSQueryPacketCreatesPendingEntry(t *testing.T) {
	c := New(config.ClientConfig{
		LocalDNSCacheMaxRecords:   8,
		LocalDNSCacheTTLSeconds:   60,
		LocalDNSPendingTimeoutSec: 30,
	}, nil, nil)
	now := time.Unix(1700000000, 0)
	c.now = func() time.Time { return now }

	query := buildClientTestDNSQuery(0x1234, "example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSQ_CLASS_IN)
	response, dispatch := c.handleDNSQueryPacket(query)
	if dispatch == nil {
		t.Fatal("expected pending dispatch request")
	}
	if len(response) == 0 {
		t.Fatal("expected temporary servfail response")
	}
	cacheKey := dnscache.BuildKey("example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSQ_CLASS_IN)
	entry, ok := c.LocalDNSCache().Snapshot(cacheKey)
	if !ok {
		t.Fatal("expected cache entry to be created")
	}
	if entry.Status != dnscache.StatusPending {
		t.Fatalf("expected pending cache status, got=%d", entry.Status)
	}
}

func TestHandleDNSQueryPacketUsesReadyCache(t *testing.T) {
	c := New(config.ClientConfig{
		LocalDNSCacheMaxRecords:   8,
		LocalDNSCacheTTLSeconds:   60,
		LocalDNSPendingTimeoutSec: 30,
	}, nil, nil)
	now := time.Unix(1700000000, 0)
	c.now = func() time.Time { return now }

	query := buildClientTestDNSQuery(0x1234, "example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSQ_CLASS_IN)
	cacheKey := dnscache.BuildKey("example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSQ_CLASS_IN)
	rawResponse := []byte{
		0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	rawResponse = append(rawResponse, encodeClientTestDNSName("example.com")...)
	rawResponse = append(rawResponse, 0x00, byte(Enums.DNS_RECORD_TYPE_A), 0x00, byte(Enums.DNSQ_CLASS_IN))
	c.LocalDNSCache().SetReady(cacheKey, "example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSQ_CLASS_IN, rawResponse, now)

	response, dispatch := c.handleDNSQueryPacket(query)
	if dispatch != nil {
		t.Fatal("did not expect dispatch for ready cache hit")
	}
	if len(response) < 2 {
		t.Fatal("expected cached response")
	}
	if binary.BigEndian.Uint16(response[:2]) != 0x1234 {
		t.Fatalf("expected patched response id, got=%#x", binary.BigEndian.Uint16(response[:2]))
	}
}

func TestHandleDNSQueryPacketRejectsUnsupportedQueryType(t *testing.T) {
	c := New(config.ClientConfig{}, nil, nil)
	query := buildClientTestDNSQuery(0x1234, "example.com", Enums.DNS_RECORD_TYPE_ANY, Enums.DNSQ_CLASS_IN)

	response, dispatch := c.handleDNSQueryPacket(query)
	if dispatch != nil {
		t.Fatal("unsupported query should not dispatch")
	}
	if len(response) < 4 {
		t.Fatal("expected not-implemented response")
	}
	if got := binary.BigEndian.Uint16(response[2:4]) & 0x000F; got != Enums.DNSR_CODE_NOT_IMPLEMENTED {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, Enums.DNSR_CODE_NOT_IMPLEMENTED)
	}
}

func TestResolveDNSQueryPacketDedupesInflightDispatch(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	c := New(config.ClientConfig{
		LocalDNSPendingTimeoutSec: 1,
	}, nil, codec)
	now := time.Unix(1700000000, 0)
	c.now = func() time.Time { return now }
	c.connections = []Connection{{
		Domain:        "v.example.com",
		Resolver:      "127.0.0.1",
		ResolverPort:  5353,
		ResolverLabel: "127.0.0.1:5353",
		Key:           "127.0.0.1|5353|v.example.com",
		IsValid:       true,
	}}
	c.connectionsByKey = map[string]int{c.connections[0].Key: 0}
	c.rebuildBalancer()
	c.sessionID = 7
	c.sessionCookie = 9

	query := buildClientTestDNSQuery(0x1234, "example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSQ_CLASS_IN)
	serverFailure, err := DnsParser.BuildServerFailureResponse(query)
	if err != nil {
		t.Fatalf("BuildServerFailureResponse returned error: %v", err)
	}

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var callCount int
	c.exchangeQueryFn = func(conn Connection, packet []byte, timeout time.Duration) ([]byte, error) {
		callCount++
		if callCount == 1 {
			started <- struct{}{}
			<-release
		}
		queryPacket, err := DnsParser.ParsePacketLite(packet)
		if err != nil || !queryPacket.HasQuestion {
			t.Fatalf("unexpected tunnel dns query: err=%v", err)
		}
		vpnPacket, err := VpnProto.ParseFromLabels(extractTestTunnelLabels(queryPacket.FirstQuestion.Name, "v.example.com"), c.codec)
		if err != nil {
			t.Fatalf("ParseFromLabels returned error: %v", err)
		}
		return DnsParser.BuildVPNResponsePacket(packet, queryPacket.FirstQuestion.Name, VpnProto.Packet{
			SessionID:      c.sessionID,
			SessionCookie:  c.sessionCookie,
			PacketType:     Enums.PACKET_DNS_QUERY_RES,
			StreamID:       0,
			SequenceNum:    vpnPacket.SequenceNum,
			FragmentID:     0,
			TotalFragments: 1,
			Payload:        serverFailure,
		}, false)
	}

	results := make(chan []byte, 2)
	go func() { results <- c.resolveDNSQueryPacket(query) }()
	<-started
	go func() { results <- c.resolveDNSQueryPacket(query) }()
	close(release)

	response1 := <-results
	response2 := <-results
	if string(response1) != string(serverFailure) || string(response2) != string(serverFailure) {
		t.Fatal("expected both queries to reuse same inflight response")
	}
	if callCount != 1 {
		t.Fatalf("expected one tunnel dispatch, got=%d", callCount)
	}
}

func TestHandleDNSQueryPacketRejectsMalformedQuery(t *testing.T) {
	c := New(config.ClientConfig{}, nil, nil)
	response, dispatch := c.handleDNSQueryPacket([]byte{0x12, 0x34, 0x00})
	if dispatch != nil {
		t.Fatal("did not expect dispatch for malformed query")
	}
	if response != nil {
		t.Fatal("short non-dns packet should be ignored")
	}

	query := buildClientTestDNSQuery(0x1234, "example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSQ_CLASS_IN)
	query = query[:len(query)-2]
	response, dispatch = c.handleDNSQueryPacket(query)
	if dispatch != nil {
		t.Fatal("did not expect dispatch for malformed dns query")
	}
	if len(response) == 0 {
		t.Fatal("expected format error response for malformed dns query")
	}
}

func TestDispatchDNSQueryCachesReadyTunnelResponse(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	c := New(config.ClientConfig{
		BaseEncodeData:            false,
		LocalDNSCacheMaxRecords:   8,
		LocalDNSCacheTTLSeconds:   60,
		LocalDNSPendingTimeoutSec: 5,
		CompressionMinSize:        compression.DefaultMinSize,
	}, nil, codec)
	now := time.Unix(1700000000, 0)
	c.now = func() time.Time { return now }
	c.connections = []Connection{{
		Domain:        "v.example.com",
		Resolver:      "127.0.0.1",
		ResolverPort:  5353,
		ResolverLabel: "127.0.0.1:5353",
		Key:           "127.0.0.1|5353|v.example.com",
		IsValid:       true,
	}}
	c.connectionsByKey = map[string]int{c.connections[0].Key: 0}
	c.rebuildBalancer()
	c.sessionID = 7
	c.sessionCookie = 9
	c.responseMode = mtuProbeRawResponse

	rawQuery := buildClientTestDNSQuery(0x1234, "example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSQ_CLASS_IN)
	rawResponse := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	rawResponse = append(rawResponse, encodeClientTestDNSName("example.com")...)
	rawResponse = append(rawResponse, 0x00, byte(Enums.DNS_RECORD_TYPE_A), 0x00, byte(Enums.DNSQ_CLASS_IN))

	c.exchangeQueryFn = func(conn Connection, packet []byte, timeout time.Duration) ([]byte, error) {
		if conn.Key != c.connections[0].Key {
			t.Fatalf("unexpected connection key: got=%q want=%q", conn.Key, c.connections[0].Key)
		}
		if timeout <= 0 {
			t.Fatal("expected positive timeout")
		}

		queryPacket, err := DnsParser.ParsePacketLite(packet)
		if err != nil || !queryPacket.HasQuestion {
			t.Fatalf("unexpected tunnel dns query: err=%v", err)
		}

		vpnPacket, err := VpnProto.ParseFromLabels(extractTestTunnelLabels(queryPacket.FirstQuestion.Name, "v.example.com"), c.codec)
		if err != nil {
			t.Fatalf("ParseFromLabels returned error: %v", err)
		}
		if vpnPacket.PacketType != Enums.PACKET_DNS_QUERY_REQ {
			t.Fatalf("unexpected request packet type: got=%d", vpnPacket.PacketType)
		}
		if vpnPacket.StreamID != 0 {
			t.Fatalf("unexpected request stream id: got=%d", vpnPacket.StreamID)
		}

		return DnsParser.BuildVPNResponsePacket(packet, queryPacket.FirstQuestion.Name, VpnProto.Packet{
			SessionID:      c.sessionID,
			SessionCookie:  c.sessionCookie,
			PacketType:     Enums.PACKET_DNS_QUERY_RES,
			StreamID:       0,
			SequenceNum:    vpnPacket.SequenceNum,
			FragmentID:     0,
			TotalFragments: 1,
			Payload:        rawResponse,
		}, false)
	}

	request := &dnsDispatchRequest{
		CacheKey: dnscache.BuildKey("example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSQ_CLASS_IN),
		Query:    rawQuery,
		Domain:   "example.com",
		QType:    Enums.DNS_RECORD_TYPE_A,
		QClass:   Enums.DNSQ_CLASS_IN,
	}

	response, err := c.dispatchDNSQuery(request)
	if err != nil {
		t.Fatalf("dispatchDNSQuery returned error: %v", err)
	}
	if string(response) != string(rawResponse) {
		t.Fatal("unexpected tunnel dns response payload")
	}

	cached, ok := c.LocalDNSCache().GetReady(request.CacheKey, rawQuery, now)
	if !ok {
		t.Fatal("expected response to be cached")
	}
	if binary.BigEndian.Uint16(cached[:2]) != 0x1234 {
		t.Fatalf("expected cached response id to be patched, got=%#x", binary.BigEndian.Uint16(cached[:2]))
	}
}

func TestDispatchDNSQueryDoesNotCacheServerFailures(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	c := New(config.ClientConfig{
		LocalDNSCacheMaxRecords:   8,
		LocalDNSCacheTTLSeconds:   60,
		LocalDNSPendingTimeoutSec: 5,
	}, nil, codec)
	now := time.Unix(1700000000, 0)
	c.now = func() time.Time { return now }
	c.connections = []Connection{{
		Domain:        "v.example.com",
		Resolver:      "127.0.0.1",
		ResolverPort:  5353,
		ResolverLabel: "127.0.0.1:5353",
		Key:           "127.0.0.1|5353|v.example.com",
		IsValid:       true,
	}}
	c.connectionsByKey = map[string]int{c.connections[0].Key: 0}
	c.rebuildBalancer()
	c.sessionID = 7
	c.sessionCookie = 9

	rawQuery := buildClientTestDNSQuery(0x1234, "example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSQ_CLASS_IN)
	serverFailure, err := DnsParser.BuildServerFailureResponse(rawQuery)
	if err != nil {
		t.Fatalf("BuildServerFailureResponse returned error: %v", err)
	}

	c.exchangeQueryFn = func(conn Connection, packet []byte, timeout time.Duration) ([]byte, error) {
		queryPacket, err := DnsParser.ParsePacketLite(packet)
		if err != nil || !queryPacket.HasQuestion {
			t.Fatalf("unexpected tunnel dns query: err=%v", err)
		}
		vpnPacket, err := VpnProto.ParseFromLabels(extractTestTunnelLabels(queryPacket.FirstQuestion.Name, "v.example.com"), c.codec)
		if err != nil {
			t.Fatalf("ParseFromLabels returned error: %v", err)
		}
		return DnsParser.BuildVPNResponsePacket(packet, queryPacket.FirstQuestion.Name, VpnProto.Packet{
			SessionID:      c.sessionID,
			SessionCookie:  c.sessionCookie,
			PacketType:     Enums.PACKET_DNS_QUERY_RES,
			StreamID:       0,
			SequenceNum:    vpnPacket.SequenceNum,
			FragmentID:     0,
			TotalFragments: 1,
			Payload:        serverFailure,
		}, false)
	}

	request := &dnsDispatchRequest{
		CacheKey: dnscache.BuildKey("example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSQ_CLASS_IN),
		Query:    rawQuery,
		Domain:   "example.com",
		QType:    Enums.DNS_RECORD_TYPE_A,
		QClass:   Enums.DNSQ_CLASS_IN,
	}

	response, err := c.dispatchDNSQuery(request)
	if err != nil {
		t.Fatalf("dispatchDNSQuery returned error: %v", err)
	}
	if string(response) != string(serverFailure) {
		t.Fatal("unexpected dns failure payload")
	}

	if _, ok := c.LocalDNSCache().GetReady(request.CacheKey, rawQuery, now); ok {
		t.Fatal("server failure responses must not be cached")
	}
}

func TestDispatchDNSQuerySplitsLargePayloadAcrossFragments(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	c := New(config.ClientConfig{
		LocalDNSPendingTimeoutSec: 5,
	}, nil, codec)
	c.connections = []Connection{{
		Domain:        "v.example.com",
		Resolver:      "127.0.0.1",
		ResolverPort:  5353,
		ResolverLabel: "127.0.0.1:5353",
		Key:           "127.0.0.1|5353|v.example.com",
		IsValid:       true,
	}}
	c.connectionsByKey = map[string]int{c.connections[0].Key: 0}
	c.rebuildBalancer()
	c.sessionID = 7
	c.sessionCookie = 9
	c.syncedUploadMTU = 20

	rawQuery := buildClientTestDNSQuery(0x1234, "example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSQ_CLASS_IN)
	serverFailure, err := DnsParser.BuildServerFailureResponse(rawQuery)
	if err != nil {
		t.Fatalf("BuildServerFailureResponse returned error: %v", err)
	}

	seenFragments := make([]uint8, 0, 4)
	seenTotals := make([]uint8, 0, 4)
	seenSeq := uint16(0)
	c.exchangeQueryFn = func(conn Connection, packet []byte, timeout time.Duration) ([]byte, error) {
		queryPacket, err := DnsParser.ParsePacketLite(packet)
		if err != nil || !queryPacket.HasQuestion {
			t.Fatalf("unexpected tunnel dns query: err=%v", err)
		}
		vpnPacket, err := VpnProto.ParseFromLabels(extractTestTunnelLabels(queryPacket.FirstQuestion.Name, "v.example.com"), c.codec)
		if err != nil {
			t.Fatalf("ParseFromLabels returned error: %v", err)
		}
		seenFragments = append(seenFragments, vpnPacket.FragmentID)
		seenTotals = append(seenTotals, vpnPacket.TotalFragments)
		if seenSeq == 0 {
			seenSeq = vpnPacket.SequenceNum
		} else if vpnPacket.SequenceNum != seenSeq {
			t.Fatalf("fragment sequence mismatch: got=%d want=%d", vpnPacket.SequenceNum, seenSeq)
		}

		if vpnPacket.FragmentID+1 < vpnPacket.TotalFragments {
			return DnsParser.BuildEmptyNoErrorResponse(packet)
		}

		return DnsParser.BuildVPNResponsePacket(packet, queryPacket.FirstQuestion.Name, VpnProto.Packet{
			SessionID:      c.sessionID,
			SessionCookie:  c.sessionCookie,
			PacketType:     Enums.PACKET_DNS_QUERY_RES,
			StreamID:       0,
			SequenceNum:    vpnPacket.SequenceNum,
			FragmentID:     0,
			TotalFragments: 1,
			Payload:        serverFailure,
		}, false)
	}

	request := &dnsDispatchRequest{
		CacheKey: dnscache.BuildKey("example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSQ_CLASS_IN),
		Query:    rawQuery,
		Domain:   "example.com",
		QType:    Enums.DNS_RECORD_TYPE_A,
		QClass:   Enums.DNSQ_CLASS_IN,
	}

	if _, err := c.dispatchDNSQuery(request); err != nil {
		t.Fatalf("dispatchDNSQuery returned error: %v", err)
	}
	if len(seenFragments) < 2 {
		t.Fatalf("expected multiple fragments, got=%d", len(seenFragments))
	}
	for i, total := range seenTotals {
		if total != seenTotals[0] {
			t.Fatalf("fragment total mismatch at %d: got=%d want=%d", i, total, seenTotals[0])
		}
	}
}

func TestStream0RuntimeQueuesPingAfterDNSActivity(t *testing.T) {
	oldNoStreamThreshold := stream0PingIdleNoStreamThreshold
	oldHighThreshold := stream0PingIdleHighThreshold
	oldMediumThreshold := stream0PingIdleMediumThreshold
	oldNoStreamInterval := stream0PingNoStreamInterval
	oldHighInterval := stream0PingHighIdleInterval
	oldMediumInterval := stream0PingMediumIdleInterval
	oldBusyInterval := stream0PingBusyInterval
	oldNoStreamSleep := stream0PingNoStreamMaxSleep
	oldHighSleep := stream0PingHighIdleMaxSleep
	oldMediumSleep := stream0PingMediumIdleMaxSleep
	oldBusySleep := stream0PingBusyMaxSleep
	stream0PingIdleNoStreamThreshold = 50 * time.Millisecond
	stream0PingIdleHighThreshold = 25 * time.Millisecond
	stream0PingIdleMediumThreshold = 10 * time.Millisecond
	stream0PingNoStreamInterval = 25 * time.Millisecond
	stream0PingHighIdleInterval = 20 * time.Millisecond
	stream0PingMediumIdleInterval = 15 * time.Millisecond
	stream0PingBusyInterval = 10 * time.Millisecond
	stream0PingNoStreamMaxSleep = 10 * time.Millisecond
	stream0PingHighIdleMaxSleep = 10 * time.Millisecond
	stream0PingMediumIdleMaxSleep = 10 * time.Millisecond
	stream0PingBusyMaxSleep = 10 * time.Millisecond
	defer func() {
		stream0PingIdleNoStreamThreshold = oldNoStreamThreshold
		stream0PingIdleHighThreshold = oldHighThreshold
		stream0PingIdleMediumThreshold = oldMediumThreshold
		stream0PingNoStreamInterval = oldNoStreamInterval
		stream0PingHighIdleInterval = oldHighInterval
		stream0PingMediumIdleInterval = oldMediumInterval
		stream0PingBusyInterval = oldBusyInterval
		stream0PingNoStreamMaxSleep = oldNoStreamSleep
		stream0PingHighIdleMaxSleep = oldHighSleep
		stream0PingMediumIdleMaxSleep = oldMediumSleep
		stream0PingBusyMaxSleep = oldBusySleep
	}()

	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	c := New(config.ClientConfig{
		LocalDNSPendingTimeoutSec: 1,
	}, nil, codec)
	c.connections = []Connection{{
		Domain:        "v.example.com",
		Resolver:      "127.0.0.1",
		ResolverPort:  5353,
		ResolverLabel: "127.0.0.1:5353",
		Key:           "127.0.0.1|5353|v.example.com",
		IsValid:       true,
	}}
	c.connectionsByKey = map[string]int{c.connections[0].Key: 0}
	c.rebuildBalancer()
	c.sessionID = 7
	c.sessionCookie = 9
	c.responseMode = mtuProbeRawResponse

	pingSeen := make(chan struct{}, 1)
	c.exchangeQueryFn = func(conn Connection, packet []byte, timeout time.Duration) ([]byte, error) {
		queryPacket, err := DnsParser.ParsePacketLite(packet)
		if err != nil || !queryPacket.HasQuestion {
			t.Fatalf("unexpected tunnel query: err=%v", err)
		}
		vpnPacket, err := VpnProto.ParseFromLabels(extractTestTunnelLabels(queryPacket.FirstQuestion.Name, "v.example.com"), c.codec)
		if err != nil {
			t.Fatalf("ParseFromLabels returned error: %v", err)
		}
		if vpnPacket.PacketType != Enums.PACKET_PING {
			t.Fatalf("expected ping packet, got=%d", vpnPacket.PacketType)
		}
		select {
		case pingSeen <- struct{}{}:
		default:
		}
		return DnsParser.BuildVPNResponsePacket(packet, queryPacket.FirstQuestion.Name, VpnProto.Packet{
			SessionID:     c.sessionID,
			SessionCookie: c.sessionCookie,
			PacketType:    Enums.PACKET_PONG,
			Payload:       []byte("PO:test"),
		}, false)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.startStream0Runtime(ctx); err != nil {
		t.Fatalf("startStream0Runtime returned error: %v", err)
	}

	c.stream0Runtime.NotifyDNSActivity()

	select {
	case <-pingSeen:
	case <-time.After(time.Second):
		t.Fatal("expected ping to be sent after dns activity")
	}
}

func TestStream0RuntimeRetriesDNSQueryAfterTransientFailure(t *testing.T) {
	oldBaseDelay := stream0DNSRetryBaseDelay
	oldMaxDelay := stream0DNSRetryMaxDelay
	stream0DNSRetryBaseDelay = 20 * time.Millisecond
	stream0DNSRetryMaxDelay = 40 * time.Millisecond
	defer func() {
		stream0DNSRetryBaseDelay = oldBaseDelay
		stream0DNSRetryMaxDelay = oldMaxDelay
	}()

	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	c := New(config.ClientConfig{
		LocalDNSPendingTimeoutSec: 1,
	}, nil, codec)
	c.connections = []Connection{{
		Domain:        "v.example.com",
		Resolver:      "127.0.0.1",
		ResolverPort:  5353,
		ResolverLabel: "127.0.0.1:5353",
		Key:           "127.0.0.1|5353|v.example.com",
		IsValid:       true,
	}}
	c.connectionsByKey = map[string]int{c.connections[0].Key: 0}
	c.rebuildBalancer()
	c.sessionID = 7
	c.sessionCookie = 9
	c.responseMode = mtuProbeRawResponse

	rawQuery := buildClientTestDNSQuery(0x1234, "example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSQ_CLASS_IN)
	serverFailure, err := DnsParser.BuildServerFailureResponse(rawQuery)
	if err != nil {
		t.Fatalf("BuildServerFailureResponse returned error: %v", err)
	}

	callCount := 0
	c.exchangeQueryFn = func(conn Connection, packet []byte, timeout time.Duration) ([]byte, error) {
		callCount++
		if callCount == 1 {
			return nil, errors.New("temporary failure")
		}

		queryPacket, err := DnsParser.ParsePacketLite(packet)
		if err != nil || !queryPacket.HasQuestion {
			t.Fatalf("unexpected tunnel dns query: err=%v", err)
		}
		vpnPacket, err := VpnProto.ParseFromLabels(extractTestTunnelLabels(queryPacket.FirstQuestion.Name, "v.example.com"), c.codec)
		if err != nil {
			t.Fatalf("ParseFromLabels returned error: %v", err)
		}
		return DnsParser.BuildVPNResponsePacket(packet, queryPacket.FirstQuestion.Name, VpnProto.Packet{
			SessionID:      c.sessionID,
			SessionCookie:  c.sessionCookie,
			PacketType:     Enums.PACKET_DNS_QUERY_RES,
			StreamID:       0,
			SequenceNum:    vpnPacket.SequenceNum,
			FragmentID:     0,
			TotalFragments: 1,
			Payload:        serverFailure,
		}, false)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.startStream0Runtime(ctx); err != nil {
		t.Fatalf("startStream0Runtime returned error: %v", err)
	}

	packet, err := c.stream0Runtime.ExchangeDNSQuery(rawQuery, time.Second)
	if err != nil {
		t.Fatalf("ExchangeDNSQuery returned error: %v", err)
	}
	if packet.PacketType != Enums.PACKET_DNS_QUERY_RES {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, Enums.PACKET_DNS_QUERY_RES)
	}
	if callCount < 2 {
		t.Fatalf("expected retry to happen, got callCount=%d", callCount)
	}
}

func TestDispatchDNSQueryFailsWithoutValidConnections(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}
	c := New(config.ClientConfig{}, nil, codec)
	c.sessionID = 7
	c.sessionCookie = 9

	_, dispatchErr := c.dispatchDNSQuery(&dnsDispatchRequest{
		CacheKey: []byte("key"),
		Query:    []byte{1},
	})
	if !errors.Is(dispatchErr, ErrNoValidConnections) {
		t.Fatalf("unexpected error: %v", dispatchErr)
	}
}

func extractTestTunnelLabels(qName string, baseDomain string) string {
	suffix := "." + baseDomain
	if len(qName) <= len(suffix) || qName[len(qName)-len(suffix):] != suffix {
		return ""
	}
	labels := qName[:len(qName)-len(suffix)]
	out := make([]byte, 0, len(labels))
	for i := 0; i < len(labels); i++ {
		if labels[i] != '.' {
			out = append(out, labels[i])
		}
	}
	return string(out)
}

func buildClientTestDNSQuery(id uint16, name string, qType uint16, qClass uint16) []byte {
	packet := []byte{
		byte(id >> 8), byte(id),
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}
	packet = append(packet, encodeClientTestDNSName(name)...)
	packet = append(packet, byte(qType>>8), byte(qType), byte(qClass>>8), byte(qClass))
	return packet
}

func encodeClientTestDNSName(name string) []byte {
	if name == "" {
		return []byte{0x00}
	}

	encoded := make([]byte, 0, len(name)+2)
	labelStart := 0
	for i := 0; i <= len(name); i++ {
		if i < len(name) && name[i] != '.' {
			continue
		}
		label := name[labelStart:i]
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, label...)
		labelStart = i + 1
	}
	encoded = append(encoded, 0x00)
	return encoded
}
