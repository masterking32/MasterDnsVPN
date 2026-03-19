// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func TestHandlePacketDropsDNSResponses(t *testing.T) {
	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, nil)

	packet := buildServerTestQuery(0x1001, "vpn.a.com", Enums.DNS_RECORD_TYPE_TXT)
	packet[2] |= 0x80

	if response := srv.handlePacket(packet); response != nil {
		t.Fatal("handlePacket should drop DNS response packets")
	}
}

func TestHandlePacketReturnsNoDataForUnauthorizedDomain(t *testing.T) {
	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, nil)

	packet := buildServerTestQuery(0x2002, "evil.com", Enums.DNS_RECORD_TYPE_TXT)
	response := srv.handlePacket(packet)
	if len(response) == 0 {
		t.Fatal("handlePacket should return a DNS response for unauthorized DNS queries")
	}

	if got := binary.BigEndian.Uint16(response[0:2]); got != 0x2002 {
		t.Fatalf("unexpected response id: got=%#x want=%#x", got, 0x2002)
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&0x000F != Enums.DNSR_CODE_NO_ERROR {
		t.Fatalf("unexpected rcode: got=%d want=%d", flags&0x000F, Enums.DNSR_CODE_NO_ERROR)
	}
}

func TestHandlePacketRespondsToMTUUpProbe(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	verifyCode := []byte{0x11, 0x22, 0x33, 0x44}
	payload := append([]byte{0}, verifyCode...)
	payload = append(payload, bytes.Repeat([]byte{0xAB}, 64)...)
	query := buildTunnelQuery(t, codec, "a.com", Enums.PACKET_MTU_UP_REQ, payload)
	response := srv.handlePacket(query)
	if len(response) == 0 {
		t.Fatal("handlePacket should return a vpn mtu-up response")
	}

	packet, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != Enums.PACKET_MTU_UP_RES {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, Enums.PACKET_MTU_UP_RES)
	}
	if len(packet.Payload) != 6 {
		t.Fatalf("unexpected mtu-up response length: got=%d want=%d", len(packet.Payload), 6)
	}
	if !bytes.Equal(packet.Payload[:4], verifyCode) {
		t.Fatalf("unexpected echoed verify code: got=%v want=%v", packet.Payload[:4], verifyCode)
	}
	if got := int(binary.BigEndian.Uint16(packet.Payload[4:6])); got != len(payload) {
		t.Fatalf("unexpected echoed mtu size: got=%d want=%d", got, len(payload))
	}
}

func TestHandlePacketRespondsToMTUDownProbe(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	verifyCode := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	payload := make([]byte, 128)
	payload[0] = 0
	copy(payload[1:5], verifyCode)
	binary.BigEndian.PutUint16(payload[5:7], 128)
	copy(payload[7:], bytes.Repeat([]byte{0xAB}, len(payload)-7))
	query := buildTunnelQuery(t, codec, "a.com", Enums.PACKET_MTU_DOWN_REQ, payload)
	response := srv.handlePacket(query)
	if len(response) == 0 {
		t.Fatal("handlePacket should return a vpn mtu-down response")
	}

	packet, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != Enums.PACKET_MTU_DOWN_RES {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, Enums.PACKET_MTU_DOWN_RES)
	}
	if len(packet.Payload) != 128 {
		t.Fatalf("unexpected mtu-down payload length: got=%d want=%d", len(packet.Payload), 128)
	}
	if !bytes.Equal(packet.Payload[:4], verifyCode) {
		t.Fatalf("unexpected mtu-down verify prefix: got=%v want=%v", packet.Payload[:4], verifyCode)
	}
	if got := int(binary.BigEndian.Uint16(packet.Payload[4:6])); got != 128 {
		t.Fatalf("unexpected mtu-down echoed size: got=%d want=%d", got, 128)
	}
}

func TestHandlePacketRespondsToMTUUpProbeBaseEncoded(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	verifyCode := []byte{0x10, 0x20, 0x30, 0x40}
	payload := append([]byte{1}, verifyCode...)
	payload = append(payload, bytes.Repeat([]byte{0xAB}, 40)...)
	query := buildTunnelQuery(t, codec, "a.com", Enums.PACKET_MTU_UP_REQ, payload)
	response := srv.handlePacket(query)
	if len(response) == 0 {
		t.Fatal("handlePacket should return a vpn mtu-up response")
	}

	packet, err := DnsParser.ExtractVPNResponse(response, true)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != Enums.PACKET_MTU_UP_RES {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, Enums.PACKET_MTU_UP_RES)
	}
	if !bytes.Equal(packet.Payload[:4], verifyCode) {
		t.Fatalf("unexpected echoed verify code: got=%v want=%v", packet.Payload[:4], verifyCode)
	}
}

func TestHandlePacketCreatesAndReusesSessionInit(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	verifyCode := []byte{0x44, 0x33, 0x22, 0x11}
	payload := []byte{
		1,
		0x21,
		0x00, 0x96,
		0x00, 0xC8,
		verifyCode[0], verifyCode[1], verifyCode[2], verifyCode[3],
	}

	query1 := buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, payload)
	response1 := srv.handlePacket(query1)
	if len(response1) == 0 {
		t.Fatal("handlePacket should return a session accept response")
	}

	packet1, err := DnsParser.ExtractVPNResponse(response1, true)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet1.PacketType != Enums.PACKET_SESSION_ACCEPT {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet1.PacketType, Enums.PACKET_SESSION_ACCEPT)
	}
	if len(packet1.Payload) != 7 {
		t.Fatalf("unexpected session payload len: got=%d want=7", len(packet1.Payload))
	}
	if !bytes.Equal(packet1.Payload[3:7], verifyCode) {
		t.Fatalf("unexpected verify code: got=%v want=%v", packet1.Payload[3:7], verifyCode)
	}

	query2 := buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, payload)
	response2 := srv.handlePacket(query2)
	packet2, err := DnsParser.ExtractVPNResponse(response2, true)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}

	if packet1.Payload[0] != packet2.Payload[0] {
		t.Fatalf("expected reused session id: got=%d want=%d", packet2.Payload[0], packet1.Payload[0])
	}
	if packet1.Payload[1] != packet2.Payload[1] {
		t.Fatalf("expected reused session cookie: got=%d want=%d", packet2.Payload[1], packet1.Payload[1])
	}
	if packet1.SessionID != 0 || packet2.SessionID != 0 {
		t.Fatalf("session accept should stay in pre-session header space: got1=%d got2=%d", packet1.SessionID, packet2.SessionID)
	}
}

func TestHandleStreamSynConnectsForwardTargetForTCPMode(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
		ForwardIP:         "127.0.0.1",
		ForwardPort:       8080,
	}, nil, codec)

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	srv.dialStreamUpstreamFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
		if network != "tcp" || address != "127.0.0.1:8080" {
			t.Fatalf("unexpected dial target: network=%s address=%s", network, address)
		}
		return serverSide, nil
	}

	verifyCode := []byte{1, 2, 3, 4}
	initPayload := []byte{0, 0x00, 0x00, 0x96, 0x00, 0xC8, verifyCode[0], verifyCode[1], verifyCode[2], verifyCode[3]}
	initResponse := srv.handlePacket(buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, initPayload))
	packet, err := DnsParser.ExtractVPNResponse(initResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}

	sessionID := packet.Payload[0]
	sessionCookie := packet.Payload[1]
	query := buildTunnelStreamQuery(t, codec, "a.com", sessionID, sessionCookie, Enums.PACKET_STREAM_SYN, 9, 1, VpnProto.TCPForwardSynPayload())
	response := srv.handlePacket(query)
	if len(response) == 0 {
		t.Fatal("expected stream syn response")
	}
	vpnResponse, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if vpnResponse.PacketType != Enums.PACKET_STREAM_SYN_ACK {
		t.Fatalf("unexpected packet type: got=%d want=%d", vpnResponse.PacketType, Enums.PACKET_STREAM_SYN_ACK)
	}
	record, ok := srv.streams.Lookup(sessionID, 9)
	if !ok || record == nil || !record.Connected || record.TargetHost != "127.0.0.1" || record.TargetPort != 8080 {
		t.Fatalf("expected connected forward stream, got=%+v ok=%v", record, ok)
	}
}

func TestHandlePacketRejectsMalformedSessionInit(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	payload := []byte{1, 0x21, 0x00, 0x96, 0x00, 0xC8, 0x44, 0x33, 0x22, 0x11, 0x99}
	query := buildTunnelQueryWithSessionID(t, codec, "a.com", 9, Enums.PACKET_SESSION_INIT, payload)
	if response := srv.handlePacket(query); len(response) != 0 {
		t.Fatal("malformed session init must be rejected")
	}
}

func TestHandlePacketRejectsShortSessionInit(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	payload := []byte{1, 0x21, 0x00, 0x96}
	query := buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, payload)
	if response := srv.handlePacket(query); len(response) != 0 {
		t.Fatal("short session init must be rejected")
	}
}

func TestHandlePacketNegotiatesUnsupportedCompressionToOff(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:                     65535,
		Domain:                            []string{"a.com"},
		MinVPNLabelLength:                 3,
		SupportedUploadCompressionTypes:   []int{0, 3},
		SupportedDownloadCompressionTypes: []int{0},
	}, nil, codec)

	payload := []byte{1, 0x31, 0x00, 0x96, 0x00, 0xC8, 0x44, 0x33, 0x22, 0x11}
	query := buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, payload)
	response := srv.handlePacket(query)
	if len(response) == 0 {
		t.Fatal("handlePacket should return a session accept response")
	}

	packet, err := DnsParser.ExtractVPNResponse(response, true)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if got := packet.Payload[2]; got != 0x30 {
		t.Fatalf("unexpected negotiated compression pair: got=%#x want=%#x", got, 0x30)
	}
}

func TestHandlePacketDropsPostSessionPacketWithInvalidCookie(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	verifyCode := []byte{0x44, 0x33, 0x22, 0x11}
	initPayload := []byte{
		1,
		0x00,
		0x00, 0x96,
		0x00, 0xC8,
		verifyCode[0], verifyCode[1], verifyCode[2], verifyCode[3],
	}

	initResponse := srv.handlePacket(buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, initPayload))
	packet, err := DnsParser.ExtractVPNResponse(initResponse, true)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}

	sessionID := packet.Payload[0]
	wrongCookie := packet.Payload[1] + 1
	postSessionQuery := buildTunnelQueryWithCookie(t, codec, "a.com", sessionID, wrongCookie, Enums.PACKET_PING, nil)
	if response := srv.handlePacket(postSessionQuery); len(response) != 0 {
		t.Fatal("post-session packet with invalid cookie must be dropped")
	}
	if _, ok := srv.sessions.Active(sessionID); !ok {
		t.Fatal("invalid cookie packet must not close a valid session")
	}

	validCookieQuery := buildTunnelQueryWithCookie(t, codec, "a.com", sessionID, packet.Payload[1], Enums.PACKET_PING, nil)
	if response := srv.handlePacket(validCookieQuery); len(response) == 0 {
		t.Fatal("valid packet after invalid cookie must still be processed")
	}
}

func TestHandlePacketAcceptsPostSessionPacketWithValidCookie(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	verifyCode := []byte{0x10, 0x20, 0x30, 0x40}
	initPayload := []byte{
		1,
		0x00,
		0x00, 0x96,
		0x00, 0xC8,
		verifyCode[0], verifyCode[1], verifyCode[2], verifyCode[3],
	}

	initResponse := srv.handlePacket(buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, initPayload))
	packet, err := DnsParser.ExtractVPNResponse(initResponse, true)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}

	sessionID := packet.Payload[0]
	sessionCookie := packet.Payload[1]
	activeBefore, ok := srv.sessions.Active(sessionID)
	if !ok {
		t.Fatal("expected active session after session init")
	}

	time.Sleep(5 * time.Millisecond)
	postSessionQuery := buildTunnelQueryWithCookie(t, codec, "a.com", sessionID, sessionCookie, Enums.PACKET_PING, nil)
	response := srv.handlePacket(postSessionQuery)
	if len(response) == 0 {
		t.Fatal("post-session packet with valid cookie should reach normal handler path")
	}

	activeAfter, ok := srv.sessions.Active(sessionID)
	if !ok {
		t.Fatal("expected active session after validated packet")
	}
	if !activeAfter.LastActivityAt.After(activeBefore.LastActivityAt) {
		t.Fatal("validated post-session packet should refresh session activity")
	}
}

func TestHandlePacketRespondsToPingWithPong(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	verifyCode := []byte{0x10, 0x20, 0x30, 0x40}
	initPayload := []byte{
		0,
		0x00,
		0x00, 0x96,
		0x00, 0xC8,
		verifyCode[0], verifyCode[1], verifyCode[2], verifyCode[3],
	}

	initResponse := srv.handlePacket(buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, initPayload))
	packet, err := DnsParser.ExtractVPNResponse(initResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}

	sessionID := packet.Payload[0]
	sessionCookie := packet.Payload[1]
	pingQuery := buildTunnelQueryWithCookie(t, codec, "a.com", sessionID, sessionCookie, Enums.PACKET_PING, []byte("PO:test"))
	response := srv.handlePacket(pingQuery)
	if len(response) == 0 {
		t.Fatal("expected pong response")
	}

	pongPacket, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if pongPacket.PacketType != Enums.PACKET_PONG {
		t.Fatalf("unexpected packet type: got=%d want=%d", pongPacket.PacketType, Enums.PACKET_PONG)
	}
	if pongPacket.SessionID != sessionID || pongPacket.SessionCookie != sessionCookie {
		t.Fatalf("unexpected session routing: sid=%d cookie=%d", pongPacket.SessionID, pongPacket.SessionCookie)
	}
	if len(pongPacket.Payload) != 7 || !bytes.Equal(pongPacket.Payload[:3], []byte("PO:")) {
		t.Fatalf("unexpected pong payload: %q", pongPacket.Payload)
	}
}

func TestHandlePacketPingReturnsQueuedStreamPacket(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	initPayload := []byte{0, 0x00, 0x00, 0x96, 0x00, 0xC8, 0x10, 0x20, 0x30, 0x40}
	initResponse := srv.handlePacket(buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, initPayload))
	packet, err := DnsParser.ExtractVPNResponse(initResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}

	sessionID := packet.Payload[0]
	sessionCookie := packet.Payload[1]
	srv.streamOutbound.Enqueue(sessionID, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    11,
		SequenceNum: 9,
		Payload:     []byte("abc"),
	})

	pingQuery := buildTunnelQueryWithCookie(t, codec, "a.com", sessionID, sessionCookie, Enums.PACKET_PING, []byte("PO:test"))
	response := srv.handlePacket(pingQuery)
	if len(response) == 0 {
		t.Fatal("expected queued stream data response")
	}

	vpnResponse, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if vpnResponse.PacketType != Enums.PACKET_STREAM_DATA {
		t.Fatalf("unexpected packet type: got=%d want=%d", vpnResponse.PacketType, Enums.PACKET_STREAM_DATA)
	}
	if vpnResponse.StreamID != 11 || vpnResponse.SequenceNum != 9 || string(vpnResponse.Payload) != "abc" {
		t.Fatalf("unexpected queued stream packet: %+v", vpnResponse)
	}
}

func TestStreamOutboundStoreSupportsWindowAndOutOfOrderAck(t *testing.T) {
	store := newStreamOutboundStore(4, 256)
	now := time.Now()

	store.Enqueue(7, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    11,
		SequenceNum: 1,
		Payload:     []byte("one"),
	})
	store.Enqueue(7, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    11,
		SequenceNum: 2,
		Payload:     []byte("two"),
	})

	first, ok := store.Next(7, now)
	if !ok || first.SequenceNum != 1 {
		t.Fatalf("unexpected first outbound packet: ok=%v packet=%+v", ok, first)
	}
	second, ok := store.Next(7, now)
	if !ok || second.SequenceNum != 2 {
		t.Fatalf("unexpected second outbound packet: ok=%v packet=%+v", ok, second)
	}

	if !store.Ack(7, Enums.PACKET_STREAM_DATA_ACK, 11, 2) {
		t.Fatal("expected out-of-order ack to clear second pending packet")
	}
	if store.Ack(7, Enums.PACKET_STREAM_DATA_ACK, 11, 9) {
		t.Fatal("unexpected ack match for unknown sequence")
	}
	if !store.Ack(7, Enums.PACKET_STREAM_DATA_ACK, 11, 1) {
		t.Fatal("expected first packet ack to clear remaining pending packet")
	}
	if _, ok := store.Next(7, now); ok {
		t.Fatal("expected no pending outbound packet after all acks")
	}
}

func TestStreamOutboundStoreResetClearsStreamBacklog(t *testing.T) {
	store := newStreamOutboundStore(4, 256)
	now := time.Now()

	store.Enqueue(9, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    33,
		SequenceNum: 1,
		Payload:     []byte("one"),
	})
	store.Enqueue(9, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    44,
		SequenceNum: 1,
		Payload:     []byte("other"),
	})
	first, ok := store.Next(9, now)
	if !ok || first.StreamID != 33 || first.PacketType != Enums.PACKET_STREAM_DATA {
		t.Fatalf("unexpected first packet: ok=%v packet=%+v", ok, first)
	}

	store.Enqueue(9, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_RST,
		StreamID:    33,
		SequenceNum: 2,
	})

	next, ok := store.Next(9, now)
	if !ok || next.PacketType != Enums.PACKET_STREAM_RST || next.StreamID != 33 {
		t.Fatalf("expected reset to preempt same-stream backlog, got ok=%v packet=%+v", ok, next)
	}
	after, ok := store.Next(9, now)
	if !ok || after.StreamID != 44 || after.PacketType != Enums.PACKET_STREAM_DATA {
		t.Fatalf("expected unrelated stream packet to remain queued, got ok=%v packet=%+v", ok, after)
	}
}

func TestStreamOutboundStoreDropsOnlyDataWhenQueueLimitReached(t *testing.T) {
	store := newStreamOutboundStore(1, 2)
	now := time.Now()

	if !store.Enqueue(3, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    7,
		SequenceNum: 1,
		Payload:     []byte("one"),
	}) {
		t.Fatal("expected first data enqueue to succeed")
	}
	first, ok := store.Next(3, now)
	if !ok || first.SequenceNum != 1 {
		t.Fatalf("unexpected first packet: ok=%v packet=%+v", ok, first)
	}
	if !store.Enqueue(3, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    7,
		SequenceNum: 2,
		Payload:     []byte("two"),
	}) {
		t.Fatal("expected second data enqueue to succeed")
	}
	if store.Enqueue(3, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    7,
		SequenceNum: 3,
		Payload:     []byte("three"),
	}) {
		t.Fatal("expected third data enqueue to be rejected by queue limit")
	}
	if !store.Enqueue(3, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_FIN,
		StreamID:    7,
		SequenceNum: 4,
	}) {
		t.Fatal("expected control packet to bypass data queue limit")
	}
}

func TestStreamOutboundStoreExpiresStalledPendingPackets(t *testing.T) {
	store := newStreamOutboundStore(1, 8)
	now := time.Now()

	if !store.Enqueue(9, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    21,
		SequenceNum: 1,
		Payload:     []byte("one"),
	}) {
		t.Fatal("expected enqueue to succeed")
	}
	if _, ok := store.Next(9, now); !ok {
		t.Fatal("expected first pending packet")
	}

	store.mu.Lock()
	if len(store.sessions[9].pending) != 1 {
		store.mu.Unlock()
		t.Fatalf("expected one pending packet, got=%d", len(store.sessions[9].pending))
	}
	store.sessions[9].pending[0].RetryCount = 2
	store.sessions[9].pending[0].CreatedAt = now.Add(-2 * time.Second)
	store.mu.Unlock()

	expired := store.ExpireStalled(9, now, 2, time.Second)
	if len(expired) != 1 || expired[0] != 21 {
		t.Fatalf("unexpected expired streams: %+v", expired)
	}
	if _, ok := store.Next(9, now); ok {
		t.Fatal("expected expired pending packet to be pruned")
	}
}

func TestStreamOutboundStoreRoundRobinsEqualPriorityStreamData(t *testing.T) {
	store := newStreamOutboundStore(1, 8)
	now := time.Now()

	if !store.Enqueue(5, VpnProto.Packet{PacketType: Enums.PACKET_STREAM_DATA, StreamID: 1, SequenceNum: 1}) {
		t.Fatal("expected enqueue to succeed")
	}
	if !store.Enqueue(5, VpnProto.Packet{PacketType: Enums.PACKET_STREAM_DATA, StreamID: 2, SequenceNum: 2}) {
		t.Fatal("expected enqueue to succeed")
	}
	if !store.Enqueue(5, VpnProto.Packet{PacketType: Enums.PACKET_STREAM_DATA, StreamID: 1, SequenceNum: 3}) {
		t.Fatal("expected enqueue to succeed")
	}

	first, ok := store.Next(5, now)
	if !ok || first.StreamID != 1 {
		t.Fatalf("unexpected first packet: ok=%v packet=%+v", ok, first)
	}
	if !store.Ack(5, Enums.PACKET_STREAM_DATA_ACK, first.StreamID, first.SequenceNum) {
		t.Fatal("expected first packet ack to succeed")
	}

	second, ok := store.Next(5, now)
	if !ok || second.StreamID != 2 {
		t.Fatalf("unexpected second packet: ok=%v packet=%+v", ok, second)
	}
}

func TestStreamOutboundStorePrioritizesControlOverQueuedData(t *testing.T) {
	store := newStreamOutboundStore(1, 8)
	now := time.Now()

	if !store.Enqueue(6, VpnProto.Packet{PacketType: Enums.PACKET_STREAM_DATA, StreamID: 10, SequenceNum: 1}) {
		t.Fatal("expected data enqueue to succeed")
	}
	if !store.Enqueue(6, VpnProto.Packet{PacketType: Enums.PACKET_STREAM_FIN, StreamID: 11, SequenceNum: 2}) {
		t.Fatal("expected fin enqueue to succeed")
	}

	first, ok := store.Next(6, now)
	if !ok || first.PacketType != Enums.PACKET_STREAM_FIN {
		t.Fatalf("expected FIN to win priority dequeue, ok=%v packet=%+v", ok, first)
	}
}

func TestStreamOutboundStoreAdaptsRetryBaseAfterAck(t *testing.T) {
	store := newStreamOutboundStore(1, 8)
	now := time.Now()

	if !store.Enqueue(7, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    3,
		SequenceNum: 1,
		Payload:     []byte("alpha"),
	}) {
		t.Fatal("expected enqueue to succeed")
	}

	packet, ok := store.Next(7, now)
	if !ok || packet.SequenceNum != 1 {
		t.Fatalf("expected first outbound packet, ok=%v packet=%+v", ok, packet)
	}

	store.mu.Lock()
	session := store.sessions[7]
	if session == nil || len(session.pending) != 1 {
		store.mu.Unlock()
		t.Fatalf("expected one pending packet, session=%v", session)
	}
	session.pending[0].LastSentAt = now.Add(-150 * time.Millisecond)
	store.mu.Unlock()

	if !store.Enqueue(7, VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    3,
		SequenceNum: 2,
		Payload:     []byte("beta"),
	}) {
		t.Fatal("expected second enqueue to succeed")
	}

	if !store.Ack(7, Enums.PACKET_STREAM_DATA_ACK, 3, 1) {
		t.Fatal("expected ack to succeed")
	}
	_, ok = store.Next(7, now.Add(time.Second))
	if !ok {
		t.Fatal("expected second outbound packet")
	}

	store.mu.Lock()
	session = store.sessions[7]
	if session == nil || len(session.pending) != 1 {
		store.mu.Unlock()
		t.Fatalf("expected active pending packet after second send, session=%v", session)
	}
	base := session.pending[0].RetryDelay
	store.mu.Unlock()

	if base == streamOutboundInitialRetryDelay {
		t.Fatalf("expected adaptive retry base to change from default, got=%v", base)
	}
	if base < streamOutboundMinRetryDelay || base > streamOutboundMaxRetryDelay {
		t.Fatalf("expected retry delay to stay clamped, got=%v", base)
	}
}

func TestHandlePacketRespondsToStreamLifecyclePackets(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	initPayload := []byte{0, 0x00, 0x00, 0x96, 0x00, 0xC8, 0x10, 0x20, 0x30, 0x40}
	initResponse := srv.handlePacket(buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, initPayload))
	packet, err := DnsParser.ExtractVPNResponse(initResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	sessionID := packet.Payload[0]
	sessionCookie := packet.Payload[1]

	synQuery := buildTunnelStreamQuery(t, codec, "a.com", sessionID, sessionCookie, Enums.PACKET_STREAM_SYN, 9, 11, nil)
	synResponse := srv.handlePacket(synQuery)
	synPacket, err := DnsParser.ExtractVPNResponse(synResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if synPacket.PacketType != Enums.PACKET_STREAM_SYN_ACK {
		t.Fatalf("unexpected syn ack packet type: got=%d want=%d", synPacket.PacketType, Enums.PACKET_STREAM_SYN_ACK)
	}
	upstreamConn, peerConn := net.Pipe()
	defer upstreamConn.Close()
	defer peerConn.Close()
	go func() {
		buffer := make([]byte, 16)
		_, _ = peerConn.Read(buffer)
	}()
	if _, ok := srv.streams.AttachUpstream(sessionID, 9, "127.0.0.1", 80, upstreamConn, time.Now()); !ok {
		t.Fatal("AttachUpstream returned false")
	}

	dataQuery := buildTunnelStreamQuery(t, codec, "a.com", sessionID, sessionCookie, Enums.PACKET_STREAM_DATA, 9, 12, []byte("hello"))
	dataResponse := srv.handlePacket(dataQuery)
	dataPacket, err := DnsParser.ExtractVPNResponse(dataResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if dataPacket.PacketType != Enums.PACKET_STREAM_DATA_ACK {
		t.Fatalf("unexpected data ack packet type: got=%d want=%d", dataPacket.PacketType, Enums.PACKET_STREAM_DATA_ACK)
	}
	if dataPacket.SequenceNum != 12 {
		t.Fatalf("unexpected data ack seq: got=%d want=12", dataPacket.SequenceNum)
	}

	finQuery := buildTunnelStreamQuery(t, codec, "a.com", sessionID, sessionCookie, Enums.PACKET_STREAM_FIN, 9, 13, nil)
	finResponse := srv.handlePacket(finQuery)
	finPacket, err := DnsParser.ExtractVPNResponse(finResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if finPacket.PacketType != Enums.PACKET_STREAM_FIN_ACK {
		t.Fatalf("unexpected fin ack packet type: got=%d want=%d", finPacket.PacketType, Enums.PACKET_STREAM_FIN_ACK)
	}

	rstQuery := buildTunnelStreamQuery(t, codec, "a.com", sessionID, sessionCookie, Enums.PACKET_STREAM_RST, 9, 14, nil)
	rstResponse := srv.handlePacket(rstQuery)
	rstPacket, err := DnsParser.ExtractVPNResponse(rstResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if rstPacket.PacketType != Enums.PACKET_STREAM_RST_ACK {
		t.Fatalf("unexpected rst ack packet type: got=%d want=%d", rstPacket.PacketType, Enums.PACKET_STREAM_RST_ACK)
	}

	if _, ok := srv.streams.Lookup(sessionID, 9); ok {
		t.Fatal("stream should be removed after reset")
	}
}

func TestHandlePacketIgnoresDuplicateStreamDataWrite(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	initPayload := []byte{0, 0x00, 0x00, 0x96, 0x00, 0xC8, 0x10, 0x20, 0x30, 0x40}
	initResponse := srv.handlePacket(buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, initPayload))
	packet, err := DnsParser.ExtractVPNResponse(initResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	sessionID := packet.Payload[0]
	sessionCookie := packet.Payload[1]

	synQuery := buildTunnelStreamQuery(t, codec, "a.com", sessionID, sessionCookie, Enums.PACKET_STREAM_SYN, 12, 1, nil)
	_ = srv.handlePacket(synQuery)

	upstreamConn, peerConn := net.Pipe()
	defer upstreamConn.Close()
	defer peerConn.Close()
	if _, ok := srv.streams.AttachUpstream(sessionID, 12, "127.0.0.1", 80, upstreamConn, time.Now()); !ok {
		t.Fatal("AttachUpstream returned false")
	}

	readDone := make(chan []byte, 2)
	go func() {
		buffer := make([]byte, 16)
		n, _ := peerConn.Read(buffer)
		readDone <- append([]byte(nil), buffer[:n]...)
		_ = peerConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := peerConn.Read(buffer)
		if err == nil {
			readDone <- append([]byte(nil), buffer[:n]...)
			return
		}
		readDone <- nil
	}()

	dataQuery := buildTunnelStreamQuery(t, codec, "a.com", sessionID, sessionCookie, Enums.PACKET_STREAM_DATA, 12, 9, []byte("hello"))
	_ = srv.handlePacket(dataQuery)
	_ = srv.handlePacket(dataQuery)

	first := <-readDone
	second := <-readDone
	if string(first) != "hello" {
		t.Fatalf("unexpected first payload: %q", first)
	}
	if second != nil {
		t.Fatalf("duplicate stream data must not be written again: %q", second)
	}
}

func TestHandlePacketResetsUnknownStreamData(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	initPayload := []byte{0, 0x00, 0x00, 0x96, 0x00, 0xC8, 0x10, 0x20, 0x30, 0x40}
	initResponse := srv.handlePacket(buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, initPayload))
	packet, err := DnsParser.ExtractVPNResponse(initResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}

	query := buildTunnelStreamQuery(t, codec, "a.com", packet.Payload[0], packet.Payload[1], Enums.PACKET_STREAM_DATA, 77, 5, []byte("hello"))
	response := srv.handlePacket(query)
	vpnResponse, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if vpnResponse.PacketType != Enums.PACKET_STREAM_RST {
		t.Fatalf("unexpected packet type: got=%d want=%d", vpnResponse.PacketType, Enums.PACKET_STREAM_RST)
	}
}

func TestHandlePacketRespondsToSocks5Syn(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	defer upstreamListener.Close()
	go func() {
		conn, acceptErr := upstreamListener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()

	initPayload := []byte{0, 0x00, 0x00, 0x96, 0x00, 0xC8, 0x10, 0x20, 0x30, 0x40}
	initResponse := srv.handlePacket(buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, initPayload))
	packet, err := DnsParser.ExtractVPNResponse(initResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	sessionID := packet.Payload[0]
	sessionCookie := packet.Payload[1]

	_ = srv.handlePacket(buildTunnelStreamQuery(t, codec, "a.com", sessionID, sessionCookie, Enums.PACKET_STREAM_SYN, 15, 1, nil))

	upstreamAddr := upstreamListener.Addr().(*net.TCPAddr)
	targetPayload := []byte{0x01, 127, 0, 0, 1, 0x00, 0x00}
	binary.BigEndian.PutUint16(targetPayload[5:], uint16(upstreamAddr.Port))
	query := buildTunnelStreamQuery(t, codec, "a.com", sessionID, sessionCookie, Enums.PACKET_SOCKS5_SYN, 15, 2, targetPayload)
	response := srv.handlePacket(query)
	vpnResponse, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if vpnResponse.PacketType != Enums.PACKET_SOCKS5_SYN_ACK {
		t.Fatalf("unexpected packet type: got=%d want=%d", vpnResponse.PacketType, Enums.PACKET_SOCKS5_SYN_ACK)
	}

	streamRecord, ok := srv.streams.Lookup(sessionID, 15)
	if !ok {
		t.Fatal("expected stream state to exist")
	}
	if streamRecord.TargetHost != "127.0.0.1" || streamRecord.TargetPort != uint16(upstreamAddr.Port) {
		t.Fatalf("unexpected bound target: %+v", streamRecord)
	}
	if !streamRecord.Connected || streamRecord.UpstreamConn == nil {
		t.Fatalf("expected upstream connection to be stored: %+v", streamRecord)
	}
	_ = streamRecord.UpstreamConn.Close()
}

func TestHandlePacketRejectsInvalidSocks5Syn(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	initPayload := []byte{0, 0x00, 0x00, 0x96, 0x00, 0xC8, 0x10, 0x20, 0x30, 0x40}
	initResponse := srv.handlePacket(buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, initPayload))
	packet, err := DnsParser.ExtractVPNResponse(initResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}

	_ = srv.handlePacket(buildTunnelStreamQuery(t, codec, "a.com", packet.Payload[0], packet.Payload[1], Enums.PACKET_STREAM_SYN, 16, 1, nil))
	query := buildTunnelStreamQuery(t, codec, "a.com", packet.Payload[0], packet.Payload[1], Enums.PACKET_SOCKS5_SYN, 16, 2, []byte{0x09, 0x00, 0x35})
	response := srv.handlePacket(query)
	vpnResponse, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if vpnResponse.PacketType != Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED {
		t.Fatalf("unexpected packet type: got=%d want=%d", vpnResponse.PacketType, Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED)
	}
}

func TestHandlePacketMapsSocks5DialFailure(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)
	srv.dialStreamUpstreamFn = func(network string, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}

	initPayload := []byte{0, 0x00, 0x00, 0x96, 0x00, 0xC8, 0x10, 0x20, 0x30, 0x40}
	initResponse := srv.handlePacket(buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, initPayload))
	packet, err := DnsParser.ExtractVPNResponse(initResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}

	_ = srv.handlePacket(buildTunnelStreamQuery(t, codec, "a.com", packet.Payload[0], packet.Payload[1], Enums.PACKET_STREAM_SYN, 25, 1, nil))
	targetPayload := []byte{0x01, 127, 0, 0, 1, 0x00, 0x50}
	query := buildTunnelStreamQuery(t, codec, "a.com", packet.Payload[0], packet.Payload[1], Enums.PACKET_SOCKS5_SYN, 25, 2, targetPayload)
	response := srv.handlePacket(query)
	vpnResponse, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if vpnResponse.PacketType != Enums.PACKET_SOCKS5_CONNECTION_REFUSED {
		t.Fatalf("unexpected packet type: got=%d want=%d", vpnResponse.PacketType, Enums.PACKET_SOCKS5_CONNECTION_REFUSED)
	}
}

func TestSessionStoreExpiresReuseSignatureWithoutDroppingSession(t *testing.T) {
	store := newSessionStore()
	payload := []byte{1, 0x21, 0x00, 0x96, 0x00, 0xC8, 0x44, 0x33, 0x22, 0x11}

	record, reused, err := store.findOrCreate(payload, 2, 1, 20)
	if err != nil {
		t.Fatalf("findOrCreate returned error: %v", err)
	}
	if reused {
		t.Fatal("first session init should not be reused")
	}
	if record == nil {
		t.Fatal("findOrCreate returned nil record")
	}

	store.mu.Lock()
	store.bySig[record.Signature] = record.ID
	record.ReuseUntil = time.Now().Add(-time.Second)
	record.reuseUntilUnixNano = record.ReuseUntil.UnixNano()
	store.nextReuseSweepUnixNano = record.reuseUntilUnixNano
	store.mu.Unlock()

	store.mu.Lock()
	store.expireReuseLocked(time.Now().UnixNano())
	if store.byID[record.ID] == nil {
		store.mu.Unlock()
		t.Fatal("expired reuse window must not remove active session record")
	}
	if _, ok := store.bySig[record.Signature]; ok {
		store.mu.Unlock()
		t.Fatal("expired reuse window should remove signature mapping")
	}
	store.mu.Unlock()
}

func TestSessionStoreCleanupMovesExpiredSessionToRecentClosed(t *testing.T) {
	store := newSessionStore()
	payload := []byte{1, 0x21, 0x00, 0x96, 0x00, 0xC8, 0x44, 0x33, 0x22, 0x11}

	record, reused, err := store.findOrCreate(payload, 3, 0, 20)
	if err != nil {
		t.Fatalf("findOrCreate returned error: %v", err)
	}
	if reused || record == nil {
		t.Fatal("expected a new session record")
	}

	store.mu.Lock()
	record.setLastActivity(time.Now().Add(-2 * time.Minute))
	expectedCookie := record.Cookie
	store.mu.Unlock()

	expired := store.Cleanup(time.Now(), time.Minute, 10*time.Minute)
	if len(expired) != 1 || expired[0] != record.ID {
		t.Fatalf("unexpected expired sessions: %#v", expired)
	}
	if _, ok := store.Active(record.ID); ok {
		t.Fatal("expired session should no longer be active")
	}
	if cookie, ok := store.ExpectedCookie(record.ID); !ok || cookie != expectedCookie {
		t.Fatalf("recently closed cookie missing: ok=%v cookie=%d expected=%d", ok, cookie, expectedCookie)
	}
	lookup, ok := store.Lookup(record.ID)
	if !ok || lookup.State != sessionLookupClosed {
		t.Fatalf("expected closed lookup state, ok=%v state=%v", ok, lookup.State)
	}
	if lookup.ResponseMode != record.ResponseMode {
		t.Fatalf("recently closed response mode mismatch: got=%d want=%d", lookup.ResponseMode, record.ResponseMode)
	}
}

func TestSessionStoreTouchRefreshesActivity(t *testing.T) {
	store := newSessionStore()
	payload := []byte{1, 0x21, 0x00, 0x96, 0x00, 0xC8, 0x44, 0x33, 0x22, 0x11}

	record, _, err := store.findOrCreate(payload, 0, 0, 20)
	if err != nil {
		t.Fatalf("findOrCreate returned error: %v", err)
	}

	old := time.Unix(0, record.lastActivity())
	time.Sleep(5 * time.Millisecond)
	if !store.Touch(record.ID, time.Now()) {
		t.Fatal("Touch returned false")
	}

	active, ok := store.Active(record.ID)
	if !ok {
		t.Fatal("Active returned false")
	}
	if !active.LastActivityAt.After(old) {
		t.Fatal("last activity timestamp was not updated")
	}
}

func TestSessionStoreValidateAndTouchRefreshesActivity(t *testing.T) {
	store := newSessionStore()
	payload := []byte{1, 0x21, 0x00, 0x96, 0x00, 0xC8, 0x44, 0x33, 0x22, 0x11}

	record, _, err := store.findOrCreate(payload, 0, 0, 20)
	if err != nil {
		t.Fatalf("findOrCreate returned error: %v", err)
	}

	old := time.Unix(0, record.lastActivity())
	time.Sleep(5 * time.Millisecond)
	result := store.ValidateAndTouch(record.ID, record.Cookie, time.Now())
	if !result.Known || !result.Valid {
		t.Fatalf("expected valid active session result, got=%+v", result)
	}
	if result.Lookup.State != sessionLookupActive {
		t.Fatalf("unexpected lookup state: got=%v want=%v", result.Lookup.State, sessionLookupActive)
	}

	active, ok := store.Active(record.ID)
	if !ok {
		t.Fatal("Active returned false")
	}
	if !active.LastActivityAt.After(old) {
		t.Fatal("ValidateAndTouch should refresh last activity timestamp")
	}
}

func TestHandlePacketReturnsInvalidSessionErrorForRecentlyClosedCookieThreshold(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:               65535,
		Domain:                      []string{"a.com"},
		MinVPNLabelLength:           3,
		InvalidCookieErrorThreshold: 1,
		InvalidCookieWindowSecs:     2.0,
		ClosedSessionRetentionSecs:  600.0,
	}, nil, codec)

	verifyCode := []byte{0x44, 0x33, 0x22, 0x11}
	initPayload := []byte{
		1,
		0x00,
		0x00, 0x96,
		0x00, 0xC8,
		verifyCode[0], verifyCode[1], verifyCode[2], verifyCode[3],
	}

	initResponse := srv.handlePacket(buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, initPayload))
	packet, err := DnsParser.ExtractVPNResponse(initResponse, true)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}

	sessionID := packet.Payload[0]
	validCookie := packet.Payload[1]
	if !srv.sessions.Close(sessionID, time.Now(), 10*time.Minute) {
		t.Fatal("expected session to close")
	}

	staleQuery := buildTunnelQueryWithCookie(t, codec, "a.com", sessionID, validCookie+1, Enums.PACKET_PING, nil)
	response := srv.handlePacket(staleQuery)
	if len(response) == 0 {
		t.Fatal("recently closed invalid cookie packet should get an error response after threshold")
	}

	errorPacket, err := DnsParser.ExtractVPNResponse(response, true)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if errorPacket.PacketType != Enums.PACKET_ERROR_DROP {
		t.Fatalf("unexpected packet type: got=%d want=%d", errorPacket.PacketType, Enums.PACKET_ERROR_DROP)
	}
	if errorPacket.SessionID != sessionID {
		t.Fatalf("unexpected session id: got=%d want=%d", errorPacket.SessionID, sessionID)
	}
}

func TestHandlePacketRespondsToDNSQueryRequest(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)
	srv.resolveDNSQueryFn = func(rawQuery []byte) ([]byte, error) {
		return DnsParser.BuildServerFailureResponse(rawQuery)
	}

	verifyCode := []byte{0x12, 0x34, 0x56, 0x78}
	initPayload := []byte{
		0,
		0x00,
		0x00, 0x96,
		0x00, 0xC8,
		verifyCode[0], verifyCode[1], verifyCode[2], verifyCode[3],
	}

	initResponse := srv.handlePacket(buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, initPayload))
	packet, err := DnsParser.ExtractVPNResponse(initResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}

	sessionID := packet.Payload[0]
	sessionCookie := packet.Payload[1]
	rawQuery := buildServerTestQuery(0x4444, "example.com", Enums.DNS_RECORD_TYPE_A)

	query := buildTunnelDNSQuery(t, codec, "a.com", sessionID, sessionCookie, 17, rawQuery)
	response := srv.handlePacket(query)
	if len(response) == 0 {
		t.Fatal("expected dns query response packet")
	}

	vpnResponse, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if vpnResponse.PacketType != Enums.PACKET_DNS_QUERY_RES {
		t.Fatalf("unexpected packet type: got=%d want=%d", vpnResponse.PacketType, Enums.PACKET_DNS_QUERY_RES)
	}
	if vpnResponse.StreamID != 0 || vpnResponse.SequenceNum != 17 {
		t.Fatalf("unexpected stream routing: stream=%d seq=%d", vpnResponse.StreamID, vpnResponse.SequenceNum)
	}
	if vpnResponse.SessionID != sessionID || vpnResponse.SessionCookie != sessionCookie {
		t.Fatalf("unexpected session routing: sid=%d cookie=%d", vpnResponse.SessionID, vpnResponse.SessionCookie)
	}

	dnsResponse, err := DnsParser.ParsePacketLite(vpnResponse.Payload)
	if err != nil || !dnsResponse.HasQuestion {
		t.Fatalf("expected raw dns response payload, err=%v", err)
	}
	if dnsResponse.Header.RCode != Enums.DNSR_CODE_SERVER_FAILURE {
		t.Fatalf("unexpected dns rcode: got=%d want=%d", dnsResponse.Header.RCode, Enums.DNSR_CODE_SERVER_FAILURE)
	}
	if dnsResponse.FirstQuestion.Name != "example.com" {
		t.Fatalf("unexpected dns qname: got=%q", dnsResponse.FirstQuestion.Name)
	}
}

func TestHandlePacketAssemblesFragmentedDNSQueryRequest(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	rawQuery := buildServerTestQuery(0x5555, "example.com", Enums.DNS_RECORD_TYPE_A)
	var upstreamCalls int
	srv.resolveDNSQueryFn = func(query []byte) ([]byte, error) {
		upstreamCalls++
		if string(query) != string(rawQuery) {
			t.Fatal("unexpected assembled dns query")
		}
		return DnsParser.BuildServerFailureResponse(query)
	}

	verifyCode := []byte{0x12, 0x34, 0x56, 0x78}
	initPayload := []byte{
		0,
		0x00,
		0x00, 0x96,
		0x00, 0xC8,
		verifyCode[0], verifyCode[1], verifyCode[2], verifyCode[3],
	}
	initResponse := srv.handlePacket(buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, initPayload))
	packet, err := DnsParser.ExtractVPNResponse(initResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}

	sessionID := packet.Payload[0]
	sessionCookie := packet.Payload[1]
	fragment0 := rawQuery[:len(rawQuery)/2]
	fragment1 := rawQuery[len(rawQuery)/2:]

	firstQuery := buildTunnelDNSQueryFragment(t, codec, "a.com", sessionID, sessionCookie, 19, 0, 2, fragment0)
	firstResponse := srv.handlePacket(firstQuery)
	if len(firstResponse) == 0 {
		t.Fatal("expected placeholder dns response for first fragment")
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream should not be called before final fragment, got=%d", upstreamCalls)
	}

	secondQuery := buildTunnelDNSQueryFragment(t, codec, "a.com", sessionID, sessionCookie, 19, 1, 2, fragment1)
	secondResponse := srv.handlePacket(secondQuery)
	if len(secondResponse) == 0 {
		t.Fatal("expected dns response packet for final fragment")
	}
	if upstreamCalls != 1 {
		t.Fatalf("unexpected upstream call count: got=%d want=1", upstreamCalls)
	}

	vpnResponse, err := DnsParser.ExtractVPNResponse(secondResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if vpnResponse.PacketType != Enums.PACKET_DNS_QUERY_RES {
		t.Fatalf("unexpected packet type: got=%d want=%d", vpnResponse.PacketType, Enums.PACKET_DNS_QUERY_RES)
	}
}

func TestHandlePacketCachesUpstreamDNSResponse(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:      65535,
		Domain:             []string{"a.com"},
		MinVPNLabelLength:  3,
		DNSCacheMaxRecords: 8,
		DNSCacheTTLSeconds: 60,
	}, nil, codec)

	rawQuery := buildServerTestQuery(0x1111, "example.com", Enums.DNS_RECORD_TYPE_A)
	var upstreamCalls int
	srv.resolveDNSQueryFn = func(query []byte) ([]byte, error) {
		upstreamCalls++
		return DnsParser.BuildServerFailureResponse(query)
	}

	verifyCode := []byte{0x12, 0x34, 0x56, 0x78}
	initPayload := []byte{
		0,
		0x00,
		0x00, 0x96,
		0x00, 0xC8,
		verifyCode[0], verifyCode[1], verifyCode[2], verifyCode[3],
	}
	initResponse := srv.handlePacket(buildTunnelQueryWithSessionID(t, codec, "a.com", 0, Enums.PACKET_SESSION_INIT, initPayload))
	packet, err := DnsParser.ExtractVPNResponse(initResponse, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}

	sessionID := packet.Payload[0]
	sessionCookie := packet.Payload[1]
	query1 := buildTunnelDNSQuery(t, codec, "a.com", sessionID, sessionCookie, 21, rawQuery)
	query2 := buildTunnelDNSQuery(t, codec, "a.com", sessionID, sessionCookie, 22, rawQuery)

	if response := srv.handlePacket(query1); len(response) == 0 {
		t.Fatal("expected dns response packet")
	}
	if response := srv.handlePacket(query2); len(response) == 0 {
		t.Fatal("expected cached dns response packet")
	}
	if upstreamCalls != 1 {
		t.Fatalf("expected cached second response, got upstreamCalls=%d", upstreamCalls)
	}
}

func buildServerTestQuery(id uint16, name string, qtype uint16) []byte {
	qname := encodeServerTestName(name)
	packet := make([]byte, 12+len(qname)+4)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)

	offset := 12
	offset += copy(packet[offset:], qname)
	binary.BigEndian.PutUint16(packet[offset:offset+2], qtype)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	return packet
}

func encodeServerTestName(name string) []byte {
	encoded := make([]byte, 0, len(name)+2)
	labelStart := 0
	for i := 0; i <= len(name); i++ {
		if i != len(name) && name[i] != '.' {
			continue
		}
		encoded = append(encoded, byte(i-labelStart))
		encoded = append(encoded, name[labelStart:i]...)
		labelStart = i + 1
	}
	return append(encoded, 0)
}

func buildTunnelQuery(t *testing.T, codec *security.Codec, name string, packetType uint8, payload []byte) []byte {
	return buildTunnelQueryWithSessionID(t, codec, name, 255, packetType, payload)
}

func buildTunnelQueryWithSessionID(t *testing.T, codec *security.Codec, name string, sessionID uint8, packetType uint8, payload []byte) []byte {
	return buildTunnelQueryWithCookie(t, codec, name, sessionID, 0, packetType, payload)
}

func buildTunnelQueryWithCookie(t *testing.T, codec *security.Codec, name string, sessionID uint8, sessionCookie uint8, packetType uint8, payload []byte) []byte {
	t.Helper()

	encoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID:      sessionID,
		PacketType:     packetType,
		SessionCookie:  sessionCookie,
		StreamID:       1,
		SequenceNum:    1,
		TotalFragments: 1,
		Payload:        payload,
	}, codec)
	if err != nil {
		t.Fatalf("BuildEncoded returned error: %v", err)
	}

	questionName, err := DnsParser.BuildTunnelQuestionName(name, encoded)
	if err != nil {
		t.Fatalf("BuildTunnelQuestionName returned error: %v", err)
	}

	query, err := DnsParser.BuildTXTQuestionPacket(questionName, Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}
	return query
}

func buildTunnelDNSQuery(t *testing.T, codec *security.Codec, name string, sessionID uint8, sessionCookie uint8, sequenceNum uint16, payload []byte) []byte {
	return buildTunnelDNSQueryFragment(t, codec, name, sessionID, sessionCookie, sequenceNum, 0, 1, payload)
}

func buildTunnelStreamQuery(t *testing.T, codec *security.Codec, name string, sessionID uint8, sessionCookie uint8, packetType uint8, streamID uint16, sequenceNum uint16, payload []byte) []byte {
	t.Helper()

	encoded, err := VpnProto.BuildEncodedAuto(VpnProto.BuildOptions{
		SessionID:       sessionID,
		PacketType:      packetType,
		SessionCookie:   sessionCookie,
		StreamID:        streamID,
		SequenceNum:     sequenceNum,
		FragmentID:      0,
		TotalFragments:  1,
		CompressionType: 0,
		Payload:         payload,
	}, codec, 100)
	if err != nil {
		t.Fatalf("BuildEncodedAuto returned error: %v", err)
	}

	questionName, err := DnsParser.BuildTunnelQuestionName(name, encoded)
	if err != nil {
		t.Fatalf("BuildTunnelQuestionName returned error: %v", err)
	}

	query, err := DnsParser.BuildTXTQuestionPacket(questionName, Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}
	return query
}

func buildTunnelDNSQueryFragment(t *testing.T, codec *security.Codec, name string, sessionID uint8, sessionCookie uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, payload []byte) []byte {
	t.Helper()

	encoded, err := VpnProto.BuildEncodedAuto(VpnProto.BuildOptions{
		SessionID:       sessionID,
		PacketType:      Enums.PACKET_DNS_QUERY_REQ,
		SessionCookie:   sessionCookie,
		StreamID:        0,
		SequenceNum:     sequenceNum,
		FragmentID:      fragmentID,
		TotalFragments:  totalFragments,
		CompressionType: 0,
		Payload:         payload,
	}, codec, 100)
	if err != nil {
		t.Fatalf("BuildEncodedAuto returned error: %v", err)
	}

	questionName, err := DnsParser.BuildTunnelQuestionName(name, encoded)
	if err != nil {
		t.Fatalf("BuildTunnelQuestionName returned error: %v", err)
	}

	query, err := DnsParser.BuildTXTQuestionPacket(questionName, Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}
	return query
}
