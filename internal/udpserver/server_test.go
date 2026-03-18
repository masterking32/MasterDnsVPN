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
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	ENUMS "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	VPNProto "masterdnsvpn-go/internal/vpnproto"
)

func TestHandlePacketDropsDNSResponses(t *testing.T) {
	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, nil)

	packet := buildServerTestQuery(0x1001, "vpn.a.com", ENUMS.DNSRecordTypeTXT)
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

	packet := buildServerTestQuery(0x2002, "evil.com", ENUMS.DNSRecordTypeTXT)
	response := srv.handlePacket(packet)
	if len(response) == 0 {
		t.Fatal("handlePacket should return a DNS response for unauthorized DNS queries")
	}

	if got := binary.BigEndian.Uint16(response[0:2]); got != 0x2002 {
		t.Fatalf("unexpected response id: got=%#x want=%#x", got, 0x2002)
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&0x000F != ENUMS.DNSRCodeNoError {
		t.Fatalf("unexpected rcode: got=%d want=%d", flags&0x000F, ENUMS.DNSRCodeNoError)
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
	query := buildTunnelQuery(t, codec, "a.com", ENUMS.PacketMTUUpReq, payload)
	response := srv.handlePacket(query)
	if len(response) == 0 {
		t.Fatal("handlePacket should return a vpn mtu-up response")
	}

	packet, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != ENUMS.PacketMTUUpRes {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, ENUMS.PacketMTUUpRes)
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
	query := buildTunnelQuery(t, codec, "a.com", ENUMS.PacketMTUDownReq, payload)
	response := srv.handlePacket(query)
	if len(response) == 0 {
		t.Fatal("handlePacket should return a vpn mtu-down response")
	}

	packet, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != ENUMS.PacketMTUDownRes {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, ENUMS.PacketMTUDownRes)
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
	query := buildTunnelQuery(t, codec, "a.com", ENUMS.PacketMTUUpReq, payload)
	response := srv.handlePacket(query)
	if len(response) == 0 {
		t.Fatal("handlePacket should return a vpn mtu-up response")
	}

	packet, err := DnsParser.ExtractVPNResponse(response, true)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != ENUMS.PacketMTUUpRes {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, ENUMS.PacketMTUUpRes)
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

	query1 := buildTunnelQueryWithSessionID(t, codec, "a.com", 0, ENUMS.PacketSessionInit, payload)
	response1 := srv.handlePacket(query1)
	if len(response1) == 0 {
		t.Fatal("handlePacket should return a session accept response")
	}

	packet1, err := DnsParser.ExtractVPNResponse(response1, true)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet1.PacketType != ENUMS.PacketSessionAccept {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet1.PacketType, ENUMS.PacketSessionAccept)
	}
	if len(packet1.Payload) != 7 {
		t.Fatalf("unexpected session payload len: got=%d want=7", len(packet1.Payload))
	}
	if !bytes.Equal(packet1.Payload[3:7], verifyCode) {
		t.Fatalf("unexpected verify code: got=%v want=%v", packet1.Payload[3:7], verifyCode)
	}

	query2 := buildTunnelQueryWithSessionID(t, codec, "a.com", 0, ENUMS.PacketSessionInit, payload)
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
	query := buildTunnelQueryWithSessionID(t, codec, "a.com", 9, ENUMS.PacketSessionInit, payload)
	if response := srv.handlePacket(query); len(response) != 0 {
		t.Fatal("malformed session init must be rejected")
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
	query := buildTunnelQueryWithSessionID(t, codec, "a.com", 0, ENUMS.PacketSessionInit, payload)
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

func TestSessionStoreExpiresReuseSignatureWithoutDroppingSession(t *testing.T) {
	store := newSessionStore()
	payload := []byte{1, 0x21, 0x00, 0x96, 0x00, 0xC8, 0x44, 0x33, 0x22, 0x11}

	record, reused, err := store.findOrCreate(payload, 2, 1)
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
	store.mu.Unlock()

	store.mu.Lock()
	store.expireReuseLocked(time.Now())
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

	record, reused, err := store.findOrCreate(payload, 3, 0)
	if err != nil {
		t.Fatalf("findOrCreate returned error: %v", err)
	}
	if reused || record == nil {
		t.Fatal("expected a new session record")
	}

	store.mu.Lock()
	record.LastActivityAt = time.Now().Add(-2 * time.Minute)
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
}

func TestSessionStoreTouchRefreshesActivity(t *testing.T) {
	store := newSessionStore()
	payload := []byte{1, 0x21, 0x00, 0x96, 0x00, 0xC8, 0x44, 0x33, 0x22, 0x11}

	record, _, err := store.findOrCreate(payload, 0, 0)
	if err != nil {
		t.Fatalf("findOrCreate returned error: %v", err)
	}

	old := record.LastActivityAt
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

func buildServerTestQuery(id uint16, name string, qtype uint16) []byte {
	qname := encodeServerTestName(name)
	packet := make([]byte, 12+len(qname)+4)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)

	offset := 12
	offset += copy(packet[offset:], qname)
	binary.BigEndian.PutUint16(packet[offset:offset+2], qtype)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], ENUMS.DNSQClassIN)
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
	t.Helper()

	encoded, err := VPNProto.BuildEncoded(VPNProto.BuildOptions{
		SessionID:      sessionID,
		PacketType:     packetType,
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

	query, err := DnsParser.BuildTXTQuestionPacket(questionName, ENUMS.DNSRecordTypeTXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}
	return query
}
