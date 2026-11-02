package udpserver

import (
	"encoding/binary"
	"sync"
	"testing"

	"masterdnsvpn-go/internal/arq"
	"masterdnsvpn-go/internal/compression"
	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func TestSessionInitPolicyMTULimitsAreAppliedToServerSession(t *testing.T) {
	store := newSessionStore(16, 32)
	payload := make([]byte, sessionInitDataSize)
	payload[0] = mtuProbeModeRaw
	binary.BigEndian.PutUint16(payload[2:4], 999)
	binary.BigEndian.PutUint16(payload[4:6], 9999)
	copy(payload[6:10], []byte{1, 2, 3, 4})

	record, reused, err := store.findOrCreate(payload, 0, 0, 10, 150, 2048)
	if err != nil {
		t.Fatalf("findOrCreate returned error: %v", err)
	}
	if reused {
		t.Fatal("expected first session init not to be reused")
	}
	if record.UploadMTU != 150 {
		t.Fatalf("unexpected upload mtu clamp: got=%d want=%d", record.UploadMTU, 150)
	}
	if record.DownloadMTU != 2048 {
		t.Fatalf("unexpected download mtu clamp: got=%d want=%d", record.DownloadMTU, 2048)
	}
}

func TestSessionStoreHonorsConfiguredActiveSessionLimit(t *testing.T) {
	store := newSessionStore(16, 32)
	store.maxActiveSessions = 1

	payloadA := make([]byte, sessionInitDataSize)
	payloadA[0] = mtuProbeModeRaw
	copy(payloadA[6:10], []byte{1, 2, 3, 4})

	record, reused, err := store.findOrCreate(payloadA, 0, 0, 10, 150, 2048)
	if err != nil {
		t.Fatalf("first findOrCreate returned error: %v", err)
	}
	if reused || record == nil {
		t.Fatal("expected first session to be created")
	}

	payloadB := make([]byte, sessionInitDataSize)
	payloadB[0] = mtuProbeModeRaw
	copy(payloadB[6:10], []byte{5, 6, 7, 8})

	record, reused, err = store.findOrCreate(payloadB, 0, 0, 10, 150, 2048)
	if err != ErrSessionTableFull {
		t.Fatalf("expected ErrSessionTableFull, got record=%v reused=%v err=%v", record != nil, reused, err)
	}
}

func TestHandleSessionInitRequestIncludesServerClientPolicy(t *testing.T) {
	cfg := config.ServerConfig{
		ClientMaxPacketDuplicationCount: 5,
		ClientMaxSetupDuplicationCount:  6,
		ClientMaxUploadMTU:              150,
		ClientMaxDownloadMTU:            4096,
		ClientMaxRxTxWorkers:            64,
		ClientMinPingAggressiveInterval: 0.10,
		ClientMaxPacketsPerBatch:        20,
		ClientMaxARQWindowSize:          6000,
		ClientMaxARQDataNackMaxGap:      200,
		ClientMinCompressionMinSize:     120,
		ClientMinARQInitialRTOSeconds:   0.25,
	}

	s := &Server{
		cfg:                     cfg,
		sessions:                newSessionStore(16, 32),
		uploadCompressionMask:   1 << compression.TypeOff,
		downloadCompressionMask: 1 << compression.TypeOff,
	}

	query, err := DnsParser.BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	verifyCode := [4]byte{1, 2, 3, 4}
	initPayload := make([]byte, sessionInitDataSize)
	initPayload[0] = mtuProbeModeRaw
	initPayload[1] = compression.PackPair(compression.TypeOff, compression.TypeOff)
	binary.BigEndian.PutUint16(initPayload[2:4], 220)
	binary.BigEndian.PutUint16(initPayload[4:6], 5000)
	copy(initPayload[6:10], verifyCode[:])

	response := s.handleSessionInitRequest(query, domainMatcher.Decision{RequestName: "x.v.example.com"}, VpnProto.Packet{
		SessionID:  0,
		PacketType: Enums.PACKET_SESSION_INIT,
		Payload:    initPayload,
	})
	if response == nil {
		t.Fatal("expected session accept response")
	}

	packet, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != Enums.PACKET_SESSION_ACCEPT {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, Enums.PACKET_SESSION_ACCEPT)
	}

	accept, err := VpnProto.DecodeSessionAcceptPayload(packet.Payload)
	if err != nil {
		t.Fatalf("DecodeSessionAcceptPayload returned error: %v", err)
	}
	if !accept.HasClientPolicySync {
		t.Fatal("expected session accept to include client policy sync block")
	}
	if accept.VerifyCode != verifyCode {
		t.Fatalf("unexpected verify code: got=%v want=%v", accept.VerifyCode, verifyCode)
	}
	if accept.ClientPolicy.MaxPacketDuplicationCount != cfg.ClientMaxPacketDuplicationCount {
		t.Fatalf("unexpected max packet duplication: got=%d want=%d", accept.ClientPolicy.MaxPacketDuplicationCount, cfg.ClientMaxPacketDuplicationCount)
	}
	if accept.ClientPolicy.MaxSetupDuplicationCount != cfg.ClientMaxSetupDuplicationCount {
		t.Fatalf("unexpected max setup duplication: got=%d want=%d", accept.ClientPolicy.MaxSetupDuplicationCount, cfg.ClientMaxSetupDuplicationCount)
	}
	if accept.ClientPolicy.MaxUploadMTU != cfg.ClientMaxUploadMTU {
		t.Fatalf("unexpected max upload mtu: got=%d want=%d", accept.ClientPolicy.MaxUploadMTU, cfg.ClientMaxUploadMTU)
	}
	if accept.ClientPolicy.MaxDownloadMTU != cfg.ClientMaxDownloadMTU {
		t.Fatalf("unexpected max download mtu: got=%d want=%d", accept.ClientPolicy.MaxDownloadMTU, cfg.ClientMaxDownloadMTU)
	}
	if accept.ClientPolicy.MaxRxTxWorkers != cfg.ClientMaxRxTxWorkers {
		t.Fatalf("unexpected max rx/tx workers: got=%d want=%d", accept.ClientPolicy.MaxRxTxWorkers, cfg.ClientMaxRxTxWorkers)
	}
	if accept.ClientPolicy.MinPingAggressiveInterval < 0.095 || accept.ClientPolicy.MinPingAggressiveInterval > 0.105 {
		t.Fatalf("unexpected min ping aggressive interval: got=%f", accept.ClientPolicy.MinPingAggressiveInterval)
	}
	if accept.ClientPolicy.MaxPacketsPerBatch != cfg.ClientMaxPacketsPerBatch {
		t.Fatalf("unexpected max packets per batch: got=%d want=%d", accept.ClientPolicy.MaxPacketsPerBatch, cfg.ClientMaxPacketsPerBatch)
	}
	if accept.ClientPolicy.MaxARQWindowSize != cfg.ClientMaxARQWindowSize {
		t.Fatalf("unexpected max arq window size: got=%d want=%d", accept.ClientPolicy.MaxARQWindowSize, cfg.ClientMaxARQWindowSize)
	}
	if accept.ClientPolicy.MaxARQDataNackMaxGap != cfg.ClientMaxARQDataNackMaxGap {
		t.Fatalf("unexpected max arq data nack gap: got=%d want=%d", accept.ClientPolicy.MaxARQDataNackMaxGap, cfg.ClientMaxARQDataNackMaxGap)
	}
	if accept.ClientPolicy.MinCompressionMinSize != cfg.ClientMinCompressionMinSize {
		t.Fatalf("unexpected min compression size: got=%d want=%d", accept.ClientPolicy.MinCompressionMinSize, cfg.ClientMinCompressionMinSize)
	}
	if accept.ClientPolicy.MinARQInitialRTOSeconds < 0.245 || accept.ClientPolicy.MinARQInitialRTOSeconds > 0.255 {
		t.Fatalf("unexpected min arq initial rto: got=%f", accept.ClientPolicy.MinARQInitialRTOSeconds)
	}
}

func TestHandleStreamSynRequestRejectsWhenActiveStreamLimitIsReached(t *testing.T) {
	store := newSessionStore(16, 32)
	store.maxActiveStreams = 1

	payload := make([]byte, sessionInitDataSize)
	payload[0] = mtuProbeModeRaw
	copy(payload[6:10], []byte{1, 2, 3, 4})

	record, reused, err := store.findOrCreate(payload, 0, 0, 10, 150, 2048)
	if err != nil {
		t.Fatalf("findOrCreate returned error: %v", err)
	}
	if reused || record == nil {
		t.Fatal("expected a fresh session record")
	}

	stream := record.getOrCreateStream(1, arq.Config{}, nil, nil)
	if stream == nil {
		t.Fatal("expected first user stream to be created")
	}

	s := &Server{sessions: store}
	packet := VpnProto.Packet{
		SessionID:      record.ID,
		SessionCookie:  record.Cookie,
		PacketType:     Enums.PACKET_STREAM_SYN,
		StreamID:       2,
		HasStreamID:    true,
		SequenceNum:    77,
		HasSequenceNum: true,
	}

	if !s.handleStreamSynRequest(packet, &sessionRuntimeView{ID: record.ID}) {
		t.Fatal("expected stream syn over limit to be handled")
	}
	if _, exists := record.getStream(2); exists {
		t.Fatal("did not expect a new stream to be created when limit is reached")
	}

	orphan, _, ok := record.OrphanQueue.Pop()
	if !ok {
		t.Fatal("expected rejection packet in orphan queue")
	}
	if orphan.PacketType != Enums.PACKET_STREAM_CONNECT_FAIL {
		t.Fatalf("unexpected rejection packet type: got=%d want=%d", orphan.PacketType, Enums.PACKET_STREAM_CONNECT_FAIL)
	}
	if orphan.StreamID != 2 || orphan.SequenceNum != 77 {
		t.Fatalf("unexpected rejection packet identity: stream=%d seq=%d", orphan.StreamID, orphan.SequenceNum)
	}
}

// A client races identical SESSION_INIT queries and resolvers retry them, so
// the DNS workers handle duplicates of one session init at the same time and
// all get the same session record. Run with -race.
func TestHandleSessionInitRequestConcurrentDuplicatesShareSessionRecord(t *testing.T) {
	s := New(config.ServerConfig{
		ClientMaxUploadMTU:   150,
		ClientMaxDownloadMTU: 4096,
	}, nil, nil)

	query, err := DnsParser.BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}
	initPayload := make([]byte, sessionInitDataSize)
	initPayload[0] = mtuProbeModeRaw
	initPayload[1] = compression.PackPair(compression.TypeOff, compression.TypeOff)
	binary.BigEndian.PutUint16(initPayload[2:4], 120)
	binary.BigEndian.PutUint16(initPayload[4:6], 400)
	copy(initPayload[6:10], []byte{1, 2, 3, 4})
	packet := VpnProto.Packet{
		SessionID:  0,
		PacketType: Enums.PACKET_SESSION_INIT,
		Payload:    initPayload,
	}

	const duplicates = 4
	responses := make([][]byte, duplicates)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range duplicates {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			responses[i] = s.handleSessionInitRequest(query, domainMatcher.Decision{RequestName: "x.v.example.com"}, packet)
		}()
	}
	close(start)
	wg.Wait()

	var sessionID uint8
	for i, response := range responses {
		if response == nil {
			t.Fatalf("expected session accept response for duplicate %d", i)
		}
		accepted, err := DnsParser.ExtractVPNResponse(response, false)
		if err != nil {
			t.Fatalf("ExtractVPNResponse returned error: %v", err)
		}
		accept, err := VpnProto.DecodeSessionAcceptPayload(accepted.Payload)
		if err != nil {
			t.Fatalf("DecodeSessionAcceptPayload returned error: %v", err)
		}
		if i == 0 {
			sessionID = accept.SessionID
		} else if accept.SessionID != sessionID {
			t.Fatalf("expected duplicates to share session %d, got %d", sessionID, accept.SessionID)
		}
	}

	record, ok := s.sessions.Get(sessionID)
	if !ok {
		t.Fatalf("expected session %d to exist", sessionID)
	}
	if record.streamCleanup == nil {
		t.Fatal("expected the session record to clean up stream artifacts")
	}
}
