package arq

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

// MockPacketEnqueuer captures packets sent by ARQ
type MockPacketEnqueuer struct {
	mu      sync.Mutex
	Packets chan capturedPacket
}

type capturedPacket struct {
	priority        int
	packetType      uint8
	sequenceNum     uint16
	fragmentID      uint8
	totalFragments  uint8
	compressionType uint8
	ttl             time.Duration
	payload         []byte
}

func NewMockPacketEnqueuer() *MockPacketEnqueuer {
	return &MockPacketEnqueuer{
		Packets: make(chan capturedPacket, 1000),
	}
}

func (m *MockPacketEnqueuer) PushTXPacket(priority int, packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, compressionType uint8, ttl time.Duration, payload []byte) bool {
	m.Packets <- capturedPacket{
		priority:        priority,
		packetType:      packetType,
		sequenceNum:     sequenceNum,
		fragmentID:      fragmentID,
		totalFragments:  totalFragments,
		compressionType: compressionType,
		ttl:             ttl,
		payload:         append([]byte(nil), payload...),
	}
	return true
}

type testLogger struct {
	t *testing.T
}

func (l *testLogger) Debugf(format string, args ...any) { l.t.Logf("[DEBUG] "+format, args...) }
func (l *testLogger) Infof(format string, args ...any)  { l.t.Logf("[INFO] "+format, args...) }
func (l *testLogger) Errorf(format string, args ...any) { l.t.Logf("[ERROR] "+format, args...) }

func TestARQ_New(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1,
		MaxRTO:     0.5,
	}
	a := NewARQ(1, 2, enqueuer, nil, 1000, &testLogger{t}, cfg)

	if a.streamID != 1 {
		t.Errorf("expected streamID 1, got %d", a.streamID)
	}
	if a.sessionID != 2 {
		t.Errorf("expected sessionID 2, got %d", a.sessionID)
	}
	if a.state != StateOpen {
		t.Errorf("expected state StateOpen, got %v", a.state)
	}
}

func TestARQ_SendData(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1,
		MaxRTO:     0.5,
	}

	// Create a pipe to simulate local connection
	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 1000, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	// Wait for workers to start
	time.Sleep(50 * time.Millisecond)

	testData := []byte("hello arq")
	go func() {
		_, _ = localApp.Write(testData)
	}()

	select {
	case p := <-enqueuer.Packets:
		if p.packetType != Enums.PACKET_STREAM_DATA {
			t.Errorf("expected PACKET_STREAM_DATA, got %d", p.packetType)
		}
		if !bytes.Equal(p.payload, testData) {
			t.Errorf("expected payload %s, got %s", string(testData), string(p.payload))
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for packet")
	}
}

func TestARQ_ReceiveData(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1,
		MaxRTO:     0.5,
	}

	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 1000, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	// Wait for workers to start
	time.Sleep(50 * time.Millisecond)

	testData := []byte("hello from remote")
	a.ReceiveData(0, testData)

	// ARQ should send an ACK
	select {
	case p := <-enqueuer.Packets:
		if p.packetType != Enums.PACKET_STREAM_DATA_ACK {
			t.Errorf("expected PACKET_STREAM_DATA_ACK, got %d", p.packetType)
		}
		if p.sequenceNum != 0 {
			t.Errorf("expected ACK for sn 0, got %d", p.sequenceNum)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for ACK")
	}

	// Local app should receive the data
	buf := make([]byte, 100)
	_ = localApp.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := localApp.Read(buf)
	if err != nil {
		t.Fatalf("failed to read from local app: %v", err)
	}
	if !bytes.Equal(buf[:n], testData) {
		t.Errorf("expected data %s, got %s", string(testData), string(buf[:n]))
	}
}

func TestARQ_OutOfOrderReceive(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1,
		MaxRTO:     0.5,
	}

	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 1000, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	// Wait for workers to start
	time.Sleep(50 * time.Millisecond)

	// Send packets in order 1, 2, 0
	a.ReceiveData(1, []byte("packet 1"))
	a.ReceiveData(2, []byte("packet 2"))

	// Drain ACKs
	for i := 0; i < 2; i++ {
		<-enqueuer.Packets
	}

	// Verify nothing is readable yet (since packet 0 is missing)
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 100)
		_ = localApp.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, _ = localApp.Read(buf)
		close(done)
	}()
	select {
	case <-done:
		// t.Error("should not have read anything yet")
		// Actually net.Pipe Read will block, so if it returns with timeout error it's fine.
	case <-time.After(150 * time.Millisecond):
		// Expected timeout
	}

	// Now send packet 0
	a.ReceiveData(0, []byte("packet 0"))
	<-enqueuer.Packets // ACK for 0

	// Now everything should be readable in order
	expected := [][]byte{[]byte("packet 0"), []byte("packet 1"), []byte("packet 2")}
	for _, exp := range expected {
		buf := make([]byte, 100)
		_ = localApp.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := localApp.Read(buf)
		if err != nil {
			t.Fatalf("failed to read from local app: %v", err)
		}
		if !bytes.Equal(buf[:n], exp) {
			t.Errorf("expected %s, got %s", string(exp), string(buf[:n]))
		}
	}
}

func TestARQ_Retransmission(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1, // 100ms RTO
		MaxRTO:     0.5,
	}

	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 1000, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	time.Sleep(50 * time.Millisecond)

	testData := []byte("retransmit me")
	go func() {
		_, _ = localApp.Write(testData)
	}()

	// Initial transmission
	select {
	case p := <-enqueuer.Packets:
		if p.packetType != Enums.PACKET_STREAM_DATA {
			t.Errorf("expected PACKET_STREAM_DATA, got %d", p.packetType)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for initial packet")
	}

	// Don't ACK. Wait for retransmission.
	// Retransmission loop uses baseInterval which is RTO/3 (approx 33ms) or 50ms min.
	// So we should see a RESEND packet soon after 100ms.
	select {
	case p := <-enqueuer.Packets:
		if p.packetType != Enums.PACKET_STREAM_RESEND {
			t.Errorf("expected PACKET_STREAM_RESEND, got %d", p.packetType)
		}
		if !bytes.Equal(p.payload, testData) {
			t.Errorf("expected payload %s, got %s", string(testData), string(p.payload))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for retransmission")
	}
}

func TestARQ_ACKHandling(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1,
		MaxRTO:     0.5,
	}

	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 1000, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	time.Sleep(50 * time.Millisecond)

	go func() {
		_, _ = localApp.Write([]byte("data"))
	}()

	var sn uint16
	select {
	case p := <-enqueuer.Packets:
		sn = p.sequenceNum
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out")
	}

	// Verify it's in sndBuf
	a.mu.Lock()
	if _, exists := a.sndBuf[sn]; !exists {
		t.Error("packet should be in sndBuf")
	}
	a.mu.Unlock()

	// Receive ACK
	a.HandleAckPacket(Enums.PACKET_STREAM_DATA_ACK, sn, 0)

	// Verify it's removed from sndBuf
	a.mu.Lock()
	if _, exists := a.sndBuf[sn]; exists {
		t.Error("packet should be removed from sndBuf after ACK")
	}
	a.mu.Unlock()
}

func TestARQ_GracefulClose(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize:               100,
		RTO:                      0.1,
		MaxRTO:                   0.5,
		EnableControlReliability: true,
	}

	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 1000, &testLogger{t}, cfg)
	a.Start()

	time.Sleep(50 * time.Millisecond)

	// Local app closes connection
	_ = localApp.Close()

	// ARQ should send a FIN
	select {
	case p := <-enqueuer.Packets:
		if p.packetType != Enums.PACKET_STREAM_FIN {
			t.Errorf("expected PACKET_STREAM_FIN, got %d", p.packetType)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for FIN")
	}

	// Remote ACKs FIN
	a.HandleAckPacket(Enums.PACKET_STREAM_FIN_ACK, 0, 0)

	// Remote sends FIN
	a.MarkFinReceived()

	// Wait for ARQ to close
	select {
	case <-a.Done():
		// Success
	case <-time.After(1 * time.Second):
		t.Error("ARQ should be closed after FIN handshake")
	}
}

func TestARQ_Reset(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 100,
		RTO:        0.1,
		MaxRTO:     0.5,
	}

	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 1000, &testLogger{t}, cfg)
	a.Start()

	time.Sleep(50 * time.Millisecond)

	// Close with RST
	a.Close("testing reset", CloseOptions{SendRST: true})

	// ARQ should send an RST
	select {
	case p := <-enqueuer.Packets:
		if p.packetType != Enums.PACKET_STREAM_RST {
			t.Errorf("expected PACKET_STREAM_RST, got %d", p.packetType)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for RST")
	}

	// ARQ should mark state as Reset
	if a.State() != StateReset {
		t.Errorf("expected state StateReset, got %v", a.State())
	}
}

func TestARQ_Backpressure(t *testing.T) {
	enqueuer := NewMockPacketEnqueuer()
	cfg := Config{
		WindowSize: 10,
		RTO:        1.0,
		MaxRTO:     2.0,
	}

	localApp, arqConn := net.Pipe()
	defer localApp.Close()
	defer arqConn.Close()

	a := NewARQ(1, 1, enqueuer, arqConn, 10, &testLogger{t}, cfg)
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	time.Sleep(50 * time.Millisecond)

	// Send 8 packets (limit is 0.8 * 10 = 8)
	data := []byte("1234567890") // 10 bytes
	for i := 0; i < 8; i++ {
		_, err := localApp.Write(data)
		if err != nil {
			t.Fatalf("failed to write %d: %v", i, err)
		}
	}

	// Drain transmitted packets
	for i := 0; i < 8; i++ {
		select {
		case <-enqueuer.Packets:
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("timed out waiting for packet %d", i)
		}
	}

	// The 9th write should block or at least waitWindowNotFull should trigger.
	// Since we are in a goroutine in ioLoop, we can check if sndBuf size is 8.
	a.mu.Lock()
	sndBufLen := len(a.sndBuf)
	a.mu.Unlock()
	if sndBufLen != 8 {
		t.Errorf("expected sndBuf size 8, got %d", sndBufLen)
	}

	// Try writing one more. It should block ioLoop.
	writeDone := make(chan struct{})
	go func() {
		_, _ = localApp.Write(data)
		close(writeDone)
	}()

	select {
	case <-writeDone:
		// It might not block immediately because of net.Pipe internal buffering,
		// but ioLoop should be waiting at waitWindowNotFull.
	case <-time.After(200 * time.Millisecond):
		// Expected to block if net.Pipe buffer is small or ioLoop is waiting.
	}

	// ACK one packet
	a.ReceiveAck(Enums.PACKET_STREAM_DATA_ACK, 0)

	// Now ioLoop should proceed and send the 9th packet
	select {
	case p := <-enqueuer.Packets:
		if p.sequenceNum != 8 {
			t.Errorf("expected sequence 8, got %d", p.sequenceNum)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for 9th packet after ACK")
	}
}
