package arq

import (
	"io"
	"sync"
	"testing"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

type recordedPacket struct {
	packetType  uint8
	sequenceNum uint16
	payload     []byte
}

type recordingEnqueuer struct {
	mu      sync.Mutex
	packets []recordedPacket
}

func (r *recordingEnqueuer) PushTXPacket(priority int, packetType uint8, sequenceNum uint16, fragmentID uint8, totalFragments uint8, compressionType uint8, payload []byte) bool {
	r.mu.Lock()
	r.packets = append(r.packets, recordedPacket{
		packetType:  packetType,
		sequenceNum: sequenceNum,
		payload:     append([]byte(nil), payload...),
	})
	r.mu.Unlock()
	return true
}

func (r *recordingEnqueuer) count(packetType uint8) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, pkt := range r.packets {
		if pkt.packetType == packetType {
			count++
		}
	}
	return count
}

func (r *recordingEnqueuer) has(packetType uint8) bool {
	return r.count(packetType) > 0
}

type scriptedConn struct {
	mu     sync.Mutex
	reads  [][]byte
	closed bool
}

func newScriptedConn(reads ...[]byte) *scriptedConn {
	cp := make([][]byte, 0, len(reads))
	for _, chunk := range reads {
		cp = append(cp, append([]byte(nil), chunk...))
	}
	return &scriptedConn{reads: cp}
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.EOF
	}
	if len(c.reads) == 0 {
		return 0, io.EOF
	}
	chunk := c.reads[0]
	c.reads = c.reads[1:]
	n := copy(p, chunk)
	return n, nil
}

func (c *scriptedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func (c *scriptedConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func waitUntil(t *testing.T, timeout time.Duration, fn func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestServerNaturalEOFDrainsOutstandingDataBeforeSendingFIN(t *testing.T) {
	conn := newScriptedConn([]byte("hello"))
	enq := &recordingEnqueuer{}
	a := NewARQ(1, 1, enq, conn, 1200, nil, Config{
		IsClient:             false,
		WindowSize:           64,
		RTO:                  0.05,
		MaxRTO:               0.2,
		FinDrainTimeout:      300.0,
		GracefulDrainTimeout: 600.0,
	})
	a.Start()
	defer a.ForceClose("test cleanup")

	waitUntil(t, time.Second, func() bool {
		return enq.has(Enums.PACKET_STREAM_DATA)
	}, "expected server-side ARQ to enqueue initial STREAM_DATA")

	time.Sleep(100 * time.Millisecond)
	if enq.has(Enums.PACKET_STREAM_FIN) {
		t.Fatal("FIN was sent before outstanding data ACKed")
	}
	if enq.has(Enums.PACKET_STREAM_RST) {
		t.Fatal("RST was sent during natural drain before outstanding data ACKed")
	}

	a.ReceiveAck(0)

	waitUntil(t, time.Second, func() bool {
		return enq.has(Enums.PACKET_STREAM_FIN)
	}, "expected FIN after outstanding data drained")

	if enq.has(Enums.PACKET_STREAM_RST) {
		t.Fatal("did not expect RST after successful drain")
	}
}

func TestClientEOFWithOutstandingDataSendsRST(t *testing.T) {
	conn := newScriptedConn([]byte("hello"))
	enq := &recordingEnqueuer{}
	a := NewARQ(2, 1, enq, conn, 1200, nil, Config{
		IsClient:             true,
		WindowSize:           64,
		RTO:                  0.05,
		MaxRTO:               0.2,
		FinDrainTimeout:      300.0,
		GracefulDrainTimeout: 600.0,
	})
	a.Start()
	defer a.ForceClose("test cleanup")

	waitUntil(t, time.Second, func() bool {
		return enq.has(Enums.PACKET_STREAM_RST)
	}, "expected client-side ARQ to send RST after local EOF with outstanding data")

	if enq.has(Enums.PACKET_STREAM_FIN) {
		t.Fatal("did not expect FIN for client-side explicit cancel with outstanding data")
	}
}

func TestRemoteFINWaitsForMissingTailDataBeforeClosing(t *testing.T) {
	enq := &recordingEnqueuer{}
	a := NewARQ(3, 1, enq, nil, 1200, nil, Config{
		IsClient:             false,
		WindowSize:           64,
		RTO:                  0.05,
		MaxRTO:               0.2,
		FinDrainTimeout:      300.0,
		GracefulDrainTimeout: 600.0,
	})
	defer a.ForceClose("test cleanup")

	a.MarkFinReceived(1)

	if a.remoteWriteClosed {
		t.Fatal("remote write should not close before missing tail data arrives")
	}

	a.ReceiveData(0, []byte("tail"))

	waitUntil(t, time.Second, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.remoteWriteClosed
	}, "expected remote EOF to finalize after missing tail data arrived")
}

func TestServerAbortDefersRSTUntilOutstandingDataDrains(t *testing.T) {
	conn := newScriptedConn([]byte("hello"))
	enq := &recordingEnqueuer{}
	a := NewARQ(4, 1, enq, conn, 1200, nil, Config{
		IsClient:               false,
		WindowSize:             64,
		RTO:                    0.05,
		MaxRTO:                 0.2,
		TerminalDrainTimeout:   60.0,
		TerminalAckWaitTimeout: 30.0,
	})
	a.Start()
	defer a.ForceClose("test cleanup")

	waitUntil(t, time.Second, func() bool {
		return enq.has(Enums.PACKET_STREAM_DATA)
	}, "expected initial STREAM_DATA before abort")

	a.Abort("server-side failure after data queued", true)
	time.Sleep(100 * time.Millisecond)

	if enq.has(Enums.PACKET_STREAM_RST) {
		t.Fatal("RST was sent before outstanding data drained")
	}

	a.ReceiveAck(0)

	waitUntil(t, time.Second, func() bool {
		return enq.has(Enums.PACKET_STREAM_RST)
	}, "expected deferred RST after outstanding data drained")
}

func TestTerminalAckTimeoutEventuallyClosesStream(t *testing.T) {
	enq := &recordingEnqueuer{}
	a := NewARQ(5, 1, enq, nil, 1200, nil, Config{
		IsClient:               true,
		WindowSize:             64,
		RTO:                    0.05,
		MaxRTO:                 0.2,
		TerminalDrainTimeout:   60.0,
		TerminalAckWaitTimeout: 30.0,
	})
	a.terminalAckWait = 50 * time.Millisecond
	a.Start()
	defer a.ForceClose("test cleanup")

	a.Abort("client reset", true)

	waitUntil(t, time.Second, func() bool {
		return enq.has(Enums.PACKET_STREAM_RST)
	}, "expected immediate RST")

	waitUntil(t, time.Second, func() bool {
		return a.IsClosed()
	}, "expected stream to close after terminal ack timeout")
}
