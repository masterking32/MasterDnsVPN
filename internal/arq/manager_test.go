// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package arq

import (
	"testing"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

func TestDataAckRemovesOutOfOrderAndOpensWindow(t *testing.T) {
	now := time.Unix(1700000000, 0)
	manager := NewManager(3, DefaultDataPolicy(), DefaultControlPolicy())

	if !manager.EnqueueData(Enums.PACKET_STREAM_DATA, 1, 1, []byte("a"), now) {
		t.Fatal("enqueue seq=1 failed")
	}
	if !manager.EnqueueData(Enums.PACKET_STREAM_DATA, 1, 2, []byte("b"), now) {
		t.Fatal("enqueue seq=2 failed")
	}
	if !manager.EnqueueData(Enums.PACKET_STREAM_DATA, 1, 3, []byte("c"), now) {
		t.Fatal("enqueue seq=3 failed")
	}
	if manager.CanEnqueueData() {
		t.Fatal("window should be full")
	}

	if !manager.AcknowledgeData(2) {
		t.Fatal("ack seq=2 should succeed")
	}
	if manager.PendingData() != 2 {
		t.Fatalf("unexpected pending data count: got=%d want=2", manager.PendingData())
	}
	if !manager.CanEnqueueData() {
		t.Fatal("window should have reopened after out-of-order ack")
	}
}

func TestControlAckRemovesTrackedPacket(t *testing.T) {
	now := time.Unix(1700000000, 0)
	manager := NewManager(4, DefaultDataPolicy(), DefaultControlPolicy())

	ok := manager.EnqueueControl(
		Enums.PACKET_STREAM_RST,
		Enums.PACKET_STREAM_RST_ACK,
		1,
		77,
		nil,
		0,
		true,
		now,
	)
	if !ok {
		t.Fatal("enqueue control failed")
	}

	if !manager.AcknowledgeControl(Enums.PACKET_STREAM_RST_ACK, 77) {
		t.Fatal("control ack should remove tracked packet")
	}

	due := manager.NextControl(now.Add(time.Second), 10)
	if len(due) != 0 {
		t.Fatalf("expected no due control packets after ack, got=%d", len(due))
	}
}

func TestRetransmitSchedulerAvoidsSpam(t *testing.T) {
	now := time.Unix(1700000000, 0)
	manager := NewManager(4, DefaultDataPolicy(), DefaultControlPolicy())

	if !manager.EnqueueData(Enums.PACKET_STREAM_DATA, 1, 1, []byte("hello"), now) {
		t.Fatal("enqueue data failed")
	}

	first := manager.NextData(now, 10)
	if len(first) != 1 {
		t.Fatalf("expected first due send, got=%d", len(first))
	}

	immediate := manager.NextData(now, 10)
	if len(immediate) != 0 {
		t.Fatalf("packet should not be resent immediately, got=%d", len(immediate))
	}

	tooEarly := manager.NextData(now.Add(700*time.Millisecond), 10)
	if len(tooEarly) != 0 {
		t.Fatalf("packet should not be resent before RTO, got=%d", len(tooEarly))
	}

	second := manager.NextData(now.Add(1200*time.Millisecond), 10)
	if len(second) != 1 {
		t.Fatalf("expected resend after RTO, got=%d", len(second))
	}
	if second[0].Retries != 1 {
		t.Fatalf("unexpected retry count on resend packet: got=%d want=1", second[0].Retries)
	}
}

func TestHandleRemoteResetKeepsOnlyEssentialControlPackets(t *testing.T) {
	now := time.Unix(1700000000, 0)
	manager := NewManager(4, DefaultDataPolicy(), DefaultControlPolicy())

	if !manager.EnqueueData(Enums.PACKET_STREAM_DATA, 1, 1, []byte("hello"), now) {
		t.Fatal("enqueue data failed")
	}
	if !manager.EnqueueControl(Enums.PACKET_STREAM_DATA_ACK, 0, 1, 1, nil, 0, false, now) {
		t.Fatal("enqueue ack control failed")
	}
	if !manager.EnqueueControl(Enums.PACKET_STREAM_RST_ACK, Enums.PACKET_STREAM_RST_ACK, 1, 2, nil, 0, true, now) {
		t.Fatal("enqueue rst-ack control failed")
	}

	droppedData, droppedControl := manager.HandleRemoteReset()
	if droppedData != 1 {
		t.Fatalf("unexpected dropped data count: got=%d want=1", droppedData)
	}
	if droppedControl != 1 {
		t.Fatalf("unexpected dropped control count: got=%d want=1", droppedControl)
	}

	remaining := manager.NextControl(now, 10)
	if len(remaining) != 1 {
		t.Fatalf("expected one essential control packet to remain, got=%d", len(remaining))
	}
	if remaining[0].PacketType != Enums.PACKET_STREAM_RST_ACK {
		t.Fatalf("unexpected surviving control packet: got=%d want=%d", remaining[0].PacketType, Enums.PACKET_STREAM_RST_ACK)
	}
}

func TestControlPriorityOrdering(t *testing.T) {
	now := time.Unix(1700000000, 0)
	manager := NewManager(4, DefaultDataPolicy(), DefaultControlPolicy())

	if !manager.EnqueueControl(Enums.PACKET_SOCKS5_SYN_ACK, Enums.PACKET_SOCKS5_SYN_ACK, 1, 9, nil, 5, false, now) {
		t.Fatal("enqueue high-priority-number control failed")
	}
	if !manager.EnqueueControl(Enums.PACKET_STREAM_RST_ACK, Enums.PACKET_STREAM_RST_ACK, 1, 10, nil, 0, true, now) {
		t.Fatal("enqueue low-priority-number control failed")
	}

	packets := manager.NextControl(now, 2)
	if len(packets) != 2 {
		t.Fatalf("expected two due control packets, got=%d", len(packets))
	}
	if packets[0].PacketType != Enums.PACKET_STREAM_RST_ACK {
		t.Fatalf("unexpected first control packet: got=%d want=%d", packets[0].PacketType, Enums.PACKET_STREAM_RST_ACK)
	}
}
