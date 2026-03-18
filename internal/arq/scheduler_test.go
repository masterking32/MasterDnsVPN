// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package arq

import (
	"testing"

	Enums "masterdnsvpn-go/internal/enums"
)

func TestPackedControlBlockLimitUsesMtuAndCap(t *testing.T) {
	if got := ComputeClientPackedControlBlockLimit(200, 99); got != 20 {
		t.Fatalf("unexpected client pack limit: got=%d want=20", got)
	}
	if got := ComputeServerPackedControlBlockLimit(200, 99); got != 32 {
		t.Fatalf("unexpected server pack limit: got=%d want=32", got)
	}
	if got := ComputeClientPackedControlBlockLimit(10, 99); got != 1 {
		t.Fatalf("small mtu should clamp to 1, got=%d", got)
	}
	if got := ComputeServerPackedControlBlockLimit(4096, 20); got != 20 {
		t.Fatalf("user cap should still apply, got=%d", got)
	}
}

func TestSchedulerRejectsDuplicateDataAndQueuedResend(t *testing.T) {
	scheduler := NewScheduler(4)

	data := QueuedPacket{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    7,
		SequenceNum: 11,
		Priority:    2,
	}
	if !scheduler.Enqueue(QueueTargetStream, data) {
		t.Fatal("expected first data enqueue to succeed")
	}
	if scheduler.Enqueue(QueueTargetStream, data) {
		t.Fatal("duplicate data packet should be rejected")
	}
	if scheduler.Enqueue(QueueTargetStream, QueuedPacket{
		PacketType:  Enums.PACKET_STREAM_RESEND,
		StreamID:    7,
		SequenceNum: 11,
		Priority:    2,
	}) {
		t.Fatal("resend should be rejected while original data is still queued")
	}
}

func TestSchedulerPreservesRoundRobinForSamePriority(t *testing.T) {
	scheduler := NewScheduler(1)
	if !scheduler.Enqueue(QueueTargetStream, QueuedPacket{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    1,
		SequenceNum: 1,
		Priority:    2,
	}) {
		t.Fatal("expected stream 1 enqueue to succeed")
	}
	if !scheduler.Enqueue(QueueTargetStream, QueuedPacket{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    2,
		SequenceNum: 1,
		Priority:    2,
	}) {
		t.Fatal("expected stream 2 enqueue to succeed")
	}

	first, ok := scheduler.Dequeue()
	if !ok || first.Packet.StreamID != 1 {
		t.Fatalf("expected stream 1 first, got %+v ok=%v", first.Packet, ok)
	}

	second, ok := scheduler.Dequeue()
	if !ok || second.Packet.StreamID != 2 {
		t.Fatalf("expected stream 2 second, got %+v ok=%v", second.Packet, ok)
	}
}

func TestSchedulerPacksSamePriorityControlBlocksAcrossStreams(t *testing.T) {
	scheduler := NewScheduler(4)
	packets := []QueuedPacket{
		{PacketType: Enums.PACKET_STREAM_SYN_ACK, StreamID: 1, SequenceNum: 10, Priority: 3},
		{PacketType: Enums.PACKET_STREAM_FIN_ACK, StreamID: 1, SequenceNum: 11, Priority: 3},
		{PacketType: Enums.PACKET_STREAM_RST_ACK, StreamID: 2, SequenceNum: 20, Priority: 3},
		{PacketType: Enums.PACKET_SOCKS5_CONNECT_FAIL, StreamID: 2, SequenceNum: 21, Priority: 3},
		{PacketType: Enums.PACKET_STREAM_DATA, StreamID: 3, SequenceNum: 1, Priority: 4},
	}
	for _, packet := range packets {
		if !scheduler.Enqueue(QueueTargetStream, packet) {
			t.Fatalf("failed to enqueue packet: %+v", packet)
		}
	}

	result, ok := scheduler.Dequeue()
	if !ok {
		t.Fatal("expected dequeue result")
	}
	if result.Packet.PacketType != Enums.PACKET_PACKED_CONTROL_BLOCKS {
		t.Fatalf("expected packed control blocks, got packet type=%d", result.Packet.PacketType)
	}
	if result.PackedBlocks != 3 {
		t.Fatalf("unexpected packed block count: got=%d want=3", result.PackedBlocks)
	}
	if len(result.Packet.Payload) != 3*PackedControlBlockSize {
		t.Fatalf("unexpected packed payload size: got=%d", len(result.Packet.Payload))
	}

	next, ok := scheduler.Dequeue()
	if !ok || next.Packet.PacketType != Enums.PACKET_SOCKS5_CONNECT_FAIL {
		t.Fatalf("expected remaining same-stream control packet, got=%+v ok=%v", next.Packet, ok)
	}

	last, ok := scheduler.Dequeue()
	if !ok || last.Packet.PacketType != Enums.PACKET_STREAM_DATA {
		t.Fatalf("expected remaining data packet, got=%+v ok=%v", next.Packet, ok)
	}
}

func TestSchedulerSkipsPingWhenRealTrafficExists(t *testing.T) {
	scheduler := NewScheduler(1)
	if !scheduler.Enqueue(QueueTargetMain, QueuedPacket{
		PacketType: Enums.PACKET_PING,
		StreamID:   0,
		Priority:   2,
	}) {
		t.Fatal("failed to enqueue ping")
	}
	if !scheduler.Enqueue(QueueTargetStream, QueuedPacket{
		PacketType:  Enums.PACKET_STREAM_DATA,
		StreamID:    8,
		SequenceNum: 1,
		Priority:    2,
	}) {
		t.Fatal("failed to enqueue data")
	}

	result, ok := scheduler.Dequeue()
	if !ok || result.Packet.PacketType != Enums.PACKET_STREAM_DATA {
		t.Fatalf("expected data to win over ping, got=%+v ok=%v", result.Packet, ok)
	}
	if scheduler.Pending() != 0 {
		t.Fatalf("expected ping to be dropped after data was preferred, pending=%d", scheduler.Pending())
	}
}

func TestSchedulerHandleStreamResetKeepsOnlyResetControlsInMain(t *testing.T) {
	scheduler := NewScheduler(4)
	queued := []struct {
		target QueueTarget
		packet QueuedPacket
	}{
		{QueueTargetStream, QueuedPacket{PacketType: Enums.PACKET_STREAM_DATA, StreamID: 4, SequenceNum: 1, Priority: 2}},
		{QueueTargetMain, QueuedPacket{PacketType: Enums.PACKET_STREAM_FIN_ACK, StreamID: 4, SequenceNum: 2, Priority: 0}},
		{QueueTargetMain, QueuedPacket{PacketType: Enums.PACKET_STREAM_RST, StreamID: 4, SequenceNum: 3, Priority: 0}},
		{QueueTargetMain, QueuedPacket{PacketType: Enums.PACKET_STREAM_RST_ACK, StreamID: 4, SequenceNum: 4, Priority: 0}},
		{QueueTargetStream, QueuedPacket{PacketType: Enums.PACKET_STREAM_DATA, StreamID: 9, SequenceNum: 1, Priority: 2}},
	}
	for _, queuedPacket := range queued {
		if !scheduler.Enqueue(queuedPacket.target, queuedPacket.packet) {
			t.Fatalf("failed to enqueue packet: %+v", queuedPacket.packet)
		}
	}

	dropped := scheduler.HandleStreamReset(4)
	if dropped != 2 {
		t.Fatalf("unexpected dropped count: got=%d want=2", dropped)
	}

	first, ok := scheduler.Dequeue()
	if !ok || first.Packet.PacketType != Enums.PACKET_PACKED_CONTROL_BLOCKS {
		t.Fatalf("expected reset controls to remain as packed block, got=%+v ok=%v", first.Packet, ok)
	}
	if first.PackedBlocks != 2 {
		t.Fatalf("expected packed reset block count=2, got=%d", first.PackedBlocks)
	}
	second, ok := scheduler.Dequeue()
	if !ok || second.Packet.StreamID != 9 || second.Packet.PacketType != Enums.PACKET_STREAM_DATA {
		t.Fatalf("expected unrelated stream data to remain queued, got=%+v ok=%v", second.Packet, ok)
	}
}

func TestSchedulerRejectsPacketsThatMustNotEnterQueues(t *testing.T) {
	scheduler := NewScheduler(1)
	if scheduler.Enqueue(QueueTargetMain, QueuedPacket{
		PacketType: Enums.PACKET_PACKED_CONTROL_BLOCKS,
	}) {
		t.Fatal("PACKED_CONTROL_BLOCKS should never be queued directly")
	}
}
