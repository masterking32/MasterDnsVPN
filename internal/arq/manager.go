// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package arq

import (
	"container/heap"
	"sync"
	"time"
)

type QueueKind uint8

const (
	QueueKindData QueueKind = iota + 1
	QueueKindControl
)

type RetryPolicy struct {
	BaseRTO    time.Duration
	MaxRTO     time.Duration
	TTL        time.Duration
	MaxRetries int
}

type Packet struct {
	Queue          QueueKind
	PacketType     uint8
	StreamID       uint16
	SequenceNum    uint16
	Payload        []byte
	Priority       int
	AckPacketType  uint8
	RequiresAck    bool
	KeepAfterReset bool
	Retries        int
	CreatedAt      time.Time
	LastSentAt     time.Time
}

type Manager struct {
	mu            sync.Mutex
	windowSize    int
	dataPolicy    RetryPolicy
	controlPolicy RetryPolicy
	dataQueue     packetQueue
	controlQueue  packetQueue
}

type packetQueue struct {
	items    map[uint32]*queuedPacket
	ackIndex map[uint32]uint32
	order    uint64
	due      packetHeap
}

type queuedPacket struct {
	key        uint32
	ackKey     uint32
	packet     Packet
	currentRTO time.Duration
	nextSendAt time.Time
	removed    bool
	order      uint64
}

type packetHeap []*queuedPacket

func DefaultDataPolicy() RetryPolicy {
	return normalizePolicy(RetryPolicy{
		BaseRTO:    800 * time.Millisecond,
		MaxRTO:     1500 * time.Millisecond,
		TTL:        10 * time.Minute,
		MaxRetries: 400,
	})
}

func DefaultControlPolicy() RetryPolicy {
	return normalizePolicy(RetryPolicy{
		BaseRTO:    800 * time.Millisecond,
		MaxRTO:     2500 * time.Millisecond,
		TTL:        10 * time.Minute,
		MaxRetries: 15,
	})
}

func NewManager(windowSize int, dataPolicy RetryPolicy, controlPolicy RetryPolicy) *Manager {
	if windowSize < 1 {
		windowSize = 1
	}

	manager := &Manager{
		windowSize:    windowSize,
		dataPolicy:    normalizePolicy(dataPolicy),
		controlPolicy: normalizePolicy(controlPolicy),
	}
	manager.dataQueue.init()
	manager.controlQueue.init()
	return manager
}

func (m *Manager) PendingData() int {
	if m == nil {
		return 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.dataQueue.items)
}

func (m *Manager) WindowAvailable() int {
	if m == nil {
		return 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	available := m.windowSize - len(m.dataQueue.items)
	if available < 0 {
		return 0
	}
	return available
}

func (m *Manager) CanEnqueueData() bool {
	return m.WindowAvailable() > 0
}

func (m *Manager) EnqueueData(packetType uint8, streamID uint16, sequenceNum uint16, payload []byte, now time.Time) bool {
	if m == nil {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.dataQueue.items) >= m.windowSize {
		return false
	}

	packet := Packet{
		Queue:       QueueKindData,
		PacketType:  packetType,
		StreamID:    streamID,
		SequenceNum: sequenceNum,
		Payload:     clonePayload(payload),
		Priority:    0,
		RequiresAck: true,
		CreatedAt:   now,
		LastSentAt:  time.Time{},
	}
	return m.dataQueue.enqueueData(packet, m.dataPolicy, now)
}

func (m *Manager) EnqueueControl(packetType uint8, ackPacketType uint8, streamID uint16, sequenceNum uint16, payload []byte, priority int, keepAfterReset bool, now time.Time) bool {
	if m == nil {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	packet := Packet{
		Queue:          QueueKindControl,
		PacketType:     packetType,
		StreamID:       streamID,
		SequenceNum:    sequenceNum,
		Payload:        clonePayload(payload),
		Priority:       priority,
		AckPacketType:  ackPacketType,
		RequiresAck:    ackPacketType != 0,
		KeepAfterReset: keepAfterReset,
		CreatedAt:      now,
		LastSentAt:     time.Time{},
	}
	return m.controlQueue.enqueueControl(packet, m.controlPolicy, now)
}

func (m *Manager) AcknowledgeData(sequenceNum uint16) bool {
	if m == nil {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dataQueue.removeByKey(uint32(sequenceNum))
}

func (m *Manager) AcknowledgeControl(ackPacketType uint8, sequenceNum uint16) bool {
	if m == nil {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.controlQueue.removeByAck(ackKey(ackPacketType, sequenceNum))
}

func (m *Manager) NextData(now time.Time, limit int) []Packet {
	if m == nil || limit <= 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dataQueue.collectDue(now, limit, m.dataPolicy)
}

func (m *Manager) NextControl(now time.Time, limit int) []Packet {
	if m == nil || limit <= 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.controlQueue.collectDue(now, limit, m.controlPolicy)
}

func (m *Manager) HandleRemoteReset() (droppedData int, droppedControl int) {
	if m == nil {
		return 0, 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	droppedData = m.dataQueue.clearAll()
	droppedControl = m.controlQueue.prune(func(packet Packet) bool {
		return packet.KeepAfterReset
	})
	return droppedData, droppedControl
}

func normalizePolicy(policy RetryPolicy) RetryPolicy {
	if policy.BaseRTO <= 0 {
		policy.BaseRTO = 800 * time.Millisecond
	}
	if policy.MaxRTO < policy.BaseRTO {
		policy.MaxRTO = policy.BaseRTO
	}
	if policy.TTL <= 0 {
		policy.TTL = 10 * time.Minute
	}
	if policy.MaxRetries < 1 {
		policy.MaxRetries = 1
	}
	return policy
}

func clonePayload(payload []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	cloned := make([]byte, len(payload))
	copy(cloned, payload)
	return cloned
}

func packetKey(packetType uint8, sequenceNum uint16) uint32 {
	return (uint32(packetType) << 16) | uint32(sequenceNum)
}

func ackKey(ackPacketType uint8, sequenceNum uint16) uint32 {
	return (uint32(ackPacketType) << 16) | uint32(sequenceNum)
}

func (q *packetQueue) init() {
	q.items = make(map[uint32]*queuedPacket)
	q.ackIndex = make(map[uint32]uint32)
	q.due = nil
	q.order = 0
}

func (q *packetQueue) enqueueData(packet Packet, policy RetryPolicy, now time.Time) bool {
	key := uint32(packet.SequenceNum)
	if _, exists := q.items[key]; exists {
		return false
	}

	item := &queuedPacket{
		key:        key,
		packet:     packet,
		currentRTO: policy.BaseRTO,
		nextSendAt: now,
		order:      q.nextOrder(),
	}
	q.items[key] = item
	heap.Push(&q.due, item)
	return true
}

func (q *packetQueue) enqueueControl(packet Packet, policy RetryPolicy, now time.Time) bool {
	key := packetKey(packet.PacketType, packet.SequenceNum)
	if _, exists := q.items[key]; exists {
		return false
	}

	item := &queuedPacket{
		key:        key,
		packet:     packet,
		currentRTO: policy.BaseRTO,
		nextSendAt: now,
		order:      q.nextOrder(),
	}
	if packet.RequiresAck {
		item.ackKey = ackKey(packet.AckPacketType, packet.SequenceNum)
		if _, exists := q.ackIndex[item.ackKey]; exists {
			return false
		}
		q.ackIndex[item.ackKey] = key
	}
	q.items[key] = item
	heap.Push(&q.due, item)
	return true
}

func (q *packetQueue) collectDue(now time.Time, limit int, policy RetryPolicy) []Packet {
	if limit <= 0 {
		return nil
	}

	out := make([]Packet, 0, limit)
	for len(out) < limit {
		item := q.peekLive()
		if item == nil || item.nextSendAt.After(now) {
			break
		}

		heap.Pop(&q.due)
		if item.removed {
			continue
		}

		if now.Sub(item.packet.CreatedAt) >= policy.TTL || item.packet.Retries >= policy.MaxRetries {
			q.remove(item)
			continue
		}

		packet := item.packet
		packet.Retries = item.packet.Retries
		packet.LastSentAt = now
		out = append(out, packet)

		if !item.packet.RequiresAck {
			q.remove(item)
			continue
		}

		item.packet.LastSentAt = now
		item.packet.Retries++
		item.currentRTO = nextRTO(item.currentRTO, policy)
		item.nextSendAt = now.Add(item.currentRTO)
		heap.Push(&q.due, item)
	}
	return out
}

func (q *packetQueue) removeByKey(key uint32) bool {
	item, ok := q.items[key]
	if !ok {
		return false
	}
	q.remove(item)
	return true
}

func (q *packetQueue) removeByAck(ack uint32) bool {
	key, ok := q.ackIndex[ack]
	if !ok {
		return false
	}
	item, ok := q.items[key]
	if !ok {
		delete(q.ackIndex, ack)
		return false
	}
	q.remove(item)
	return true
}

func (q *packetQueue) clearAll() int {
	removed := len(q.items)
	q.init()
	return removed
}

func (q *packetQueue) prune(keep func(Packet) bool) int {
	removed := 0
	for key, item := range q.items {
		if keep != nil && keep(item.packet) {
			continue
		}
		item.removed = true
		delete(q.items, key)
		if item.ackKey != 0 {
			delete(q.ackIndex, item.ackKey)
		}
		removed++
	}
	return removed
}

func (q *packetQueue) remove(item *queuedPacket) {
	if item == nil || item.removed {
		return
	}
	item.removed = true
	delete(q.items, item.key)
	if item.ackKey != 0 {
		delete(q.ackIndex, item.ackKey)
	}
}

func (q *packetQueue) peekLive() *queuedPacket {
	for q.due.Len() > 0 {
		item := q.due[0]
		if item == nil || item.removed {
			heap.Pop(&q.due)
			continue
		}
		return item
	}
	return nil
}

func (q *packetQueue) nextOrder() uint64 {
	order := q.order
	q.order++
	return order
}

func nextRTO(current time.Duration, policy RetryPolicy) time.Duration {
	if current <= 0 {
		return policy.BaseRTO
	}
	next := current + current/2
	if next < policy.BaseRTO {
		next = policy.BaseRTO
	}
	if next > policy.MaxRTO {
		return policy.MaxRTO
	}
	return next
}

func (h packetHeap) Len() int { return len(h) }

func (h packetHeap) Less(i, j int) bool {
	if !h[i].nextSendAt.Equal(h[j].nextSendAt) {
		return h[i].nextSendAt.Before(h[j].nextSendAt)
	}
	if h[i].packet.Priority != h[j].packet.Priority {
		return h[i].packet.Priority < h[j].packet.Priority
	}
	return h[i].order < h[j].order
}

func (h packetHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *packetHeap) Push(x any) {
	*h = append(*h, x.(*queuedPacket))
}

func (h *packetHeap) Pop() any {
	old := *h
	last := len(old) - 1
	item := old[last]
	*h = old[:last]
	return item
}
