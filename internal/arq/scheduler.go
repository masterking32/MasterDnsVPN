// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package arq

import (
	"container/heap"
	"math/bits"

	Enums "masterdnsvpn-go/internal/enums"
)

const (
	PackedControlBlockSize         = 5
	clientPackedBlockUsagePercent  = 50
	serverPackedBlockUsagePercent  = 80
	maxSchedulerPriority           = 63
	defaultPackedControlBlockLimit = 1
)

type QueueTarget uint8

const (
	QueueTargetMain QueueTarget = iota
	QueueTargetStream
)

type QueuedPacket struct {
	PacketType  uint8
	StreamID    uint16
	SequenceNum uint16
	Payload     []byte
	Priority    int
}

type DequeueResult struct {
	Packet       QueuedPacket
	PackedBlocks int
}

type Scheduler struct {
	maxPackedBlocks int
	nextOrder       uint64
	totalQueued     int
	pingQueued      int
	activeMask      uint64
	owners          map[uint16]*queueOwner
	rosters         [maxSchedulerPriority + 1]activeRoster
}

type queueOwner struct {
	streamID        uint16
	queue           packetPriorityHeap
	priorityCounts  [maxSchedulerPriority + 1]uint16
	trackTypes      map[uint32]struct{}
	trackData       map[uint32]struct{}
	trackAck        map[uint32]struct{}
	trackResend     map[uint32]struct{}
	trackSeqPackets map[typeSeqKey]struct{}
	trackFragments  map[fragmentKey]struct{}
}

type queuedItem struct {
	packet   QueuedPacket
	priority int
	order    uint64
}

type typeSeqKey struct {
	packetType  uint8
	streamID    uint16
	sequenceNum uint16
}

type fragmentKey struct {
	packetType  uint8
	streamID    uint16
	sequenceNum uint16
	payload     string
}

type packetPriorityHeap []*queuedItem

type activeRoster struct {
	ids    []uint16
	index  map[uint16]int
	cursor int
}

func NewScheduler(maxPackedBlocks int) *Scheduler {
	scheduler := &Scheduler{
		owners:          make(map[uint16]*queueOwner, 8),
		maxPackedBlocks: normalizePackedBlockLimit(maxPackedBlocks),
	}
	scheduler.owners[0] = newQueueOwner(0)
	return scheduler
}

func ComputeClientPackedControlBlockLimit(uploadMTU int, maxPacketsPerBatch int) int {
	return computePackedControlBlockLimit(uploadMTU, clientPackedBlockUsagePercent, maxPacketsPerBatch)
}

func ComputeServerPackedControlBlockLimit(downloadMTU int, maxPacketsPerBatch int) int {
	return computePackedControlBlockLimit(downloadMTU, serverPackedBlockUsagePercent, maxPacketsPerBatch)
}

func (s *Scheduler) SetMaxPackedBlocks(limit int) {
	if s == nil {
		return
	}
	s.maxPackedBlocks = normalizePackedBlockLimit(limit)
}

func (s *Scheduler) MaxPackedBlocks() int {
	if s == nil {
		return defaultPackedControlBlockLimit
	}
	return normalizePackedBlockLimit(s.maxPackedBlocks)
}

func (s *Scheduler) Pending() int {
	if s == nil {
		return 0
	}
	return s.totalQueued
}

func (s *Scheduler) PendingPings() int {
	if s == nil {
		return 0
	}
	return s.pingQueued
}

func (s *Scheduler) Enqueue(target QueueTarget, packet QueuedPacket) bool {
	if s == nil || isDropQueuePacket(packet.PacketType) {
		return false
	}

	owner := s.ownerFor(target, packet.StreamID)
	packet.Priority = effectivePriorityForPacket(packet.PacketType, packet.Priority)
	packet.Payload = clonePayload(packet.Payload)

	if !owner.track(packet) {
		return false
	}

	item := &queuedItem{
		packet:   packet,
		priority: normalizePriority(packet.Priority),
		order:    s.nextOrder,
	}
	s.nextOrder++
	heap.Push(&owner.queue, item)
	s.activateOwnerPriority(owner, item.priority)
	s.totalQueued++
	if packet.PacketType == Enums.PACKET_PING {
		s.pingQueued++
	}
	return true
}

func (s *Scheduler) Dequeue() (DequeueResult, bool) {
	if s == nil || s.totalQueued == 0 {
		return DequeueResult{}, false
	}

	for attempts := 0; attempts < s.totalQueued+1; attempts++ {
		priority, ok := s.highestActivePriority()
		if !ok {
			return DequeueResult{}, false
		}

		ownerID, ok := s.rosters[priority].next()
		if !ok {
			s.activeMask &^= 1 << uint(priority)
			continue
		}

		owner := s.owners[ownerID]
		item, ok := s.popHead(owner)
		if !ok {
			continue
		}

		if item.packet.PacketType == Enums.PACKET_PING && s.totalQueued > s.pingQueued {
			continue
		}

		if !isPackableControlPacket(item.packet) || s.maxPackedBlocks <= 1 {
			return DequeueResult{Packet: item.packet, PackedBlocks: 1}, true
		}

		return s.dequeuePacked(item, ownerID), true
	}

	return DequeueResult{}, false
}

func (s *Scheduler) HandleStreamReset(streamID uint16) int {
	if s == nil || streamID == 0 {
		return 0
	}

	dropped := 0
	if owner, ok := s.owners[streamID]; ok {
		dropped += s.clearOwner(owner)
		delete(s.owners, streamID)
	}
	dropped += s.pruneOwner(s.owners[0], func(packet QueuedPacket) bool {
		if packet.StreamID != streamID {
			return true
		}
		return packet.PacketType == Enums.PACKET_STREAM_RST || packet.PacketType == Enums.PACKET_STREAM_RST_ACK
	})
	return dropped
}

func (s *Scheduler) HandleSessionReset() int {
	if s == nil {
		return 0
	}

	dropped := 0
	for ownerID, owner := range s.owners {
		if ownerID == 0 {
			continue
		}
		dropped += s.clearOwner(owner)
		delete(s.owners, ownerID)
	}

	dropped += s.pruneOwner(s.owners[0], func(packet QueuedPacket) bool {
		return packet.PacketType == Enums.PACKET_STREAM_RST || packet.PacketType == Enums.PACKET_STREAM_RST_ACK
	})
	return dropped
}

func (s *Scheduler) ownerFor(target QueueTarget, streamID uint16) *queueOwner {
	if target == QueueTargetMain || streamID == 0 {
		return s.owners[0]
	}

	owner, ok := s.owners[streamID]
	if ok {
		return owner
	}

	owner = newQueueOwner(streamID)
	s.owners[streamID] = owner
	return owner
}

func (s *Scheduler) highestActivePriority() (int, bool) {
	if s.activeMask == 0 {
		return 0, false
	}
	return bits.TrailingZeros64(s.activeMask), true
}

func (s *Scheduler) dequeuePacked(first *queuedItem, firstOwnerID uint16) DequeueResult {
	blocks := make([]byte, 0, s.maxPackedBlocks*PackedControlBlockSize)
	blocks = appendPackedControlBlock(blocks, first.packet)
	blockCount := 1
	priority := first.priority

	if owner := s.owners[firstOwnerID]; owner != nil {
		for blockCount < s.maxPackedBlocks {
			next, ok := s.popPackableHead(owner, priority)
			if !ok {
				break
			}
			blocks = appendPackedControlBlock(blocks, next.packet)
			blockCount++
		}
	}

	ownerCount := s.rosters[priority].Len()
	currentOwnerID := firstOwnerID
	for visited := 0; blockCount < s.maxPackedBlocks && visited < ownerCount; visited++ {
		nextOwnerID, ok := s.rosters[priority].nextAfter(currentOwnerID)
		if !ok || nextOwnerID == firstOwnerID {
			break
		}
		currentOwnerID = nextOwnerID
		owner := s.owners[nextOwnerID]
		for blockCount < s.maxPackedBlocks {
			next, ok := s.popPackableHead(owner, priority)
			if !ok {
				break
			}
			blocks = appendPackedControlBlock(blocks, next.packet)
			blockCount++
		}
	}

	if blockCount == 1 {
		return DequeueResult{
			Packet:       first.packet,
			PackedBlocks: 1,
		}
	}

	return DequeueResult{
		Packet: QueuedPacket{
			PacketType: Enums.PACKET_PACKED_CONTROL_BLOCKS,
			StreamID:   0,
			Priority:   priority,
			Payload:    blocks,
		},
		PackedBlocks: blockCount,
	}
}

func (s *Scheduler) popPackableHead(owner *queueOwner, priority int) (*queuedItem, bool) {
	if owner == nil || owner.queue.Len() == 0 {
		return nil, false
	}

	head := owner.queue[0]
	if head == nil || head.priority != priority || !isPackableControlPacket(head.packet) {
		return nil, false
	}
	return s.popHead(owner)
}

func (s *Scheduler) popHead(owner *queueOwner) (*queuedItem, bool) {
	if owner == nil || owner.queue.Len() == 0 {
		return nil, false
	}

	item := heap.Pop(&owner.queue).(*queuedItem)
	s.deactivateOwnerPriority(owner, item.priority)
	owner.release(item.packet)
	s.totalQueued--
	if item.packet.PacketType == Enums.PACKET_PING {
		s.pingQueued--
	}
	return item, true
}

func (s *Scheduler) activateOwnerPriority(owner *queueOwner, priority int) {
	if owner == nil {
		return
	}
	if owner.priorityCounts[priority] == 0 {
		s.rosters[priority].add(owner.streamID)
		s.activeMask |= 1 << uint(priority)
	}
	owner.priorityCounts[priority]++
}

func (s *Scheduler) deactivateOwnerPriority(owner *queueOwner, priority int) {
	if owner == nil || owner.priorityCounts[priority] == 0 {
		return
	}
	owner.priorityCounts[priority]--
	if owner.priorityCounts[priority] == 0 {
		s.rosters[priority].remove(owner.streamID)
		if s.rosters[priority].Len() == 0 {
			s.activeMask &^= 1 << uint(priority)
		}
	}
}

func (s *Scheduler) clearOwner(owner *queueOwner) int {
	if s == nil || owner == nil {
		return 0
	}

	removed := 0
	for owner.queue.Len() > 0 {
		item, ok := s.popHead(owner)
		if !ok || item == nil {
			break
		}
		removed++
	}
	return removed
}

func (s *Scheduler) pruneOwner(owner *queueOwner, keep func(QueuedPacket) bool) int {
	if s == nil || owner == nil || owner.queue.Len() == 0 {
		return 0
	}

	for priority, count := range owner.priorityCounts {
		if count == 0 {
			continue
		}
		s.rosters[priority].remove(owner.streamID)
		if s.rosters[priority].Len() == 0 {
			s.activeMask &^= 1 << uint(priority)
		}
	}

	oldQueue := owner.queue
	owner.queue = make(packetPriorityHeap, 0, len(oldQueue))
	owner.priorityCounts = [maxSchedulerPriority + 1]uint16{}
	owner.resetTracking()

	removed := 0
	for _, item := range oldQueue {
		if item == nil {
			continue
		}
		if keep != nil && keep(item.packet) {
			if !owner.track(item.packet) {
				removed++
				s.totalQueued--
				if item.packet.PacketType == Enums.PACKET_PING {
					s.pingQueued--
				}
				continue
			}
			heap.Push(&owner.queue, item)
			s.activateOwnerPriority(owner, item.priority)
			continue
		}
		removed++
		s.totalQueued--
		if item.packet.PacketType == Enums.PACKET_PING {
			s.pingQueued--
		}
	}
	return removed
}

func newQueueOwner(streamID uint16) *queueOwner {
	return &queueOwner{
		streamID:        streamID,
		queue:           make(packetPriorityHeap, 0, 8),
		trackTypes:      make(map[uint32]struct{}, 8),
		trackData:       make(map[uint32]struct{}, 8),
		trackAck:        make(map[uint32]struct{}, 8),
		trackResend:     make(map[uint32]struct{}, 8),
		trackSeqPackets: make(map[typeSeqKey]struct{}, 8),
		trackFragments:  make(map[fragmentKey]struct{}, 8),
	}
}

func (o *queueOwner) track(packet QueuedPacket) bool {
	streamSeq := composeStreamSeqKey(packet.StreamID, packet.SequenceNum)
	streamType := composeStreamTypeKey(packet.StreamID, packet.PacketType)

	switch packet.PacketType {
	case Enums.PACKET_STREAM_RESEND:
		if _, exists := o.trackData[streamSeq]; exists {
			return false
		}
		if _, exists := o.trackResend[streamSeq]; exists {
			return false
		}
		o.trackResend[streamSeq] = struct{}{}
		return true
	case Enums.PACKET_STREAM_DATA_ACK:
		if _, exists := o.trackAck[streamSeq]; exists {
			return false
		}
		o.trackAck[streamSeq] = struct{}{}
		return true
	case Enums.PACKET_STREAM_DATA:
		if _, exists := o.trackData[streamSeq]; exists {
			return false
		}
		if _, exists := o.trackResend[streamSeq]; exists {
			return false
		}
		o.trackData[streamSeq] = struct{}{}
		return true
	}

	if isSingleInstanceQueuePacket(packet.PacketType) {
		if _, exists := o.trackTypes[streamType]; exists {
			return false
		}
		o.trackTypes[streamType] = struct{}{}
		return true
	}

	if isSequenceKeyedQueuePacket(packet.PacketType) {
		key := typeSeqKey{
			packetType:  packet.PacketType,
			streamID:    packet.StreamID,
			sequenceNum: packet.SequenceNum,
		}
		if _, exists := o.trackSeqPackets[key]; exists {
			return false
		}
		o.trackSeqPackets[key] = struct{}{}
		return true
	}

	if isFragmentKeyedQueuePacket(packet.PacketType) {
		key := fragmentKey{
			packetType:  packet.PacketType,
			streamID:    packet.StreamID,
			sequenceNum: packet.SequenceNum,
			payload:     string(packet.Payload),
		}
		if _, exists := o.trackFragments[key]; exists {
			return false
		}
		o.trackFragments[key] = struct{}{}
		return true
	}

	return true
}

func (o *queueOwner) release(packet QueuedPacket) {
	streamSeq := composeStreamSeqKey(packet.StreamID, packet.SequenceNum)
	streamType := composeStreamTypeKey(packet.StreamID, packet.PacketType)

	switch packet.PacketType {
	case Enums.PACKET_STREAM_RESEND:
		delete(o.trackResend, streamSeq)
	case Enums.PACKET_STREAM_DATA_ACK:
		delete(o.trackAck, streamSeq)
	case Enums.PACKET_STREAM_DATA:
		delete(o.trackData, streamSeq)
	default:
		if isSingleInstanceQueuePacket(packet.PacketType) {
			delete(o.trackTypes, streamType)
		}
		if isSequenceKeyedQueuePacket(packet.PacketType) {
			delete(o.trackSeqPackets, typeSeqKey{
				packetType:  packet.PacketType,
				streamID:    packet.StreamID,
				sequenceNum: packet.SequenceNum,
			})
		}
		if isFragmentKeyedQueuePacket(packet.PacketType) {
			delete(o.trackFragments, fragmentKey{
				packetType:  packet.PacketType,
				streamID:    packet.StreamID,
				sequenceNum: packet.SequenceNum,
				payload:     string(packet.Payload),
			})
		}
	}
}

func (o *queueOwner) resetTracking() {
	clear(o.trackTypes)
	clear(o.trackData)
	clear(o.trackAck)
	clear(o.trackResend)
	clear(o.trackSeqPackets)
	clear(o.trackFragments)
}

func computePackedControlBlockLimit(mtu int, usagePercent int, maxPacketsPerBatch int) int {
	if mtu < 1 {
		return defaultPackedControlBlockLimit
	}

	usableBudget := (mtu * usagePercent) / 100
	mtuLimit := usableBudget / PackedControlBlockSize
	if mtuLimit < 1 {
		mtuLimit = defaultPackedControlBlockLimit
	}

	userLimit := normalizePackedBlockLimit(maxPacketsPerBatch)
	if userLimit < mtuLimit {
		return userLimit
	}
	return mtuLimit
}

func normalizePackedBlockLimit(limit int) int {
	if limit < 1 {
		return defaultPackedControlBlockLimit
	}
	return limit
}

func normalizePriority(priority int) int {
	if priority < 0 {
		return 0
	}
	if priority > maxSchedulerPriority {
		return maxSchedulerPriority
	}
	return priority
}

func effectivePriorityForPacket(packetType uint8, priority int) int {
	switch packetType {
	case Enums.PACKET_STREAM_DATA_ACK,
		Enums.PACKET_STREAM_RST,
		Enums.PACKET_STREAM_RST_ACK,
		Enums.PACKET_STREAM_FIN_ACK,
		Enums.PACKET_STREAM_SYN_ACK,
		Enums.PACKET_SOCKS5_SYN_ACK:
		return 0
	case Enums.PACKET_STREAM_RESEND:
		return 1
	case Enums.PACKET_STREAM_FIN:
		return 4
	default:
		return normalizePriority(priority)
	}
}

func isDropQueuePacket(packetType uint8) bool {
	return packetType == Enums.PACKET_PACKED_CONTROL_BLOCKS || packetType == Enums.PACKET_ERROR_DROP
}

func isSingleInstanceQueuePacket(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_STREAM_FIN,
		Enums.PACKET_STREAM_RST,
		Enums.PACKET_STREAM_RST_ACK,
		Enums.PACKET_STREAM_FIN_ACK,
		Enums.PACKET_STREAM_SYN,
		Enums.PACKET_STREAM_SYN_ACK:
		return true
	default:
		return false
	}
}

func isSequenceKeyedQueuePacket(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_SOCKS5_CONNECT_FAIL,
		Enums.PACKET_SOCKS5_CONNECT_FAIL_ACK,
		Enums.PACKET_SOCKS5_RULESET_DENIED,
		Enums.PACKET_SOCKS5_RULESET_DENIED_ACK,
		Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE,
		Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_HOST_UNREACHABLE,
		Enums.PACKET_SOCKS5_HOST_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_CONNECTION_REFUSED,
		Enums.PACKET_SOCKS5_CONNECTION_REFUSED_ACK,
		Enums.PACKET_SOCKS5_TTL_EXPIRED,
		Enums.PACKET_SOCKS5_TTL_EXPIRED_ACK,
		Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED,
		Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
		Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_AUTH_FAILED,
		Enums.PACKET_SOCKS5_AUTH_FAILED_ACK,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK:
		return true
	default:
		return false
	}
}

func isFragmentKeyedQueuePacket(packetType uint8) bool {
	return packetType == Enums.PACKET_SOCKS5_SYN ||
		packetType == Enums.PACKET_SOCKS5_SYN_ACK ||
		packetType == Enums.PACKET_DNS_QUERY_REQ ||
		packetType == Enums.PACKET_DNS_QUERY_RES
}

func isPackableControlPacket(packet QueuedPacket) bool {
	if len(packet.Payload) != 0 {
		return false
	}

	switch packet.PacketType {
	case Enums.PACKET_STREAM_DATA_ACK,
		Enums.PACKET_STREAM_SYN,
		Enums.PACKET_STREAM_SYN_ACK,
		Enums.PACKET_STREAM_FIN,
		Enums.PACKET_STREAM_FIN_ACK,
		Enums.PACKET_STREAM_RST,
		Enums.PACKET_STREAM_RST_ACK,
		Enums.PACKET_SOCKS5_SYN_ACK,
		Enums.PACKET_SOCKS5_CONNECT_FAIL,
		Enums.PACKET_SOCKS5_CONNECT_FAIL_ACK,
		Enums.PACKET_SOCKS5_RULESET_DENIED,
		Enums.PACKET_SOCKS5_RULESET_DENIED_ACK,
		Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE,
		Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_HOST_UNREACHABLE,
		Enums.PACKET_SOCKS5_HOST_UNREACHABLE_ACK,
		Enums.PACKET_SOCKS5_CONNECTION_REFUSED,
		Enums.PACKET_SOCKS5_CONNECTION_REFUSED_ACK,
		Enums.PACKET_SOCKS5_TTL_EXPIRED,
		Enums.PACKET_SOCKS5_TTL_EXPIRED_ACK,
		Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED,
		Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
		Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
		Enums.PACKET_SOCKS5_AUTH_FAILED,
		Enums.PACKET_SOCKS5_AUTH_FAILED_ACK,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
		Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE_ACK:
		return true
	default:
		return false
	}
}

func composeStreamSeqKey(streamID uint16, sequenceNum uint16) uint32 {
	return uint32(streamID)<<16 | uint32(sequenceNum)
}

func composeStreamTypeKey(streamID uint16, packetType uint8) uint32 {
	return uint32(streamID)<<8 | uint32(packetType)
}

func appendPackedControlBlock(dst []byte, packet QueuedPacket) []byte {
	return append(
		dst,
		packet.PacketType,
		byte(packet.StreamID>>8),
		byte(packet.StreamID),
		byte(packet.SequenceNum>>8),
		byte(packet.SequenceNum),
	)
}

func (h packetPriorityHeap) Len() int { return len(h) }

func (h packetPriorityHeap) Less(i, j int) bool {
	if h[i].priority != h[j].priority {
		return h[i].priority < h[j].priority
	}
	return h[i].order < h[j].order
}

func (h packetPriorityHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *packetPriorityHeap) Push(x any) {
	*h = append(*h, x.(*queuedItem))
}

func (h *packetPriorityHeap) Pop() any {
	old := *h
	last := len(old) - 1
	item := old[last]
	*h = old[:last]
	return item
}

func (r *activeRoster) Len() int {
	return len(r.ids)
}

func (r *activeRoster) add(id uint16) {
	if r.index == nil {
		r.index = make(map[uint16]int, 8)
	}
	if _, exists := r.index[id]; exists {
		return
	}
	r.index[id] = len(r.ids)
	r.ids = append(r.ids, id)
}

func (r *activeRoster) remove(id uint16) {
	if r.index == nil {
		return
	}
	idx, exists := r.index[id]
	if !exists {
		return
	}

	lastIdx := len(r.ids) - 1
	lastID := r.ids[lastIdx]
	r.ids[idx] = lastID
	r.index[lastID] = idx
	r.ids = r.ids[:lastIdx]
	delete(r.index, id)

	if len(r.ids) == 0 {
		r.cursor = 0
		return
	}
	if r.cursor > idx {
		r.cursor--
	}
	if r.cursor >= len(r.ids) {
		r.cursor = 0
	}
}

func (r *activeRoster) next() (uint16, bool) {
	if len(r.ids) == 0 {
		return 0, false
	}
	if r.cursor >= len(r.ids) {
		r.cursor = 0
	}
	id := r.ids[r.cursor]
	r.cursor++
	if r.cursor >= len(r.ids) {
		r.cursor = 0
	}
	return id, true
}

func (r *activeRoster) nextAfter(id uint16) (uint16, bool) {
	if len(r.ids) == 0 {
		return 0, false
	}
	idx, exists := r.index[id]
	if !exists {
		return r.next()
	}
	nextIdx := idx + 1
	if nextIdx >= len(r.ids) {
		nextIdx = 0
	}
	return r.ids[nextIdx], true
}
