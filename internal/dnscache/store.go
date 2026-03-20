// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package dnscache

import (
	"bufio"
	"container/list"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type Status uint8

const (
	StatusPending Status = iota + 1
	StatusReady
)

const (
	shardCount = 32
	shardMask  = shardCount - 1
)

type Entry struct {
	Domain         string
	QuestionType   uint16
	QuestionClass  uint16
	Status         Status
	CreatedAt      time.Time
	LastUsedAt     time.Time
	LastDispatchAt time.Time
	Response       []byte
}

type LookupResult struct {
	Status         Status
	Response       []byte
	DispatchNeeded bool
}

type cacheNode struct {
	key   string
	entry Entry
}

type shard struct {
	items map[string]*list.Element
	order *list.List
	mu    sync.RWMutex
}

type Store struct {
	maxRecords     int
	cacheTTL       time.Duration
	pendingTimeout time.Duration
	shards         [shardCount]shard
	pendingTotal   atomic.Uint64
	dirty          atomic.Uint64 // used as a flag/counter
}

func New(maxRecords int, cacheTTL time.Duration, pendingTimeout time.Duration) *Store {
	if maxRecords < 1 {
		maxRecords = 1
	}
	if cacheTTL <= 0 {
		cacheTTL = time.Hour
	}
	if pendingTimeout <= 0 {
		pendingTimeout = 30 * time.Second
	}
	s := &Store{
		maxRecords:     maxRecords,
		cacheTTL:       cacheTTL,
		pendingTimeout: pendingTimeout,
	}
	for i := 0; i < shardCount; i++ {
		s.shards[i].items = make(map[string]*list.Element, maxRecords/shardCount+1)
		s.shards[i].order = list.New()
	}
	return s
}

func BuildKey(domain string, qType uint16, qClass uint16) string {
	key := make([]byte, 4+len(domain))
	binary.BigEndian.PutUint16(key[0:2], qType)
	binary.BigEndian.PutUint16(key[2:4], qClass)
	copy(key[4:], domain)
	return string(key)
}

func getShardIndex(key string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32() & shardMask)
}

func PatchResponseForQuery(rawResponse []byte, rawQuery []byte) []byte {
	if len(rawResponse) < 2 {
		return rawResponse
	}
	if len(rawQuery) < 2 {
		return rawResponse
	}

	patched := make([]byte, len(rawResponse))
	copy(patched, rawResponse)
	copy(patched[:2], rawQuery[:2])
	if len(rawQuery) >= 4 && len(patched) >= 4 {
		queryFlags := binary.BigEndian.Uint16(rawQuery[2:4])
		responseFlags := binary.BigEndian.Uint16(patched[2:4])
		responseFlags = (responseFlags &^ 0x0110) | (queryFlags & 0x0110)
		binary.BigEndian.PutUint16(patched[2:4], responseFlags)
	}
	return patched
}

func (s *Store) LookupOrCreatePending(key string, domain string, qType uint16, qClass uint16, now time.Time) LookupResult {
	if s == nil || key == "" {
		return LookupResult{}
	}

	shardIdx := getShardIndex(key)
	shard := &s.shards[shardIdx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if element, ok := shard.items[key]; ok {
		node := element.Value.(*cacheNode)
		if !s.isExpired(&node.entry, now) {
			s.touchEntryLocked(shard, &node.entry, now)
			if node.entry.Status == StatusReady {
				shard.order.MoveToBack(element)
				return LookupResult{
					Status:   StatusReady,
					Response: PatchResponseForQuery(node.entry.Response, nil),
				}
			}
			if now.Sub(node.entry.LastDispatchAt) >= s.pendingTimeout {
				node.entry.LastDispatchAt = now
				s.dirty.Add(1)
				shard.order.MoveToBack(element)
				return LookupResult{
					Status:         StatusPending,
					DispatchNeeded: true,
				}
			}
			shard.order.MoveToBack(element)
			return LookupResult{Status: StatusPending}
		}

		s.removeElementLocked(shard, element)
	}

	entry := Entry{
		Domain:         domain,
		QuestionType:   qType,
		QuestionClass:  qClass,
		Status:         StatusPending,
		CreatedAt:      now,
		LastUsedAt:     now,
		LastDispatchAt: now,
	}
	element := shard.order.PushBack(&cacheNode{key: key, entry: entry})
	shard.items[key] = element
	s.pendingTotal.Add(1)
	s.dirty.Add(1)
	s.evictIfNeededLocked(shard)
	return LookupResult{
		Status:         StatusPending,
		DispatchNeeded: true,
	}
}

func (s *Store) GetReady(key string, rawQuery []byte, now time.Time) ([]byte, bool) {
	if s == nil || key == "" {
		return nil, false
	}

	shardIdx := getShardIndex(key)
	shard := &s.shards[shardIdx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	element, ok := shard.items[key]
	if !ok {
		return nil, false
	}

	node := element.Value.(*cacheNode)
	if s.isExpired(&node.entry, now) {
		s.removeElementLocked(shard, element)
		return nil, false
	}
	if node.entry.Status != StatusReady || len(node.entry.Response) == 0 {
		s.touchEntryLocked(shard, &node.entry, now)
		shard.order.MoveToBack(element)
		return nil, false
	}

	s.touchEntryLocked(shard, &node.entry, now)
	shard.order.MoveToBack(element)
	return PatchResponseForQuery(node.entry.Response, rawQuery), true
}

func (s *Store) SetReady(key string, domain string, qType uint16, qClass uint16, rawResponse []byte, now time.Time) {
	if s == nil || key == "" || len(rawResponse) < 2 {
		return
	}

	shardIdx := getShardIndex(key)
	shard := &s.shards[shardIdx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	normalized := make([]byte, len(rawResponse))
	copy(normalized, rawResponse)
	normalized[0], normalized[1] = 0, 0

	if element, ok := shard.items[key]; ok {
		node := element.Value.(*cacheNode)
		if node.entry.Status == StatusPending {
			if count := s.pendingTotal.Load(); count > 0 {
				s.pendingTotal.Add(^uint64(0)) // Decrement
			}
		}
		node.entry.Domain = domain
		node.entry.QuestionType = qType
		node.entry.QuestionClass = qClass
		node.entry.Status = StatusReady
		if node.entry.CreatedAt.IsZero() {
			node.entry.CreatedAt = now
		}
		node.entry.LastUsedAt = now
		node.entry.Response = normalized
		s.dirty.Add(1)
		shard.order.MoveToBack(element)
		return
	}

	entry := Entry{
		Domain:        domain,
		QuestionType:  qType,
		QuestionClass: qClass,
		Status:        StatusReady,
		CreatedAt:     now,
		LastUsedAt:    now,
		Response:      normalized,
	}
	element := shard.order.PushBack(&cacheNode{key: key, entry: entry})
	shard.items[key] = element
	s.dirty.Add(1)
	s.evictIfNeededLocked(shard)
}

func (s *Store) Snapshot(key string) (Entry, bool) {
	if s == nil || key == "" {
		return Entry{}, false
	}

	shardIdx := getShardIndex(key)
	shard := &s.shards[shardIdx]

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	element, ok := shard.items[key]
	if !ok {
		return Entry{}, false
	}
	node := element.Value.(*cacheNode)
	entry := node.entry
	if len(entry.Response) != 0 {
		entry.Response = append([]byte(nil), entry.Response...)
	}
	return entry, true
}

func (s *Store) HasPending() bool {
	if s == nil {
		return false
	}
	return s.pendingTotal.Load() > 0
}

func (s *Store) ClearPending() {
	if s == nil {
		return
	}

	for i := 0; i < shardCount; i++ {
		shard := &s.shards[i]
		shard.mu.Lock()
		for element := shard.order.Front(); element != nil; {
			next := element.Next()
			node := element.Value.(*cacheNode)
			if node.entry.Status == StatusPending {
				s.removeElementLocked(shard, element)
			}
			element = next
		}
		shard.mu.Unlock()
	}
}

func (s *Store) isExpired(entry *Entry, now time.Time) bool {
	if entry == nil {
		return true
	}
	if entry.Status == StatusPending {
		return false
	}
	return now.Sub(entry.LastUsedAt) >= s.cacheTTL
}

func (s *Store) evictIfNeededLocked(shard *shard) {
	limit := s.maxRecords / shardCount
	if limit < 1 {
		limit = 1
	}
	for len(shard.items) > limit {
		front := shard.order.Front()
		if front == nil {
			return
		}
		s.removeElementLocked(shard, front)
	}
}

func (s *Store) removeElementLocked(shard *shard, element *list.Element) {
	if element == nil {
		return
	}
	node := element.Value.(*cacheNode)
	if node.entry.Status == StatusPending {
		if count := s.pendingTotal.Load(); count > 0 {
			s.pendingTotal.Add(^uint64(0)) // Decrement
		}
	}
	delete(shard.items, node.key)
	shard.order.Remove(element)
	s.dirty.Add(1)
}

const (
	binaryMagic   uint32 = 0x444E5343 // "DNSC"
	binaryVersion uint16 = 1
)

func (s *Store) LoadFromFile(path string, now time.Time) (int, error) {
	if s == nil || path == "" {
		return 0, nil
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer file.Close()

	var magic uint32
	if err := binary.Read(file, binary.BigEndian, &magic); err != nil {
		return 0, err
	}
	if magic != binaryMagic {
		return 0, fmt.Errorf("invalid magic number")
	}

	var version uint16
	if err := binary.Read(file, binary.BigEndian, &version); err != nil {
		return 0, err
	}
	if version != binaryVersion {
		return 0, fmt.Errorf("unsupported version")
	}

	var count uint32
	if err := binary.Read(file, binary.BigEndian, &count); err != nil {
		return 0, err
	}

	s.pendingTotal.Store(0)
	for i := 0; i < shardCount; i++ {
		s.shards[i].mu.Lock()
		s.shards[i].items = make(map[string]*list.Element, s.maxRecords/shardCount+1)
		s.shards[i].order.Init()
		s.shards[i].mu.Unlock()
	}

	loaded := 0
	br := bufio.NewReader(file)
	for i := 0; i < int(count); i++ {
		entry, key, err := readBinaryEntry(br)
		if err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		if s.isExpired(&entry, now) {
			continue
		}

		shardIdx := getShardIndex(key)
		shard := &s.shards[shardIdx]
		shard.mu.Lock()
		element := shard.order.PushBack(&cacheNode{key: key, entry: entry})
		shard.items[key] = element
		shard.mu.Unlock()
		loaded++
	}

	for i := 0; i < shardCount; i++ {
		s.shards[i].mu.Lock()
		s.evictIfNeededLocked(&s.shards[i])
		s.shards[i].mu.Unlock()
	}

	s.dirty.Store(0)
	return loaded, nil
}

func (s *Store) SaveToFile(path string, now time.Time) (int, error) {
	if s == nil || path == "" {
		return 0, nil
	}

	if s.dirty.Load() == 0 {
		return 0, nil
	}

	tempPath := path + ".tmp"
	file, err := os.Create(tempPath)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = file.Close()
		if err != nil {
			_ = os.Remove(tempPath)
		}
	}()

	bw := bufio.NewWriter(file)
	if err = binary.Write(bw, binary.BigEndian, binaryMagic); err != nil {
		return 0, err
	}
	if err = binary.Write(bw, binary.BigEndian, binaryVersion); err != nil {
		return 0, err
	}

	var total uint32
	for i := 0; i < shardCount; i++ {
		shard := &s.shards[i]
		shard.mu.RLock()
		for element := shard.order.Front(); element != nil; element = element.Next() {
			node := element.Value.(*cacheNode)
			if node.entry.Status == StatusReady && !s.isExpired(&node.entry, now) {
				total++
			}
		}
		shard.mu.RUnlock()
	}

	if err = binary.Write(bw, binary.BigEndian, total); err != nil {
		return 0, err
	}

	saved := 0
	for i := 0; i < shardCount; i++ {
		shard := &s.shards[i]
		shard.mu.RLock()
		for element := shard.order.Front(); element != nil; element = element.Next() {
			node := element.Value.(*cacheNode)
			if node.entry.Status == StatusReady && !s.isExpired(&node.entry, now) {
				if err = writeBinaryEntry(bw, node.key, &node.entry); err != nil {
					shard.mu.RUnlock()
					return saved, err
				}
				saved++
			}
		}
		shard.mu.RUnlock()
	}

	if err = bw.Flush(); err != nil {
		return saved, err
	}

	if err = file.Close(); err != nil {
		return saved, err
	}

	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return saved, err
	}

	if err = os.Rename(tempPath, path); err != nil {
		return saved, err
	}

	s.dirty.Store(0)
	return saved, nil
}

func (s *Store) touchEntryLocked(shard *shard, entry *Entry, now time.Time) {
	if entry == nil {
		return
	}
	if entry.LastUsedAt.IsZero() || now.Sub(entry.LastUsedAt) >= time.Second {
		entry.LastUsedAt = now
		s.dirty.Add(1)
		return
	}
	entry.LastUsedAt = now
}

func readBinaryEntry(r io.Reader) (Entry, string, error) {
	var keyLen uint16
	if err := binary.Read(r, binary.BigEndian, &keyLen); err != nil {
		return Entry{}, "", err
	}
	keyBuf := make([]byte, keyLen)
	if _, err := io.ReadFull(r, keyBuf); err != nil {
		return Entry{}, "", err
	}

	var domainLen uint16
	if err := binary.Read(r, binary.BigEndian, &domainLen); err != nil {
		return Entry{}, "", err
	}
	domainBuf := make([]byte, domainLen)
	if _, err := io.ReadFull(r, domainBuf); err != nil {
		return Entry{}, "", err
	}

	var qType, qClass uint16
	if err := binary.Read(r, binary.BigEndian, &qType); err != nil {
		return Entry{}, "", err
	}
	if err := binary.Read(r, binary.BigEndian, &qClass); err != nil {
		return Entry{}, "", err
	}

	var resLen uint16
	if err := binary.Read(r, binary.BigEndian, &resLen); err != nil {
		return Entry{}, "", err
	}
	resBuf := make([]byte, resLen)
	if _, err := io.ReadFull(r, resBuf); err != nil {
		return Entry{}, "", err
	}

	var createdAt, lastUsedAt int64
	if err := binary.Read(r, binary.BigEndian, &createdAt); err != nil {
		return Entry{}, "", err
	}
	if err := binary.Read(r, binary.BigEndian, &lastUsedAt); err != nil {
		return Entry{}, "", err
	}

	return Entry{
		Domain:        string(domainBuf),
		QuestionType:  qType,
		QuestionClass: qClass,
		Status:        StatusReady,
		CreatedAt:     time.Unix(createdAt, 0),
		LastUsedAt:    time.Unix(lastUsedAt, 0),
		Response:      resBuf,
	}, string(keyBuf), nil
}

func writeBinaryEntry(w io.Writer, key string, entry *Entry) error {
	if err := binary.Write(w, binary.BigEndian, uint16(len(key))); err != nil {
		return err
	}
	if _, err := w.Write([]byte(key)); err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, uint16(len(entry.Domain))); err != nil {
		return err
	}
	if _, err := w.Write([]byte(entry.Domain)); err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, entry.QuestionType); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, entry.QuestionClass); err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, uint16(len(entry.Response))); err != nil {
		return err
	}
	if _, err := w.Write(entry.Response); err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, entry.CreatedAt.Unix()); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, entry.LastUsedAt.Unix()); err != nil {
		return err
	}

	return nil
}
