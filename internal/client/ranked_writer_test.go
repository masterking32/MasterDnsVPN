package client

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
)

// TestRankedPersistence_CoalescingAndMaxWait verifies that rapid bursts are coalesced,
// but continuous notifications cannot delay writes past MaxDirtyWait.
func TestRankedPersistence_CoalescingAndMaxWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log := logger.New("TestLogger", "debug")

		var writeCount atomic.Int32
		mockSave := func(path string, ranked []config.ResolverAddress) error {
			writeCount.Add(1)
			return nil
		}

		var currentRanked []config.ResolverAddress
		var mu sync.Mutex
		mockSnapshot := func(maxCount int) []config.ResolverAddress {
			mu.Lock()
			defer mu.Unlock()
			cp := make([]config.ResolverAddress, len(currentRanked))
			copy(cp, currentRanked)
			return cp
		}

		cfg := RankedPersistenceConfig{
			Enabled:       true,
			ResolversPath: "dummy.txt",
			MaxRanked:     10,
			CoalesceDelay: 40 * time.Millisecond,
			MaxDirtyWait:  150 * time.Millisecond,
		}

		w := newRankedPersistenceWriter(cfg, log, mockSnapshot, mockSave)
		defer w.Close()

		mu.Lock()
		currentRanked = []config.ResolverAddress{{IP: "1.1.1.1", Port: 53}}
		mu.Unlock()

		// 1. Rapid burst of 5 notifications within 20ms
		for i := 0; i < 5; i++ {
			w.NotifyDirty()
			time.Sleep(4 * time.Millisecond)
		}

		// Wait for coalesce delay to expire (40ms + margin)
		time.Sleep(60 * time.Millisecond)
		synctest.Wait()
		if count := writeCount.Load(); count != 1 {
			t.Fatalf("expected exactly 1 coalesced write, got %d", count)
		}

		// 2. Unchanged order -> subsequent NotifyDirty does NOT rewrite file
		w.NotifyDirty()
		time.Sleep(60 * time.Millisecond)
		synctest.Wait()
		if count := writeCount.Load(); count != 1 {
			t.Fatalf("expected write count to remain 1 on unchanged order, got %d", count)
		}

		// 3. Continuous notifications must force a write within MaxDirtyWait
		mu.Lock()
		currentRanked = []config.ResolverAddress{{IP: "8.8.8.8", Port: 53}}
		mu.Unlock()

		start := time.Now()
		for time.Since(start) < 200*time.Millisecond {
			w.NotifyDirty()
			time.Sleep(20 * time.Millisecond) // interval < CoalesceDelay (40ms)
			if writeCount.Load() >= 2 {
				break
			}
		}

		if count := writeCount.Load(); count < 2 {
			t.Fatalf("expected write to trigger under MaxDirtyWait despite continuous notifications; count=%d", count)
		}
	})
}

// TestRankedPersistence_WriteFailureAndRetry verifies that write errors retain dirty state
// and retry with backoff without losing pending updates.
func TestRankedPersistence_WriteFailureAndRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log := logger.New("TestLogger", "debug")

		var writeAttempts atomic.Int32
		var shouldFail atomic.Bool
		shouldFail.Store(true)

		mockSave := func(path string, ranked []config.ResolverAddress) error {
			writeAttempts.Add(1)
			if shouldFail.Load() {
				return errors.New("simulated disk full")
			}
			return nil
		}

		mockSnapshot := func(maxCount int) []config.ResolverAddress {
			return []config.ResolverAddress{{IP: "1.1.1.1", Port: 53}}
		}

		cfg := RankedPersistenceConfig{
			Enabled:         true,
			ResolversPath:   "dummy.txt",
			MaxRanked:       10,
			CoalesceDelay:   20 * time.Millisecond,
			MaxDirtyWait:    100 * time.Millisecond,
			RetryBackoff:    30 * time.Millisecond,
			MaxRetryBackoff: 100 * time.Millisecond,
		}

		w := newRankedPersistenceWriter(cfg, log, mockSnapshot, mockSave)
		defer w.Close()

		w.NotifyDirty()

		// Wait for initial write failure
		time.Sleep(40 * time.Millisecond)
		synctest.Wait()
		if writeAttempts.Load() < 1 {
			t.Fatalf("expected at least 1 write attempt")
		}

		// Recover storage
		shouldFail.Store(false)

		// Wait for retry to succeed
		time.Sleep(80 * time.Millisecond)
		synctest.Wait()
		if writeAttempts.Load() < 2 {
			t.Fatalf("expected retry after failure; attempts=%d", writeAttempts.Load())
		}
	})
}

// TestRankedPersistence_DisabledAndShutdownFlush verifies that disabled saves produce
// zero writes, and Close performs a bounded final flush if dirty.
func TestRankedPersistence_DisabledAndShutdownFlush(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log := logger.New("TestLogger", "debug")

		var writeCount atomic.Int32
		mockSave := func(path string, ranked []config.ResolverAddress) error {
			writeCount.Add(1)
			return nil
		}

		mockSnapshot := func(maxCount int) []config.ResolverAddress {
			return []config.ResolverAddress{{IP: "1.1.1.1", Port: 53}}
		}

		// 1. Disabled writer
		cfgDisabled := RankedPersistenceConfig{
			Enabled:       false,
			ResolversPath: "dummy.txt",
		}
		wDisabled := newRankedPersistenceWriter(cfgDisabled, log, mockSnapshot, mockSave)
		wDisabled.NotifyDirty()
		wDisabled.Close()
		if writeCount.Load() != 0 {
			t.Fatalf("disabled writer must produce 0 writes; got %d", writeCount.Load())
		}

		// 2. Shutdown flush on dirty state
		cfgEnabled := RankedPersistenceConfig{
			Enabled:       true,
			ResolversPath: "dummy.txt",
			MaxRanked:     10,
			CoalesceDelay: 1 * time.Second, // long coalesce delay
			MaxDirtyWait:  5 * time.Second,
		}
		wEnabled := newRankedPersistenceWriter(cfgEnabled, log, mockSnapshot, mockSave)
		wEnabled.NotifyDirty()

		// Immediately close without waiting for timer
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = ctx

		wEnabled.Close()
		if writeCount.Load() != 1 {
			t.Fatalf("expected Close to flush pending dirty changes; got %d writes", writeCount.Load())
		}
	})
}

// TestRankedPersistence_ConcurrentFlushSerialization verifies that concurrent calls to
// Flush / performSave strictly serialize executions of saveFn, never allowing concurrent disk writes.
func TestRankedPersistence_ConcurrentFlushSerialization(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log := logger.New("TestLogger", "debug")

		var activeSaves atomic.Int32
		var maxConcurrent atomic.Int32

		mockSave := func(path string, ranked []config.ResolverAddress) error {
			cur := activeSaves.Add(1)
			for {
				old := maxConcurrent.Load()
				if cur <= old || maxConcurrent.CompareAndSwap(old, cur) {
					break
				}
			}
			time.Sleep(25 * time.Millisecond) // simulate disk write latency
			activeSaves.Add(-1)
			return nil
		}

		mockSnapshot := func(maxCount int) []config.ResolverAddress {
			return []config.ResolverAddress{{IP: "1.1.1.1", Port: 53}}
		}

		cfg := RankedPersistenceConfig{
			Enabled:       true,
			ResolversPath: "dummy.txt",
			MaxRanked:     10,
			CoalesceDelay: 10 * time.Second, // don't let timer trigger automatically
			MaxDirtyWait:  10 * time.Second,
		}
		w := newRankedPersistenceWriter(cfg, log, mockSnapshot, mockSave)
		defer w.Close()

		w.NotifyDirty()

		// Launch multiple concurrent Flush calls
		const numGoroutines = 8
		var wg sync.WaitGroup
		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				_ = w.Flush(context.Background())
			}()
		}
		wg.Wait()

		if max := maxConcurrent.Load(); max > 1 {
			t.Fatalf("expected strictly serialized saveFn execution (max 1), got %d concurrent saves", max)
		}
	})
}

func TestRankedPersistence_CloseBoundsBlockedStorage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
		w := newRankedPersistenceWriter(RankedPersistenceConfig{Enabled: true, ResolversPath: "unused"}, nil,
			func(int) []config.ResolverAddress { return []config.ResolverAddress{{IP: "1.1.1.1", Port: 53}} },
			func(string, []config.ResolverAddress) error {
				close(entered)
				<-release
				defer close(finished)
				return nil
			})
		w.NotifyDirty()
		<-entered
		start := time.Now()
		w.Close()
		if elapsed := time.Since(start); elapsed != 2*time.Second {
			t.Fatalf("shutdown took %s, want bounded 2 seconds", elapsed)
		}
		select {
		case <-w.doneCh:
		default:
			t.Fatal("writer scheduler was not joined")
		}
		close(release) // A blocked OS write cannot be forcibly cancelled by Go.
		<-finished
	})
}

func TestRankedPersistence_ChangesDuringWriteStartNewCoalescingWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var snapshots atomic.Int32
		entered, release := make(chan struct{}), make(chan struct{})
		w := newRankedPersistenceWriter(RankedPersistenceConfig{
			Enabled: true, ResolversPath: "unused",
			CoalesceDelay: 20 * time.Millisecond, MaxDirtyWait: 100 * time.Millisecond,
		}, nil, func(int) []config.ResolverAddress {
			snapshots.Add(1)
			return []config.ResolverAddress{{IP: "1.1.1.1", Port: 53}}
		}, func(string, []config.ResolverAddress) error {
			close(entered)
			<-release
			return nil
		})
		defer w.Close()
		// Keep dirty work arriving until the first MaxDirtyWait deadline.
		w.NotifyDirty()
		for range 10 {
			time.Sleep(10 * time.Millisecond)
			w.NotifyDirty()
		}
		<-entered
		w.NotifyDirty() // This change belongs to a new window, not the expired one.
		close(release)
		synctest.Wait()
		if got := snapshots.Load(); got != 1 {
			t.Fatalf("new observations bypassed coalescing after write: snapshots=%d", got)
		}
		time.Sleep(20 * time.Millisecond)
		synctest.Wait()
		if got := snapshots.Load(); got != 2 {
			t.Fatalf("expected pending observations to be reconciled, snapshots=%d", got)
		}
	})
}

func TestRankedPersistence_MinWriteInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log := logger.New("TestLogger", "debug")

		var writeCount atomic.Int32
		mockSave := func(path string, ranked []config.ResolverAddress) error {
			writeCount.Add(1)
			return nil
		}

		var currentRanked []config.ResolverAddress
		var mu sync.Mutex
		mockSnapshot := func(maxCount int) []config.ResolverAddress {
			mu.Lock()
			defer mu.Unlock()
			cp := make([]config.ResolverAddress, len(currentRanked))
			copy(cp, currentRanked)
			return cp
		}

		cfg := RankedPersistenceConfig{
			Enabled:          true,
			ResolversPath:    "dummy.txt",
			MaxRanked:        10,
			CoalesceDelay:    20 * time.Millisecond,
			MaxDirtyWait:     50 * time.Millisecond,
			MinWriteInterval: 200 * time.Millisecond,
		}

		w := newRankedPersistenceWriter(cfg, log, mockSnapshot, mockSave)
		defer w.Close()

		mu.Lock()
		currentRanked = []config.ResolverAddress{{IP: "1.1.1.1", Port: 53}}
		mu.Unlock()

		// 1. Initial write triggers after CoalesceDelay since lastWriteAt is zero
		w.NotifyDirty()
		time.Sleep(30 * time.Millisecond)
		synctest.Wait()
		if count := writeCount.Load(); count != 1 {
			t.Fatalf("expected first write after coalesce delay, got %d", count)
		}

		// 2. Change ranking snapshot and notify dirty immediately
		mu.Lock()
		currentRanked = []config.ResolverAddress{{IP: "8.8.8.8", Port: 53}}
		mu.Unlock()
		w.NotifyDirty()

		// Sleep past CoalesceDelay and MaxDirtyWait, but before MinWriteInterval (e.g. 60ms)
		time.Sleep(60 * time.Millisecond)
		synctest.Wait()
		if count := writeCount.Load(); count != 1 {
			t.Fatalf("write must be deferred by MinWriteInterval, expected 1 got %d", count)
		}

		// 3. Sleep past MinWriteInterval (200ms - 90ms = 110ms + buffer)
		time.Sleep(150 * time.Millisecond)
		synctest.Wait()
		if count := writeCount.Load(); count != 2 {
			t.Fatalf("expected second write once MinWriteInterval elapsed, got %d", count)
		}

		// 4. Explicit Flush bypasses MinWriteInterval
		mu.Lock()
		currentRanked = []config.ResolverAddress{{IP: "9.9.9.9", Port: 53}}
		mu.Unlock()
		w.NotifyDirty()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := w.Flush(ctx); err != nil {
			t.Fatalf("flush failed: %v", err)
		}
		if count := writeCount.Load(); count != 3 {
			t.Fatalf("Flush must immediately persist ignoring MinWriteInterval, got %d", count)
		}
	})
}
