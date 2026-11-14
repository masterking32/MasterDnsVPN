package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
)

// RankedPersistenceConfig tunes the background writer behavior.
type RankedPersistenceConfig struct {
	Enabled         bool
	ResolversPath   string
	MaxRanked       int
	CoalesceDelay   time.Duration
	MaxDirtyWait    time.Duration
	MinWriteInterval time.Duration
	RetryBackoff    time.Duration
	MaxRetryBackoff time.Duration
}

func defaultRankedPersistenceConfig() RankedPersistenceConfig {
	return RankedPersistenceConfig{
		Enabled:         true,
		MaxRanked:       32,
		CoalesceDelay:   200 * time.Millisecond,
		MaxDirtyWait:    2 * time.Second,
		MinWriteInterval: 30 * time.Second,
		RetryBackoff:    500 * time.Millisecond,
		MaxRetryBackoff: 4 * time.Second,
	}
}

// RankedPersistenceWriter owns scheduling and serializes saves. At most one
// storage operation is in flight, including explicit flushes.
type RankedPersistenceWriter struct {
	mu           sync.Mutex
	cfg          RankedPersistenceConfig
	log          *logger.Logger
	snapshotFn   func(int) []config.ResolverAddress
	saveFn       func(string, []config.ResolverAddress) error
	notifyCh     chan struct{}
	flushCh      chan rankedFlush
	closeCh      chan struct{}
	doneCh       chan struct{}
	isDirty      bool
	dirtySeq     uint64
	firstDirtyAt time.Time
	closed       bool
	stopOnce     sync.Once
}

type rankedFlush struct {
	revision uint64
	done     chan error
}

type rankedSaveResult struct {
	revision  uint64
	endpoints []config.ResolverAddress
	err       error
}

func newRankedPersistenceWriter(cfg RankedPersistenceConfig, log *logger.Logger,
	snapshotFn func(int) []config.ResolverAddress,
	saveFn func(string, []config.ResolverAddress) error,
) *RankedPersistenceWriter {
	defaults := defaultRankedPersistenceConfig()
	isDefaultTiming := cfg.CoalesceDelay <= 0 && cfg.MaxDirtyWait <= 0
	if cfg.CoalesceDelay <= 0 {
		cfg.CoalesceDelay = defaults.CoalesceDelay
	}
	if cfg.MaxDirtyWait <= 0 {
		cfg.MaxDirtyWait = defaults.MaxDirtyWait
	}
	if cfg.MinWriteInterval < 0 {
		cfg.MinWriteInterval = 0
	} else if cfg.MinWriteInterval == 0 && isDefaultTiming {
		cfg.MinWriteInterval = defaults.MinWriteInterval
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = defaults.RetryBackoff
	}
	if cfg.MaxRetryBackoff <= 0 {
		cfg.MaxRetryBackoff = defaults.MaxRetryBackoff
	}
	if saveFn == nil {
		saveFn = config.UpdateResolversFileWithRanked
	}
	w := &RankedPersistenceWriter{cfg: cfg, log: log, snapshotFn: snapshotFn, saveFn: saveFn,
		notifyCh: make(chan struct{}, 1), flushCh: make(chan rankedFlush),
		closeCh: make(chan struct{}), doneCh: make(chan struct{})}
	if cfg.Enabled && cfg.ResolversPath != "" {
		go w.run()
	} else {
		close(w.doneCh)
	}
	return w
}

func (w *RankedPersistenceWriter) NotifyDirty() {
	if w == nil || !w.cfg.Enabled || w.cfg.ResolversPath == "" {
		return
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.isDirty = true
	w.dirtySeq++
	if w.firstDirtyAt.IsZero() {
		w.firstDirtyAt = time.Now()
	}
	w.mu.Unlock()
	select {
	case w.notifyCh <- struct{}{}:
	default:
	}
}

func (w *RankedPersistenceWriter) run() {
	defer close(w.doneCh)
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	var timerCh <-chan time.Time
	var shutdown *time.Timer
	var shutdownCh <-chan time.Time
	closeCh := w.closeCh
	results := make(chan rankedSaveResult, 1)
	var lastWritten []config.ResolverAddress
	var lastWriteAt time.Time
	var waiters []rankedFlush
	inFlight, stopping := false, false
	backoff := w.cfg.RetryBackoff
	var retryAt time.Time

	schedule := func() {
		w.mu.Lock()
		dirty, first := w.isDirty, w.firstDirtyAt
		w.mu.Unlock()
		if !dirty || inFlight {
			return
		}
		due := time.Now().Add(w.cfg.CoalesceDelay)
		if maxDue := first.Add(w.cfg.MaxDirtyWait); maxDue.Before(due) {
			due = maxDue
		}
		if due.Before(retryAt) {
			due = retryAt
		}
		if w.cfg.MinWriteInterval > 0 && !lastWriteAt.IsZero() && len(waiters) == 0 && !stopping {
			if earliest := lastWriteAt.Add(w.cfg.MinWriteInterval); due.Before(earliest) {
				due = earliest
			}
		}
		delay := time.Until(due)
		if delay < 0 {
			delay = 0
		}
		timer.Reset(delay)
		timerCh = timer.C
	}
	startSave := func() {
		if inFlight {
			return
		}
		w.mu.Lock()
		dirty, revision := w.isDirty, w.dirtySeq
		if dirty {
			// Notifications during this save start the next coalescing window.
			// Reusing the old deadline would cause immediate snapshot loops
			// once continuous live observations exceed MaxDirtyWait.
			w.firstDirtyAt = time.Time{}
		}
		w.mu.Unlock()
		if !dirty {
			return
		}
		inFlight = true
		previous := append([]config.ResolverAddress(nil), lastWritten...)
		go func() {
			ranked := w.snapshotFn(max(32, w.cfg.MaxRanked))
			var err error
			if !endpointOrdersEqual(ranked, previous) {
				err = w.saveFn(w.cfg.ResolversPath, ranked)
			}
			results <- rankedSaveResult{revision: revision, endpoints: ranked, err: err}
		}()
	}
	defer func() {
		if shutdown != nil {
			shutdown.Stop()
		}
		for _, waiter := range waiters {
			waiter.done <- fmt.Errorf("ranked writer stopped before flush completed")
		}
	}()

	for {
		select {
		case <-closeCh:
			closeCh = nil
			stopping = true
			shutdown = time.NewTimer(2 * time.Second)
			shutdownCh = shutdown.C
			startSave()
		case <-shutdownCh:
			if w.log != nil {
				w.log.Warnf("[Resolvers] Shutdown flush exceeded 2 seconds")
			}
			return
		case waiter := <-w.flushCh:
			w.mu.Lock()
			dirty := w.isDirty
			w.mu.Unlock()
			if !dirty {
				waiter.done <- nil
			} else {
				waiters = append(waiters, waiter)
				startSave()
			}
		case <-w.notifyCh:
			schedule()
		case <-timerCh:
			timerCh = nil
			startSave()
		case result := <-results:
			inFlight = false
			w.mu.Lock()
			if result.err == nil {
				lastWritten = append([]config.ResolverAddress(nil), result.endpoints...)
				lastWriteAt = time.Now()
				if w.dirtySeq == result.revision {
					w.isDirty = false
					w.firstDirtyAt = time.Time{}
				}
				backoff = w.cfg.RetryBackoff
				retryAt = time.Time{}
			} else {
				if w.firstDirtyAt.IsZero() {
					w.firstDirtyAt = time.Now()
				}
				retryAt = time.Now().Add(backoff)
				backoff *= 2
				if backoff > w.cfg.MaxRetryBackoff {
					backoff = w.cfg.MaxRetryBackoff
				}
			}
			w.mu.Unlock()
			if result.err != nil && w.log != nil {
				w.log.Warnf("[Resolvers] Failed to save ranked resolvers: %v", result.err)
			}
			remaining := waiters[:0]
			for _, waiter := range waiters {
				if waiter.revision <= result.revision {
					waiter.done <- result.err
				} else {
					remaining = append(remaining, waiter)
				}
			}
			waiters = remaining
			if len(waiters) > 0 && result.err == nil {
				startSave()
			} else {
				schedule()
			}
		}
		if stopping && !inFlight {
			w.mu.Lock()
			dirty := w.isDirty
			w.mu.Unlock()
			if !dirty {
				return
			}
		}
	}
}

// Flush asks the single writer to persist the current dirty revision. Cancelling
// a waiter never spawns another save or blocks the writer's completion path.
func (w *RankedPersistenceWriter) Flush(ctx context.Context) error {
	if w == nil || !w.cfg.Enabled || w.cfg.ResolversPath == "" {
		return nil
	}
	w.mu.Lock()
	request := rankedFlush{revision: w.dirtySeq, done: make(chan error, 1)}
	closed := w.closed
	w.mu.Unlock()
	if closed {
		return fmt.Errorf("ranked writer is closed")
	}
	select {
	case <-ctx.Done():
		return fmt.Errorf("ranked writer flush: %w", ctx.Err())
	case <-w.doneCh:
		return fmt.Errorf("ranked writer is closed")
	case w.flushCh <- request:
	}
	select {
	case <-ctx.Done():
		return fmt.Errorf("ranked writer flush: %w", ctx.Err())
	case err := <-request.done:
		if err != nil {
			return fmt.Errorf("ranked writer flush: %w", err)
		}
		return nil
	}
}

// Close stops notifications, allows up to two seconds for final persistence, and
// joins the scheduling goroutine. Go cannot cancel a blocked filesystem syscall;
// a single outstanding storage operation may finish after the deadline.
func (w *RankedPersistenceWriter) Close() {
	if w == nil {
		return
	}
	w.stopOnce.Do(func() {
		w.mu.Lock()
		w.closed = true
		w.mu.Unlock()
		close(w.closeCh)
		<-w.doneCh
	})
}

func endpointOrdersEqual(a, b []config.ResolverAddress) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].IP != b[i].IP || a[i].Port != b[i].Port {
			return false
		}
	}
	return true
}
