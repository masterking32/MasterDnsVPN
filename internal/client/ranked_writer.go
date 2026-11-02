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
	RetryBackoff    time.Duration
	MaxRetryBackoff time.Duration
}

func defaultRankedPersistenceConfig() RankedPersistenceConfig {
	return RankedPersistenceConfig{
		Enabled:         true,
		MaxRanked:       32,
		CoalesceDelay:   200 * time.Millisecond,
		MaxDirtyWait:    2 * time.Second,
		RetryBackoff:    500 * time.Millisecond,
		MaxRetryBackoff: 4 * time.Second,
	}
}

// RankedPersistenceWriter batches, coalesces, and serializes ranked endpoint saves
// on a Client-owned background goroutine, decoupling file I/O from pool mutation locks.
type RankedPersistenceWriter struct {
	mu         sync.Mutex
	saveMu     sync.Mutex
	cfg        RankedPersistenceConfig
	log        *logger.Logger
	snapshotFn func(maxCount int) []config.ResolverAddress
	saveFn     func(path string, ranked []config.ResolverAddress) error

	notifyCh chan struct{}
	closeCh  chan struct{}
	doneCh   chan struct{}

	isDirty      bool
	dirtySeq     uint64
	cleanSeq     uint64
	firstDirtyAt time.Time
	lastWritten  []config.ResolverAddress

	currentBackoff time.Duration
	stopOnce       sync.Once
	closed         bool
}

func newRankedPersistenceWriter(
	cfg RankedPersistenceConfig,
	log *logger.Logger,
	snapshotFn func(maxCount int) []config.ResolverAddress,
	saveFn func(path string, ranked []config.ResolverAddress) error,
) *RankedPersistenceWriter {
	if cfg.CoalesceDelay <= 0 {
		cfg.CoalesceDelay = 200 * time.Millisecond
	}
	if cfg.MaxDirtyWait <= 0 {
		cfg.MaxDirtyWait = 2 * time.Second
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 500 * time.Millisecond
	}
	if cfg.MaxRetryBackoff <= 0 {
		cfg.MaxRetryBackoff = 4 * time.Second
	}
	if saveFn == nil {
		saveFn = config.UpdateResolversFileWithRanked
	}

	w := &RankedPersistenceWriter{
		cfg:            cfg,
		log:            log,
		snapshotFn:     snapshotFn,
		saveFn:         saveFn,
		notifyCh:       make(chan struct{}, 1),
		closeCh:        make(chan struct{}),
		doneCh:         make(chan struct{}),
		currentBackoff: cfg.RetryBackoff,
	}

	if cfg.Enabled && cfg.ResolversPath != "" {
		go w.run()
	} else {
		close(w.doneCh)
	}

	return w
}

// NotifyDirty nonblockingly records that candidate rankings have changed.
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

	var timer *time.Timer
	var timerCh <-chan time.Time

	stopTimer := func() {
		if timer != nil {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timerCh = nil
		}
	}

	resetTimer := func(d time.Duration) {
		stopTimer()
		if timer == nil {
			timer = time.NewTimer(d)
		} else {
			timer.Reset(d)
		}
		timerCh = timer.C
	}

	for {
		select {
		case <-w.closeCh:
			stopTimer()
			return

		case <-w.notifyCh:
			w.mu.Lock()
			if !w.isDirty {
				w.mu.Unlock()
				continue
			}
			now := time.Now()
			coalesceTarget := now.Add(w.cfg.CoalesceDelay)
			maxTarget := w.firstDirtyAt.Add(w.cfg.MaxDirtyWait)

			delay := w.cfg.CoalesceDelay
			if maxTarget.Before(coalesceTarget) {
				delay = maxTarget.Sub(now)
				if delay < 0 {
					delay = 0
				}
			}
			w.mu.Unlock()

			resetTimer(delay)

		case <-timerCh:
			stopTimer()
			err := w.performSave()
			if err != nil {
				// Retry with backoff
				w.mu.Lock()
				backoff := w.currentBackoff
				w.currentBackoff *= 2
				if w.currentBackoff > w.cfg.MaxRetryBackoff {
					w.currentBackoff = w.cfg.MaxRetryBackoff
				}
				w.mu.Unlock()
				resetTimer(backoff)
			}
		}
	}
}

// performSave serializes snapshot acquisition and persistence under lock.
func (w *RankedPersistenceWriter) performSave() error {
	w.saveMu.Lock()
	defer w.saveMu.Unlock()

	w.mu.Lock()
	if !w.isDirty {
		w.mu.Unlock()
		return nil
	}
	targetSeq := w.dirtySeq
	w.mu.Unlock()

	maxRanked := w.cfg.MaxRanked
	if maxRanked < 32 {
		maxRanked = 32
	}
	ranked := w.snapshotFn(maxRanked)

	w.mu.Lock()
	if endpointOrdersEqual(ranked, w.lastWritten) {
		// Telemetry changed but endpoint order remained unchanged -> no file rewrite
		if w.dirtySeq == targetSeq {
			w.isDirty = false
			w.firstDirtyAt = time.Time{}
		}
		w.currentBackoff = w.cfg.RetryBackoff
		w.mu.Unlock()
		return nil
	}
	w.mu.Unlock()

	err := w.saveFn(w.cfg.ResolversPath, ranked)

	w.mu.Lock()
	defer w.mu.Unlock()

	if err != nil {
		if w.log != nil {
			w.log.Warnf("<yellow>[Resolvers]</yellow> Failed to auto-save ranked resolvers to <cyan>%s</cyan>: %v",
				w.cfg.ResolversPath, err)
		}
		return fmt.Errorf("save ranked resolvers: %w", err)
	}

	w.lastWritten = make([]config.ResolverAddress, len(ranked))
	copy(w.lastWritten, ranked)
	w.currentBackoff = w.cfg.RetryBackoff

	if w.dirtySeq == targetSeq {
		w.isDirty = false
		w.firstDirtyAt = time.Time{}
	}

	if w.log != nil {
		w.log.Debugf("<green>[Resolvers]</green> Saved %d ranked resolvers to <cyan>%s</cyan>",
			len(ranked), w.cfg.ResolversPath)
	}

	return nil
}

// Flush immediately flushes dirty ranked endpoints.
func (w *RankedPersistenceWriter) Flush(ctx context.Context) error {
	if w == nil || !w.cfg.Enabled || w.cfg.ResolversPath == "" {
		return nil
	}
	done := make(chan error, 1)
	go func() {
		done <- w.performSave()
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("ranked writer flush context: %w", ctx.Err())
	case err := <-done:
		if err != nil {
			return fmt.Errorf("ranked writer flush: %w", err)
		}
		return nil
	}
}

// Close gracefully flushes pending changes within bounded timeout and joins the background writer.
func (w *RankedPersistenceWriter) Close() {
	if w == nil {
		return
	}
	w.stopOnce.Do(func() {
		w.mu.Lock()
		w.closed = true
		dirty := w.isDirty
		w.mu.Unlock()

		if dirty && w.cfg.Enabled && w.cfg.ResolversPath != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = w.Flush(ctx)
			cancel()
		}

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
