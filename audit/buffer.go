package audit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultBufferCapacity absorbs a short audit-database outage without
	// allowing audit memory to grow without bound.
	DefaultBufferCapacity = 10_000
	// DefaultMaxSeenIDs bounds the in-process idempotency set. Durable
	// event_id unique constraints remain the cross-process guarantee.
	DefaultMaxSeenIDs = 100_000

	defaultRetryInitial = 50 * time.Millisecond
	defaultRetryMax     = 2 * time.Second
	defaultMaxAttempts  = 4
)

var (
	ErrAuditorClosed = errors.New("audit auditor is closed")
	// ErrShutdownTimeout is returned by Close when a backend call does not
	// finish before the bounded shutdown wait. The worker may still finish in
	// the background, but Close has unblocked the caller.
	ErrShutdownTimeout = errors.New("audit auditor shutdown timed out")
)

// EventSink is the optional error-returning persistence interface. Postgres
// implements it; ordinary Auditor implementations remain source compatible.
type EventSink interface {
	SaveAuditEvent(ctx context.Context, event Event) error
}

// EventSaver is an alternate sink name implemented by some audit backends.
type EventSaver interface {
	SaveEvent(ctx context.Context, event Event) error
}

// AnySaver accepts a normalized or implementation-specific event.
type AnySaver interface {
	Save(ctx context.Context, event any) error
}

// DropReporter is implemented by components that want a callback whenever the
// bounded buffer drops events.
type DropReporter interface {
	ReportAuditDropped(dropped uint64)
}

// BufferStats is a point-in-time view of a BufferedAuditor.
type BufferStats struct {
	Capacity   int    `json:"capacity"`
	Pending    int    `json:"pending"`
	Enqueued   uint64 `json:"enqueued"`
	Processed  uint64 `json:"processed"`
	Dropped    uint64 `json:"dropped"`
	Duplicates uint64 `json:"duplicates"`
	SeenIDs    int    `json:"seen_ids"`
	LastError  string `json:"last_error,omitempty"`
}

// BufferedAuditor wraps an Auditor with a bounded FIFO queue. Handle never
// blocks on the downstream backend: when the queue is full, incoming events
// are counted as dropped. A single worker reads the queue, which preserves
// submission order. Duplicate event identities are enqueued at most once.
type BufferedAuditor struct {
	next     Auditor
	capacity int
	redactor *Redactor

	ctx             context.Context
	cancel          context.CancelFunc
	shutdownTimeout time.Duration

	queue chan bufferedEnvelope

	enqueueMu sync.Mutex
	closed    bool
	closeOnce sync.Once
	wg        sync.WaitGroup

	enqueued   atomic.Uint64
	processed  atomic.Uint64
	dropped    atomic.Uint64
	duplicates atomic.Uint64
	attempts   atomic.Uint64

	lastError atomic.Value // string

	seenMu  sync.Mutex
	seen    map[string]struct{}
	seenQ   []string
	maxSeen int

	maxAttempts  int
	retryInitial time.Duration
	retryMax     time.Duration
	reporter     func(uint64)
}

type bufferedEnvelope struct {
	event      any
	identity   string
	enqueuedAt time.Time
}

// BufferOption configures a BufferedAuditor.
type BufferOption func(*BufferedAuditor)

// WithRedactor redacts events before they are passed to an EventSink.
func WithRedactor(r *Redactor) BufferOption {
	return func(b *BufferedAuditor) { b.redactor = r }
}

// WithMaxSeenIDs sets the bound for the in-memory idempotency set.
func WithMaxSeenIDs(n int) BufferOption {
	return func(b *BufferedAuditor) {
		if n > 0 {
			b.maxSeen = n
		}
	}
}

// WithRetry configures persistence retries for backends implementing an error
// returning sink. maxAttempts <= 0 means retry until the event is delivered or
// the auditor is closed.
func WithRetry(maxAttempts int, initial, maxBackoff time.Duration) BufferOption {
	return func(b *BufferedAuditor) {
		b.maxAttempts = maxAttempts
		if initial > 0 {
			b.retryInitial = initial
		}
		if maxBackoff > 0 {
			b.retryMax = maxBackoff
		}
	}
}

// WithDropReporter installs a callback invoked with the cumulative drop count
// after each drop.
func WithDropReporter(report func(dropped uint64)) BufferOption {
	return func(b *BufferedAuditor) { b.reporter = report }
}

// WithShutdownTimeout bounds how long Close waits for a blocked backend.
func WithShutdownTimeout(d time.Duration) BufferOption {
	return func(b *BufferedAuditor) {
		if d >= 0 {
			b.shutdownTimeout = d
		}
	}
}

// NewBufferedAuditor creates a bounded asynchronous auditor. A capacity <= 0
// selects DefaultBufferCapacity.
func NewBufferedAuditor(next Auditor, capacity int, opts ...BufferOption) *BufferedAuditor {
	if capacity <= 0 {
		capacity = DefaultBufferCapacity
	}
	b := &BufferedAuditor{
		next:            next,
		capacity:        capacity,
		queue:           make(chan bufferedEnvelope, capacity),
		redactor:        DefaultRedactor(),
		seen:            make(map[string]struct{}),
		maxSeen:         DefaultMaxSeenIDs,
		maxAttempts:     defaultMaxAttempts,
		retryInitial:    defaultRetryInitial,
		retryMax:        defaultRetryMax,
		shutdownTimeout: time.Second,
	}
	b.ctx, b.cancel = context.WithCancel(context.Background())
	for _, opt := range opts {
		opt(b)
	}
	b.wg.Add(1)
	go b.worker()
	return b
}

// NewAsyncAuditor is an alternate constructor name for NewBufferedAuditor.
func NewAsyncAuditor(next Auditor, capacity int, opts ...BufferOption) *BufferedAuditor {
	return NewBufferedAuditor(next, capacity, opts...)
}

// Handle enqueues an event without blocking on the audit backend.
func (b *BufferedAuditor) Handle(event any) {
	if b == nil {
		return
	}
	id := EventIdentity(event)

	b.enqueueMu.Lock()
	if b.closed {
		n := b.dropped.Add(1)
		b.enqueueMu.Unlock()
		b.reportDrop(n)
		return
	}
	if b.isSeenLocked(id) {
		b.duplicates.Add(1)
		b.enqueueMu.Unlock()
		return
	}

	env := bufferedEnvelope{event: event, identity: id, enqueuedAt: time.Now().UTC()}
	// Account for the event before making it available to the worker. This
	// closes a narrow Flush race where the worker could process and count an
	// event before enqueued was incremented.
	b.enqueued.Add(1)
	var droppedN uint64
	select {
	case b.queue <- env:
		b.addSeenLocked(id)
	default:
		// Bounded buffer is full. Roll back the enqueue account, then count
		// and report the drop without blocking the decryption path. The ID is
		// intentionally not remembered so a later retry can fit if the backend
		// catches up.
		b.enqueued.Add(^uint64(0))
		droppedN = b.dropped.Add(1)
	}
	b.enqueueMu.Unlock()

	if droppedN != 0 {
		b.reportDrop(droppedN)
	}
}

// DroppedCount returns the cumulative number of events rejected because the
// buffer was full or the auditor was closed.
func (b *BufferedAuditor) DroppedCount() int64 { return int64(b.dropped.Load()) }

// DroppedCountUint64 returns the cumulative drop counter as uint64.
func (b *BufferedAuditor) DroppedCountUint64() uint64 { return b.dropped.Load() }

// DroppedEvents is an alias for DroppedCount.
func (b *BufferedAuditor) DroppedEvents() int64 { return b.DroppedCount() }

// Dropped is a concise alias for DroppedCount.
func (b *BufferedAuditor) Dropped() int64 { return b.DroppedCount() }

// DuplicateCount returns the number of duplicate Handle calls suppressed.
func (b *BufferedAuditor) DuplicateCount() int64 { return int64(b.duplicates.Load()) }

// Pending returns the number of events currently buffered.
func (b *BufferedAuditor) Pending() int { return len(b.queue) }

// Stats returns buffer counters.
func (b *BufferedAuditor) Stats() BufferStats {
	b.seenMu.Lock()
	seen := len(b.seen)
	b.seenMu.Unlock()
	last, _ := b.lastError.Load().(string)
	return BufferStats{
		Capacity:   b.capacity,
		Pending:    len(b.queue),
		Enqueued:   b.enqueued.Load(),
		Processed:  b.processed.Load(),
		Dropped:    b.dropped.Load(),
		Duplicates: b.duplicates.Load(),
		SeenIDs:    seen,
		LastError:  last,
	}
}

// Flush waits until all accepted events have been processed or ctx ends.
func (b *BufferedAuditor) Flush(ctx context.Context) error {
	if b == nil {
		return nil
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if b.processed.Load() >= b.enqueued.Load() && len(b.queue) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Close stops acceptance, closes the queue and waits up to the configured
// shutdown timeout for the worker to drain. If an error-returning sink is
// stuck, its context is canceled when the timeout expires. A legacy Auditor
// implementation that blocks inside Handle cannot be canceled by Go, so in
// that case Close returns ErrShutdownTimeout rather than hanging the caller.
func (b *BufferedAuditor) Close() error {
	if b == nil {
		return nil
	}
	b.closeOnce.Do(func() {
		b.enqueueMu.Lock()
		b.closed = true
		close(b.queue)
		b.enqueueMu.Unlock()
	})

	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()

	timeout := b.shutdownTimeout
	if timeout < 0 {
		timeout = 0
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		b.cancel()
		return nil
	case <-timer.C:
		b.cancel()
		return ErrShutdownTimeout
	}
}

func (b *BufferedAuditor) worker() {
	defer b.wg.Done()
	for env := range b.queue {
		b.deliver(env)
		b.processed.Add(1)
	}
}

func (b *BufferedAuditor) deliver(env bufferedEnvelope) {
	backoff := b.retryInitial
	attempt := 0
	for {
		err := b.deliverOnce(env.event)
		if err == nil {
			return
		}
		b.lastError.Store(err.Error())
		attempt++
		b.attempts.Add(1)
		if b.maxAttempts > 0 && attempt >= b.maxAttempts {
			// Retries exhausted. Count this as a drop so operators can report
			// audit loss even when the queue itself was not full.
			n := b.dropped.Add(1)
			b.reportDrop(n)
			return
		}
		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
		case <-b.ctx.Done():
			timer.Stop()
			return
		}
		if backoff < b.retryMax {
			backoff *= 2
			if backoff > b.retryMax {
				backoff = b.retryMax
			}
		}
	}
}

func (b *BufferedAuditor) deliverOnce(raw any) error {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	// Prefer an error-returning sink so temporary database failures can be
	// retried without dropping the head-of-line event.
	if sink, ok := b.next.(EventSink); ok {
		e := b.safeEvent(raw)
		return sink.SaveAuditEvent(ctx, e)
	}
	if sink, ok := b.next.(EventSaver); ok {
		e := b.safeEvent(raw)
		return sink.SaveEvent(ctx, e)
	}
	if sink, ok := b.next.(AnySaver); ok {
		e := b.safeEvent(raw)
		return sink.Save(ctx, e)
	}

	var err error
	eventForAuditor := b.safeLegacyEvent(raw)
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = errors.New("audit auditor panicked")
				b.lastError.Store(err.Error())
				log.WithField("panic", r).Warn("Audit backend panicked")
			}
		}()
		b.next.Handle(eventForAuditor)
	}()
	return err
}

func (b *BufferedAuditor) safeEvent(raw any) Event {
	e := NormalizeEvent(raw)
	if b.redactor != nil {
		e = b.redactor.RedactEvent(e)
	}
	return e
}

// safeLegacyEvent redacts known historical event types while preserving their
// concrete type for existing Auditor implementations. Unknown event structs
// are converted to the safe canonical Event.
func (b *BufferedAuditor) safeLegacyEvent(raw any) any {
	r := b.redactor
	if r == nil {
		r = DefaultRedactor()
	}
	switch v := raw.(type) {
	case Event:
		return r.RedactEvent(v)
	case *Event:
		if v == nil {
			return nil
		}
		e := r.RedactEvent(*v)
		return &e
	case DecryptEvent:
		e := r.RedactEvent(NormalizeEvent(v))
		return DecryptEvent{ID: e.ID, File: e.File, Timestamp: e.Timestamp, KeyGroupID: e.KeyGroupID, Result: e.Result, Username: e.Username, Details: e.Details}
	case *DecryptEvent:
		if v == nil {
			return nil
		}
		e := r.RedactEvent(NormalizeEvent(*v))
		cp := DecryptEvent{ID: e.ID, File: e.File, Timestamp: e.Timestamp, KeyGroupID: e.KeyGroupID, Result: e.Result, Username: e.Username, Details: e.Details}
		return &cp
	case EncryptEvent:
		e := r.RedactEvent(NormalizeEvent(v))
		return EncryptEvent{ID: e.ID, File: e.File, Timestamp: e.Timestamp, KeyGroupID: e.KeyGroupID, Result: e.Result, Username: e.Username, Details: e.Details}
	case *EncryptEvent:
		if v == nil {
			return nil
		}
		e := r.RedactEvent(NormalizeEvent(*v))
		cp := EncryptEvent{ID: e.ID, File: e.File, Timestamp: e.Timestamp, KeyGroupID: e.KeyGroupID, Result: e.Result, Username: e.Username, Details: e.Details}
		return &cp
	case RotateEvent:
		e := r.RedactEvent(NormalizeEvent(v))
		return RotateEvent{ID: e.ID, File: e.File, Timestamp: e.Timestamp, KeyGroupID: e.KeyGroupID, Result: e.Result, Username: e.Username, Details: e.Details}
	case *RotateEvent:
		if v == nil {
			return nil
		}
		e := r.RedactEvent(NormalizeEvent(*v))
		cp := RotateEvent{ID: e.ID, File: e.File, Timestamp: e.Timestamp, KeyGroupID: e.KeyGroupID, Result: e.Result, Username: e.Username, Details: e.Details}
		return &cp
	default:
		return r.RedactEvent(NormalizeEvent(raw))
	}
}

func (b *BufferedAuditor) reportDrop(n uint64) {
	if n == 1 || n%1000 == 0 {
		log.WithField("dropped", n).Warn("Audit buffer dropped events")
	}
	if b.reporter != nil {
		b.reporter(n)
	}
	if reporter, ok := b.next.(DropReporter); ok {
		reporter.ReportAuditDropped(n)
	}
}

func (b *BufferedAuditor) isSeenLocked(id string) bool {
	b.seenMu.Lock()
	defer b.seenMu.Unlock()
	_, ok := b.seen[id]
	return ok
}

func (b *BufferedAuditor) addSeenLocked(id string) {
	b.seenMu.Lock()
	defer b.seenMu.Unlock()
	if _, ok := b.seen[id]; ok {
		return
	}
	b.seen[id] = struct{}{}
	b.seenQ = append(b.seenQ, id)
	if b.maxSeen > 0 && len(b.seenQ) > b.maxSeen {
		oldest := b.seenQ[0]
		b.seenQ = b.seenQ[1:]
		delete(b.seen, oldest)
	}
}

// IdempotentAuditor suppresses duplicate event identities before delegating to
// Next. It is useful when a caller wants idempotency without asynchronous
// buffering.
type IdempotentAuditor struct {
	Next Auditor

	mu         sync.Mutex
	seen       map[string]struct{}
	order      []string
	maxSeen    int
	duplicates atomic.Uint64
}

// NewIdempotentAuditor creates a deduplicating Auditor.
func NewIdempotentAuditor(next Auditor) *IdempotentAuditor {
	return &IdempotentAuditor{Next: next, seen: make(map[string]struct{}), maxSeen: DefaultMaxSeenIDs}
}

// Handle implements Auditor.
func (a *IdempotentAuditor) Handle(event any) {
	if a == nil || a.Next == nil {
		return
	}
	id := EventIdentity(event)
	a.mu.Lock()
	if _, ok := a.seen[id]; ok {
		a.duplicates.Add(1)
		a.mu.Unlock()
		return
	}
	a.seen[id] = struct{}{}
	a.order = append(a.order, id)
	if a.maxSeen > 0 && len(a.order) > a.maxSeen {
		oldest := a.order[0]
		a.order = a.order[1:]
		delete(a.seen, oldest)
	}
	a.mu.Unlock()
	a.Next.Handle(event)
}

// DuplicateCount returns suppressed duplicate calls.
func (a *IdempotentAuditor) DuplicateCount() uint64 { return a.duplicates.Load() }

// RedactingAuditor applies a Redactor before delegating. For legacy Auditor
// values it passes the normalized safe Event to Next.
type RedactingAuditor struct {
	Next     Auditor
	Redactor *Redactor
}

// NewRedactingAuditor constructs a redaction wrapper.
func NewRedactingAuditor(next Auditor, redactor *Redactor) *RedactingAuditor {
	if redactor == nil {
		redactor = DefaultRedactor()
	}
	return &RedactingAuditor{Next: next, Redactor: redactor}
}

// Handle implements Auditor.
func (a *RedactingAuditor) Handle(event any) {
	if a == nil || a.Next == nil {
		return
	}
	e := a.Redactor.RedactEvent(NormalizeEvent(event))
	a.Next.Handle(e)
}

// SaveAuditEvent implements EventSink when Next supports it.
func (a *RedactingAuditor) SaveAuditEvent(ctx context.Context, event Event) error {
	e := a.Redactor.RedactEvent(event)
	if sink, ok := a.Next.(EventSink); ok {
		return sink.SaveAuditEvent(ctx, e)
	}
	if sink, ok := a.Next.(EventSaver); ok {
		return sink.SaveEvent(ctx, e)
	}
	a.Next.Handle(e)
	return nil
}
