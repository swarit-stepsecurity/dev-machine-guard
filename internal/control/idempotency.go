package control

import (
	"container/list"
	"sync"
	"time"
)

// Defaults match the API contract: 1000 entries, 10 minutes.
const (
	DefaultCacheSize = 1000
	DefaultCacheTTL  = 10 * time.Minute
)

// cacheState tracks where an entry is in the result lifecycle.
type cacheState int

const (
	stateInFlight  cacheState = iota // reserved, handler still running
	stateCompleted                   // handler returned, result cached
)

type cacheEntry struct {
	id        string
	state     cacheState
	result    Result    // valid when state == stateCompleted
	completed time.Time // valid when state == stateCompleted; for TTL eviction
}

// ResultCache is the LRU+TTL idempotency store described in the API
// contract. It serves three purposes simultaneously:
//
//  1. Replay: same id, already completed → re-emit the cached result
//     without re-executing.
//  2. In-flight detection: same id, handler still running → caller gets
//     back an in_progress signal so it can reply with the right code.
//  3. Bounded memory: capped at MaxSize entries, with lazy TTL eviction
//     on every lookup.
//
// All operations hold a single mutex; the cache is not optimized for
// extreme contention because the registry's single-slot executor means
// at most one Reserve+Publish round runs at a time anyway.
type ResultCache struct {
	mu      sync.Mutex
	entries map[string]*list.Element // id -> *list.Element holding *cacheEntry
	order   *list.List               // MRU at front, LRU at back
	maxSize int
	ttl     time.Duration
	now     func() time.Time // injectable for tests
}

// NewResultCache returns a ResultCache. Pass 0 for size or ttl to use
// the package defaults.
func NewResultCache(maxSize int, ttl time.Duration) *ResultCache {
	if maxSize <= 0 {
		maxSize = DefaultCacheSize
	}
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &ResultCache{
		entries: make(map[string]*list.Element),
		order:   list.New(),
		maxSize: maxSize,
		ttl:     ttl,
		now:     time.Now,
	}
}

// Outcome describes what GetOrReserve found at id.
type Outcome int

const (
	// OutcomeReserved means the caller is now responsible for running
	// the handler and calling Publish with the result. No prior entry
	// existed for this id within the TTL window.
	OutcomeReserved Outcome = iota

	// OutcomeReplay means a completed result is cached for this id.
	// The caller must re-emit Cached without re-executing.
	OutcomeReplay

	// OutcomeInFlight means another caller is currently running the
	// handler for this id. The caller must NOT execute and should
	// reply with CodeInProgress.
	OutcomeInFlight
)

// GetOrReserve atomically inspects the cache for id. The caller's next
// step depends on Outcome:
//
//   - OutcomeReserved: run the handler, then call publish(result) so
//     the cache transitions the entry to completed and unblocks any
//     duplicate replays.
//   - OutcomeReplay: emit cached and return; do NOT call publish.
//   - OutcomeInFlight: emit an in_progress error; do NOT call publish.
//
// publish is non-nil only on OutcomeReserved.
func (c *ResultCache) GetOrReserve(id string) (cached Result, out Outcome, publish func(Result)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.evictExpiredLocked()

	if elem, ok := c.entries[id]; ok {
		entry := elem.Value.(*cacheEntry)
		// Refresh LRU position on any hit so popular replays don't get
		// evicted by a flood of new ids.
		c.order.MoveToFront(elem)
		switch entry.state {
		case stateCompleted:
			return entry.result, OutcomeReplay, nil
		case stateInFlight:
			return Result{}, OutcomeInFlight, nil
		}
	}

	// New id — reserve.
	entry := &cacheEntry{id: id, state: stateInFlight}
	elem := c.order.PushFront(entry)
	c.entries[id] = elem
	c.evictOverflowLocked()

	publish = func(r Result) {
		c.mu.Lock()
		defer c.mu.Unlock()
		// The reserve element may have been evicted under a tiny TTL
		// or if the cache filled up; in that case we just don't cache
		// the result. The caller already returned the result over the
		// wire; the cache miss only matters on duplicate replay.
		elem, ok := c.entries[id]
		if !ok {
			return
		}
		e := elem.Value.(*cacheEntry)
		e.state = stateCompleted
		e.result = r
		e.completed = c.now()
		c.order.MoveToFront(elem)
	}
	return Result{}, OutcomeReserved, publish
}

// evictExpiredLocked walks back from the LRU end removing completed
// entries whose TTL elapsed. In-flight entries are never expired —
// they're held until publish fires (or the daemon dies, which clears
// the whole cache anyway).
func (c *ResultCache) evictExpiredLocked() {
	now := c.now()
	for {
		back := c.order.Back()
		if back == nil {
			return
		}
		entry := back.Value.(*cacheEntry)
		if entry.state != stateCompleted {
			return // in-flight; nothing further back is older
		}
		if now.Sub(entry.completed) <= c.ttl {
			return
		}
		c.order.Remove(back)
		delete(c.entries, entry.id)
	}
}

// evictOverflowLocked pops the LRU entry if the cache exceeded maxSize.
// Called after every Reserve so the cap is enforced without a separate
// background goroutine. In-flight entries can be evicted too — that's
// acceptable: the result just won't be cacheable on completion.
func (c *ResultCache) evictOverflowLocked() {
	for c.order.Len() > c.maxSize {
		back := c.order.Back()
		if back == nil {
			return
		}
		entry := back.Value.(*cacheEntry)
		c.order.Remove(back)
		delete(c.entries, entry.id)
	}
}
