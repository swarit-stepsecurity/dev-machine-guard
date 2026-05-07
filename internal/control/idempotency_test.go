package control

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// completedResult is a tiny convenience for tests that need a
// realistic-ish Result payload to publish.
func completedResult(id string, data any) Result {
	now := time.Now().UTC()
	return successResult(id, now, now, data)
}

func TestResultCache_FreshIDReserves(t *testing.T) {
	c := NewResultCache(0, 0)
	cached, out, pub := c.GetOrReserve("a")
	if out != OutcomeReserved {
		t.Fatalf("outcome = %v, want OutcomeReserved", out)
	}
	if pub == nil {
		t.Fatal("expected non-nil publish closure on Reserved")
	}
	if cached.ID != "" || cached.Ok {
		t.Errorf("cached should be zero on Reserved, got %+v", cached)
	}
}

func TestResultCache_ReplayAfterPublish(t *testing.T) {
	c := NewResultCache(0, 0)
	_, _, pub := c.GetOrReserve("a")
	pub(completedResult("a", "first"))

	cached, out, _ := c.GetOrReserve("a")
	if out != OutcomeReplay {
		t.Fatalf("second call: outcome = %v, want OutcomeReplay", out)
	}
	if cached.Data != "first" {
		t.Errorf("cached.Data = %v, want 'first'", cached.Data)
	}
}

func TestResultCache_InFlightReturnsInFlight(t *testing.T) {
	c := NewResultCache(0, 0)
	// First caller reserves but does NOT publish.
	_, _, _ = c.GetOrReserve("a")

	// Second caller must see in-flight.
	_, out, pub := c.GetOrReserve("a")
	if out != OutcomeInFlight {
		t.Fatalf("outcome = %v, want OutcomeInFlight", out)
	}
	if pub != nil {
		t.Error("publish must be nil when not reserved")
	}
}

func TestResultCache_TTLEvictsCompleted(t *testing.T) {
	c := NewResultCache(0, 50*time.Millisecond)
	_, _, pub := c.GetOrReserve("a")
	pub(completedResult("a", "first"))

	// Force the clock forward.
	c.now = func() time.Time { return time.Now().Add(time.Second) }

	cached, out, _ := c.GetOrReserve("a")
	if out != OutcomeReserved {
		t.Fatalf("expected eviction → re-reserve; got outcome=%v cached=%+v", out, cached)
	}
}

func TestResultCache_LRUEvictsOldestWhenFull(t *testing.T) {
	c := NewResultCache(2, time.Hour)
	for _, id := range []string{"a", "b"} {
		_, _, pub := c.GetOrReserve(id)
		pub(completedResult(id, id))
	}

	// Adding "c" should evict "a" (LRU).
	_, _, pubC := c.GetOrReserve("c")
	pubC(completedResult("c", "c"))

	// Query MRU-first so checking the missing entry doesn't cascade-evict
	// the surviving ones (each missed lookup is a fresh Reserve and
	// would otherwise push an entry out at the back).
	if _, out, _ := c.GetOrReserve("c"); out != OutcomeReplay {
		t.Errorf("expected 'c' replayed, got %v", out)
	}
	if _, out, _ := c.GetOrReserve("b"); out != OutcomeReplay {
		t.Errorf("expected 'b' replayed, got %v", out)
	}
	cached, out, _ := c.GetOrReserve("a")
	if out != OutcomeReserved {
		t.Errorf("expected 'a' evicted; got outcome=%v cached=%+v", out, cached)
	}
}

func TestResultCache_LRURefreshesOnHit(t *testing.T) {
	c := NewResultCache(2, time.Hour)
	for _, id := range []string{"a", "b"} {
		_, _, pub := c.GetOrReserve(id)
		pub(completedResult(id, id))
	}

	// Touch "a" → "a" is now MRU, "b" becomes LRU.
	if _, out, _ := c.GetOrReserve("a"); out != OutcomeReplay {
		t.Fatalf("a outcome = %v, want OutcomeReplay", out)
	}
	// Add "c" → should evict "b".
	_, _, pubC := c.GetOrReserve("c")
	pubC(completedResult("c", "c"))

	// Query "a" first (MRU survivor) before the missed lookup of "b" —
	// see TestResultCache_LRUEvictsOldestWhenFull for why order matters.
	if _, out, _ := c.GetOrReserve("a"); out != OutcomeReplay {
		t.Errorf("expected 'a' replayed, got %v", out)
	}
	if _, out, _ := c.GetOrReserve("b"); out != OutcomeReserved {
		t.Errorf("expected 'b' evicted by LRU after 'a' refresh; got %v", out)
	}
}

// TestResultCache_RaceReserveAndPublish exercises concurrent
// GetOrReserve calls to ensure the in-flight + reserved transitions
// are atomic. A second caller landing while the first is between
// Reserve and Publish must see OutcomeInFlight, never racing into a
// duplicate Reserve.
func TestResultCache_RaceReserveAndPublish(t *testing.T) {
	c := NewResultCache(0, 0)

	const id = "a"
	_, _, pub := c.GetOrReserve(id)

	var inFlightCount int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, out, _ := c.GetOrReserve(id)
			if out == OutcomeInFlight {
				atomic.AddInt32(&inFlightCount, 1)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&inFlightCount); got != 50 {
		t.Errorf("expected 50 in-flight outcomes, got %d", got)
	}

	pub(completedResult(id, "done"))

	// After publish, every caller sees Replay.
	if _, out, _ := c.GetOrReserve(id); out != OutcomeReplay {
		t.Errorf("post-publish outcome = %v, want OutcomeReplay", out)
	}
}
