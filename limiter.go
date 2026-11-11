package netloom

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// rateLimiter is a token bucket enforcing both per-second and per-minute caps;
// a request proceeds only when both buckets have a token, so the stricter
// constraint wins. A nil sub-bucket means that dimension is unlimited.
type rateLimiter struct {
	perSecond *bucket
	perMinute *bucket
}

func newRateLimiter(perSecond, perMinute int) *rateLimiter {
	rl := &rateLimiter{}
	if perSecond > 0 {
		rl.perSecond = newBucket(perSecond, time.Second)
	}
	if perMinute > 0 {
		rl.perMinute = newBucket(perMinute, time.Minute)
	}
	return rl
}

// wait blocks until a token is available in every active bucket, or ctx ends.
func (rl *rateLimiter) wait(ctx context.Context) error {
	if rl.perSecond != nil {
		if err := rl.perSecond.wait(ctx); err != nil {
			return fmt.Errorf("netloom.rateLimiter: %w", err)
		}
	}
	if rl.perMinute != nil {
		if err := rl.perMinute.wait(ctx); err != nil {
			return fmt.Errorf("netloom.rateLimiter: %w", err)
		}
	}
	return nil
}

// bucket is a leaky/token bucket: `capacity` tokens refilled evenly over `per`.
type bucket struct {
	mu       sync.Mutex
	capacity float64
	tokens   float64
	rate     float64 // tokens per second
	last     time.Time
}

func newBucket(capacity int, per time.Duration) *bucket {
	c := float64(capacity)
	// Start with a single token rather than a full bucket: a full initial
	// bucket would let `capacity` requests fire instantly (a burst of one whole
	// window), defeating steady-state rate precision. One token lets the very
	// first request proceed immediately while the rest are paced by `rate`.
	return &bucket{
		capacity: c,
		tokens:   1,
		rate:     c / per.Seconds(),
		last:     time.Now(),
	}
}

func (b *bucket) wait(ctx context.Context) error {
	for {
		b.mu.Lock()
		now := time.Now()
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
		if b.tokens >= 1 {
			b.tokens--
			b.mu.Unlock()
			return nil
		}
		deficit := 1 - b.tokens
		sleep := time.Duration(deficit / b.rate * float64(time.Second))
		b.mu.Unlock()

		if sleep <= 0 {
			sleep = time.Millisecond
		}
		timer := time.NewTimer(sleep)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// hostSemaphore caps concurrent in-flight requests per host. References include
// holders AND waiters: an idle entry can only disappear once neither remains.
// This prevents a new channel from bypassing waiters on an evicted entry.
type hostSemaphore struct {
	mu    sync.Mutex
	limit int
	used  map[string]*hostSlots
}

type hostSlots struct {
	slots chan struct{}
	refs  int
}

func newHostSemaphore(limit int) *hostSemaphore {
	if limit <= 0 {
		limit = 1
	}
	return &hostSemaphore{limit: limit, used: map[string]*hostSlots{}}
}

func (h *hostSemaphore) acquire(ctx context.Context, host string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	entry := h.used[host]
	if entry == nil {
		entry = &hostSlots{slots: make(chan struct{}, h.limit)}
		h.used[host] = entry
	}
	entry.refs++
	h.mu.Unlock()

	select {
	case entry.slots <- struct{}{}:
		// Cancellation may race a newly available slot. Do not retain it.
		if err := ctx.Err(); err != nil {
			h.release(host)
			return err
		}
		return nil
	case <-ctx.Done():
		h.mu.Lock()
		h.unref(host, entry)
		h.mu.Unlock()
		return ctx.Err()
	}
}

// unref runs under mu, including on canceled waiters that never held a slot.
func (h *hostSemaphore) unref(host string, entry *hostSlots) {
	entry.refs--
	if entry.refs == 0 {
		delete(h.used, host)
	}
}

func (h *hostSemaphore) release(host string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	entry := h.used[host]
	if entry == nil {
		return
	}
	select {
	case <-entry.slots:
		h.unref(host, entry)
	default:
	}
}
