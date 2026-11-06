package httpclient

import (
	"context"
	"sync"
	"time"
)

// tokenBucket is a classic token bucket: `capacity` tokens refilled evenly at
// `rate` tokens per second. wait blocks until a token is available or ctx ends.
type tokenBucket struct {
	mu       sync.Mutex
	capacity float64
	tokens   float64
	rate     float64
	last     time.Time
}

// newTokenBucket builds a bucket allowing `events` per `per`. A non-positive
// events count yields an unlimited bucket (wait returns immediately).
func newTokenBucket(events int, per time.Duration) *tokenBucket {
	if events <= 0 || per <= 0 {
		return nil
	}
	c := float64(events)
	return &tokenBucket{
		capacity: c,
		tokens:   c,
		rate:     c / per.Seconds(),
		last:     time.Now(),
	}
}

func (b *tokenBucket) wait(ctx context.Context) error {
	if b == nil {
		return ctx.Err()
	}
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

// limiterRegistry is a process-level, per-source registry of token buckets.
//
// WHY process-level (not per-Session): remote APIs rate-limit per account. If
// each Session held its own bucket, N concurrent Sessions on the same source
// would emit N× the allowed rate and trip the provider's abuse controls. A
// single shared bucket per source keeps aggregate throughput within bounds
// regardless of how many Sessions/goroutines call concurrently.
type limiterRegistry struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

var globalLimiters = &limiterRegistry{buckets: make(map[string]*tokenBucket)}

// sourceRate describes the rate limit for a named source.
type sourceRate struct {
	events int
	per    time.Duration
}

// builtinRates holds conservative local per-source defaults, not subscription
// guarantees. Quake/FOFA allow 1/s, Hunter 15/s, and enterprise sources one
// request per several seconds. Callers must also respect provider quotas.
var builtinRates = map[string]sourceRate{
	"fofa":       {1, time.Second},
	"quake":      {1, time.Second},
	"hunter":     {15, time.Second},
	"aiqicha":    {1, 3 * time.Second},
	"tianyancha": {1, 3 * time.Second},
	"kuaicha":    {1, 3 * time.Second},
	"riskbird":   {1, 5 * time.Second},
}

// defaultRate applies to any source not present in builtinRates.
var defaultRate = sourceRate{5, time.Second}

// bucketFor returns the shared bucket for source, creating it on first use from
// the built-in rate table (falling back to defaultRate).
func (r *limiterRegistry) bucketFor(source string) *tokenBucket {
	r.mu.Lock()
	defer r.mu.Unlock()
	if b, ok := r.buckets[source]; ok {
		return b
	}
	rate, ok := builtinRates[source]
	if !ok {
		rate = defaultRate
	}
	b := newTokenBucket(rate.events, rate.per)
	r.buckets[source] = b
	return b
}

// waitForSource blocks until the shared bucket for source grants a token.
func waitForSource(ctx context.Context, source string) error {
	return globalLimiters.bucketFor(source).wait(ctx)
}
