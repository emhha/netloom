package netloom

import "time"

const defaultMaxBodySize = 2 << 20 // 2 MB

// Config tunes concurrency, rate, retry and response-size limits. The zero
// value is completed by withDefaults.
type Config struct {
	// Concurrency.
	Threads              int // global worker count (default 50)
	MaxConcurrentPerHost int // max concurrent requests per host (default 10)

	// Rate control. RatePerSecond and RatePerMinute both apply; the stricter
	// constraint wins. Delay is the per-request minimum spacing, layered on top.
	RatePerSecond int
	RatePerMinute int // 0 means unlimited
	Delay         time.Duration

	// Retry / fault tolerance.
	Retries       int          // legacy safe-method network retries (default 2); overridden by RetryPolicy
	RetryPolicy   *RetryPolicy // opt-in status/backoff/observer policy; copied by New
	MaxHostErrors int          // consecutive per-host error cap (default 30); host skipped after

	// Timeout / body limits.
	Timeout       time.Duration // per-request timeout (default 10s)
	PhaseTimeouts PhaseTimeouts // optional HTTP phase and cross-attempt budgets
	MaxBodySize   int           // max body bytes read (default 2MB); excess discarded

	// CookieJar opts into a private bounded memory cookie Session with default
	// limits, isolated by logical hostname plus explicit port. Default false
	// preserves stateless behavior when Session is also nil. Raw is unaffected.
	CookieJar bool

	// Session injects a caller-owned, concurrency-safe memory cookie session.
	// Non-nil enables cookies regardless of CookieJar and takes precedence over
	// its private default session. Multiple Engines may share it; Engine.Close
	// does not clear it. No persistence or implicit credential/file discovery.
	Session *Session

	// ConnectionPool opts into bounded, origin-scoped client reuse. Nil retains
	// the historical fresh-client-per-attempt behavior. See ConnectionPoolConfig.
	ConnectionPool *ConnectionPoolConfig
}

// ConnectionPoolConfig bounds both cached clients and active client leases.
// Each client is leased exclusively until the response body is closed; this
// first implementation reuses H2 connections sequentially, not multiplexed.
// Custom/explicit profiles, TLSOptions, strict H2 and non-HTTP proxy schemes
// use uncached leases under the same capacity bound. Cookie session storage has
// a separate lifecycle.
// The configuration is copied by New and must not be mutated concurrently.
type ConnectionPoolConfig struct {
	MaxClients  int           // default 64; includes active, idle and uncached clients
	IdleTimeout time.Duration // default 30s; socket idle timeout and idle entry TTL
}

func (c Config) withDefaults() Config {
	if c.Threads <= 0 {
		c.Threads = 50
	}
	if c.MaxConcurrentPerHost <= 0 {
		c.MaxConcurrentPerHost = 10
	}
	if c.RatePerSecond <= 0 {
		c.RatePerSecond = 150
	}
	if c.Retries < 0 {
		c.Retries = 0
	} else if c.Retries == 0 {
		c.Retries = 2
	}
	if c.MaxHostErrors <= 0 {
		c.MaxHostErrors = 30
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.MaxBodySize <= 0 {
		c.MaxBodySize = defaultMaxBodySize
	}
	return c
}
