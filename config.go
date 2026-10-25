package netrt

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
	Retries       int // retries on network error/timeout (default 2); 4xx/5xx never retried
	MaxHostErrors int // consecutive per-host error cap (default 30); host skipped after

	// Timeout / body limits.
	Timeout     time.Duration // per-request timeout (default 10s)
	MaxBodySize int           // max body bytes read (default 2MB); excess discarded

	// CookieJar enables per-host session cookies. Each unique host gets its own
	// jar shared across requests, so Set-Cookie is honoured for redirects,
	// retries and concurrent requests to the same host, while cookies never
	// leak between different hosts. Default false: stateless requests, exactly
	// the historical behaviour. rawTransport is unaffected (it writes raw
	// bytes, not through the fhttp client).
	CookieJar bool
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
