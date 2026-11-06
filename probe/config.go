// Package probe implements batch HTTP/HTTPS liveness detection (探活).
//
// It runs on top of the netloom network runtime and is zero-business-dependency:
// scope authorization is performed by the caller (service layer) before Run is
// invoked. The netloom Transport enforces loopback/link-local rejection at the
// dial layer regardless of any probe configuration.
//
// Typical usage:
//
//	cfg := &probe.Config{ProbeConfig: probe.ProbeConfig{RateMode: probe.RateNormal}}
//	for r := range probe.Run(ctx, targets, cfg) {
//	    // handle r
//	}
package probe

import (
	"context"
	"time"
)

// RateMode is a named speed preset for the probe engine.
type RateMode string

const (
	RateSlow       RateMode = "slow"       // 5 req/s
	RateNormal     RateMode = "normal"     // 50 req/s
	RateFast       RateMode = "fast"       // 200 req/s
	RateAggressive RateMode = "aggressive" // 500 req/s
	RateCustom     RateMode = "custom"     // CustomRate field is used
)

// ProbeConfig contains all tunable parameters for a probe run.
type ProbeConfig struct {
	// Speed / concurrency.
	RateMode   RateMode // pre-set speed mode
	CustomRate int      // req/s when RateMode == RateCustom
	Threads    int      // worker count; 0 = inferred from RateMode

	// Timeout & retry.
	Timeout    time.Duration // per-request timeout (default 10s)
	MaxRetries int           // retries on network/timeout errors (zero defaults to 2; negative disables)
	RetryDelay time.Duration // delay between retries (default 1s; unused by netloom directly, kept for reference)

	// TLS / proxy.
	TLSProfile string // browser TLS fingerprint name, resolved via netloom.ProfileByName (e.g. "chrome_131")
	SkipVerify bool   // explicitly skip TLS verification; service scan defaults set this to true
	ProxyURL   string // optional HTTP/SOCKS proxy

	// Response body.
	MaxBodySize int  // max bytes read from body (default 2 MB)
	SaveBody    bool // when true the service layer may persist body to probe_results

	// Behaviour.
	FollowRedirect bool              // follow HTTP redirects (default true)
	MaxRedirects   int               // maximum redirect hops (default 10)
	CustomHeaders  map[string]string // extra request headers
	NoFallback     bool              // disable HTTPS → HTTP fallback

	// EnableCookies turns on netloom's per-host cookie jar: Set-Cookie from a
	// host is honoured on later requests to the same host (redirects, retries,
	// concurrent same-host requests), while cookies never leak across hosts.
	// Default false keeps probe stateless. Requires each target to be probed
	// through the same netloom Engine, which probe.Run does automatically.
	EnableCookies bool
}

// Config is the top-level configuration passed to Run.
type Config struct {
	ProbeConfig
	ValidateURL       func(context.Context, string) error // caller-supplied authorization for every hop
	EnableFingerprint bool                                // run fingerprint detection on each alive result
}

// rateParams returns the req/s and suggested thread count for this config.
func (c *ProbeConfig) rateParams() (ratePerSecond, threads int) {
	switch c.RateMode {
	case RateSlow:
		ratePerSecond, threads = 5, 5
	case RateNormal:
		ratePerSecond, threads = 50, 50
	case RateFast:
		ratePerSecond, threads = 200, 100
	case RateAggressive:
		ratePerSecond, threads = 500, 200
	case RateCustom:
		ratePerSecond = c.CustomRate
		if ratePerSecond <= 0 {
			ratePerSecond = 50
		}
		threads = ratePerSecond / 4
		if threads < 10 {
			threads = 10
		}
	default:
		ratePerSecond, threads = 50, 50
	}
	if c.Threads > 0 {
		threads = c.Threads
	}
	return
}

// maxBodySize returns the effective body size cap.
func (c *ProbeConfig) maxBodySize() int {
	if c.MaxBodySize > 0 {
		return c.MaxBodySize
	}
	return 2 << 20 // 2 MB default
}

// timeout returns the effective per-request timeout.
func (c *ProbeConfig) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 10 * time.Second
}
