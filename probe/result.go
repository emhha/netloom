package probe

import (
	"fmt"
	"github.com/emhha/netloom"
	"net/url"
	"strconv"
	"time"
)

// Result is the liveness outcome for a single target URL.
type Result struct {
	// Target is the original input string supplied by the caller.
	Target string
	// URL is the final request URL (after any redirect chain processing).
	URL string
	// TargetKey is the canonical unique identifier: scheme://domain:port
	// (domain is preferred over IP; if no domain, IP is used).
	TargetKey string

	Redirects     []netloom.RedirectHop
	StatusCode    int
	Title         string
	WebServer     string
	IP            string
	CNAME         string
	ResponseTime  time.Duration
	ContentLength int64
	BodyHash      string
	TLS           *netloom.TLSInfo
	Fingerprints  []string // populated when Config.EnableFingerprint is true
	IsSoft404     bool

	// Error is non-empty when the probe failed (no HTTP response received).
	Error string
}

// buildTargetKey constructs scheme://domain:port from a URL string.
// If the URL has no parseable host, the raw URL is returned as-is.
func buildTargetKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}

	host := u.Hostname()
	portStr := u.Port()
	port := defaultPort(scheme)
	if portStr != "" {
		if p, err2 := strconv.Atoi(portStr); err2 == nil {
			port = p
		}
	}

	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

// defaultPort returns the conventional port for the given scheme.
func defaultPort(scheme string) int {
	switch scheme {
	case "https":
		return 443
	case "http":
		return 80
	default:
		return 443
	}
}
