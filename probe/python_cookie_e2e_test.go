//go:build integration

package probe

import (
	"context"
	"testing"
	"time"
)

// TestPythonCookieServerE2E drives probe.Run (the real probe entry point)
// against a caller-provided virtual-host cookie service; see docs/testing.md
// for external service prerequisites.
//
// The server must be reachable on the private IP that the /etc/hosts entries
// below resolve to. Add to /etc/hosts:
//
//	<private-ip> cookie.test other.test
//
// where <private-ip> is this box's RFC1918 address (e.g. 192.168.81.167).
// netloom's dial guard rejects loopback/link-local but permits RFC1918, so probe
// runs through its real production path here (real DNS via hosts file, real
// dial, real tls-client transport, real redirect following).
//
// Behaviour verified:
//   - EnableCookies=true  : a single /login target sets a cookie and the
//     redirect hop to /check must carry it back (final status 200).
//   - Cross-host isolation: after cookie.test sets its cookie, other.test
//     /login->/check must NOT see it (final status 412).
//   - EnableCookies=false (default): /login->/check stays stateless (412).
func TestPythonCookieServerE2E(t *testing.T) {
	const (
		loginURL = "http://cookie.test:9099/login"
		otherURL = "http://other.test:9099/login"
	)

	// Reachability gate: probe / on cookie.test and other.test.
	if !reachable(t, []string{
		"http://cookie.test:9099/",
		"http://other.test:9099/",
	}) {
		t.Skip("caller-provided cookie service or private DNS mapping unavailable; see docs/testing.md")
	}

	// --- EnableCookies=true: redirect-chain cookie carry (single target) ---
	{
		cfg := &Config{
			ProbeConfig: ProbeConfig{
				NoFallback:     true,
				FollowRedirect: true,
				MaxRedirects:   5,
				MaxRetries:     0,
				EnableCookies:  true,
			},
		}
		got := collectResults(t, []string{loginURL}, cfg)
		r := got[loginURL]
		if r.Error != "" {
			t.Fatalf("ENABLED /login error: %v", r.Error)
		}
		if r.StatusCode != 200 {
			t.Fatalf("ENABLED /login final status=%d, want 200 (cookie carried through redirect)", r.StatusCode)
		}
		t.Logf("ENABLED: cookie.test carried session cookie across redirect (final status=200)")
	}

	// --- EnableCookies=true: cross-host isolation ---
	{
		cfg := &Config{
			ProbeConfig: ProbeConfig{
				NoFallback:     true,
				FollowRedirect: true,
				MaxRedirects:   5,
				MaxRetries:     0,
				EnableCookies:  true,
			},
		}
		// Both hosts in the SAME Run, same Engine: if the jar were shared
		// globally (not per-host), one host's /login would overwrite the
		// other's cookie and that host's /check would fail (412). Per-host
		// isolation means both carry their own cookie and both finish 200.
		got := collectResults(t, []string{loginURL, otherURL}, cfg)
		rA := got[loginURL]
		rB := got[otherURL]
		if rA.Error != "" || rA.StatusCode != 200 {
			t.Fatalf("ISOLATION cookie.test final status=%d err=%v, want 200", rA.StatusCode, rA.Error)
		}
		if rB.Error != "" || rB.StatusCode != 200 {
			t.Fatalf("ISOLATION other.test final status=%d err=%v, want 200", rB.StatusCode, rB.Error)
		}
		t.Logf("ISOLATION: cookie.test and other.test each kept their own jar in one Run (both 200)")
	}

	// --- EnableCookies=false (default): stateless ---
	{
		cfg := &Config{
			ProbeConfig: ProbeConfig{
				NoFallback:     true,
				FollowRedirect: true,
				MaxRedirects:   5,
				MaxRetries:     0,
				EnableCookies:  false,
			},
		}
		got := collectResults(t, []string{loginURL}, cfg)
		r := got[loginURL]
		if r.Error != "" {
			t.Fatalf("DISABLED /login error: %v", r.Error)
		}
		if r.StatusCode != 412 {
			t.Fatalf("DISABLED /login final status=%d, want 412 (must be stateless)", r.StatusCode)
		}
		t.Logf("DISABLED: no cookie carried (final status=412)")
	}
}

// reachable probes each URL and reports whether any request got an HTTP
// response (as opposed to a network error).
func reachable(t *testing.T, urls []string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for r := range Run(ctx, urls, &Config{}) {
		if r.Error == "" {
			return true
		}
		t.Logf("reachability %s: %v", r.Target, r.Error)
	}
	return false
}

// collectResults runs probe.Run over targets and returns results keyed by URL.
func collectResults(t *testing.T, targets []string, cfg *Config) map[string]*Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out := make(map[string]*Result)
	for r := range Run(ctx, targets, cfg) {
		out[r.Target] = r
	}
	return out
}
