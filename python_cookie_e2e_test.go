//go:build integration

package netloom

import (
	"context"
	"fmt"
	"testing"
)

// TestPythonCookieServerE2E drives a Python HTTP server that sets a cookie and
// then verifies whether it was sent back, exercising the real tls-client jar
// path. Supply a controlled service implementing the responses asserted below;
// see docs/testing.md for external service prerequisites. The test is skipped
// unless the service is reachable.
//
//   - with per-host cookies ENABLED, /check must see "has:..."
//   - with per-host cookies DISABLED (default), /check must see "none"
func TestPythonCookieServerE2E(t *testing.T) {
	const base = "http://127.0.0.1:9099"

	// Sanity: skip when the Python server is not running.
	tr := newTLSTransport(defaultMaxBodySize)
	probe, err := tr.roundTripNoGuard(context.Background(), &Request{URL: base + "/"})
	if err != nil {
		t.Skipf("caller-provided cookie service not reachable; see docs/testing.md: %v", err)
	}
	if string(probe.Body) != "cookiejar test server ok" {
		t.Fatalf("unexpected probe response: %q", probe.Body)
	}

	// --- Enabled: cookie must carry to /check ---
	on := newTLSTransportWithJar(defaultMaxBodySize, true)
	r1, err := on.roundTripNoGuard(context.Background(), &Request{URL: base + "/set"})
	if err != nil {
		t.Fatalf("enabled /set: %v", err)
	}
	fmt.Printf("enabled /set  -> status=%d cookies=%v body=%q\n", r1.StatusCode, r1.Cookies, r1.Body)

	r2, err := on.roundTripNoGuard(context.Background(), &Request{URL: base + "/check"})
	if err != nil {
		t.Fatalf("enabled /check: %v", err)
	}
	fmt.Printf("enabled /check-> status=%d body=%q\n", r2.StatusCode, r2.Body)
	if string(r2.Body) != "has:"+string(r1.Body[len("set:"):]) {
		t.Fatalf("ENABLED: cookie NOT carried back (got %q, want has:%q)", r2.Body, r1.Body[len("set:"):])
	}

	// --- Disabled: cookie must NOT carry to /check ---
	off := newTLSTransport(defaultMaxBodySize)
	if _, err := off.roundTripNoGuard(context.Background(), &Request{URL: base + "/set"}); err != nil {
		t.Fatalf("disabled /set: %v", err)
	}
	r4, err := off.roundTripNoGuard(context.Background(), &Request{URL: base + "/check"})
	if err != nil {
		t.Fatalf("disabled /check: %v", err)
	}
	fmt.Printf("disabled /set  -> (cookie stored, but no jar)\n")
	fmt.Printf("disabled /check-> status=%d body=%q\n", r4.StatusCode, r4.Body)
	if string(r4.Body) != "none" {
		t.Fatalf("DISABLED: cookie unexpectedly carried (got %q, want none)", r4.Body)
	}

	t.Log("PASS: per-host cookie jar works, default-off stays stateless")
}
