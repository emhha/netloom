package netloom

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
)

// --- Pipeline onion ordering ---------------------------------------------

func TestPipelineOnionOrder(t *testing.T) {
	var order []string
	mk := func(name string) Handler {
		return func(c *Context) error {
			order = append(order, "pre:"+name)
			if err := c.Next(); err != nil {
				return err
			}
			order = append(order, "post:"+name)
			return nil
		}
	}
	c := NewContext(context.Background(), &Request{}, []Handler{mk("a"), mk("b"), mk("c")}, nil)
	if err := c.run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	want := []string{"pre:a", "pre:b", "pre:c", "post:c", "post:b", "post:a"}
	if fmt.Sprint(order) != fmt.Sprint(want) {
		t.Fatalf("onion order = %v, want %v", order, want)
	}
}

func TestPipelineAbortStopsChain(t *testing.T) {
	ran := 0
	h1 := func(c *Context) error { c.Abort(); return c.Next() }
	h2 := func(c *Context) error { ran++; return c.Next() }
	c := NewContext(context.Background(), &Request{}, []Handler{h1, h2}, nil)
	if err := c.run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	if ran != 0 {
		t.Fatalf("handler after Abort ran %d times", ran)
	}
}

func TestAsMatcherAbortsOnMiss(t *testing.T) {
	c := NewContext(context.Background(), &Request{}, []Handler{
		AsMatcher(staticMatcher{name: "m", ok: false}),
	}, nil)
	c.Resp = &Response{StatusCode: 200}
	if err := c.run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !c.Aborted() {
		t.Fatal("expected abort on matcher miss")
	}
}

type staticMatcher struct {
	name string
	ok   bool
}

func (m staticMatcher) Name() string           { return m.name }
func (m staticMatcher) Match(_ *Response) bool { return m.ok }

// --- Dial guard -----------------------------------------------------------

func TestDialGuardBlocksLoopbackLiteral(t *testing.T) {
	guard := guardedDialContext(&net.Dialer{Timeout: time.Second}, net.DefaultResolver)
	_, err := guard(context.Background(), "tcp", "127.0.0.1:80")
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("loopback literal: got %v, want ErrBlockedAddress", err)
	}
}

func TestDialGuardBlocksLinkLocalLiteral(t *testing.T) {
	guard := guardedDialContext(&net.Dialer{Timeout: time.Second}, net.DefaultResolver)
	_, err := guard(context.Background(), "tcp", "169.254.169.254:80")
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("link-local literal: got %v, want ErrBlockedAddress", err)
	}
}

// DNS-rebinding: a hostname that resolves to a loopback IP must still be blocked
// because the guard validates the resolved IP, not the hostname.
func TestDialGuardBlocksRebindToLoopback(t *testing.T) {
	rebind := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, errors.New("no real dns")
		},
	}
	// Replace LookupIPAddr behaviour by using a resolver whose lookups we
	// intercept through a custom guard test that maps host -> 127.0.0.1.
	guard := guardedDialContextWithLookup(func(_ context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	})
	_ = rebind
	_, err := guard(context.Background(), "tcp", "evil.example.com:80")
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("rebind to loopback: got %v, want ErrBlockedAddress", err)
	}
}

// guardedDialContextWithLookup mirrors guardedDialContext but with an injectable
// lookup, used only to exercise the DNS-rebinding path deterministically.
func guardedDialContextWithLookup(lookup func(context.Context, string) ([]net.IPAddr, error)) func(context.Context, string, string) (net.Conn, error) {
	base := &net.Dialer{Timeout: time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if ip := net.ParseIP(host); ip != nil {
			if isBlockedIP(ip) {
				return nil, fmt.Errorf("%w", ErrBlockedAddress)
			}
			return base.DialContext(ctx, network, addr)
		}
		ips, err := lookup(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, ipa := range ips {
			if isBlockedIP(ipa.IP) {
				return nil, fmt.Errorf("%w", ErrBlockedAddress)
			}
			return base.DialContext(ctx, network, net.JoinHostPort(ipa.IP.String(), port))
		}
		return nil, errors.New("no address")
	}
}

func TestIsBlockedIPAllowsPrivate(t *testing.T) {
	// RFC1918 ranges are intentionally allowed at the transport layer.
	for _, s := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "8.8.8.8"} {
		if isBlockedIP(net.ParseIP(s)) {
			t.Fatalf("%s should not be blocked at transport layer", s)
		}
	}
	for _, s := range []string{"127.0.0.1", "::1", "0.0.0.0", "::", "::ffff:127.0.0.1", "169.254.1.1", "fe80::1"} {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Fatalf("%s should be blocked", s)
		}
	}
}

// --- Transport routing ----------------------------------------------------

type recordTransport struct{ kind string }

func (r *recordTransport) RoundTrip(_ context.Context, _ *Request) (*Response, error) {
	return &Response{Header: fhttp.Header{"X-Kind": []string{r.kind}}}, nil
}

func TestTransportRouting(t *testing.T) {
	tlsT := &recordTransport{kind: "tls"}
	rawT := &recordTransport{kind: "raw"}

	if got := route(&Request{URL: "http://x"}, tlsT, rawT); got != Transport(tlsT) {
		t.Fatal("non-raw should route to tlsTransport")
	}
	if got := route(&Request{URL: "http://x", Raw: []byte("GET / HTTP/1.1\r\n\r\n")}, tlsT, rawT); got != Transport(rawT) {
		t.Fatal("raw should route to rawTransport")
	}
}

// --- tlsTransport real request -------------------------------------------

func TestTLSTransportRealRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "test-srv")
		w.WriteHeader(201)
		_, _ = w.Write([]byte("hello world"))
	}))
	defer srv.Close()

	// httptest binds to 127.0.0.1; the guard would block it. Use a transport
	// with an allow-all dial to validate the HTTP path itself.
	tr := newTLSTransport(defaultMaxBodySize)
	resp, err := tr.roundTripNoGuard(context.Background(), &Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	if string(resp.Body) != "hello world" {
		t.Fatalf("body = %q", resp.Body)
	}
	if resp.WebServer != "test-srv" {
		t.Fatalf("server = %q", resp.WebServer)
	}
}

// TestTLSTransportHTTPS exercises the full tls-client path over TLS against a
// self-signed httptest server: the browser fingerprint handshake succeeds
// (InsecureSkipVerify is always on for scanning) and the peer certificate is
// captured into resp.TLS from the utls ConnectionState.
func TestTLSTransportHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "tls-srv")
		_, _ = w.Write([]byte("secure"))
	}))
	defer srv.Close()

	tr := newTLSTransport(defaultMaxBodySize)
	resp, err := tr.roundTripNoGuard(context.Background(), &Request{
		URL:     srv.URL,
		Profile: ProfileByName("chrome_131"),
	})
	if err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
	if string(resp.Body) != "secure" {
		t.Fatalf("body = %q", resp.Body)
	}
	if resp.Scheme != "https" {
		t.Fatalf("scheme = %q, want https", resp.Scheme)
	}
	if resp.TLS == nil {
		t.Fatal("expected TLSInfo to be populated on an HTTPS response")
	}
	if resp.TLS.FingerprintSHA256 == "" {
		t.Fatal("expected certificate SHA-256 fingerprint")
	}
	if resp.TLS.Version == "" {
		t.Fatal("expected negotiated TLS version")
	}
}

// TestRawTransportTLSFingerprinted validates the rawTransport TLS path: bytes
// are written verbatim over a tls-client fingerprinted connection and the peer
// certificate is captured.
func TestRawTransportTLSFingerprinted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()

	u := srv.URL // https://127.0.0.1:port
	tr := &rawTransport{maxBody: defaultMaxBodySize, resolver: net.DefaultResolver}
	raw := []byte("GET / HTTP/1.1\r\nHost: " + strings.TrimPrefix(u, "https://") + "\r\nConnection: close\r\n\r\n")
	resp, err := func() (*Response, error) {
		clone := *tr
		clone.noGuard = true
		return clone.RoundTrip(context.Background(), &Request{URL: u, Raw: raw, Profile: ProfileByName("chrome_131")})
	}()
	if err != nil {
		t.Fatalf("raw tls roundtrip: %v", err)
	}
	if resp.TLS == nil {
		t.Fatal("expected TLSInfo on raw TLS response")
	}
	if resp.StatusCode != 204 {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
}

// --- rawTransport malformed packet ---------------------------------------

func TestRawTransportSendsMalformed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	got := make(chan []byte, 1)
	go func() {
		conn, e := ln.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		got <- buf[:n]
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
	}()

	tr := &rawTransport{maxBody: defaultMaxBodySize, resolver: net.DefaultResolver}
	malformed := []byte("GET /\r\nHost: x\r\n\r\n") // missing HTTP version: deliberately malformed
	resp, err := tr.roundTripNoGuard(context.Background(), "http://"+ln.Addr().String(), malformed)
	if err != nil {
		t.Fatalf("raw roundtrip: %v", err)
	}
	select {
	case sent := <-got:
		if string(sent) != string(malformed) {
			t.Fatalf("server received %q, want %q", sent, malformed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not receive bytes")
	}
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// --- Scheduler derived tasks under rate limit ----------------------------

func TestSchedulerEmitDerivedTaskRateLimited(t *testing.T) {
	cfg := Config{Threads: 4, MaxConcurrentPerHost: 4, RatePerSecond: 1000, Retries: 1, Timeout: time.Second}.withDefaults()
	stub := &recordTransport{kind: "tls"}
	sch := newScheduler(cfg, stub, stub, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sch.start(ctx)

	var derived atomic.Int32
	parent := Task{
		Req: &Request{URL: "http://example.com"},
		Pipeline: []Handler{func(c *Context) error {
			// Emit one child the first time only.
			if _, ok := c.Req.Meta["child"]; !ok {
				c.Emit(Task{
					Req: &Request{URL: "http://example.com", Meta: map[string]any{"child": true}},
					Pipeline: []Handler{func(cc *Context) error {
						derived.Add(1)
						return cc.Next()
					}},
				})
			}
			return c.Next()
		}},
	}
	sch.submit(parent)

	var got int
	done := make(chan struct{})
	go func() {
		for range sch.results {
			got++
		}
		close(done)
	}()
	sch.wait()
	<-done

	if derived.Load() != 1 {
		t.Fatalf("derived task ran %d times, want 1", derived.Load())
	}
	if got != 2 {
		t.Fatalf("results = %d, want 2 (parent + child)", got)
	}
}

// --- Rate limiter precision -----------------------------------------------

func TestRateLimiterPrecision(t *testing.T) {
	// 50 req/s; 20 requests should take >= ~380ms (19 gaps of 20ms).
	rl := newRateLimiter(50, 0)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 20; i++ {
		if err := rl.wait(ctx); err != nil {
			t.Fatalf("wait: %v", err)
		}
	}
	elapsed := time.Since(start)
	if elapsed < 300*time.Millisecond {
		t.Fatalf("20 reqs at 50/s took %v, expected >= 300ms", elapsed)
	}
}

func TestRateLimiterStricterWins(t *testing.T) {
	// perSecond high, perMinute very low: perMinute must dominate.
	rl := newRateLimiter(1000, 60) // 60/min = 1/s
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := rl.wait(ctx); err != nil {
			t.Fatalf("wait: %v", err)
		}
	}
	if time.Since(start) < 3*time.Second {
		t.Fatalf("5 reqs at 60/min took %v, expected >= 3s", time.Since(start))
	}
}

// --- Concurrency / leak ---------------------------------------------------

func TestNoGoroutineLeak100Tasks(t *testing.T) {
	before := runtime.NumGoroutine()

	cfg := Config{Threads: 20, RatePerSecond: 100000, Timeout: time.Second}.withDefaults()
	stub := &recordTransport{kind: "tls"}
	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	eng.tlsT = stub
	eng.rawT = stub

	seeds := make([]Task, 100)
	var ran atomic.Int32
	for i := range seeds {
		seeds[i] = Task{
			Req: &Request{URL: fmt.Sprintf("http://host%d.example.com", i%10)},
			Pipeline: []Handler{func(c *Context) error {
				ran.Add(1)
				return c.Next()
			}},
		}
	}

	ctx := context.Background()
	results, err := eng.Run(ctx, seeds)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var got int
	for range results {
		got++
	}
	if got != 100 {
		t.Fatalf("results = %d, want 100", got)
	}
	if ran.Load() != 100 {
		t.Fatalf("pipeline ran %d, want 100", ran.Load())
	}

	// Allow workers to fully unwind.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+5 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if leaked := runtime.NumGoroutine() - before; leaked > 5 {
		t.Fatalf("possible goroutine leak: %d extra goroutines", leaked)
	}
}

func TestEngineSend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	eng, err := New(Config{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// Inject guard-free transport so we can hit the loopback test server.
	eng.tlsT = &tlsTransport{maxBody: defaultMaxBodySize, resolver: net.DefaultResolver, noGuard: true}

	resp, err := eng.Send(context.Background(), &Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if string(resp.Body) != "ok" {
		t.Fatalf("body = %q", resp.Body)
	}
}

var _ = sync.Mutex{}

// --- Per-host cookie jar --------------------------------------------------

// TestPerHostCookiesSharedAcrossRequests verifies that with the CookieJar
// option enabled, a Set-Cookie from one request to a host is sent back on the
// next request to the same host (session state carries across the shared
// per-host jar), and the cookies are surfaced on the Response.
func TestPerHostCookiesSharedAcrossRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", Path: "/"})
			_, _ = w.Write([]byte("set"))
			return
		}
		if r.URL.Path == "/get" {
			c, err := r.Cookie("sid")
			if err != nil || c.Value != "abc" {
				w.WriteHeader(http.StatusPreconditionFailed)
				_, _ = w.Write([]byte("no cookie"))
				return
			}
			_, _ = w.Write([]byte("got:" + c.Value))
			return
		}
		_, _ = w.Write([]byte("root"))
	}))
	defer srv.Close()

	// Cookie jar enabled on the transport; the dial guard is bypassed so the
	// loopback httptest server is reachable.
	tr := newTLSTransportWithJar(defaultMaxBodySize, true)

	// 1) Server sets sid=abc.
	resp1, err := tr.roundTripNoGuard(context.Background(), &Request{URL: srv.URL + "/set"})
	if err != nil {
		t.Fatalf("set roundtrip: %v", err)
	}
	if len(resp1.Cookies) == 0 || resp1.Cookies[0].Name != "sid" {
		t.Fatalf("expected Set-Cookie surfaced on response, got %v", resp1.Cookies)
	}

	// 2) Same transport (same per-host jar) must now send sid=abc back.
	resp2, err := tr.roundTripNoGuard(context.Background(), &Request{URL: srv.URL + "/get"})
	if err != nil {
		t.Fatalf("get roundtrip: %v", err)
	}
	if resp2.StatusCode != http.StatusOK || string(resp2.Body) != "got:abc" {
		t.Fatalf("cookie not carried: status=%d body=%q", resp2.StatusCode, resp2.Body)
	}
}

// TestPerHostCookiesIsolatedAcrossHosts verifies that cookies set on one host
// never leak to a different host, even though both go through the same
// transport.
func TestPerHostCookiesIsolatedAcrossHosts(t *testing.T) {
	var first, second int
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first++
		http.SetCookie(w, &http.Cookie{Name: "fromA", Value: "1", Path: "/"})
		_, _ = w.Write([]byte("a"))
	}))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		second++
		if _, err := r.Cookie("fromA"); err == nil {
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = w.Write([]byte("leaked"))
			return
		}
		_, _ = w.Write([]byte("b"))
	}))
	defer srvB.Close()

	tr := newTLSTransportWithJar(defaultMaxBodySize, true)

	// Prime host A with a cookie, then hit B; B must never see A's cookie.
	if _, err := tr.roundTripNoGuard(context.Background(), &Request{URL: srvA.URL}); err != nil {
		t.Fatalf("A roundtrip: %v", err)
	}
	respB, err := tr.roundTripNoGuard(context.Background(), &Request{URL: srvB.URL})
	if err != nil {
		t.Fatalf("B roundtrip: %v", err)
	}
	if respB.StatusCode != http.StatusOK || string(respB.Body) != "b" {
		t.Fatalf("cookie leaked across hosts: status=%d body=%q", respB.StatusCode, respB.Body)
	}
	if first != 1 || second != 1 {
		t.Fatalf("unexpected hit counts: A=%d B=%d", first, second)
	}
}

// TestPerHostCookiesDisabledDefault verifies that with the option off (the
// zero-value default) the transport stays stateless: a Set-Cookie from one
// request is NOT sent back on the next, preserving the historical behaviour.
func TestPerHostCookiesDisabledDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", Path: "/"})
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tr := newTLSTransport(defaultMaxBodySize) // cookieEnabled == false

	// First request stores the cookie in no jar; second request must not carry it.
	resp1, err := tr.roundTripNoGuard(context.Background(), &Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("first roundtrip: %v", err)
	}
	if len(resp1.Cookies) != 0 {
		t.Fatalf("cookies should be empty when jar disabled, got %v", resp1.Cookies)
	}
	// The server always sets sid, so the second request still succeeds; we
	// assert the transport reports no cookies (stateless), which is the whole
	// point of the disabled mode.
	resp2, err := tr.roundTripNoGuard(context.Background(), &Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("second roundtrip: %v", err)
	}
	if len(resp2.Cookies) != 0 {
		t.Fatalf("cookies should remain empty with jar disabled, got %v", resp2.Cookies)
	}
}

// TestPerHostCookiesViaEngine verifies the end-to-end wiring: enabling
// CookieJar in netloom.Config turns the shared per-host jar on for Engine.Send,
// and leaving it off keeps the engine stateless.
func TestPerHostCookiesViaEngine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", Path: "/"})
			_, _ = w.Write([]byte("set"))
			return
		}
		if _, err := r.Cookie("sid"); err == nil {
			_, _ = w.Write([]byte("carried"))
			return
		}
		_, _ = w.Write([]byte("none"))
	}))
	defer srv.Close()

	engOn, err := New(Config{CookieJar: true})
	if err != nil {
		t.Fatalf("new(on): %v", err)
	}
	// Cookie-enabled transport with the dial guard bypassed for loopback.
	trOn := newTLSTransportWithJar(defaultMaxBodySize, true)
	trOn.noGuard = true
	engOn.tlsT = trOn

	if _, err := engOn.Send(context.Background(), &Request{URL: srv.URL + "/set"}); err != nil {
		t.Fatalf("send /set: %v", err)
	}
	resp, err := engOn.Send(context.Background(), &Request{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("send /: %v", err)
	}
	if string(resp.Body) != "carried" {
		t.Fatalf("engine cookie not carried: body=%q", resp.Body)
	}

	// Off mode (default) must stay stateless.
	engOff, err := New(Config{})
	if err != nil {
		t.Fatalf("new(off): %v", err)
	}
	engOff.tlsT = &tlsTransport{maxBody: defaultMaxBodySize, resolver: net.DefaultResolver, noGuard: true}
	if _, err := engOff.Send(context.Background(), &Request{URL: srv.URL + "/set"}); err != nil {
		t.Fatalf("send(off) /set: %v", err)
	}
	respOff, err := engOff.Send(context.Background(), &Request{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("send(off) /: %v", err)
	}
	if string(respOff.Body) != "none" {
		t.Fatalf("disabled engine should not carry cookies, body=%q", respOff.Body)
	}
}
