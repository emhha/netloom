package netloom

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
)

func sessionURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
func sessionNames(cookies []*fhttp.Cookie) string {
	var out []string
	for _, c := range cookies {
		out = append(out, c.Name+"="+c.Value)
	}
	return strings.Join(out, "; ")
}
func sessionPut(s *Session, raw, name, value string) {
	s.SetCookies(sessionURL(raw), []*fhttp.Cookie{{Name: name, Value: value}})
}

func TestSessionDefaultsValidation(t *testing.T) {
	for _, cfg := range []SessionConfig{{MaxHosts: -1}, {MaxCookiesPerHost: -1}, {IdleTimeout: -1}} {
		if _, err := NewSession(cfg); err == nil {
			t.Fatalf("accepted negative %+v", cfg)
		}
	}
	s, err := NewSession(SessionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.MaxHosts != 256 || s.cfg.MaxCookiesPerHost != 64 || s.cfg.IdleTimeout != 30*time.Minute {
		t.Fatalf("unexpected defaults %+v", s.cfg)
	}
	var zero Session
	sessionPut(&zero, "https://a.test/", "a", "zero")
	if got := sessionNames(zero.Cookies(sessionURL("https://a.test/"))); got != "a=zero" {
		t.Fatalf("zero Session: %q", got)
	}
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.tlsT.(*tlsTransport).cookies != nil {
		t.Fatal("default must stay stateless")
	}
	legacy, err := New(Config{CookieJar: true})
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if legacy.tlsT.(*tlsTransport).cookies == nil {
		t.Fatal("legacy opt-in lost")
	}
	injected, err := New(Config{Session: s})
	if err != nil {
		t.Fatal(err)
	}
	defer injected.Close()
	if injected.tlsT.(*tlsTransport).cookies != s {
		t.Fatal("injected session not enabled")
	}
}

func TestSessionRFCIsolationAndDeletion(t *testing.T) {
	s, _ := NewSession(SessionConfig{})
	u := sessionURL("https://alpha.example.test/dir/start")
	s.SetCookies(u, []*fhttp.Cookie{
		{Name: "root", Value: "r", Path: "/"}, {Name: "same", Value: "root", Path: "/"}, {Name: "same", Value: "deep", Path: "/dir"},
		{Name: "secure", Value: "yes", Secure: true}, {Name: "domain", Value: "yes", Domain: ".example.test"},
		{Name: "empty", Value: ""}, {Name: "invalid", Value: "no", Domain: "elsewhere.test"}, {Name: "suffix", Value: "no", Domain: "test"},
	})
	got := sessionNames(s.Cookies(u))
	for _, want := range []string{"same=deep", "same=root", "root=r", "secure=yes", "domain=yes", "empty="} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if strings.Index(got, "same=deep") > strings.Index(got, "same=root") {
		t.Fatalf("RFC path ordering %q", got)
	}
	if strings.Contains(got, "invalid=") || strings.Contains(got, "suffix=") {
		t.Fatalf("invalid domains accepted: %q", got)
	}
	plain := sessionNames(s.Cookies(sessionURL("http://alpha.example.test/dir/start")))
	if strings.Contains(plain, "secure=") {
		t.Fatalf("secure cookie on HTTP: %q", plain)
	}
	outside := sessionNames(s.Cookies(sessionURL("https://alpha.example.test/directory")))
	if strings.Contains(outside, "same=deep") || strings.Contains(outside, "secure=") {
		t.Fatalf("path prefix incorrectly matched %q", outside)
	}
	for _, raw := range []string{"https://beta.example.test/dir/start", "https://alpha.example.test:443/dir/start"} {
		if got := s.Cookies(sessionURL(raw)); len(got) != 0 {
			t.Fatalf("host/explicitport leak for %s: %v", raw, got)
		}
	}
	s.SetCookies(u, []*fhttp.Cookie{{Name: "same", Value: "gone", Path: "/dir", MaxAge: -1}, {Name: "root", Path: "/", Expires: time.Now().Add(-time.Hour)}})
	got = sessionNames(s.Cookies(u))
	if strings.Contains(got, "same=deep") || strings.Contains(got, "root=r") {
		t.Fatalf("deletion failed: %q", got)
	}
	s.SetCookies(u, []*fhttp.Cookie{{Name: "long", Value: "lived", Path: "/", MaxAge: int(^uint(0) >> 1), Expires: time.Now().Add(-time.Hour)}})
	if got := sessionNames(s.Cookies(u)); !strings.Contains(got, "long=lived") {
		t.Fatalf("positive MaxAge overflowed or did not override past Expires: %q", got)
	}
	s.SetCookies(u, []*fhttp.Cookie{{Name: "same", Value: "bad", Path: "/", Domain: "bad.test", MaxAge: -1}})
	if got := sessionNames(s.Cookies(u)); !strings.Contains(got, "same=root") {
		t.Fatalf("invalid deletion removed valid cookie: %q", got)
	}
}

func TestSessionBoundedLRUTTLAndValues(t *testing.T) {
	s, _ := NewSession(SessionConfig{MaxHosts: 2, MaxCookiesPerHost: 2, IdleTimeout: time.Minute})
	now := time.Now()
	s.now = func() time.Time { return now }
	sessionPut(s, "https://a.test/", "a", "1")
	sessionPut(s, "https://b.test/", "b", "2")
	_ = s.Cookies(sessionURL("https://a.test/"))
	sessionPut(s, "https://c.test/", "c", "3")
	if len(s.Cookies(sessionURL("https://b.test/"))) != 0 {
		t.Fatal("host LRU failed")
	}
	if len(s.GetAllCookies()) != 2 {
		t.Fatal("host cap failed")
	}
	sessionPut(s, "https://a.test/", "second", "2")
	sessionPut(s, "https://a.test/", "third", "3")
	got := sessionNames(s.Cookies(sessionURL("https://a.test/")))
	if strings.Contains(got, "a=1") || !strings.Contains(got, "second=2") || !strings.Contains(got, "third=3") {
		t.Fatalf("cookie LRU cap failed %q", got)
	}
	u := sessionURL("https://a.test/")
	s.SetCookies(u, []*fhttp.Cookie{{Name: "huge", Value: strings.Repeat("x", maxSessionCookieBytes)}, {Name: "third", Value: "3", Raw: strings.Repeat("x", 1<<20), RawExpires: strings.Repeat("x", 1<<20), Unparsed: []string{strings.Repeat("x", 1<<20)}}})
	all := s.GetAllCookies()
	for _, c := range all["a.test"] {
		if c.Name == "huge" || c.Raw != "" || c.RawExpires != "" || c.Unparsed != nil {
			t.Fatalf("unbounded metadata retained: %s", c.Name)
		}
	}
	// Returned semantic cookie snapshots and request cookies cannot mutate storage.
	all["a.test"][0].Value = "mutated"
	returned := s.Cookies(u)
	returned[0].Value = "changed"
	if got := sessionNames(s.Cookies(u)); strings.Contains(got, "mutated") || strings.Contains(got, "changed") {
		t.Fatalf("snapshot alias %q", got)
	}
	now = now.Add(time.Minute)
	if len(s.GetAllCookies()) != 0 {
		t.Fatal("idle TTL did not reclaim hosts at boundary")
	}
	if len(s.hosts) != 0 || s.lru.Len() != 0 {
		t.Fatal("expired session bookkeeping retained")
	}
	// Unknown/invalid/oversized cookies must not allocate a host or evict a valid host.
	s.SetCookies(u, []*fhttp.Cookie{{Name: "oversized", Value: strings.Repeat("x", maxSessionCookieBytes)}})
	if len(s.hosts) != 0 {
		t.Fatal("oversized cookie allocated host")
	}
	sessionPut(s, "https://a.test/", "a", "1")
	s.ClearHost("a.test/invalid-authority")
	if len(s.Cookies(u)) != 1 {
		t.Fatal("invalid ClearHost authority changed session")
	}
	s.ClearHost("https://A.TEST/ignored")
	if len(s.GetAllCookies()) != 0 {
		t.Fatal("ClearHost URL/case canonicalization failed")
	}
}

func TestSessionDynamicFacadeResetAndEviction(t *testing.T) {
	s, _ := NewSession(SessionConfig{MaxHosts: 1})
	tr := newTLSTransport(1024)
	tr.cookies = s
	req := &Request{URL: "https://a.test/"}
	jar := tr.jarFor(req)
	u := sessionURL(req.URL)
	jar.SetCookies(u, []*fhttp.Cookie{{Name: "a", Value: "old"}})
	s.Clear()
	if len(jar.Cookies(u)) != 0 {
		t.Fatal("cached facade resurrected cleared jar")
	}
	jar.SetCookies(u, []*fhttp.Cookie{{Name: "a", Value: "inflight"}})
	if got := sessionNames(jar.Cookies(u)); got != "a=inflight" {
		t.Fatalf("documented in-flight repopulation failed: %q", got)
	}
	sessionPut(s, "https://b.test/", "b", "new")
	if len(jar.Cookies(u)) != 0 {
		t.Fatal("cached facade resurrected evicted jar")
	}
	jar.SetCookies(sessionURL("https://b.test/"), []*fhttp.Cookie{{Name: "leak", Value: "no"}})
	if got := sessionNames(s.Cookies(sessionURL("https://b.test/"))); got != "b=new" {
		t.Fatalf("facade crossed host: %q", got)
	}
	s.ClearHost("b.test")
	if len(s.GetAllCookies()) != 0 {
		t.Fatal("ClearHost failed")
	}
	sessionPut(s, "https://[::1]/", "v6", "yes")
	s.ClearHost("::1")
	if len(s.GetAllCookies()) != 0 {
		t.Fatal("bare IPv6 ClearHost failed")
	}
	var nilSession *Session
	nilSession.Clear()
	nilSession.ClearHost("a")
	if nilSession.Cookies(u) != nil || len(nilSession.GetAllCookies()) != 0 {
		t.Fatal("nil session not inert")
	}
}

func sessionEngine(t *testing.T, s *Session) *Engine {
	t.Helper()
	e, err := New(Config{Session: s, Retries: -1, RatePerSecond: 100000, ConnectionPool: &ConnectionPoolConfig{MaxClients: 4}})
	if err != nil {
		t.Fatal(err)
	}
	e.tlsT.(*tlsTransport).noGuard = true
	t.Cleanup(func() { _ = e.Close() })
	return e
}
func sessionRequest(t *testing.T, server *httptest.Server, host, path, version string) *Request {
	t.Helper()
	u := sessionURL(server.URL)
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return &Request{URL: u.Scheme + "://" + net.JoinHostPort(host, u.Port()) + path, HTTPVersion: version, Network: &NetworkOptions{Resolve: []ResolveRule{{Host: host, Port: port, Addresses: []string{"127.0.0.1"}}}}}
}
func sessionFetch(t *testing.T, e *Engine, req *Request, stream bool) string {
	t.Helper()
	if stream {
		r, err := e.SendStream(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(r.Body)
		closeErr := r.Body.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("stream read=%v close=%v", err, closeErr)
		}
		return string(body)
	}
	r, err := e.Send(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return string(r.Body)
}

func TestSessionLocalBufferedStreamReuseClearShared(t *testing.T) {
	for _, version := range []string{"1.1", "2", "2-only"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%v", version, stream), func(t *testing.T) {
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/set" {
						http.SetCookie(w, &http.Cookie{Name: "login", Value: "yes", Path: "/", Secure: true, Domain: ".example.test"})
						http.SetCookie(w, &http.Cookie{Name: "scoped", Value: "yes", Path: "/scope"})
					}
					_, _ = io.WriteString(w, r.Header.Get("Cookie"))
				}))
				server.EnableHTTP2 = true
				server.StartTLS()
				defer server.Close()
				s, _ := NewSession(SessionConfig{MaxHosts: 2})
				e1 := sessionEngine(t, s)
				e2 := sessionEngine(t, s)
				req := func(host, path string) *Request { return sessionRequest(t, server, host, path, version) }
				_ = sessionFetch(t, e1, req("a.example.test", "/set"), stream)
				got := sessionFetch(t, e1, req("a.example.test", "/scope/check"), stream)
				if !strings.Contains(got, "login=yes") || !strings.Contains(got, "scoped=yes") {
					t.Fatalf("cookie reuse/path %q", got)
				}
				if got := sessionFetch(t, e1, req("a.example.test", "/scope-other"), stream); strings.Contains(got, "scoped=yes") {
					t.Fatalf("path boundary %q", got)
				}
				if got := sessionFetch(t, e2, req("a.example.test", "/check"), stream); !strings.Contains(got, "login=yes") {
					t.Fatalf("shared engine cookie missing %q", got)
				}
				if got := sessionFetch(t, e1, req("b.example.test", "/scope/check"), stream); got != "" {
					t.Fatalf("domain cookie leaked to another logical host %q", got)
				}
				u := sessionURL(req("a.example.test", "/").URL)
				s.ClearHost(u.Host)
				if got := sessionFetch(t, e1, req("a.example.test", "/check"), stream); got != "" {
					t.Fatalf("cached client retained ClearHost cookies %q", got)
				}
				_ = sessionFetch(t, e2, req("a.example.test", "/set"), stream)
				s.Clear()
				if got := sessionFetch(t, e1, req("a.example.test", "/check"), stream); got != "" {
					t.Fatalf("cached client retained Clear cookies %q", got)
				}
				_ = sessionFetch(t, e1, req("a.example.test", "/set"), stream)
				if err := e1.Close(); err != nil {
					t.Fatal(err)
				}
				if got := sessionFetch(t, e2, req("a.example.test", "/check"), stream); !strings.Contains(got, "login=yes") {
					t.Fatalf("Engine.Close erased shared session %q", got)
				}
			})
		}
	}
}

func TestSessionLocalSecurePortCapacityExpiry(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%v", stream), func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/set" {
					http.SetCookie(w, &http.Cookie{Name: "regular", Value: "yes", Path: "/"})
					http.SetCookie(w, &http.Cookie{Name: "secure", Value: "no", Secure: true, Path: "/"})
					http.SetCookie(w, &http.Cookie{Name: "expired", Value: "no", Expires: time.Now().Add(-time.Hour), Path: "/"})
				}
				_, _ = io.WriteString(w, r.Header.Get("Cookie"))
			})
			a := httptest.NewServer(handler)
			defer a.Close()
			b := httptest.NewServer(handler)
			defer b.Close()
			s, _ := NewSession(SessionConfig{MaxHosts: 1, IdleTimeout: time.Minute})
			now := time.Now()
			s.now = func() time.Time { return now }
			e := sessionEngine(t, s)
			request := func(server *httptest.Server, path string) *Request { return &Request{URL: server.URL + path} }
			_ = sessionFetch(t, e, request(a, "/set"), stream)
			if got := sessionFetch(t, e, request(a, "/get"), stream); got != "regular=yes" {
				t.Fatalf("secure/expiry HTTP filtering %q", got)
			}
			if got := sessionFetch(t, e, request(b, "/get"), stream); got != "" {
				t.Fatalf("explicit port leak %q", got)
			}
			_ = sessionFetch(t, e, request(b, "/set"), stream)
			if got := sessionFetch(t, e, request(a, "/get"), stream); got != "" {
				t.Fatalf("cached jar survived host eviction %q", got)
			}
			now = now.Add(time.Minute)
			if got := sessionFetch(t, e, request(b, "/get"), stream); got != "" {
				t.Fatalf("cached jar survived idle expiry %q", got)
			}
		})
	}
}

func TestSessionLocalInflightClear(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%v", stream), func(t *testing.T) {
			entered, resume := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/wait" {
					close(entered)
					<-resume
					http.SetCookie(w, &http.Cookie{Name: "late", Value: "response"})
				}
				_, _ = io.WriteString(w, r.Header.Get("Cookie"))
			}))
			defer server.Close()
			s, _ := NewSession(SessionConfig{})
			e := sessionEngine(t, s)
			sessionPut(s, server.URL+"/", "old", "request")
			done := make(chan error, 1)
			go func() {
				req := &Request{URL: server.URL + "/wait"}
				if stream {
					r, err := e.SendStream(context.Background(), req)
					if err != nil {
						done <- err
						return
					}
					body, err := io.ReadAll(r.Body)
					_ = r.Body.Close()
					if err == nil && string(body) != "old=request" {
						err = fmt.Errorf("already sent header changed: %q", body)
					}
					done <- err
				} else {
					r, err := e.Send(context.Background(), req)
					if err == nil && string(r.Body) != "old=request" {
						err = fmt.Errorf("already sent header changed: %q", r.Body)
					}
					done <- err
				}
			}()
			<-entered
			s.Clear()
			close(resume)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if got := sessionFetch(t, e, &Request{URL: server.URL + "/check"}, stream); got != "late=response" {
				t.Fatalf("late response should repopulate fresh session %q", got)
			}
		})
	}
}

func TestSessionConcurrentBoundedAndRealRequests(t *testing.T) {
	s, _ := NewSession(SessionConfig{MaxHosts: 3, MaxCookiesPerHost: 4})
	e := sessionEngine(t, s)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "live", Value: "yes"})
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	var wg sync.WaitGroup
	errors := make(chan error, 24)
	for worker := 0; worker < 12; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 12; i++ {
				raw := fmt.Sprintf("https://host%d.test/", (worker+i)%7)
				sessionPut(s, raw, fmt.Sprintf("cookie%d", i%9), "value")
				_ = s.Cookies(sessionURL(raw))
				_ = s.GetAllCookies()
				if i%5 == 0 {
					s.ClearHost(fmt.Sprintf("host%d.test", (worker+i+1)%7))
				}
				if worker == 0 && i == 6 {
					s.Clear()
				}
				req := &Request{URL: server.URL + "/"}
				if worker%2 == 0 {
					r, err := e.Send(context.Background(), req)
					if err != nil {
						errors <- err
						return
					}
					if string(r.Body) != "ok" {
						errors <- fmt.Errorf("body=%q", r.Body)
						return
					}
				} else {
					r, err := e.SendStream(context.Background(), req)
					if err != nil {
						errors <- err
						return
					}
					_, err = io.Copy(io.Discard, r.Body)
					_ = r.Body.Close()
					if err != nil {
						errors <- err
						return
					}
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.hosts) > 3 || s.lru.Len() != len(s.hosts) {
		t.Fatalf("host limit/bookkeeping failed %d", len(s.hosts))
	}
	for _, h := range s.hosts {
		if len(h.cookies) > 4 {
			t.Fatalf("cookie limit failed %d", len(h.cookies))
		}
	}
}
