package netloom

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bogdanfinn/fhttp/http2"
)

func pooledEngine(t *testing.T, max int) *Engine {
	t.Helper()
	e, err := New(Config{Retries: -1, RatePerSecond: 10000, ConnectionPool: &ConnectionPoolConfig{MaxClients: max}})
	if err != nil {
		t.Fatal(err)
	}
	e.tlsT.(*tlsTransport).noGuard = true
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func poolSize(p *clientPool) (entries, idle int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries), p.idle.Len()
}

func TestConnectionPoolReuseAndActualEvidence(t *testing.T) {
	for _, version := range []string{"1.1", "2"} {
		t.Run(version, func(t *testing.T) {
			var connections atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "reused") }))
			server.EnableHTTP2 = true
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			server.StartTLS()
			defer server.Close()
			e := pooledEngine(t, 1)
			wantProto := "HTTP/1.1"
			if version == "2" {
				wantProto = "HTTP/2.0"
			}
			fingerprint := sha256.Sum256(server.Certificate().Raw)
			for i := 0; i < 4; i++ {
				var resp *Response
				if i%2 == 0 {
					var err error
					resp, err = e.Send(context.Background(), &Request{URL: server.URL, HTTPVersion: version})
					if err != nil {
						t.Fatal(err)
					}
				} else {
					s, err := e.SendStream(context.Background(), &Request{URL: server.URL, HTTPVersion: version})
					if err != nil {
						t.Fatal(err)
					}
					_, err = io.ReadAll(s.Body)
					_ = s.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					resp = s.Response
				}
				if resp.HTTPVersion != wantProto || resp.IP != "127.0.0.1" {
					t.Fatalf("actual connection evidence: %+v", resp)
				}
				if resp.TLS == nil || resp.TLS.FingerprintSHA256 != hex.EncodeToString(fingerprint[:]) {
					t.Fatalf("actual TLS missing/wrong: %+v", resp.TLS)
				}
				if i > 0 && (resp.Timings.ConnectMS != nil || resp.Timings.TLSMS != nil || resp.Timings.DNSMS != nil) {
					t.Fatalf("reused connection has fabricated setup timings: %+v", resp.Timings)
				}
			}
			if got := connections.Load(); got != 1 {
				t.Fatalf("connections=%d; want one shared by buffered/stream requests", got)
			}
		})
	}
}

func TestConnectionPoolDefaultsFreshAndTLSIsolation(t *testing.T) {
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	e := pooledEngine(t, 2)
	send := func(req *Request) {
		t.Helper()
		if _, err := e.Send(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	send(&Request{URL: server.URL, HTTPVersion: "1.1"})
	send(&Request{URL: server.URL, HTTPVersion: "1.1", FreshConnection: true})
	send(&Request{URL: server.URL, HTTPVersion: "1.1"})
	if got := connections.Load(); got != 2 {
		t.Fatalf("fresh request displaced/reused cached client: connections=%d", got)
	}
	// A verified request must not borrow the previous insecure connection.
	if _, err := e.Send(context.Background(), &Request{URL: server.URL, VerifyTLS: true}); err == nil {
		t.Fatal("insecure connection bypassed verification")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	send(&Request{URL: server.URL, VerifyTLS: true, TLSConfig: &TLSOptions{Roots: roots}})
	if _, err := e.Send(context.Background(), &Request{URL: server.URL, VerifyTLS: true, TLSConfig: &TLSOptions{Roots: x509.NewCertPool()}}); err == nil {
		t.Fatal("custom roots crossed client identities")
	}

	fresh, err := New(Config{Retries: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	fresh.tlsT.(*tlsTransport).noGuard = true
	before := connections.Load()
	for i := 0; i < 2; i++ {
		if _, err := fresh.Send(context.Background(), &Request{URL: server.URL}); err != nil {
			t.Fatal(err)
		}
	}
	if got := connections.Load() - before; got != 2 {
		t.Fatalf("nil pool changed fresh-client default: %d", got)
	}
}

func TestConnectionPoolKeyAndUncacheableIdentities(t *testing.T) {
	e := pooledEngine(t, 16)
	tr := e.tlsT.(*tlsTransport)
	base := Request{URL: "https://example.invalid/a", Timeout: time.Second}
	first, err := tr.acquireClient(context.Background(), &base)
	if err != nil {
		t.Fatal(err)
	}
	identity := first.client
	first.release(true)
	for _, change := range []func(*Request){
		func(r *Request) { r.URL = "https://example.invalid/b" },
		func(r *Request) { r.Timeout = 2 * time.Second },
		func(r *Request) { r.HTTPVersion = "2" },
	} {
		r := base
		change(&r)
		lease, err := tr.acquireClient(context.Background(), &r)
		if err != nil {
			t.Fatal(err)
		}
		if lease.client != identity {
			t.Fatal("equivalent direct configuration did not reuse client")
		}
		lease.release(true)
	}
	for name, change := range map[string]func(*Request){
		"origin": func(r *Request) { r.URL = "https://other.invalid/a" },
		"scheme": func(r *Request) { r.URL = "http://example.invalid/a" },
		"port":   func(r *Request) { r.URL = "https://example.invalid:443/a" },
		"verify": func(r *Request) { r.VerifyTLS = true },
		"http1":  func(r *Request) { r.HTTPVersion = "1.1" },
		"proxy":  func(r *Request) { r.Proxy = "http://user:pass@127.0.0.1:8080" },
	} {
		t.Run(name, func(t *testing.T) {
			r := base
			change(&r)
			lease, err := tr.acquireClient(context.Background(), &r)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.release(true)
			if lease.client == identity {
				t.Fatal("isolated configuration shared client")
			}
		})
	}
	// Same ClientHelloID is not sufficient profile identity: H2 maps differ.
	p1 := cloneClientProfile(tr.defaultProfile)
	p2 := cloneClientProfile(p1)
	p2.GetSettings()[http2.SettingHeaderTableSize]++
	for _, r := range []Request{
		{URL: base.URL, Profile: p1}, {URL: base.URL, Profile: p2},
		{URL: base.URL, TLSConfig: &TLSOptions{}}, {URL: base.URL, FreshConnection: true},
		{URL: base.URL, HTTPVersion: "2-only"},
	} {
		before, _ := poolSize(tr.pool)
		lease, err := tr.acquireClient(context.Background(), &r)
		if err != nil {
			t.Fatal(err)
		}
		if lease.client == identity {
			t.Fatal("unkeyable identity was pooled")
		}
		lease.release(true)
		after, _ := poolSize(tr.pool)
		if after != before {
			t.Fatalf("uncached lease persisted: %d -> %d", before, after)
		}
	}
	proxy := base
	proxy.Proxy = "http://u:p@127.0.0.1:8080"
	proxy.Timeout = time.Second
	lease, err := tr.acquireClient(context.Background(), &proxy)
	if err != nil {
		t.Fatal(err)
	}
	proxyClient := lease.client
	lease.release(true)
	proxy.Timeout += time.Nanosecond
	lease, err = tr.acquireClient(context.Background(), &proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.release(true)
	if lease.client == proxyClient {
		t.Fatal("proxy client timeout not isolated")
	}
}

func TestConnectionPoolLRUCapacityCancellationAndIdleTTL(t *testing.T) {
	e := pooledEngine(t, 1)
	tr := e.tlsT.(*tlsTransport)
	a := &Request{URL: "https://a.invalid"}
	b := &Request{URL: "https://b.invalid"}
	lease, err := tr.acquireClient(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	firstClient := lease.client
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := tr.acquireClient(ctx, b); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("busy capacity did not respect context: %v", err)
	}
	if count, idle := poolSize(tr.pool); count != 1 || idle != 0 {
		t.Fatalf("busy entry evicted/overflowed: %d/%d", count, idle)
	}
	lease.release(true)
	lease, err = tr.acquireClient(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	lease.release(true)
	lease, err = tr.acquireClient(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if lease.client == firstClient {
		t.Fatal("LRU entry was not evicted")
	}
	firstClient = lease.client
	lease.release(true)
	tr.pool.mu.Lock()
	tr.pool.idle.Back().Value.(*pooledClient).idleSince = time.Now().Add(-2 * tr.pool.idleTimeout)
	tr.pool.mu.Unlock()
	lease, err = tr.acquireClient(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.release(true)
	if lease.client == firstClient {
		t.Fatal("expired client entry was reused")
	}
}

func TestConnectionPoolStreamLeaseAndEngineClose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "complete") }))
	defer server.Close()
	e := pooledEngine(t, 1)
	req := &Request{URL: server.URL}
	s, err := e.SendStream(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(s.Body)
	if err != nil {
		t.Fatal(err)
	}
	// EOF alone does not release either the stream or its client lease.
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := e.Send(ctx, req); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("EOF released lease without Close: %v", err)
	}
	if err := s.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Send(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	s, err = e.SendStream(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan error, 1)
	go func() { _, err := e.Send(context.Background(), req); waiting <- err }()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waiting:
		if !errors.Is(err, context.Canceled) && !errors.Is(err, ErrEngineClosed) {
			t.Fatalf("waiter close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close left a pool waiter blocked")
	}
	if !s.Status().Closed {
		t.Fatal("Close left stream open")
	}
	if count, idle := poolSize(e.tlsT.(*tlsTransport).pool); count != 0 || idle != 0 {
		t.Fatalf("Close leaked clients: %d/%d", count, idle)
	}
	if _, err := e.Send(context.Background(), req); !errors.Is(err, ErrEngineClosed) {
		t.Fatalf("closed engine accepted work: %v", err)
	}
}

func TestConnectionPoolConcurrentRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	e := pooledEngine(t, 2)
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < cap(errs); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := e.Send(context.Background(), &Request{URL: server.URL})
			if err != nil {
				errs <- err
				return
			}
			if string(r.Body) != "ok" || r.IP != "127.0.0.1" {
				errs <- errors.New("incorrect response/connection evidence")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if count, idle := poolSize(e.tlsT.(*tlsTransport).pool); count > 2 || idle != count {
		t.Fatalf("client bound violated: %d/%d", count, idle)
	}
}

func TestConnectionPoolConfigurationValidationAndSnapshot(t *testing.T) {
	for _, cfg := range []ConnectionPoolConfig{{MaxClients: -1}, {IdleTimeout: -1}} {
		if _, err := New(Config{ConnectionPool: &cfg}); err == nil {
			t.Fatal("accepted invalid pool configuration")
		}
	}
	cfg := &ConnectionPoolConfig{MaxClients: 1}
	e, err := New(Config{ConnectionPool: cfg})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	cfg.MaxClients = 99
	if e.cfg.ConnectionPool.MaxClients != 1 || e.tlsT.(*tlsTransport).pool.max != 1 {
		t.Fatal("Engine retained caller's mutable pool config")
	}
	tr := e.tlsT.(*tlsTransport)
	profile := cloneClientProfile(tr.defaultProfile)
	profile.GetSettings()[http2.SettingHeaderTableSize]++
	if profile.GetSettings()[http2.SettingHeaderTableSize] == tr.defaultProfile.GetSettings()[http2.SettingHeaderTableSize] {
		t.Fatal("profile snapshot shares mutable settings")
	}
}
