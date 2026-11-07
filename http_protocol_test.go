package netloom

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	utls "github.com/bogdanfinn/utls"
)

func protocolTestClient(t *testing.T, jar tls_client.CookieJar, dial func(context.Context, string, string) (net.Conn, error)) tls_client.HttpClient {
	t.Helper()
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	opts := []tls_client.HttpClientOption{tls_client.WithDialContext(dial), tls_client.WithDisableHttp3(), tls_client.WithClientProfile(profileOrDefault(Request{}.Profile)), tls_client.WithTimeoutMilliseconds(0)}
	if jar != nil {
		opts = append(opts, tls_client.WithCookieJar(jar))
	}
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func TestHTTPProtocolStrictCONNECTProxy(t *testing.T) {
	var targetHits, tunnels atomic.Int64
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials leaked to origin")
		}
		if r.ProtoMajor != 2 {
			t.Errorf("target protocol=%s", r.Proto)
		}
		_, _ = io.WriteString(w, "proxied-h2")
	}))
	target.EnableHTTP2 = true
	target.StartTLS()
	defer target.Close()
	u, _ := url.Parse(target.URL)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != u.Host || r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
			t.Errorf("unexpected CONNECT method=%q host=%q auth=%q", r.Method, r.Host, r.Header.Get("Proxy-Authorization"))
			http.Error(w, "CONNECT required", 400)
			return
		}
		tunnels.Add(1)
		upstream, err := net.DialTimeout("tcp", u.Host, time.Second)
		if err != nil {
			t.Error(err)
			http.Error(w, "dial failed", 502)
			return
		}
		defer upstream.Close()
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if err := rw.Flush(); err != nil {
			return
		}
		done := make(chan struct{})
		go func() { _, _ = io.Copy(upstream, rw); _ = upstream.Close(); close(done) }()
		_, _ = io.Copy(conn, upstream)
		_ = conn.Close()
		<-done
	}))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)
	pu.User = url.UserPassword("user", "pass")
	e, err := New(Config{Retries: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req := &Request{URL: target.URL, Proxy: pu.String(), HTTPVersion: "2-only", Timeout: time.Second}
	r, err := e.Send(ctx, req)
	if err != nil || r == nil || string(r.Body) != "proxied-h2" || r.HTTPVersion != "HTTP/2.0" {
		t.Fatalf("response=%+v err=%v", r, err)
	}
	s, err := e.SendStream(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(s.Body)
	_ = s.Body.Close()
	if err != nil || string(body) != "proxied-h2" || s.Response.HTTPVersion != "HTTP/2.0" {
		t.Fatalf("body=%q response=%+v err=%v", body, s.Response, err)
	}
	if targetHits.Load() != 2 || tunnels.Load() != 2 {
		t.Fatalf("target hits=%d tunnels=%d", targetHits.Load(), tunnels.Load())
	}
}

func TestHTTPProtocolStrictCONNECTTimeoutAndHandshakeCancel(t *testing.T) {
	for _, cancelHandshake := range []bool{false, true} {
		t.Run(map[bool]string{false: "CONNECT-timeout", true: "TLS-handshake-cancel"}[cancelHandshake], func(t *testing.T) {
			started := make(chan struct{}, 1)
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				if cancelHandshake {
					_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
					if err = rw.Flush(); err != nil {
						return
					}
					if _, err = rw.ReadByte(); err != nil {
						return
					}
					started <- struct{}{}
				}
				_, _ = io.Copy(io.Discard, rw)
			}))
			defer proxy.Close()
			e, err := New(Config{Retries: -1})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			timeout := 75 * time.Millisecond
			if cancelHandshake {
				timeout = time.Second
			}
			result := make(chan error, 1)
			go func() {
				_, err := e.Send(ctx, &Request{URL: "https://example.invalid/", Proxy: proxy.URL, HTTPVersion: "2-only", Timeout: timeout})
				result <- err
			}()
			want := context.DeadlineExceeded
			if cancelHandshake {
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("TLS handshake did not start")
				}
				cancel()
				want = context.Canceled
			}
			select {
			case err := <-result:
				if !errors.Is(err, want) {
					t.Fatalf("err=%v want=%v", err, want)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("strict proxy request did not stop")
			}
		})
	}
}

func TestHTTPProtocolStrictCONNECTEarlyCancellation(t *testing.T) {
	for _, mode := range []string{"caller-cancel", "caller-deadline", "engine-close"} {
		for _, stream := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/send", true: "/stream"}[stream], func(t *testing.T) {
				started := make(chan struct{}, 1)
				proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					conn, rw, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
					started <- struct{}{}
					// The proxy receives CONNECT but never sends any response.
					_, _ = io.Copy(io.Discard, rw)
				}))
				defer proxy.Close()
				e, err := New(Config{Retries: -1})
				if err != nil {
					t.Fatal(err)
				}
				defer e.Close()
				ctx, cancel := context.WithCancel(context.Background())
				if mode == "caller-deadline" {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 75*time.Millisecond)
				}
				defer cancel()
				result := make(chan error, 1)
				req := &Request{URL: "https://example.invalid/", Proxy: proxy.URL, HTTPVersion: "2-only", Timeout: 10 * time.Second}
				go func() {
					if stream {
						r, err := e.SendStream(ctx, req)
						if r != nil {
							_ = r.Body.Close()
						}
						result <- err
					} else {
						_, err := e.Send(ctx, req)
						result <- err
					}
				}()
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("CONNECT did not start")
				}
				closed := make(chan struct{})
				want := context.Canceled
				switch mode {
				case "caller-cancel":
					cancel()
					close(closed)
				case "caller-deadline":
					want = context.DeadlineExceeded
					close(closed)
				case "engine-close":
					go func() { _ = e.Close(); close(closed) }()
				}
				watchdog := time.NewTimer(300 * time.Millisecond)
				defer watchdog.Stop()
				select {
				case err := <-result:
					if !errors.Is(err, want) {
						t.Fatalf("err=%v want=%v", err, want)
					}
				case <-watchdog.C:
					t.Fatal("CONNECT ignored early cancellation")
				}
				select {
				case <-closed:
				case <-watchdog.C:
					t.Fatal("Engine.Close ignored CONNECT cancellation")
				}
			})
		}
	}
}

func TestHTTPProtocolProxyHeaderLimitAndBufferedTunnel(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		wantError      bool
	}{
		{name: "buffered-tunnel", response: "HTTP/1.1 200 Connection Established\r\n\r\nprefix"},
		{name: "oversized-headers", response: "HTTP/1.1 200 Connection Established\r\nX-Large: " + strings.Repeat("x", 65<<10) + "\r\n\r\n", wantError: true},
		{name: "non-200", response: "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				_, _ = rw.WriteString(tc.response)
				if err = rw.Flush(); err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, rw)
			}))
			defer proxy.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := dialHTTPProxy(ctx, proxy.URL, "tcp", "example.test:443")
			if tc.wantError {
				if err == nil {
					_ = conn.Close()
					t.Fatal("invalid proxy response accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			prefix := make([]byte, 6)
			if _, err = io.ReadFull(conn, prefix); err != nil || string(prefix) != "prefix" {
				t.Fatalf("tunnel prefix=%q err=%v", prefix, err)
			}
		})
	}
	for _, proxyURL := range []string{"https://127.0.0.1:1", "socks5://127.0.0.1:1"} {
		if conn, err := dialHTTPProxy(context.Background(), proxyURL, "tcp", "example.test:443"); err == nil {
			_ = conn.Close()
			t.Fatalf("unsupported proxy accepted: %s", proxyURL)
		}
	}
}

func TestHTTPProtocolValidation(t *testing.T) {
	for _, version := range []string{"", "auto", "1.1", "2", "2-only"} {
		if err := validateHTTPVersion(version); err != nil {
			t.Fatal(err)
		}
	}
	for _, version := range []string{"2.0", "3", "h2", "2-only ", "HTTP/2"} {
		if err := validateHTTPVersion(version); err == nil {
			t.Fatalf("accepted %q", version)
		}
	}
}

func TestHTTPProtocolStrictNegotiationBeforeRequest(t *testing.T) {
	for _, tc := range []struct {
		name       string
		secure, h2 bool
		alpn       []string
	}{
		{name: "h2", secure: true, h2: true, alpn: []string{"h2", "http/1.1"}},
		{name: "h1", secure: true, alpn: []string{"http/1.1"}},
		{name: "no-alpn", secure: true, alpn: []string{}},
		{name: "plaintext"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits, conns atomic.Int64
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.ProtoMajor != 2 {
					t.Errorf("application request used %s", r.Proto)
				}
				_, _ = io.WriteString(w, "strict-h2")
			}))
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					conns.Add(1)
				}
			}
			if tc.secure {
				server.EnableHTTP2 = tc.h2
				server.TLS = &stdtls.Config{NextProtos: tc.alpn}
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			hreq, _ := fhttp.NewRequestWithContext(ctx, "GET", server.URL, nil)
			response, err := doHTTPRequest(protocolTestClient(t, nil, nil), &Request{HTTPVersion: "2-only"}, hreq)
			if tc.h2 {
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil || string(body) != "strict-h2" || response.ProtoMajor != 2 || response.TLS == nil || response.TLS.NegotiatedProtocol != "h2" {
					t.Fatalf("body=%q err=%v response=%+v", body, err, response)
				}
				if hits.Load() != 1 || conns.Load() != 1 {
					t.Fatalf("hits=%d connections=%d", hits.Load(), conns.Load())
				}
			} else {
				if !errors.Is(err, ErrHTTP2Unavailable) || response != nil {
					t.Fatalf("response=%+v err=%v", response, err)
				}
				if hits.Load() != 0 {
					t.Fatalf("transmitted %d HTTP requests without h2", hits.Load())
				}
				wantConns := int64(1)
				if !tc.secure {
					wantConns = 0
				}
				if conns.Load() != wantConns {
					t.Fatalf("connections=%d want=%d", conns.Load(), wantConns)
				}
			}
		})
	}
}

func TestHTTPProtocolStrictTrustCookiesAndAuth(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit := hits.Add(1)
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Error("client certificate missing")
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "secret" {
			t.Errorf("Basic Auth missing")
		}
		if hit == 2 {
			if cookie, err := r.Cookie("session"); err != nil || cookie.Value != "one" {
				t.Errorf("cookie=%v err=%v", cookie, err)
			}
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "one", Path: "/"})
		_, _ = io.WriteString(w, "ok")
	}))
	server.EnableHTTP2 = true
	server.TLS = &stdtls.Config{ClientAuth: stdtls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	certificate := server.TLS.Certificates[0]
	clientCertificates := []utls.Certificate{{Certificate: certificate.Certificate, PrivateKey: certificate.PrivateKey}}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	u, _ := url.Parse(server.URL)
	u.User = url.UserPassword("user", "secret")
	client := protocolTestClient(t, tls_client.NewCookieJar(), nil)
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		hreq, _ := fhttp.NewRequestWithContext(ctx, "GET", u.String(), nil)
		response, err := doHTTPRequest(client, &Request{HTTPVersion: "2-only", VerifyTLS: true, TLSConfig: &TLSOptions{Roots: roots, Certificates: clientCertificates}}, hreq)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("hits=%d", hits.Load())
	}
}

func TestHTTPProtocolStrictCancellationDuringInitialization(t *testing.T) {
	seed := httptest.NewTLSServer(http.NotFoundHandler())
	certificates := seed.TLS.Certificates
	seed.Close()
	clientPipe, serverPipe := net.Pipe()
	handshakeDone := make(chan error, 1)
	serverDone := make(chan struct{})
	defer close(serverDone)
	go func() {
		defer serverPipe.Close()
		conn := stdtls.Server(serverPipe, &stdtls.Config{Certificates: certificates, NextProtos: []string{"h2"}, MinVersion: stdtls.VersionTLS12, MaxVersion: stdtls.VersionTLS12})
		handshakeDone <- conn.Handshake()
		// Do not read the HTTP/2 preface: NewClientConn's synchronous Flush
		// must be interrupted by cancellation even before RoundTrip exists.
		<-serverDone
	}()
	defer clientPipe.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hreq, _ := fhttp.NewRequestWithContext(ctx, "GET", "https://example.test/", nil)
	client := protocolTestClient(t, nil, func(context.Context, string, string) (net.Conn, error) { return clientPipe, nil })
	result := make(chan error, 1)
	go func() {
		r, err := doHTTPRequest(client, &Request{HTTPVersion: "2-only"}, hreq)
		if r != nil {
			_ = r.Body.Close()
		}
		result <- err
	}()
	select {
	case err := <-handshakeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not complete")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not interrupt initialization")
	}
}

func TestHTTPProtocolStrictStreamCancellation(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	for _, closeEngine := range []bool{false, true} {
		t.Run(map[bool]string{false: "caller-cancel", true: "engine-close"}[closeEngine], func(t *testing.T) {
			e, err := New(Config{Retries: -1})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			e.tlsT.(*tlsTransport).noGuard = true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, err := e.SendStream(ctx, &Request{URL: server.URL, HTTPVersion: "2-only", Timeout: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Body.Close()
			first := make([]byte, 5)
			if _, err := io.ReadFull(s.Body, first); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { _, err := io.ReadAll(s.Body); result <- err }()
			closed := make(chan struct{})
			if closeEngine {
				go func() { _ = e.Close(); close(closed) }()
			} else {
				cancel()
				close(closed)
			}
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("read err=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("body read ignored cancellation")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("Engine.Close did not return")
			}
		})
	}
}

func TestHTTPProtocolStrictEngineSendAndStream(t *testing.T) {
	var conns atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("protocol=%s", r.Proto)
		}
		_, _ = io.WriteString(w, "h2-engine")
	}))
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	e, err := New(Config{Retries: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.tlsT.(*tlsTransport).noGuard = true
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req := &Request{URL: server.URL, HTTPVersion: "2-only"}
	r, err := e.Send(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Body) != "h2-engine" || r.HTTPVersion != "HTTP/2.0" || r.TLS == nil {
		t.Fatalf("response=%+v", r)
	}
	s, err := e.SendStream(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(s.Body)
	_ = s.Body.Close()
	if err != nil || string(body) != "h2-engine" || s.Response.HTTPVersion != "HTTP/2.0" || !s.Status().Complete {
		t.Fatalf("body=%q err=%v status=%+v", body, err, s.Status())
	}
	if conns.Load() != 2 {
		t.Fatalf("connections=%d want one per dedicated strict request", conns.Load())
	}
}
