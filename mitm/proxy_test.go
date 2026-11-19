package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testBackend struct {
	calls                             atomic.Int32
	cookie, authorization, requestURL string
}

func (b *testBackend) CheckTarget(_ context.Context, u *url.URL) error {
	if u.Hostname() != "example.com" {
		return fmt.Errorf("out of scope")
	}
	return nil
}
func (b *testBackend) RoundTrip(r *http.Request) (*http.Response, error) {
	b.calls.Add(1)
	b.cookie, b.authorization, b.requestURL = r.Header.Get("Cookie"), r.Header.Get("Proxy-Authorization"), r.URL.String()
	if _, err := io.ReadAll(r.Body); err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: 200, Header: http.Header{
		"Content-Type": {"application/javascript"}, "Set-Cookie": {"a=1", "b=2"},
		"Connection": {"X-Hop"}, "X-Hop": {"remove-me"},
	}, Body: io.NopCloser(strings.NewReader("const token='test';"))}, nil
}

func proxyAuth() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("client:password"))
}

func TestHTTPProxyAuthScopeAndHeaders(t *testing.T) {
	ca, err := NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	backend := &testBackend{}
	proxy := New(ca, backend, Options{Username: "client", Password: "password"})
	defer proxy.Close()
	for _, tc := range []struct {
		url, auth string
		status    int
	}{
		{"http://example.com/app.js", "", 407},
		{"http://outside.example/app.js", proxyAuth(), 403},
		{"http://example.com/app.js", proxyAuth(), 200},
	} {
		req := httptest.NewRequest("GET", tc.url, nil)
		req.Header.Set("Proxy-Authorization", tc.auth)
		req.Header.Set("Cookie", "browser=original")
		rr := httptest.NewRecorder()
		proxy.ServeHTTP(rr, req)
		if rr.Code != tc.status {
			t.Fatalf("status %d, want %d", rr.Code, tc.status)
		}
		if tc.status == 200 {
			if len(rr.Header().Values("Set-Cookie")) != 2 || rr.Header().Get("X-Hop") != "" || rr.Body.String() != "const token='test';" {
				t.Fatalf("forwarded response changed: %s", rr.Body.String())
			}
		}
	}
	if backend.calls.Load() != 1 || backend.cookie != "browser=original" || backend.authorization != "" {
		t.Fatal("scope, browser cookies, or proxy credentials were not handled correctly")
	}
	proxy.Close()
	req := httptest.NewRequest("GET", "http://example.com/app.js", nil)
	req.Header.Set("Proxy-Authorization", proxyAuth())
	rr := httptest.NewRecorder()
	proxy.ServeHTTP(rr, req)
	if rr.Code != 503 || backend.calls.Load() != 1 {
		t.Fatal("closed proxy accepted new traffic")
	}
}

type hijackWriter struct {
	conn   net.Conn
	header http.Header
}

func (w *hijackWriter) Header() http.Header         { return w.header }
func (w *hijackWriter) WriteHeader(int)             {}
func (w *hijackWriter) Write(p []byte) (int, error) { return w.conn.Write(p) }
func (w *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

func TestHTTPSConnectDecryptsAndRestrictsTunnel(t *testing.T) {
	for _, host := range []string{"example.com", "outside.example"} {
		t.Run(host, func(t *testing.T) {
			ca, err := NewAuthority()
			if err != nil {
				t.Fatal(err)
			}
			backend := &testBackend{}
			proxy := New(ca, backend, Options{Username: "client", Password: "password"})
			clientConn, serverConn := net.Pipe()
			_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
			done := make(chan struct{})
			go func() {
				defer close(done)
				request := httptest.NewRequest("CONNECT", "http://example.com:443", nil)
				request.Host = "example.com:443"
				request.Header.Set("Proxy-Authorization", proxyAuth())
				proxy.ServeHTTP(&hijackWriter{conn: serverConn, header: make(http.Header)}, request)
			}()
			t.Cleanup(func() {
				proxy.Close()
				_ = clientConn.Close()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("CONNECT did not stop")
				}
			})
			reader := bufio.NewReader(clientConn)
			connected, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
			if err != nil || connected.StatusCode != 200 {
				t.Fatalf("CONNECT failed: %v", err)
			}
			roots := x509.NewCertPool()
			certificate, _ := ca.PEM()
			roots.AppendCertsFromPEM(certificate)
			client := tls.Client(&bufferedConn{Conn: clientConn, reader: reader}, &tls.Config{
				RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12,
			})
			if err := client.Handshake(); err != nil {
				t.Fatalf("trusted MITM handshake failed: %v", err)
			}
			if client.ConnectionState().PeerCertificates[0].Issuer.CommonName != "netloom MITM CA" {
				t.Fatal("proxy certificate was not presented")
			}
			request, err := http.NewRequest("GET", "https://"+host+"/app.js", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Cookie", "browser=original")
			if err := request.Write(client); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(client), request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if host == "example.com" {
				if response.StatusCode != 200 || string(body) != "const token='test';" || backend.calls.Load() != 1 || backend.requestURL != "https://example.com:443/app.js" || backend.cookie != "browser=original" {
					t.Fatalf("HTTPS request not forwarded correctly: status=%d calls=%d", response.StatusCode, backend.calls.Load())
				}
			} else if response.StatusCode != 403 || backend.calls.Load() != 0 {
				t.Fatal("CONNECT tunnel escaped its bound host")
			}
		})
	}
}

func TestHTTPSConnectReusesTunnelWithLiveUpstreamContext(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream response")
	}))
	t.Cleanup(origin.Close)
	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	proxy := New(ca, reuseBackend{target.Host, origin.Client().Transport}, Options{})
	var tunnels atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			tunnels.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(proxy.Close)
	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	trust := x509.NewCertPool()
	if !trust.AppendCertsFromPEM(ca.CertificatePEM()) {
		t.Fatal("cannot trust proxy CA")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trust}, MaxConnsPerHost: 1,
	}}
	t.Cleanup(client.CloseIdleConnections)
	for i := range 3 {
		resp, err := client.Get(origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || string(body) != "upstream response" {
			t.Fatalf("request %d: status=%d body=%q err=%v", i+1, resp.StatusCode, body, err)
		}
	}
	if got := tunnels.Load(); got != 1 {
		t.Fatalf("opened %d CONNECT tunnels instead of reusing one", got)
	}
}

type reuseBackend struct {
	host      string
	transport http.RoundTripper
}

func (b reuseBackend) CheckTarget(_ context.Context, u *url.URL) error {
	if u.Scheme != "https" || u.Host != b.host {
		return fmt.Errorf("out of scope")
	}
	return nil
}

func (b reuseBackend) RoundTrip(r *http.Request) (*http.Response, error) {
	return b.transport.RoundTrip(r)
}

func TestAuthorityPersistsAndSignsIPCertificates(t *testing.T) {
	ca, err := NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	certificate, key := ca.PEM()
	restored, err := LoadAuthority(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := restored.Certificate("192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certificate)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: x509.NewCertPool(), DNSName: "192.0.2.1"}); err == nil {
		t.Fatal("untrusted CA unexpectedly verified")
	}
	certificate[0] = '!'
	unchanged, _ := restored.PEM()
	if bytes.Equal(unchanged, certificate) {
		t.Fatal("caller changed authority certificate")
	}
}

func TestObservedBodyStreamsBeyondEvidenceLimit(t *testing.T) {
	input := bytes.Repeat([]byte("x"), 64<<10)
	calls := 0
	var captured []byte
	body := ObserveBody(io.NopCloser(bytes.NewReader(input)), 1024, int64(len(input)), func(data []byte, truncated bool) {
		calls++
		captured = data
		if !truncated {
			t.Error("evidence truncation was not reported")
		}
	})
	forwarded, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	_ = body.Close()
	_ = body.Close()
	if calls != 1 || len(captured) != 1024 || !bytes.Equal(input, forwarded) {
		t.Fatal("capture limit changed forwarded response or recorded more than once")
	}
}

func TestObservedBodyMarksIncompleteRead(t *testing.T) {
	var truncated bool
	body := ObserveBody(io.NopCloser(strings.NewReader("abc")), 1024, 3, func(_ []byte, incomplete bool) { truncated = incomplete })
	_ = body.Close()
	if !truncated {
		t.Fatal("unread response was marked complete")
	}
}
