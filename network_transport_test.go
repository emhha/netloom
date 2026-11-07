package netloom

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
)

func networkTransportPort(t *testing.T, addr net.Addr) int {
	t.Helper()
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// The resolver deliberately cannot reach DNS. A fully mapped request must not
// resolve either the original origin or a rewritten name, including CNAME
// enrichment after the response has already arrived.
func networkTransportNoDNS(calls *atomic.Int32) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("unexpected DNS in mapped local test")
	}}
}

func TestNetworkTransportLogicalTLSIdentity(t *testing.T) {
	for _, mode := range []string{"1.1/buffer", "1.1/stream", "2/buffer", "2/stream", "2-only/buffer", "2-only/stream", "raw"} {
		t.Run(mode, func(t *testing.T) {
			var httpCalls, dnsCalls atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				httpCalls.Add(1)
				_, _ = fmt.Fprintf(w, "%s|%s|%s|%s", r.Host, r.TLS.ServerName, r.URL.RequestURI(), r.Proto)
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			if err := server.Certificate().VerifyHostname("example.com"); err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			e := pooledEngine(t, 4)
			tr := e.tlsT.(*tlsTransport)
			tr.resolver = networkTransportNoDNS(&dnsCalls)
			raw := e.rawT.(*rawTransport)
			raw.noGuard = true
			raw.resolver = tr.resolver
			port := networkTransportPort(t, server.Listener.Addr())
			options := &NetworkOptions{
				ConnectTo: []ConnectToRule{
					{Host: "EXAMPLE.COM.", Port: 443, ConnectHost: "mapped.test", ConnectPort: port},
					// Rewrites are one-shot: this must NOT redirect the mapped name again.
					{Host: "mapped.test", Port: port, ConnectHost: "never.test", ConnectPort: 9},
				},
				Resolve: []ResolveRule{
					{Host: "mapped.test", Port: port, Addresses: []string{"127.0.0.1"}},
					// Resolve must match after ConnectTo, not the original origin.
					{Host: "example.com", Port: 443, Addresses: []string{"127.0.0.2"}},
				},
				AddressFamily: AddressFamilyIPv4,
			}
			req := &Request{URL: "https://example.com/probe?key=value", Network: options, VerifyTLS: true, TLSConfig: &TLSOptions{Roots: roots}, Timeout: time.Second}
			version, _, _ := strings.Cut(mode, "/")
			req.HTTPVersion = version
			if mode == "raw" {
				req.HTTPVersion = "1.1"
				req.Raw = []byte("GET /probe?key=value HTTP/1.1\r\nHost: raw-host.test\r\nConnection: close\r\n\r\n")
			}
			var body []byte
			var response *Response
			if strings.HasSuffix(mode, "/stream") {
				stream, err := e.SendStream(context.Background(), req)
				if err != nil {
					t.Fatal(err)
				}
				body, err = io.ReadAll(stream.Body)
				closeErr := stream.Body.Close()
				if err != nil || closeErr != nil {
					t.Fatalf("read=%v close=%v", err, closeErr)
				}
				if status := stream.Status(); !status.Complete || status.Error != nil {
					t.Fatalf("status=%+v", status)
				}
				response = stream.Response
			} else {
				var err error
				response, err = e.Send(context.Background(), req)
				if err != nil {
					t.Fatal(err)
				}
				body = response.Body
			}
			wantProto := "HTTP/1.1"
			if version == "2" || version == "2-only" {
				wantProto = "HTTP/2.0"
			}
			wantHost := "example.com"
			if mode == "raw" {
				wantHost = "raw-host.test"
			}
			want := wantHost + "|example.com|/probe?key=value|" + wantProto
			if string(body) != want {
				t.Fatalf("wire identity=%q want %q", body, want)
			}
			if response.IP != "127.0.0.1" || response.TLS == nil {
				t.Fatalf("missing actual connection evidence: %+v", response)
			}
			if response.CNAME != "" || dnsCalls.Load() != 0 {
				t.Fatalf("mapped request performed DNS/enrichment: calls=%d CNAME=%q", dnsCalls.Load(), response.CNAME)
			}
			if req.URL != "https://example.com/probe?key=value" || req.Network != options || options.ConnectTo[0].Host != "EXAMPLE.COM." {
				t.Fatal("request mapping or logical URL mutated")
			}
			if httpCalls.Load() != 1 {
				t.Fatalf("HTTP calls=%d", httpCalls.Load())
			}
		})
	}
}

func TestNetworkTransportCertificateUsesLogicalName(t *testing.T) {
	for _, mode := range []string{"1.1", "2", "2-only", "raw"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
			s.EnableHTTP2 = true
			s.StartTLS()
			defer s.Close()
			roots := x509.NewCertPool()
			roots.AddCert(s.Certificate())
			port := networkTransportPort(t, s.Listener.Addr())
			e := pooledEngine(t, 1)
			e.rawT.(*rawTransport).noGuard = true
			req := &Request{URL: "https://wrong.test/", HTTPVersion: mode, VerifyTLS: true, TLSConfig: &TLSOptions{Roots: roots}, Timeout: time.Second, Network: &NetworkOptions{ConnectTo: []ConnectToRule{{Host: "wrong.test", Port: 443, ConnectHost: "127.0.0.1", ConnectPort: port}}}}
			if mode == "raw" {
				req.HTTPVersion = "1.1"
				req.Raw = []byte("GET / HTTP/1.1\r\nHost: wrong.test\r\n\r\n")
			}
			_, err := e.Send(context.Background(), req)
			var mismatch x509.HostnameError
			if err == nil || !errors.As(err, &mismatch) {
				t.Fatalf("want logical-name certificate error, got %T %v", err, err)
			}
			if mismatch.Host != "wrong.test" {
				t.Fatalf("certificate checked mapped name instead: %q", mismatch.Host)
			}
			if calls.Load() != 0 {
				t.Fatal("HTTP sent before certificate verification")
			}
		})
	}
}

func TestNetworkTransportPoolCanonicalIdentityAndIsolation(t *testing.T) {
	var counts [2]atomic.Int32
	servers := make([]*httptest.Server, 2)
	for i := range servers {
		servers[i] = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprintf(w, "%d|%s", i, r.Host) }))
		servers[i].Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				counts[i].Add(1)
			}
		}
		servers[i].Start()
		defer servers[i].Close()
	}
	e := pooledEngine(t, 8)
	var dnsCalls atomic.Int32
	e.tlsT.(*tlsTransport).resolver = networkTransportNoDNS(&dnsCalls)
	policy := func(server int) *NetworkOptions {
		return &NetworkOptions{
			ConnectTo: []ConnectToRule{{Host: "POOL.TEST.", Port: 80, ConnectHost: "127.0.0.1", ConnectPort: networkTransportPort(t, servers[server].Listener.Addr())}},
			Resolve:   []ResolveRule{{Host: "UNUSED.TEST.", Port: 80, Addresses: []string{"::ffff:192.0.2.1"}}, {Host: "other.test", Port: 8080, Addresses: []string{"192.0.2.2"}}},
		}
	}
	send := func(p *NetworkOptions, want int, stream bool) {
		t.Helper()
		req := &Request{URL: "http://pool.test/item", HTTPVersion: "1.1", Network: p, Timeout: time.Second}
		var body []byte
		if stream {
			s, err := e.SendStream(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			body, err = io.ReadAll(s.Body)
			closeErr := s.Body.Close()
			if err != nil || closeErr != nil {
				t.Fatalf("read=%v close=%v", err, closeErr)
			}
		} else {
			r, err := e.Send(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			body = r.Body
		}
		if string(body) != fmt.Sprintf("%d|pool.test", want) {
			t.Fatalf("wrong mapped server/host: %q", body)
		}
	}
	first := policy(0)
	send(first, 0, false)
	equivalent := policy(0)
	equivalent.AddressFamily = AddressFamilyAuto
	equivalent.ConnectTo[0].Host = "pool.test"
	equivalent.Resolve[0].Host = "unused.test"
	equivalent.Resolve[0].Addresses[0] = "192.0.2.1"
	equivalent.Resolve[0], equivalent.Resolve[1] = equivalent.Resolve[1], equivalent.Resolve[0]
	send(equivalent, 0, true)
	if counts[0].Load() != 1 {
		t.Fatalf("canonical equivalent policy did not reuse: %d", counts[0].Load())
	}
	send(policy(1), 1, false)
	if counts[1].Load() != 1 || counts[0].Load() != 1 {
		t.Fatalf("changed mapping crossed cached connection: A=%d B=%d", counts[0].Load(), counts[1].Load())
	}
	ipv4 := policy(0)
	ipv4.AddressFamily = AddressFamilyIPv4
	send(ipv4, 0, false)
	if counts[0].Load() != 2 {
		t.Fatalf("family missing from cache identity: %d", counts[0].Load())
	}
	send(first, 0, true)
	if counts[0].Load() != 2 {
		t.Fatalf("original mapping was displaced or reused wrong lease: %d", counts[0].Load())
	}
	if dnsCalls.Load() != 0 {
		t.Fatalf("mapping unexpectedly used DNS: %d", dnsCalls.Load())
	}
}

func TestNetworkTransportRedirectRematchesAndClearsCredentials(t *testing.T) {
	type observed struct{ host, authorization, cookie string }
	seen := make(chan observed, 2)
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- observed{r.Host, r.Header.Get("Authorization"), r.Header.Get("Cookie")}
		_, _ = io.WriteString(w, "final")
	}))
	defer final.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- observed{r.Host, r.Header.Get("Authorization"), r.Header.Get("Cookie")}
		w.Header().Set("Location", "http://second.test/done")
		w.WriteHeader(http.StatusFound)
	}))
	defer first.Close()
	e := pooledEngine(t, 4)
	var dnsCalls atomic.Int32
	e.tlsT.(*tlsTransport).resolver = networkTransportNoDNS(&dnsCalls)
	req := &Request{URL: "http://first.test/start", HTTPVersion: "1.1", Timeout: time.Second, Header: fhttp.Header{"Authorization": []string{"Bearer secret"}, "Cookie": []string{"manual=secret"}}, Network: &NetworkOptions{ConnectTo: []ConnectToRule{
		{Host: "first.test", Port: 80, ConnectHost: "127.0.0.1", ConnectPort: networkTransportPort(t, first.Listener.Addr())},
		{Host: "second.test", Port: 80, ConnectHost: "127.0.0.1", ConnectPort: networkTransportPort(t, final.Listener.Addr())},
	}}}
	var validated []string
	ex, err := Do(context.Background(), e, req, RedirectPolicy{Follow: true, ValidateURL: func(_ context.Context, u string) error { validated = append(validated, u); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if ex.Response == nil || string(ex.Response.Body) != "final" || len(ex.Hops) != 1 {
		t.Fatalf("exchange=%+v", ex)
	}
	a, b := <-seen, <-seen
	if a.host != "first.test" || a.authorization != "Bearer secret" || a.cookie != "manual=secret" {
		t.Fatalf("first=%+v", a)
	}
	if b.host != "second.test" || b.authorization != "" || b.cookie != "" {
		t.Fatalf("redirect leaked origin identity: %+v", b)
	}
	if len(validated) != 2 || validated[0] != req.URL || validated[1] != "http://second.test/done" {
		t.Fatalf("validation did not retain logical URLs: %v", validated)
	}
	if req.Header.Get("Authorization") != "Bearer secret" || req.Header.Get("Cookie") != "manual=secret" || req.URL != "http://first.test/start" {
		t.Fatal("redirect mutated input")
	}
	if ex.Request.Network == req.Network {
		t.Fatal("redirect did not clone network policy")
	}
	ex.Request.Network.ConnectTo[0].ConnectHost = "mutated.test"
	if req.Network.ConnectTo[0].ConnectHost != "127.0.0.1" {
		t.Fatal("redirect policy aliases caller input")
	}
	if dnsCalls.Load() != 0 {
		t.Fatalf("redirect unexpectedly resolved DNS: %d", dnsCalls.Load())
	}
}
