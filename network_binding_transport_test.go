package netloom

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// networkBindingObservedListener records the peer of each real accepted TCP
// socket, including a replacement socket whose TLS handshake never completes.
type networkBindingObservedListener struct {
	net.Listener
	sources chan string
}

func (l *networkBindingObservedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	select {
	case l.sources <- conn.RemoteAddr().String():
	default:
	}
	return conn, nil
}

func networkBindingAssertAcceptedSource(t *testing.T, sources <-chan string) {
	t.Helper()
	select {
	case addr := <-sources:
		host, _, err := net.SplitHostPort(addr)
		if err != nil || host != "127.0.0.2" {
			t.Fatalf("accepted bound socket source=%q: %v", addr, err)
		}
	case <-time.After(time.Second):
		t.Fatal("missing accepted bound socket source evidence")
	}
}

func networkBindingLoopbackAlias(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("127.0.0.2 source tests require Linux's configured loopback /8; no host network changes are made")
	}
}

func networkBindingTLSMatrix(t *testing.T, device string) {
	t.Helper()
	for _, mode := range []string{"1.1/buffer", "1.1/stream", "2/buffer", "2/stream", "2-only/buffer", "2-only/stream", "raw"} {
		t.Run(mode, func(t *testing.T) {
			var dns, sockets atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				source, _, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil {
					t.Errorf("remote address: %v", err)
				}
				_, _ = fmt.Fprintf(w, "%s|%s|%s|%s|%s", source, r.Host, r.TLS.ServerName, r.URL.RequestURI(), r.Proto)
			}))
			server.EnableHTTP2 = true
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					sockets.Add(1)
				}
			}
			server.StartTLS()
			defer server.Close()
			e := pooledEngine(t, 2)
			e.rawT.(*rawTransport).noGuard = true
			e.tlsT.(*tlsTransport).resolver = networkTransportNoDNS(&dns)
			e.rawT.(*rawTransport).resolver = networkTransportNoDNS(&dns)
			req := tlsControlRequest(t, server, "example.com")
			port := networkTransportPort(t, server.Listener.Addr())
			req.Network = &NetworkOptions{
				LocalAddress: "::ffff:127.0.0.2", Interface: device,
				ConnectTo: []ConnectToRule{{Host: "EXAMPLE.COM.", Port: 443, ConnectHost: "mapped.test", ConnectPort: port}},
				Resolve:   []ResolveRule{{Host: "mapped.test", Port: port, Addresses: []string{"127.0.0.1"}}},
			}
			before := req.Network.Clone()
			version, operation, _ := strings.Cut(mode, "/")
			if mode == "raw" {
				version, operation = "1.1", "raw"
			}
			req.HTTPVersion = version
			response, err := tlsControlSend(e, req, operation)
			if err != nil {
				t.Fatal(err)
			}
			wantHost, wantProto := "example.com", "HTTP/1.1"
			if operation == "raw" {
				wantHost = "logical.test"
			} // Raw preserves caller wire Host.
			if version != "1.1" {
				wantProto = "HTTP/2.0"
			}
			want := "127.0.0.2|" + wantHost + "|example.com|/probe|" + wantProto
			if string(response.Body) != want {
				t.Fatalf("wire binding/identity=%q want %q", response.Body, want)
			}
			if response.IP != "127.0.0.1" || response.TLS == nil {
				t.Fatalf("actual destination/TLS evidence=%+v", response)
			}
			if sockets.Load() != 1 || dns.Load() != 0 {
				t.Fatalf("sockets=%d DNS=%d; binding must apply to actual socket without DNS/probe", sockets.Load(), dns.Load())
			}
			if !reflect.DeepEqual(req.Network, before) || req.URL != "https://example.com/probe" {
				t.Fatal("binding normalization mutated caller")
			}
		})
	}
}

func TestNetworkBindingTransportTLSIdentity(t *testing.T) {
	networkBindingLoopbackAlias(t)
	networkBindingTLSMatrix(t, "")
}

func TestNetworkBindingTransportSourceLoopbackPortable(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		_, _ = io.WriteString(w, host)
	}))
	defer s.Close()
	e := pooledEngine(t, 1)
	response, err := e.Send(context.Background(), &Request{URL: s.URL, HTTPVersion: "1.1", Timeout: 2 * time.Second, Network: &NetworkOptions{LocalAddress: "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Body) != "127.0.0.1" {
		t.Fatalf("actual source=%q", response.Body)
	}
}

func TestNetworkBindingTransportPoolIsolationAndConcurrency(t *testing.T) {
	networkBindingLoopbackAlias(t)
	for _, version := range []string{"1.1", "2", "2-only"} {
		t.Run(version, func(t *testing.T) {
			var sockets atomic.Int32
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.RemoteAddr) }))
			s.EnableHTTP2 = true
			s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					sockets.Add(1)
				}
			}
			s.StartTLS()
			defer s.Close()
			e := pooledEngine(t, 8)
			send := func(source string, stream bool) (string, error) {
				req := &Request{URL: s.URL, HTTPVersion: version, Timeout: 3 * time.Second, Network: &NetworkOptions{LocalAddress: source}}
				mode := "buffer"
				if stream {
					mode = "stream"
				}
				r, err := tlsControlSend(e, req, mode)
				if err != nil {
					return "", err
				}
				host, _, err := net.SplitHostPort(string(r.Body))
				want := strings.TrimPrefix(source, "::ffff:")
				if err != nil || host != want {
					return "", fmt.Errorf("source %q got %q: %v", source, r.Body, err)
				}
				return string(r.Body), nil
			}
			a, err := send("127.0.0.1", false)
			if err != nil {
				t.Fatal(err)
			}
			b, err := send("127.0.0.2", true)
			if err != nil {
				t.Fatal(err)
			}
			c, err := send("::ffff:127.0.0.2", false)
			if err != nil {
				t.Fatal(err)
			}
			d, err := send("127.0.0.1", true)
			if err != nil {
				t.Fatal(err)
			}
			if a == b {
				t.Fatal("different sources shared a socket")
			}
			if version != "2-only" && (a != d || b != c || sockets.Load() != 2) {
				t.Fatalf("canonical same-source failed reuse: %q %q %q %q sockets=%d", a, b, c, d, sockets.Load())
			}
			// Concurrent buffered/streamed requests share the origin, not binding identity.
			var wg sync.WaitGroup
			failures := make(chan error, 16)
			for i := 0; i < 16; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					source := "127.0.0.1"
					if i%2 != 0 {
						source = "127.0.0.2"
					}
					_, err := send(source, i%3 == 0)
					if err != nil {
						failures <- err
					}
				}(i)
			}
			wg.Wait()
			close(failures)
			for err := range failures {
				t.Error(err)
			}
		})
	}
}

func TestNetworkBindingTransportPhaseAndPoolRecovery(t *testing.T) {
	networkBindingLoopbackAlias(t)
	for _, version := range []string{"1.1", "2", "2-only"} {
		for _, mode := range []string{"timeout", "cancel"} {
			t.Run(version+"/"+mode, func(t *testing.T) {
				seen, closed := make(chan string, 1), make(chan struct{}, 4)
				s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					host, _, _ := net.SplitHostPort(r.RemoteAddr)
					if r.URL.Path == "/recover" {
						_, _ = io.WriteString(w, host)
						return
					}
					seen <- host
					<-r.Context().Done()
				}))
				s.EnableHTTP2 = true
				s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateClosed {
						closed <- struct{}{}
					}
				}
				s.StartTLS()
				defer s.Close()
				timeout := 100 * time.Millisecond
				if mode == "cancel" {
					timeout = 2 * time.Second
				}
				e := phaseEngine(t, PhaseTimeouts{ResponseHeader: timeout}, true)
				req := &Request{URL: s.URL + "/stall", HTTPVersion: version, Timeout: 3 * time.Second, Network: &NetworkOptions{LocalAddress: "127.0.0.2"}}
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				done := make(chan error, 1)
				go func() {
					if version == "2" {
						stream, err := e.SendStream(ctx, req)
						if stream != nil {
							_ = stream.Body.Close()
						}
						done <- err
					} else {
						_, err := e.Send(ctx, req)
						done <- err
					}
				}()
				select {
				case host := <-seen:
					if host != "127.0.0.2" {
						t.Fatalf("stall source=%q", host)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("bound request did not reach stall")
				}
				cause := errors.New("bound request caller cancellation")
				if mode == "cancel" {
					cancel(cause)
				}
				select {
				case err := <-done:
					if mode == "cancel" {
						tlsControlPhaseCanceled(t, err, cause, PhaseResponseHeader)
					} else {
						assertPhaseDeadline(t, err, PhaseResponseHeader)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("binding prevented cancellation/phase timeout")
				}
				tlsControlPhaseWait(t, closed, "failed bound socket closure")
				if count, _ := poolSize(e.tlsT.(*tlsTransport).pool); count != 0 {
					t.Fatalf("failed bound request retained %d pool entries", count)
				}
				next := *req
				next.URL = s.URL + "/recover"
				next.PhaseTimeouts = &PhaseTimeouts{ResponseHeader: time.Second}
				response, err := e.Send(context.Background(), &next)
				if err != nil || response == nil || string(response.Body) != "127.0.0.2" {
					t.Fatalf("single-slot bound recovery: response=%+v err=%v", response, err)
				}
			})
		}
	}
}

func TestNetworkBindingTransportRedirectAndImmutability(t *testing.T) {
	networkBindingLoopbackAlias(t)
	seen := make(chan string, 2)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		seen <- host + "|" + r.Host
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "http://second.test/done")
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "done")
	}))
	defer s.Close()
	e := pooledEngine(t, 2)
	var dns atomic.Int32
	e.tlsT.(*tlsTransport).resolver = networkTransportNoDNS(&dns)
	port := networkTransportPort(t, s.Listener.Addr())
	options := &NetworkOptions{LocalAddress: "::ffff:127.0.0.2", ConnectTo: []ConnectToRule{
		{Host: "first.test", Port: 80, ConnectHost: "mapped.test", ConnectPort: port},
		{Host: "second.test", Port: 80, ConnectHost: "mapped.test", ConnectPort: port},
	}, Resolve: []ResolveRule{{Host: "mapped.test", Port: port, Addresses: []string{"127.0.0.1"}}}}
	before := options.Clone()
	req := &Request{URL: "http://first.test/start", HTTPVersion: "1.1", Network: options, Timeout: 2 * time.Second}
	ex, err := Do(context.Background(), e, req, RedirectPolicy{Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	if ex.Response == nil || string(ex.Response.Body) != "done" || len(ex.Hops) != 1 {
		t.Fatalf("exchange=%+v", ex)
	}
	if a, b := <-seen, <-seen; a != "127.0.0.2|first.test" || b != "127.0.0.2|second.test" {
		t.Fatalf("redirect lost binding/logical host: %q %q", a, b)
	}
	if !reflect.DeepEqual(options, before) || req.Network != options || req.URL != "http://first.test/start" {
		t.Fatal("redirect mutated caller binding policy")
	}
	if ex.Request.Network == options || ex.Request.Network.LocalAddress != options.LocalAddress {
		t.Fatal("redirect lost binding policy or aliases caller")
	}
	ex.Request.Network.LocalAddress = "127.0.0.1"
	ex.Request.Network.Resolve[0].Addresses[0] = "127.0.0.3"
	if !reflect.DeepEqual(options, before) {
		t.Fatal("redirect policy clone aliases caller")
	}
	if dns.Load() != 0 {
		t.Fatalf("redirect performed DNS: %d", dns.Load())
	}
}
