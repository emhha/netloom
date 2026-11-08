package netloom

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientDialScopeIdleAndActiveCancellation(t *testing.T) {
	var scope clientDialScope
	ctx, cancel := context.WithCancel(context.Background())
	scope.begin(ctx)
	a, b := net.Pipe()
	defer b.Close()
	dial := scope.wrapDial(func(ctx context.Context, _, _ string) (net.Conn, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return a, nil
	})
	conn, err := dial(context.Background(), "tcp", "unused")
	if err != nil {
		t.Fatal(err)
	}
	scope.end(true)
	cancel()
	// Old cancellation must not close an idle connection after successful return.
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() { var one [1]byte; _, err := io.ReadFull(b, one[:]); read <- err }()
	if _, err := conn.Write([]byte{'x'}); err != nil {
		t.Fatalf("old lease closed idle conn: %v", err)
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	next, cancelNext := context.WithCancel(context.Background())
	scope.begin(next)
	cancelNext()
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Fatal("next active lease cancellation did not close existing raw conn")
	}
	scope.end(false)
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if len(scope.connections) != 0 || len(scope.bindings) != 0 {
		t.Fatal("scope retained closed connections/callbacks")
	}
}

func TestClientDialScopeRejectsLateDialFromPreviousLease(t *testing.T) {
	var scope clientDialScope
	scope.begin(context.Background())
	started, resume := make(chan struct{}), make(chan struct{})
	a, b := net.Pipe()
	defer b.Close()
	dial := scope.wrapDial(func(context.Context, string, string) (net.Conn, error) { close(started); <-resume; return a, nil })
	result := make(chan error, 1)
	go func() { _, err := dial(context.Background(), "tcp", "unused"); result <- err }()
	<-started
	scope.end(true)
	scope.begin(context.Background())
	close(resume)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("old background dial adopted by new lease: %v", err)
	}
	scope.end(false)
}

type stalledTLSListener struct {
	net.Listener
	count    atomic.Int32
	accepted chan struct{}
	closed   chan struct{}
}

func (l *stalledTLSListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if l.count.Add(1) == 1 {
		return conn, nil
	}
	select {
	case l.accepted <- struct{}{}:
	default:
	}
	return &stalledTLSConn{Conn: conn, closed: l.closed}, nil
}

type stalledTLSConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *stalledTLSConn) Read([]byte) (int, error) {
	// Consume ClientHello without ever returning it to the TLS server. Its
	// handshake sends no bytes; a client-side socket close still becomes EOF.
	buf := make([]byte, 4096)
	for {
		if _, err := c.Conn.Read(buf); err != nil {
			c.once.Do(func() {
				select {
				case c.closed <- struct{}{}:
				default:
				}
			})
			return 0, err
		}
	}
}

func TestConnectionPoolStaleHTTP2ReconnectCancellation(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, mode := range []string{"request-timeout", "tls-phase", "mapped-tls-phase", "bound-tls-phase", "caller-cancel", "engine-close"} {
			name := mode
			if stream {
				name += "/stream"
			}
			t.Run(name, func(t *testing.T) {
				if mode == "bound-tls-phase" {
					networkBindingLoopbackAlias(t)
				}
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "h2") }))
				listener := &stalledTLSListener{Listener: server.Listener, accepted: make(chan struct{}, 1), closed: make(chan struct{}, 1)}
				var boundSources chan string
				if mode == "bound-tls-phase" {
					boundSources = make(chan string, 4)
					listener.Listener = &networkBindingObservedListener{Listener: server.Listener, sources: boundSources}
				}
				server.Listener = listener
				server.EnableHTTP2 = true
				server.StartTLS()
				defer server.Close()
				e := pooledEngine(t, 1)
				target := server.URL
				var mapping *NetworkOptions
				var dns atomic.Int32
				if mode == "mapped-tls-phase" || mode == "bound-tls-phase" {
					host, port, err := net.SplitHostPort(server.Listener.Addr().String())
					if err != nil {
						t.Fatal(err)
					}
					portNumber, err := strconv.Atoi(port)
					if err != nil {
						t.Fatal(err)
					}
					target = "https://mapped.test"
					mapping = &NetworkOptions{ConnectTo: []ConnectToRule{{Host: "mapped.test", Port: 443, ConnectHost: host, ConnectPort: portNumber}}}
					e.tlsT.(*tlsTransport).resolver = noNetworkDNS(&dns)
					if mode == "bound-tls-phase" {
						mapping.LocalAddress = "127.0.0.2"
					}
				}
				warm, err := e.Send(context.Background(), &Request{URL: target, Network: mapping, HTTPVersion: "2", Timeout: 2 * time.Second})
				if err != nil {
					t.Fatal(err)
				}
				if warm.HTTPVersion != "HTTP/2.0" {
					t.Fatalf("warm protocol=%s", warm.HTTPVersion)
				}
				if boundSources != nil {
					networkBindingAssertAcceptedSource(t, boundSources)
				}
				server.CloseClientConnections()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				req := &Request{URL: target, Network: mapping, HTTPVersion: "2", Timeout: 3 * time.Second}
				if mode == "tls-phase" || mode == "mapped-tls-phase" || mode == "bound-tls-phase" {
					req.PhaseTimeouts = &PhaseTimeouts{TLSHandshake: 80 * time.Millisecond}
				}
				if mode == "request-timeout" {
					req.Timeout = 80 * time.Millisecond
				}
				done := make(chan error, 1)
				go func() {
					var err error
					for attempt := 0; attempt < 3; attempt++ {
						if stream {
							var s *StreamResponse
							s, err = e.SendStream(ctx, req)
							if s != nil {
								_ = s.Body.Close()
							}
						} else {
							_, err = e.Send(ctx, req)
						}
						if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrEngineClosed) || err == nil {
							break
						}
					}
					done <- err
				}()
				select {
				case <-listener.accepted:
				case err := <-done:
					t.Fatalf("no H2 reconnect occurred: %v", err)
				case <-time.After(time.Second):
					t.Fatal("H2 reconnect did not dial")
				}
				if boundSources != nil {
					networkBindingAssertAcceptedSource(t, boundSources)
				}
				if mode == "caller-cancel" {
					cancel()
				}
				if mode == "engine-close" {
					closed := make(chan struct{})
					go func() { _ = e.Close(); close(closed) }()
					select {
					case <-closed:
					case <-time.After(500 * time.Millisecond):
						t.Fatal("Close hung in background H2 TLS reconnect")
					}
				}
				select {
				case err := <-done:
					if mode == "tls-phase" || mode == "mapped-tls-phase" || mode == "bound-tls-phase" {
						assertPhaseDeadline(t, err, PhaseTLS)
					}
					if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, ErrEngineClosed) {
						t.Fatalf("reconnect cancellation cause: %v", err)
					}
				case <-time.After(500 * time.Millisecond):
					t.Fatal("background H2 reconnect ignored current lease context")
				}
				select {
				case <-listener.closed:
				case <-time.After(500 * time.Millisecond):
					t.Fatal("stalled H2 reconnect socket leaked")
				}
				if dns.Load() != 0 {
					t.Fatalf("mapped H2 warm/reconnect unexpectedly performed DNS: %d", dns.Load())
				}
			})
		}
	}
}
