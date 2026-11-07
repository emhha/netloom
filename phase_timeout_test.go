package netloom

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func phaseEngine(t *testing.T, policy PhaseTimeouts, pool bool) *Engine {
	t.Helper()
	cfg := Config{Retries: -1, RatePerSecond: 10000, PhaseTimeouts: policy}
	if pool {
		cfg.ConnectionPool = &ConnectionPoolConfig{MaxClients: 1}
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.tlsT.(*tlsTransport).noGuard = true
	t.Cleanup(func() { _ = e.Close() })
	return e
}
func assertPhaseDeadline(t *testing.T, err error, phase Phase) {
	t.Helper()
	var pe *PhaseError
	var ne net.Error
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &pe) || pe.Phase != phase || !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("want deadline in %s, got %T %v", phase, err, err)
	}
}
func phaseServer(t *testing.T, version string, handler http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	if version == "1.1" {
		s.Start()
	} else {
		s.EnableHTTP2 = true
		s.StartTLS()
	}
	t.Cleanup(s.Close)
	return s
}

func TestPhaseTimeoutResponseHeader(t *testing.T) {
	for _, version := range []string{"1.1", "2", "2-only"} {
		for _, stream := range []bool{false, true} {
			name := version
			if stream {
				name += "/stream"
			}
			t.Run(name, func(t *testing.T) {
				var stall atomic.Bool
				server := phaseServer(t, version, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					if stall.Load() {
						<-r.Context().Done()
						return
					}
					_, _ = io.WriteString(w, "warm")
				}))
				e := phaseEngine(t, PhaseTimeouts{ResponseHeader: 80 * time.Millisecond}, true)
				req := &Request{URL: server.URL, HTTPVersion: version, Timeout: 2 * time.Second, Method: "POST", Body: []byte("payload")}
				if _, err := e.Send(context.Background(), req); err != nil {
					t.Fatal(err)
				}
				stall.Store(true)
				start := time.Now()
				var err error
				if stream {
					var s *StreamResponse
					s, err = e.SendStream(context.Background(), req)
					if s != nil {
						_ = s.Body.Close()
					}
				} else {
					_, err = e.Send(context.Background(), req)
				}
				assertPhaseDeadline(t, err, PhaseResponseHeader)
				if time.Since(start) > time.Second {
					t.Fatal("header phase timer did not bound request")
				}
			})
		}
	}
}

func TestPhaseTimeoutBodyIdle(t *testing.T) {
	for _, version := range []string{"1.1", "2", "2-only"} {
		for _, stream := range []bool{false, true} {
			name := version
			if stream {
				name += "/stream"
			}
			t.Run(name, func(t *testing.T) {
				server := phaseServer(t, version, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Length", "10")
					_, _ = io.WriteString(w, "a")
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				}))
				e := phaseEngine(t, PhaseTimeouts{BodyIdle: 80 * time.Millisecond}, true)
				req := &Request{URL: server.URL, HTTPVersion: version, Timeout: 2 * time.Second}
				if stream {
					s, err := e.SendStream(context.Background(), req)
					if err != nil {
						t.Fatal(err)
					}
					defer s.Body.Close()
					body, err := io.ReadAll(s.Body)
					assertPhaseDeadline(t, err, PhaseBody)
					if string(body) != "a" {
						t.Fatalf("partial body=%q", body)
					}
					_ = s.Body.Close()
					status := s.Status()
					assertPhaseDeadline(t, status.Error, PhaseBody)
					if status.Complete || !status.Closed {
						t.Fatalf("timeout status=%+v", status)
					}
				} else {
					r, err := e.Send(context.Background(), req)
					assertPhaseDeadline(t, err, PhaseBody)
					if r == nil || r.StatusCode != 200 || string(r.Body) != "a" {
						t.Fatalf("partial response=%+v", r)
					}
					assertPhaseDeadline(t, r.Error, PhaseBody)
				}
				if count, _ := poolSize(e.tlsT.(*tlsTransport).pool); count != 0 {
					t.Fatal("failed body retained a client lease")
				}
			})
		}
	}
}

func TestPhaseTimeoutTLSSetup(t *testing.T) {
	for _, version := range []string{"1.1", "2", "2-only"} {
		for _, stream := range []bool{false, true} {
			name := version
			if stream {
				name += "/stream"
			}
			t.Run(name, func(t *testing.T) {
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("HTTP sent before TLS completed") }))
				listener := &stalledTLSListener{Listener: server.Listener, accepted: make(chan struct{}, 1), closed: make(chan struct{}, 1)}
				listener.count.Store(1)
				server.Listener = listener
				server.EnableHTTP2 = true
				server.StartTLS()
				t.Cleanup(server.Close)
				e := phaseEngine(t, PhaseTimeouts{TLSHandshake: 80 * time.Millisecond}, true)
				req := &Request{URL: server.URL, HTTPVersion: version, Timeout: 2 * time.Second}
				if version == "2" {
					req.URL = strings.Replace(server.URL, "https://", "HTTPS://", 1)
				}
				var err error
				if stream {
					_, err = e.SendStream(context.Background(), req)
				} else {
					_, err = e.Send(context.Background(), req)
				}
				assertPhaseDeadline(t, err, PhaseTLS)
				select {
				case <-listener.closed:
				case <-time.After(time.Second):
					t.Fatal("TLS phase timeout leaked socket")
				}
			})
		}
	}
}

func TestPhaseTimeoutConnectOwnsDialContext(t *testing.T) {
	ctx, clock, err := newPhaseClock(context.Background(), &Request{URL: "http://example.invalid", PhaseTimeouts: &PhaseTimeouts{Connect: 30 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	defer clock.finish()
	var scope clientDialScope
	scope.begin(ctx)
	defer scope.end(false)
	dial := scope.wrapDial(func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() })
	_, err = dial(context.Background(), "tcp", "example.invalid:80")
	assertPhaseDeadline(t, clock.failure(ctx, err), PhaseConnect)
}

func TestPhaseTimeoutStreamingConsumerPauseAndProgress(t *testing.T) {
	t.Run("consumer-pause", func(t *testing.T) {
		server := phaseServer(t, "2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "done") }))
		e := phaseEngine(t, PhaseTimeouts{BodyIdle: 30 * time.Millisecond}, true)
		s, err := e.SendStream(context.Background(), &Request{URL: server.URL, HTTPVersion: "2"})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Body.Close()
		<-time.After(90 * time.Millisecond)
		body, err := io.ReadAll(s.Body)
		if err != nil || string(body) != "done" {
			t.Fatalf("consumer pause treated as idle IO: %q %v", body, err)
		}
	})
	t.Run("progress-resets-read-budget", func(t *testing.T) {
		server := phaseServer(t, "2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for i := 0; i < 6; i++ {
				_, _ = io.WriteString(w, "x")
				w.(http.Flusher).Flush()
				select {
				case <-time.After(25 * time.Millisecond):
				case <-r.Context().Done():
					return
				}
			}
		}))
		e := phaseEngine(t, PhaseTimeouts{BodyIdle: 80 * time.Millisecond}, true)
		r, err := e.Send(context.Background(), &Request{URL: server.URL, HTTPVersion: "2"})
		if err != nil || r == nil || string(r.Body) != "xxxxxx" {
			t.Fatalf("progressing body failed: %+v %v", r, err)
		}
	})
}

func TestPhaseTimeoutOverridesValidationAndParent(t *testing.T) {
	for _, field := range []string{"connect", "tls", "header", "body", "total"} {
		p := PhaseTimeouts{}
		switch field {
		case "connect":
			p.Connect = -1
		case "tls":
			p.TLSHandshake = -1
		case "header":
			p.ResponseHeader = -1
		case "body":
			p.BodyIdle = -1
		case "total":
			p.Total = -1
		}
		if _, err := New(Config{PhaseTimeouts: p}); err == nil {
			t.Fatalf("negative %s accepted", field)
		}
	}
	server := phaseServer(t, "1.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(100 * time.Millisecond):
			_, _ = io.WriteString(w, "ok")
		case <-r.Context().Done():
		}
	}))
	e := phaseEngine(t, PhaseTimeouts{ResponseHeader: 30 * time.Millisecond}, true)
	for _, override := range []*PhaseTimeouts{nil, {}, {ResponseHeader: 300 * time.Millisecond}} {
		req := &Request{URL: server.URL, PhaseTimeouts: override}
		r, err := e.Send(context.Background(), req)
		if override == nil {
			assertPhaseDeadline(t, err, PhaseResponseHeader)
			if req.PhaseTimeouts != nil {
				t.Fatal("request mutated")
			}
		} else if err != nil || r == nil || string(r.Body) != "ok" {
			t.Fatalf("override=%+v response=%+v err=%v", override, r, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := e.Send(ctx, &Request{URL: server.URL, PhaseTimeouts: &PhaseTimeouts{ResponseHeader: time.Second}})
	assertPhaseDeadline(t, err, PhaseResponseHeader)
	_, err = e.Send(context.Background(), &Request{URL: server.URL, PhaseTimeouts: &PhaseTimeouts{Connect: -1}})
	if err == nil {
		t.Fatal("negative request duration accepted")
	}
}

func TestPhaseTimeoutNoLateHeaderTimerAfterBodyOrReuse(t *testing.T) {
	ctx, clock, err := newPhaseClock(context.Background(), &Request{URL: "http://example.invalid", PhaseTimeouts: &PhaseTimeouts{ResponseHeader: time.Nanosecond}})
	if err != nil {
		t.Fatal(err)
	}
	defer clock.finish()
	enterPhase(ctx, PhaseRequest)
	enterPhase(ctx, PhaseBody)
	enterPhase(ctx, PhaseResponseHeader)
	select {
	case <-ctx.Done():
		t.Fatal("late WroteRequest resurrected header timer")
	case <-time.After(10 * time.Millisecond):
	}
	clock.mu.Lock()
	phase := clock.phase
	clock.mu.Unlock()
	if phase != PhaseBody {
		t.Fatalf("body regressed to %s", phase)
	}
}

type phaseDeadlineOnlyContext struct {
	context.Context
	deadline time.Time
}

func (c phaseDeadlineOnlyContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestPhaseTimeoutTotalBeforeContextTimerPublishes(t *testing.T) {
	past := time.Now().Add(-time.Second)
	ctx := phaseDeadlineOnlyContext{Context: context.WithValue(context.Background(), totalBudgetKey{}, past), deadline: past}
	if ctx.Err() != nil {
		t.Fatal("fixture already published cancellation")
	}
	assertPhaseDeadline(t, requestContextError(ctx), PhaseTotal)
	earlier := ctx
	earlier.deadline = past.Add(-time.Second)
	var phaseErr *PhaseError
	if err := requestContextError(earlier); !errors.Is(err, context.DeadlineExceeded) || errors.As(err, &phaseErr) {
		t.Fatalf("earlier caller deadline mislabeled Total: %v", err)
	}
}

func TestPhaseTimeoutConnectReplacesFallbackWithoutMutatingDialer(t *testing.T) {
	base := &net.Dialer{Timeout: 10 * time.Second}
	if phaseDialer(context.Background(), base) != base {
		t.Fatal("zero policy changed legacy dialer")
	}
	ctx, clock, err := newPhaseClock(context.Background(), &Request{URL: "https://example.invalid", PhaseTimeouts: &PhaseTimeouts{Connect: 20 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	defer clock.finish()
	actual := phaseDialer(ctx, base)
	if actual == base || actual.Timeout != 0 || base.Timeout != 10*time.Second {
		t.Fatalf("per-lease Connect override mutated/capped shared dialer: base=%v actual=%v", base.Timeout, actual.Timeout)
	}
}

func TestPhaseTimeoutFinalHeadersNotFirstByte(t *testing.T) {
	for _, stream := range []bool{false, true} {
		name := "buffered"
		if stream {
			name = "stream"
		}
		t.Run(name, func(t *testing.T) {
			server := phaseServer(t, "1.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = rw.WriteString("HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.1 200 OK\r\nX-Incomplete: ")
				_ = rw.Flush()
				_, _ = io.Copy(io.Discard, conn)
			}))
			e := phaseEngine(t, PhaseTimeouts{ResponseHeader: 80 * time.Millisecond}, true)
			req := &Request{URL: server.URL, HTTPVersion: "1.1", Timeout: 2 * time.Second}
			start := time.Now()
			var err error
			if stream {
				_, err = e.SendStream(context.Background(), req)
			} else {
				_, err = e.Send(context.Background(), req)
			}
			assertPhaseDeadline(t, err, PhaseResponseHeader)
			if time.Since(start) > time.Second {
				t.Fatal("first byte incorrectly stopped header timer")
			}
		})
	}
}

func TestPhaseTimeoutReusedConnectionDoesNotStartTLS(t *testing.T) {
	server := phaseServer(t, "2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	e := phaseEngine(t, PhaseTimeouts{}, true)
	if _, err := e.Send(context.Background(), &Request{URL: server.URL, HTTPVersion: "2"}); err != nil {
		t.Fatal(err)
	}
	r, err := e.Send(context.Background(), &Request{URL: server.URL, HTTPVersion: "2", PhaseTimeouts: &PhaseTimeouts{TLSHandshake: time.Nanosecond}})
	if err != nil || r == nil || string(r.Body) != "ok" {
		t.Fatalf("reused TLS connection consumed setup budget: %+v %v", r, err)
	}
}

func TestPhaseTimeoutCallerCancellationCause(t *testing.T) {
	marker := errors.New("caller stop")
	seen := make(chan struct{}, 1)
	server := phaseServer(t, "2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	e := phaseEngine(t, PhaseTimeouts{ResponseHeader: time.Second}, true)
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(marker)
	_, err := e.Send(ctx, &Request{URL: server.URL})
	// Cancellation before admission need not have a network phase, but must keep
	// the historical canceled identity. In-flight cancellation is checked below.
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancelCause(context.Background())
	request := &Request{URL: server.URL, PhaseTimeouts: &PhaseTimeouts{ResponseHeader: time.Second}}
	done := make(chan error, 1)
	// Use a trace-independent handler signal so cancellation occurs in flight.
	go func() { _, err := e.Send(ctx, request); done <- err }()
	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("request not received")
	}
	cancel(marker)
	select {
	case err := <-done:
		if !errors.Is(err, marker) || !errors.Is(err, context.Canceled) {
			t.Fatalf("lost caller cause: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not release request")
	}
}

func TestPhaseTimeoutRejectsUnsupportedProxyBudgets(t *testing.T) {
	e := phaseEngine(t, PhaseTimeouts{}, true)
	for _, stream := range []bool{false, true} {
		req := &Request{URL: "https://example.invalid", Proxy: "socks5://127.0.0.1:1", PhaseTimeouts: &PhaseTimeouts{Connect: time.Second}}
		var err error
		if stream {
			_, err = e.SendStream(context.Background(), req)
		} else {
			_, err = e.Send(context.Background(), req)
		}
		if err == nil || !strings.Contains(err.Error(), "phase timeouts support only") {
			t.Fatalf("unsupported proxy budget accepted: %v", err)
		}
	}
}

func TestPhaseTimeoutTotalAcrossRetries(t *testing.T) {
	var hits atomic.Int32
	server := phaseServer(t, "1.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); <-r.Context().Done() }))
	e, err := New(Config{Retries: 10, RatePerSecond: 10000, Timeout: time.Second, PhaseTimeouts: PhaseTimeouts{ResponseHeader: 50 * time.Millisecond, Total: 125 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.tlsT.(*tlsTransport).noGuard = true
	start := time.Now()
	_, err = e.Send(context.Background(), &Request{URL: server.URL})
	assertPhaseDeadline(t, err, PhaseTotal)
	if n := hits.Load(); n < 2 || n > 4 {
		t.Fatalf("total budget did not span retries: hits=%d", n)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("total budget restarted per retry")
	}
}
