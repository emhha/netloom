package netloom

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bogdanfinn/fhttp/httptrace"
)

func tlsControlPhaseWait(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func tlsControlPhaseCanceled(t *testing.T, err, cause error, phase Phase) {
	t.Helper()
	var pe *PhaseError
	if !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || !errors.As(err, &pe) || pe.Phase != phase {
		t.Fatalf("lost cancellation cause/stage %s: %T %v", phase, err, err)
	}
}

func tlsControlPhaseRecover(t *testing.T, e *Engine, req *Request) {
	t.Helper()
	if count, _ := poolSize(e.tlsT.(*tlsTransport).pool); count != 0 {
		t.Fatalf("failed controlled request retained %d leases", count)
	}
	next := *req
	next.PhaseTimeouts = &PhaseTimeouts{TLSHandshake: time.Second, ResponseHeader: time.Second, BodyIdle: time.Second}
	response, err := e.Send(context.Background(), &next)
	if err != nil || response == nil || string(response.Body) != "recovered" {
		t.Fatalf("one-slot pool did not recover: response=%+v err=%v", response, err)
	}
	if count, _ := poolSize(e.tlsT.(*tlsTransport).pool); count != 0 {
		t.Fatalf("completed dedicated request retained %d leases", count)
	}
}

func TestTLSControlsPhaseTLSHandshake(t *testing.T) {
	for _, version := range []string{"1.1", "2", "2-only"} {
		for _, mode := range []string{"timeout", "cancel"} {
			t.Run(version+"/"+mode, func(t *testing.T) {
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "recovered") }))
				listener := &stalledTLSListener{Listener: server.Listener, accepted: make(chan struct{}, 1), closed: make(chan struct{}, 1)}
				listener.count.Store(1)
				server.Listener = listener
				server.EnableHTTP2 = true
				server.StartTLS()
				defer server.Close()
				policy := PhaseTimeouts{TLSHandshake: 80 * time.Millisecond}
				if mode == "cancel" {
					policy.TLSHandshake = time.Second
				}
				e := phaseEngine(t, policy, true)
				req := tlsControlRequest(t, server, "logical.test")
				req.HTTPVersion = version
				req.TLSConfig.ServerName = "example.com"
				started := make(chan struct{}, 1)
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{TLSHandshakeStart: func() { started <- struct{}{} }})
				done := make(chan error, 1)
				go func() { _, err := e.Send(ctx, req); done <- err }()
				tlsControlPhaseWait(t, started, "controlled TLS handshake start")
				tlsControlPhaseWait(t, listener.accepted, "TLS stall socket acceptance")
				cause := errors.New("controlled TLS handshake caller stop")
				if mode == "cancel" {
					cancel(cause)
				}
				select {
				case err := <-done:
					if mode == "cancel" {
						tlsControlPhaseCanceled(t, err, cause, PhaseTLS)
					} else {
						assertPhaseDeadline(t, err, PhaseTLS)
					}
				case <-time.After(time.Second):
					t.Fatal("controlled TLS setup did not stop")
				}
				tlsControlPhaseWait(t, listener.closed, "TLS stall socket closure")
				listener.count.Store(0)
				tlsControlPhaseRecover(t, e, req)
			})
		}
	}
}

func TestTLSControlsPhaseResponseHeader(t *testing.T) {
	for _, version := range []string{"1.1", "2", "2-only"} {
		for _, mode := range []string{"timeout", "cancel"} {
			t.Run(version+"/"+mode, func(t *testing.T) {
				seen, closed := make(chan struct{}, 1), make(chan struct{}, 2)
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/recover" {
						_, _ = io.WriteString(w, "recovered")
						return
					}
					_, _ = io.Copy(io.Discard, r.Body)
					seen <- struct{}{}
					<-r.Context().Done()
				}))
				server.EnableHTTP2 = true
				server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateClosed {
						closed <- struct{}{}
					}
				}
				server.StartTLS()
				defer server.Close()
				policy := PhaseTimeouts{ResponseHeader: 80 * time.Millisecond}
				if mode == "cancel" {
					policy.ResponseHeader = time.Second
				}
				e := phaseEngine(t, policy, true)
				req := tlsControlRequest(t, server, "logical.test")
				req.HTTPVersion = version
				req.TLSConfig.ServerName = "example.com"
				req.Method = "POST"
				req.Body = []byte("payload")
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				done := make(chan error, 1)
				go func() {
					if version == "2" {
						s, err := e.SendStream(ctx, req)
						if s != nil {
							_ = s.Body.Close()
						}
						done <- err
					} else {
						_, err := e.Send(ctx, req)
						done <- err
					}
				}()
				tlsControlPhaseWait(t, seen, "controlled request header stall")
				cause := errors.New("controlled header caller stop")
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
				case <-time.After(time.Second):
					t.Fatal("controlled response-header stall did not stop")
				}
				tlsControlPhaseWait(t, closed, "header failure socket closure")
				recoverRequest := *req
				recoverRequest.URL = strings.TrimSuffix(req.URL, "/probe") + "/recover"
				tlsControlPhaseRecover(t, e, &recoverRequest)
			})
		}
	}
}

func TestTLSControlsPhaseStreamBody(t *testing.T) {
	for _, version := range []string{"1.1", "2", "2-only"} {
		for _, mode := range []string{"timeout", "cancel"} {
			t.Run(version+"/"+mode, func(t *testing.T) {
				closed := make(chan struct{}, 2)
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/recover" {
						_, _ = io.WriteString(w, "recovered")
						return
					}
					w.Header().Set("Content-Length", "10")
					_, _ = io.WriteString(w, "a")
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				}))
				server.EnableHTTP2 = true
				server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateClosed {
						closed <- struct{}{}
					}
				}
				server.StartTLS()
				defer server.Close()
				policy := PhaseTimeouts{BodyIdle: 80 * time.Millisecond}
				if mode == "cancel" {
					policy.BodyIdle = time.Second
				}
				e := phaseEngine(t, policy, true)
				req := tlsControlRequest(t, server, "logical.test")
				req.HTTPVersion = version
				req.TLSConfig.ServerName = "example.com"
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				stream, err := e.SendStream(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
				defer stream.Body.Close()
				first := make([]byte, 1)
				if _, err := io.ReadFull(stream.Body, first); err != nil || string(first) != "a" {
					t.Fatalf("lost first body byte: %q %v", first, err)
				}
				cause := errors.New("controlled streamed body caller stop")
				if mode == "cancel" {
					cancel(cause)
				}
				remaining, err := io.ReadAll(stream.Body)
				if len(remaining) != 0 {
					t.Fatalf("unexpected body remainder=%q", remaining)
				}
				if mode == "cancel" {
					tlsControlPhaseCanceled(t, err, cause, PhaseBody)
				} else {
					assertPhaseDeadline(t, err, PhaseBody)
				}
				_ = stream.Body.Close()
				status := stream.Status()
				if status.Complete || !status.Closed || !status.Finished || status.BytesRead != 1 {
					t.Fatalf("partial stream status=%+v", status)
				}
				if mode == "cancel" {
					tlsControlPhaseCanceled(t, status.Error, cause, PhaseBody)
				} else {
					assertPhaseDeadline(t, status.Error, PhaseBody)
				}
				tlsControlPhaseWait(t, closed, "body failure socket closure")
				recoverRequest := *req
				recoverRequest.URL = strings.TrimSuffix(req.URL, "/probe") + "/recover"
				tlsControlPhaseRecover(t, e, &recoverRequest)
			})
		}
	}
}

func TestTLSControlsPhaseCookieJar(t *testing.T) {
	for _, version := range []string{"1.1", "2", "2-only"} {
		t.Run(version, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/set" {
					http.SetCookie(w, &http.Cookie{Name: "tls-control", Value: "saved", Path: "/", Secure: true, HttpOnly: true})
				}
				_, _ = fmt.Fprintf(w, "%s|%s|%s", r.Header.Get("Cookie"), r.Host, r.TLS.ServerName)
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			e, err := New(Config{Retries: -1, RatePerSecond: 10000, CookieJar: true, ConnectionPool: &ConnectionPoolConfig{MaxClients: 1}})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			e.tlsT.(*tlsTransport).noGuard = true
			req := tlsControlRequest(t, server, "logical.test")
			req.HTTPVersion = version
			req.TLSConfig.ServerName = "example.com"
			req.URL = "https://logical.test/set"
			response, err := e.Send(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if len(response.Cookies) != 1 || response.Cookies[0].Name != "tls-control" || response.Cookies[0].Value != "saved" {
				t.Fatalf("dedicated response cookie not stored: %+v", response.Cookies)
			}
			req.URL = "https://logical.test/check"
			response, err = tlsControlSend(e, req, "stream")
			if err != nil {
				t.Fatal(err)
			}
			if string(response.Body) != "tls-control=saved|logical.test|example.com" {
				t.Fatalf("dedicated client lost cookie jar or logical identity: %q", response.Body)
			}
			other := tlsControlRequest(t, server, "second.test")
			other.HTTPVersion = version
			other.TLSConfig.ServerName = "example.com"
			response, err = e.Send(context.Background(), other)
			if err != nil {
				t.Fatal(err)
			}
			if string(response.Body) != "|second.test|example.com" {
				t.Fatalf("TLS verification name became cookie origin: %q", response.Body)
			}
		})
	}
}
