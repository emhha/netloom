package netloom

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestConnectionPoolCookieSessionsSurviveClientEviction(t *testing.T) {
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "private", Path: "/"})
		}
		_, _ = io.WriteString(w, r.Header.Get("Cookie"))
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Header.Get("Cookie")) }))
	defer b.Close()
	e, err := New(Config{Retries: -1, CookieJar: true, ConnectionPool: &ConnectionPoolConfig{MaxClients: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.tlsT.(*tlsTransport).noGuard = true
	for _, step := range []struct{ url, want string }{{a.URL + "/set", ""}, {a.URL + "/check", "session=private"}, {b.URL, ""}, {a.URL + "/check", "session=private"}} {
		r, err := e.Send(context.Background(), &Request{URL: step.url})
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Body) != step.want {
			t.Fatalf("cookie session/isolation: got %q want %q", r.Body, step.want)
		}
	}
}

func TestConnectionPoolStillEnforcesDialGuard(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	e := pooledEngine(t, 2)
	if _, err := e.Send(context.Background(), &Request{URL: server.URL}); err != nil {
		t.Fatal(err)
	}
	// The no-guard fixture must not lend its already-open connection to guarded
	// requests; production never changes this internal test flag.
	e.tlsT.(*tlsTransport).noGuard = false
	if _, err := e.Send(context.Background(), &Request{URL: server.URL}); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("pool bypassed dial guard: %v", err)
	}
}

func TestConnectionPoolCloseActuallyClosesIdleConnections(t *testing.T) {
	closed := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	server.Start()
	defer server.Close()
	e := pooledEngine(t, 1)
	if _, err := e.Send(context.Background(), &Request{URL: server.URL}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
		t.Fatal("successful request closed rather than pooled connection")
	default:
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Engine.Close did not close idle socket")
	}
}

func TestConnectionPoolEarlyCloseAndTimeoutReleaseCapacity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/blocked" {
			w.Header().Set("Content-Length", "20")
			_, _ = io.WriteString(w, "first")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	for _, mode := range []string{"early-close", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			e := pooledEngine(t, 1)
			s, err := e.SendStream(context.Background(), &Request{URL: server.URL + "/blocked", Timeout: 50 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "early-close" {
				_ = s.Body.Close()
			} else {
				_, err := io.ReadAll(s.Body)
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("body timeout: %v", err)
				}
				_ = s.Body.Close()
			}
			if count, idle := poolSize(e.tlsT.(*tlsTransport).pool); count != 0 || idle != 0 {
				t.Fatalf("failed stream retained lease: %d/%d", count, idle)
			}
			if _, err := e.Send(context.Background(), &Request{URL: server.URL}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
