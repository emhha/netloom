package netloom

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPProxyCONNECTCancellationClosesSocket(t *testing.T) {
	for _, pooled := range []bool{false, true} {
		for _, stream := range []bool{false, true} {
			for _, mode := range []string{"cancel", "deadline", "engine-close"} {
				name := mode
				if pooled {
					name += "/pooled"
				}
				if stream {
					name += "/stream"
				}
				t.Run(name, func(t *testing.T) {
					seen, socketClosed := make(chan struct{}), make(chan struct{})
					proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						close(seen)
						// Never send CONNECT headers; detect the socket being closed,
						// not just the public Send call returning early.
						<-r.Context().Done()
						close(socketClosed)
					}))
					defer proxy.Close()
					cfg := Config{Retries: -1, Timeout: 10 * time.Second}
					if pooled {
						cfg.ConnectionPool = &ConnectionPoolConfig{MaxClients: 1}
					}
					e, err := New(cfg)
					if err != nil {
						t.Fatal(err)
					}
					defer e.Close()
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					if mode == "deadline" {
						var cancelDeadline context.CancelFunc
						ctx, cancelDeadline = context.WithTimeout(ctx, 80*time.Millisecond)
						defer cancelDeadline()
					}
					done := make(chan error, 1)
					go func() {
						req := &Request{URL: "https://example.invalid/", Proxy: proxy.URL}
						if stream {
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
					select {
					case <-seen:
					case <-time.After(time.Second):
						t.Fatal("CONNECT not received")
					}
					if mode == "cancel" {
						cancel()
					}
					if mode == "engine-close" {
						closed := make(chan struct{})
						go func() { _ = e.Close(); close(closed) }()
						select {
						case <-closed:
						case <-time.After(500 * time.Millisecond):
							t.Fatal("Close blocked on CONNECT")
						}
					}
					select {
					case err := <-done:
						if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
							t.Fatalf("CONNECT cancellation cause: %v", err)
						}
					case <-time.After(500 * time.Millisecond):
						t.Fatal("CONNECT ignored context")
					}
					select {
					case <-socketClosed:
					case <-time.After(500 * time.Millisecond):
						t.Fatal("CONNECT left a socket/dial goroutine behind")
					}
					if pooled {
						if count, idle := poolSize(e.tlsT.(*tlsTransport).pool); count != 0 || idle != 0 {
							t.Fatalf("canceled CONNECT retained client: %d/%d", count, idle)
						}
					}
				})
			}
		}
	}
}
