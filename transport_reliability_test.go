package netloom

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReliabilityTimeoutAcrossSendModes(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, source := range []string{"config", "request", "context"} {
			t.Run(source+map[bool]string{false: "/buffered", true: "/stream"}[stream], func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
				defer server.Close()
				cfg := Config{Retries: -1, Timeout: time.Second}
				req := &Request{URL: server.URL}
				ctx := context.Background()
				switch source {
				case "config":
					cfg.Timeout = 60 * time.Millisecond
				case "request":
					req.Timeout = 60 * time.Millisecond
				case "context":
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 60*time.Millisecond)
					defer cancel()
				}
				e, err := New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer e.Close()
				e.tlsT.(*tlsTransport).noGuard = true
				start := time.Now()
				if stream {
					_, err = e.SendStream(ctx, req)
				} else {
					_, err = e.Send(ctx, req)
				}
				if err == nil {
					t.Fatal("blocked headers did not time out")
				}
				if time.Since(start) > 800*time.Millisecond {
					t.Fatalf("timeout source ignored: %v", err)
				}
				if source != "request" && req.Timeout != 0 {
					t.Fatal("caller request mutated")
				}
			})
		}
	}
}

func TestReliabilityRequestTimeoutOverridesConfig(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "buffered", true: "stream"}[stream], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-time.After(80 * time.Millisecond):
					_, _ = io.WriteString(w, "ok")
				case <-r.Context().Done():
				}
			}))
			defer server.Close()
			e, _ := New(Config{Retries: -1, Timeout: 10 * time.Millisecond})
			defer e.Close()
			e.tlsT.(*tlsTransport).noGuard = true
			req := &Request{URL: server.URL, Timeout: time.Second}
			if stream {
				s, err := e.SendStream(context.Background(), req)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Body.Close()
				b, err := io.ReadAll(s.Body)
				if err != nil || string(b) != "ok" {
					t.Fatalf("body=%q err=%v", b, err)
				}
			} else {
				r, err := e.Send(context.Background(), req)
				if err != nil || string(r.Body) != "ok" {
					t.Fatalf("response=%+v err=%v", r, err)
				}
			}
		})
	}
}

func TestReliabilityTLSMetadataUsesOnlyRequestConnection(t *testing.T) {
	for _, version := range []string{"auto", "1.1"} {
		t.Run(version, func(t *testing.T) {
			var connections atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "tls") }))
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			e, _ := New(Config{Retries: -1})
			defer e.Close()
			e.tlsT.(*tlsTransport).noGuard = true
			r, err := e.Send(context.Background(), &Request{URL: server.URL, HTTPVersion: version})
			if err != nil {
				t.Fatal(err)
			}
			if got := connections.Load(); got != 1 {
				t.Fatalf("metadata opened extra connection: %d", got)
			}
			wantProto := "HTTP/2.0"
			if version == "1.1" {
				wantProto = "HTTP/1.1"
			}
			if r.HTTPVersion != wantProto {
				t.Fatalf("protocol=%q want=%q", r.HTTPVersion, wantProto)
			}
			// Metadata may be absent for a backend that cannot expose the real state;
			// anything provided must match the certificate on this server.
			fingerprint := sha256.Sum256(server.Certificate().Raw)
			if r.TLS != nil && r.TLS.FingerprintSHA256 != hex.EncodeToString(fingerprint[:]) {
				t.Fatalf("TLS evidence belongs to another connection: %+v", r.TLS)
			}
			if r.Timings == nil || r.Timings.TotalMS < r.Timings.HeadersMS || r.Timings.BodyMS < 0 {
				t.Fatalf("invalid timings: %+v", r.Timings)
			}
		})
	}
}

func TestReliabilityBufferedReadErrorKeepsTimings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10")
		_, _ = io.WriteString(w, "short")
	}))
	defer server.Close()
	e, _ := New(Config{Retries: -1})
	defer e.Close()
	e.tlsT.(*tlsTransport).noGuard = true
	r, err := e.Send(context.Background(), &Request{URL: server.URL})
	if !errors.Is(err, io.ErrUnexpectedEOF) || r == nil || string(r.Body) != "short" || r.StatusCode != 200 || r.Timings == nil {
		t.Fatalf("response=%+v err=%v", r, err)
	}
}

func TestReliabilityStreamStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "stream") }))
	defer server.Close()
	e, _ := New(Config{Retries: -1})
	defer e.Close()
	e.tlsT.(*tlsTransport).noGuard = true
	s, err := e.SendStream(context.Background(), &Request{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	initial := s.Response.Timings.TotalMS
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = s.Status()
			}
		}
	}()
	defer func() { close(stop); wg.Wait() }()
	data, err := io.ReadAll(s.Body)
	if err != nil || string(data) != "stream" {
		t.Fatalf("data=%q err=%v", data, err)
	}
	if err = s.Body.Close(); err != nil {
		t.Fatal(err)
	}
	status := s.Status()
	if !status.Complete || !status.Finished || !status.Closed || status.Error != nil || status.BytesRead != 6 || status.Timings.TotalMS < status.Timings.HeadersMS {
		t.Fatalf("status=%+v", status)
	}
	if s.Response.Timings.TotalMS != initial {
		t.Fatal("header metadata mutated")
	}
	if status.Timings.FirstByteMS != nil {
		*status.Timings.FirstByteMS = -1
		if *s.Status().Timings.FirstByteMS == -1 {
			t.Fatal("status shares timing pointers")
		}
	}
}

func TestReliabilityStreamEarlyCloseAndReadError(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(map[bool]string{false: "early-close", true: "read-error"}[broken], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "10")
				_, _ = io.WriteString(w, "short")
			}))
			defer server.Close()
			e, _ := New(Config{Retries: -1})
			defer e.Close()
			e.tlsT.(*tlsTransport).noGuard = true
			s, err := e.SendStream(context.Background(), &Request{URL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			if broken {
				_, err = io.ReadAll(s.Body)
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal(err)
				}
			}
			_ = s.Body.Close()
			status := s.Status()
			want := ErrStreamClosedEarly
			if broken {
				want = io.ErrUnexpectedEOF
			}
			if !status.Finished || status.Complete || !status.Closed || !errors.Is(status.Error, want) {
				t.Fatalf("status=%+v want=%v", status, want)
			}
		})
	}
}

func TestReliabilitySubMillisecondStreamTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	e, _ := New(Config{Retries: -1})
	defer e.Close()
	e.tlsT.(*tlsTransport).noGuard = true
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := e.SendStream(ctx, &Request{URL: server.URL, Timeout: time.Nanosecond})
	if !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		t.Fatalf("request deadline lost to millisecond rounding: err=%v watchdog=%v", err, ctx.Err())
	}
}

func TestReliabilityBodyTimeout(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, requestOverride := range []bool{false, true} {
			t.Run(fmt.Sprintf("stream=%v/request=%v", stream, requestOverride), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.WriteString(w, "first")
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				}))
				defer server.Close()
				cfg := Config{Retries: -1, Timeout: 100 * time.Millisecond}
				req := &Request{URL: server.URL}
				if requestOverride {
					cfg.Timeout = time.Second
					req.Timeout = 100 * time.Millisecond
				}
				e, _ := New(cfg)
				defer e.Close()
				e.tlsT.(*tlsTransport).noGuard = true
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if stream {
					s, err := e.SendStream(ctx, req)
					if err != nil {
						t.Fatal(err)
					}
					defer s.Body.Close()
					body, err := io.ReadAll(s.Body)
					if !errors.Is(err, context.DeadlineExceeded) || string(body) != "first" || ctx.Err() != nil {
						t.Fatalf("body=%q err=%v watchdog=%v", body, err, ctx.Err())
					}
					_ = s.Body.Close()
					status := s.Status()
					if status.Complete || !status.Closed || !errors.Is(status.Error, context.DeadlineExceeded) {
						t.Fatalf("status=%+v", status)
					}
				} else {
					r, err := e.Send(ctx, req)
					if !errors.Is(err, context.DeadlineExceeded) || r == nil || string(r.Body) != "first" || ctx.Err() != nil {
						t.Fatalf("response=%+v err=%v watchdog=%v", r, err, ctx.Err())
					}
				}
			})
		}
	}
}

func TestReliabilityProxyBodyTimeout(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%v", stream), func(t *testing.T) {
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodConnect {
					http.Error(w, "CONNECT required", 400)
					return
				}
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
				if err = rw.Flush(); err != nil {
					return
				}
				req, err := http.ReadRequest(rw.Reader)
				if err != nil {
					return
				}
				_ = req.Body.Close()
				_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
				if err = rw.Flush(); err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, rw)
			}))
			defer proxy.Close()
			e, _ := New(Config{Retries: -1, Timeout: 100 * time.Millisecond})
			defer e.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			req := &Request{URL: "http://example.invalid/", Proxy: proxy.URL}
			if stream {
				s, err := e.SendStream(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Body.Close()
				body, err := io.ReadAll(s.Body)
				_ = s.Body.Close()
				if !errors.Is(err, context.DeadlineExceeded) || string(body) != "first" || !errors.Is(s.Status().Error, context.DeadlineExceeded) {
					t.Fatalf("body=%q err=%v status=%+v", body, err, s.Status())
				}
			} else {
				r, err := e.Send(ctx, req)
				if !errors.Is(err, context.DeadlineExceeded) || r == nil || string(r.Body) != "first" {
					t.Fatalf("response=%+v err=%v", r, err)
				}
			}
			if ctx.Err() != nil {
				t.Fatal("request timeout lost to watchdog")
			}
		})
	}
}

func TestReliabilityEngineCloseInterruptsBlockedRead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	e, _ := New(Config{Retries: -1})
	defer e.Close()
	e.tlsT.(*tlsTransport).noGuard = true
	s, err := e.SendStream(context.Background(), &Request{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(s.Body, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() { _, err := s.Body.Read(make([]byte, 1)); readDone <- err }()
	closeDone := make(chan struct{})
	go func() { _ = e.Close(); close(closeDone) }()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("blocked read succeeded after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked read not canceled")
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Engine.Close blocked")
	}
	status := s.Status()
	if !status.Closed || status.Complete || !errors.Is(status.Error, context.Canceled) {
		t.Fatalf("status=%+v", status)
	}
}

func TestReliabilityStreamCancellationStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	e, _ := New(Config{Retries: -1})
	defer e.Close()
	e.tlsT.(*tlsTransport).noGuard = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := e.SendStream(ctx, &Request{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = s.Body.Close()
	status := s.Status()
	if status.Complete || !status.Closed || !errors.Is(status.Error, context.Canceled) {
		t.Fatalf("status=%+v", status)
	}
}
