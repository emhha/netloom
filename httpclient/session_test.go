package httpclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGet429RetryAfterThenSuccess(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	s := NewSession(Options{RetryMax: 2, RetryWait: 5 * time.Millisecond})
	defer s.Close()

	resp, err := s.Get(context.Background(), srv.URL, "test-429", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	body, _ := ReadBody(resp)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected 2 calls, got %d", got)
	}
}

func TestRetryOn5xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewSession(Options{RetryMax: 3, RetryWait: time.Millisecond})
	defer s.Close()

	resp, err := s.Get(context.Background(), srv.URL, "test-5xx", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_, _ = ReadBody(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("expected 3 calls, got %d", got)
	}
}

func TestNoRetryOn4xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	s := NewSession(Options{RetryMax: 3, RetryWait: time.Millisecond})
	defer s.Close()

	resp, err := s.Get(context.Background(), srv.URL, "test-4xx", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_, _ = ReadBody(resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 call (no retry), got %d", got)
	}
}

// TestSharedLimiterAcrossSessions verifies the per-source bucket is shared at
// process level: two Sessions hitting the same source serialize through one
// 1-req/s bucket, so the second request waits roughly one period.
func TestSharedLimiterAcrossSessions(t *testing.T) {
	// Register a strict 1/s bucket for a private source name.
	const source = "test-shared-source"
	globalLimiters.mu.Lock()
	globalLimiters.buckets[source] = newTokenBucket(1, 200*time.Millisecond)
	globalLimiters.mu.Unlock()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s1 := NewSession(Options{RetryMax: 0})
	s2 := NewSession(Options{RetryMax: 0})
	defer s1.Close()
	defer s2.Close()

	ctx := context.Background()
	start := time.Now()
	// First call consumes the initial token immediately.
	r1, err := s1.Get(ctx, srv.URL, source, nil)
	if err != nil {
		t.Fatalf("s1.Get: %v", err)
	}
	_, _ = ReadBody(r1)
	// Second call (different Session, same source) must wait for refill.
	r2, err := s2.Get(ctx, srv.URL, source, nil)
	if err != nil {
		t.Fatalf("s2.Get: %v", err)
	}
	_, _ = ReadBody(r2)
	elapsed := time.Since(start)
	if elapsed < 150*time.Millisecond {
		t.Fatalf("expected shared bucket to throttle second session, elapsed=%v", elapsed)
	}
}

func TestInvalidProxyFailClosed(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(old)
	invalids := []string{" ", "http://", "http://user:secret%zz@host", "ftp://user:secret@host:21", "socks4://user:secret@host:1080", "http://host:", "http://host:0", "http://host:65536", "http://host/path", "http://host/?", "http://host/#", "socks5://host"}
	for _, raw := range invalids {
		for _, method := range []string{"Get", "Post", "Do"} {
			t.Run(raw+"/"+method, func(t *testing.T) {
				s := NewSession(Options{Proxy: raw, RetryMax: 5})
				defer s.Close()
				if !errors.Is(s.Err(), ErrInvalidProxy) {
					t.Fatalf("constructor error: %v", s.Err())
				}
				if strings.HasPrefix(raw, "ftp:") || strings.HasPrefix(raw, "socks4:") {
					if !errors.Is(s.Err(), ErrUnsupportedProxy) {
						t.Fatal("unsupported sentinel lost")
					}
				}
				calls, replays := 0, 0
				s.client.Transport = proxyTestRoundTripper(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected send") })
				source := "invalid-proxy/" + t.Name()
				bucket := newTokenBucket(1, time.Hour)
				globalLimiters.mu.Lock()
				globalLimiters.buckets[source] = bucket
				globalLimiters.mu.Unlock()
				defer func() { globalLimiters.mu.Lock(); delete(globalLimiters.buckets, source); globalLimiters.mu.Unlock() }()
				req, _ := http.NewRequest("POST", "http://example.invalid", strings.NewReader("body"))
				req.GetBody = func() (io.ReadCloser, error) { replays++; return nil, errors.New("unexpected replay") }
				var err error
				switch method {
				case "Get":
					_, err = s.Get(context.Background(), req.URL.String(), source, nil)
				case "Post":
					_, err = s.Post(context.Background(), req.URL.String(), source, []byte("body"), nil)
				case "Do":
					_, err = s.Do(context.Background(), source, req)
				}
				if err != s.Err() || !errors.Is(err, ErrInvalidProxy) || errors.Is(err, ErrRetryExhausted) {
					t.Fatalf("request error: %v", err)
				}
				if calls != 0 || replays != 0 || bucket.tokens != 1 || req.Header.Get("User-Agent") != "" {
					t.Fatalf("side effects: calls=%d replays=%d tokens=%v headers=%v", calls, replays, bucket.tokens, req.Header)
				}
				if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "user") {
					t.Fatalf("unsafe error: %v", err)
				}
			})
		}
	}
	if logs.Len() != 0 {
		t.Fatalf("invalid proxy construction must not log credentials: %s", &logs)
	}
}

type proxyTestRoundTripper func(*http.Request) (*http.Response, error)

func (f proxyTestRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProxyParsingAndExplicitDirect(t *testing.T) {
	for _, raw := range []string{"", "http://proxy.test", "https://proxy.test/", "HTTP://proxy.test", "http://[fe80::1%25eth0]/", "HTTPS://user:secret@[::1]/", "socks5://proxy.test:1080", "socks5h://user:secret@[::1]:1080/"} {
		s := NewSession(Options{Proxy: raw})
		if s.Err() != nil {
			t.Fatalf("valid proxy %q: %v", raw, s.Err())
		}
		tr := s.client.Transport.(*http.Transport)
		if raw == "" && (tr.Proxy != nil || tr.DialContext != nil) {
			t.Fatal("empty proxy must use direct mode, not environment")
		}
		s.Close()
	}
}

func TestContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewSession(Options{RetryMax: 1, RetryWait: time.Second})
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := s.Get(ctx, srv.URL, "test-cancel", nil)
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
}
