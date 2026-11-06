package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestUnsupportedProxyIgnored(t *testing.T) {
	// An invalid proxy scheme must not panic; session falls back to direct.
	s := NewSession(Options{Proxy: "ftp://nope:1"})
	if s == nil || s.client == nil {
		t.Fatal("session should be constructed despite bad proxy")
	}
	s.Close()
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
