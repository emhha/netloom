package netloom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryStatusReplayAndObservation(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(string(rune('0'+map[bool]int{false: 0, true: 1}[replay])), func(t *testing.T) {
			var hits, opens, closes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				if string(b) != "abc" {
					t.Errorf("body=%q", b)
				}
				n := hits.Add(1)
				if n < 3 {
					w.WriteHeader(503)
				} else {
					_, _ = w.Write([]byte("done"))
				}
			}))
			defer server.Close()
			e := pooledEngine(t, 1)
			var source *Upload
			opener := func(context.Context) (io.ReadCloser, error) {
				opens.Add(1)
				return &retryCloseReader{Reader: strings.NewReader("abc"), closes: &closes}, nil
			}
			if replay {
				source, _ = NewReplayableUpload(3, opener)
			} else {
				b, _ := opener(context.Background())
				source, _ = NewUpload(b, 3)
			}
			var observed []AttemptInfo
			p := &RetryPolicy{MaxRetries: 2, Methods: []string{"POST"}, StatusCodes: []int{503}, Observer: func(info AttemptInfo) { observed = append(observed, info) }}
			resp, err := e.Send(context.Background(), &Request{URL: server.URL, Method: "POST", Upload: source, RetryPolicy: p})
			if err != nil {
				t.Fatal(err)
			}
			want := int32(1)
			if replay {
				want = 3
			}
			if hits.Load() != want || opens.Load() != want || closes.Load() != want || len(observed) != int(want) {
				t.Fatalf("hits=%d opens=%d closes=%d observations=%d", hits.Load(), opens.Load(), closes.Load(), len(observed))
			}
			if observed[len(observed)-1].WillRetry {
				t.Fatal("last event promises retry")
			}
			if replay && resp.StatusCode != 200 {
				t.Fatalf("status=%d", resp.StatusCode)
			}
		})
	}
}

type retryCloseReader struct {
	io.Reader
	closes *atomic.Int32
}

func (r *retryCloseReader) Close() error { r.closes.Add(1); return nil }

func TestRetrySafeMethodsSharedByRunAndSend(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		for _, run := range []bool{false, true} {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(503) }))
			e := pooledEngine(t, 1)
			req := &Request{URL: server.URL, Method: method, RetryPolicy: &RetryPolicy{MaxRetries: 2, StatusCodes: []int{503}}}
			if run {
				ch, err := e.Run(context.Background(), []Task{{Req: req}})
				if err != nil {
					t.Fatal(err)
				}
				for result := range ch {
					if result.Ctx.Resp.StatusCode != 503 {
						t.Fatal("status lost")
					}
				}
			} else {
				if _, err := e.Send(context.Background(), req); err != nil {
					t.Fatal(err)
				}
			}
			want := int32(1)
			if method == "GET" {
				want = 3
			}
			if hits.Load() != want {
				t.Fatalf("method=%s run=%v hits=%d", method, run, hits.Load())
			}
			server.Close()
		}
	}
}

func TestRetryBackoffTotalAndRetryAfter(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(429)
	}))
	defer server.Close()
	e := pooledEngine(t, 1)
	var events []AttemptInfo
	start := time.Now()
	resp, err := e.Send(context.Background(), &Request{URL: server.URL, PhaseTimeouts: &PhaseTimeouts{Total: 40 * time.Millisecond}, RetryPolicy: &RetryPolicy{MaxRetries: 2, StatusCodes: []int{429}, RespectRetryAfter: true, MaxDelay: time.Second, Observer: func(a AttemptInfo) { events = append(events, a) }}})
	var phase *PhaseError
	if !errors.As(err, &phase) || phase.Phase != PhaseTotal || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
	if resp == nil || resp.StatusCode != 429 || hits.Load() != 1 || time.Since(start) > time.Second {
		t.Fatalf("resp=%+v hits=%d elapsed=%s", resp, hits.Load(), time.Since(start))
	}
	if len(events) != 1 || events[0].Delay != time.Second || !events[0].WillRetry {
		t.Fatalf("events=%+v", events)
	}
}

func TestRetryStreamingDoesNotRetryStatus(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(503)
		_, _ = w.Write([]byte("partial"))
	}))
	defer server.Close()
	e := pooledEngine(t, 1)
	var events []AttemptInfo
	s, err := e.SendStream(context.Background(), &Request{URL: server.URL, RetryPolicy: &RetryPolicy{MaxRetries: 5, StatusCodes: []int{503}, Observer: func(a AttemptInfo) { events = append(events, a) }}})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, s.Body)
	_ = s.Body.Close()
	if hits.Load() != 1 || len(events) != 1 || events[0].WillRetry {
		t.Fatalf("hits=%d events=%+v", hits.Load(), events)
	}
}

func TestRetryPolicyValidationAndDelay(t *testing.T) {
	for _, p := range []*RetryPolicy{{MaxRetries: -1}, {MaxRetries: 101}, {BaseDelay: -1}, {MaxDelay: 2 * time.Minute}, {Methods: []string{"post"}}, {StatusCodes: []int{200}}} {
		if p.Validate() == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
	p := &RetryPolicy{BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}
	for i, want := range []time.Duration{time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond, 5 * time.Millisecond} {
		if got := retryDelay(p, i, nil); got != want {
			t.Fatalf("delay=%s want=%s", got, want)
		}
	}
}
