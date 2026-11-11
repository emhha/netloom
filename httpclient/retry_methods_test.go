package httpclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type retryRoundTripper func(*http.Request) (*http.Response, error)

func (f retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

var retrySourceSequence atomic.Uint64

// A unique source per operation keeps repeat/race runs independent of shared
// production buckets. Each operation uses at most four of its five initial tokens.
func retryTestSession(t *testing.T, opts Options, transport retryRoundTripper) (*Session, string) {
	t.Helper()
	opts.RetryWait = time.Nanosecond
	s := NewSession(opts)
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	s.client.Transport = transport
	t.Cleanup(s.Close)
	return s, fmt.Sprintf("%s-%d", t.Name(), retrySourceSequence.Add(1))
}

type retryTrackedBody struct {
	*strings.Reader
	closes int
}

func (b *retryTrackedBody) Close() error { b.closes++; return nil }

func retryTestResponse(status int, bodies *[]*retryTrackedBody) *http.Response {
	body := &retryTrackedBody{Reader: strings.NewReader("response")}
	*bodies = append(*bodies, body)
	return &http.Response{StatusCode: status, Header: http.Header{"Retry-After": {"0"}}, Body: body}
}

func checkRetryResponseOwnership(t *testing.T, resp *http.Response, bodies []*retryTrackedBody) {
	t.Helper()
	if len(bodies) == 0 || resp == nil || resp.Body == nil {
		t.Fatal("final response was not returned to the caller")
	}
	// http.Client.Timeout may wrap resp.Body. Assert resource ownership by
	// observing read/close behavior, not the wrapper's pointer identity.
	for i, body := range bodies {
		want := 1
		if i == len(bodies)-1 {
			want = 0
		}
		if body.closes != want {
			t.Fatalf("response %d closes=%d; want %d", i, body.closes, want)
		}
		if i < len(bodies)-1 && body.Len() != 0 {
			t.Fatalf("retry response %d was not drained", i)
		}
	}
	data, err := ReadBody(resp)
	if err != nil || string(data) != "response" || bodies[len(bodies)-1].closes != 1 {
		t.Fatalf("final response body=%q error=%v", data, err)
	}
}

func TestRetryMethodsDefault(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "OPTIONS", "", "POST", "PATCH", "PUT", "DELETE", "get", "post"} {
		t.Run("method="+method, func(t *testing.T) {
			for _, status := range []int{0, 429, 503} {
				t.Run(fmt.Sprintf("status=%d", status), func(t *testing.T) {
					cause := errors.New("transport failed")
					calls := 0
					var bodies []*retryTrackedBody
					s, source := retryTestSession(t, Options{RetryMax: 1}, func(*http.Request) (*http.Response, error) {
						calls++
						if status == 0 {
							return nil, cause
						}
						return retryTestResponse(status, &bodies), nil
					})
					req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.invalid", nil)
					if err != nil {
						t.Fatal(err)
					}
					req.Method = method
					resp, err := s.Do(context.Background(), source, req)
					want := 1
					if method == "GET" || method == "HEAD" || method == "OPTIONS" || method == "" {
						want = 2
					}
					if calls != want {
						t.Fatalf("calls=%d; want %d", calls, want)
					}
					if status == 0 {
						if resp != nil || !errors.Is(err, cause) || !errors.Is(err, ErrRetryExhausted) {
							t.Fatalf("response=%v error=%v; want exhausted error chain", resp, err)
						}
					} else {
						if err != nil || resp.StatusCode != status {
							t.Fatalf("response=%v error=%v", resp, err)
						}
						checkRetryResponseOwnership(t, resp, bodies)
					}
				})
			}
		})
	}
}

func TestPostRetriesRequireExplicitMethod(t *testing.T) {
	for _, tc := range []struct {
		name    string
		methods []string
		want    int
	}{
		{name: "nil defaults", want: 1},
		{name: "explicit empty", methods: []string{}, want: 1},
		{name: "GET only", methods: []string{"GET"}, want: 1},
		{name: "explicit POST", methods: []string{"POST"}, want: 3},
		{name: "invalid only", methods: []string{"post", "", "POST ", "PO ST", "PÖST", "POST\r\n"}, want: 1},
		{name: "mixed", methods: []string{"post", "POST", "GET "}, want: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, status := range []int{0, 429, 503} {
				t.Run(fmt.Sprintf("status=%d", status), func(t *testing.T) {
					cause := errors.New("transport failed")
					calls := 0
					var bodies []*retryTrackedBody
					s, source := retryTestSession(t, Options{RetryMax: 2, RetryMethods: tc.methods}, func(req *http.Request) (*http.Response, error) {
						calls++
						data, err := io.ReadAll(req.Body)
						_ = req.Body.Close()
						if err != nil || string(data) != "payload" {
							t.Fatalf("attempt %d body=%q error=%v", calls, data, err)
						}
						if status == 0 {
							return nil, cause
						}
						return retryTestResponse(status, &bodies), nil
					})
					resp, err := s.Post(context.Background(), "https://example.invalid", source, []byte("payload"), map[string]string{"Idempotency-Key": "caller-controlled"})
					if calls != tc.want {
						t.Fatalf("calls=%d; want %d", calls, tc.want)
					}
					if status == 0 {
						if resp != nil || !errors.Is(err, cause) || !errors.Is(err, ErrRetryExhausted) {
							t.Fatalf("response=%v error=%v", resp, err)
						}
					} else {
						if err != nil {
							t.Fatal(err)
						}
						checkRetryResponseOwnership(t, resp, bodies)
					}
				})
			}
		})
	}
}

func TestRetryMethodsEmptyAndCopied(t *testing.T) {
	for _, tc := range []struct {
		name    string
		methods []string
		want    int
	}{
		{name: "nil", want: 2},
		{name: "empty", methods: []string{}, want: 1},
		{name: "invalid", methods: []string{"get", "GET ", ""}, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s, source := retryTestSession(t, Options{RetryMax: 1, RetryMethods: tc.methods}, func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 503, Body: http.NoBody}, nil
			})
			resp, err := s.Get(context.Background(), "https://example.invalid", source, nil)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if calls != tc.want {
				t.Fatalf("calls=%d; want %d", calls, tc.want)
			}
		})
	}
	methods := []string{"GET"}
	calls := 0
	s, source := retryTestSession(t, Options{RetryMax: 1, RetryMethods: methods}, func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 503, Body: http.NoBody}, nil
	})
	methods[0] = "POST"
	resp, err := s.Get(context.Background(), "https://example.invalid", source, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if calls != 2 {
		t.Fatalf("caller mutation changed copied GET policy: calls=%d", calls)
	}
	resp, err = s.Post(context.Background(), "https://example.invalid", source, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if calls != 3 {
		t.Fatalf("caller mutation enabled POST retry: total calls=%d", calls)
	}
}

func TestRetryCountsAndDisablePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts Options
		want int
	}{
		{name: "zero means three", want: 4},
		{name: "positive", opts: Options{RetryMax: 2}, want: 3},
		{name: "negative", opts: Options{RetryMax: -1}, want: 1},
		{name: "disable default", opts: Options{DisableRetries: true}, want: 1},
		{name: "disable overrides positive", opts: Options{RetryMax: 3, DisableRetries: true}, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, status := range []int{0, 429, 503} {
				t.Run(fmt.Sprintf("status=%d", status), func(t *testing.T) {
					calls := 0
					cause := errors.New("transport failed")
					opts := tc.opts
					opts.RetryMethods = []string{"POST"}
					s, source := retryTestSession(t, opts, func(*http.Request) (*http.Response, error) {
						calls++
						if status == 0 {
							return nil, cause
						}
						return &http.Response{StatusCode: status, Header: http.Header{"Retry-After": {"0"}}, Body: http.NoBody}, nil
					})
					resp, err := s.Post(context.Background(), "https://example.invalid", source, nil, nil)
					if calls != tc.want {
						t.Fatalf("calls=%d; want %d", calls, tc.want)
					}
					if status == 0 {
						if !errors.Is(err, cause) || !errors.Is(err, ErrRetryExhausted) {
							t.Fatalf("error=%v", err)
						}
					} else {
						if err != nil || resp == nil || resp.StatusCode != status {
							t.Fatalf("response=%v error=%v", resp, err)
						}
						_ = resp.Body.Close()
					}
				})
			}
		})
	}
}

func TestDoRetryBodyReplayGate(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		for _, replayable := range []bool{false, true} {
			for _, status := range []int{0, 429, 503} {
				t.Run(fmt.Sprintf("%s/replay=%v/status=%d", method, replayable, status), func(t *testing.T) {
					calls, opens := 0, 0
					var requestBodies []*retryTrackedBody
					var responseBodies []*retryTrackedBody
					cause := errors.New("transport failed")
					original := &retryTrackedBody{Reader: strings.NewReader("payload")}
					req, err := http.NewRequestWithContext(context.Background(), method, "https://example.invalid", original)
					if err != nil {
						t.Fatal(err)
					}
					if replayable {
						t.Cleanup(func() { _ = original.Close() })
						req.GetBody = func() (io.ReadCloser, error) {
							opens++
							body := &retryTrackedBody{Reader: strings.NewReader("payload")}
							requestBodies = append(requestBodies, body)
							return body, nil
						}
					} else {
						requestBodies = append(requestBodies, original)
					}
					s, source := retryTestSession(t, Options{RetryMax: 2, RetryMethods: []string{method}}, func(req *http.Request) (*http.Response, error) {
						calls++
						data, err := io.ReadAll(req.Body)
						_ = req.Body.Close()
						if err != nil || string(data) != "payload" {
							t.Fatalf("attempt %d body=%q error=%v", calls, data, err)
						}
						if status == 0 {
							return nil, cause
						}
						return retryTestResponse(status, &responseBodies), nil
					})
					resp, err := s.Do(context.Background(), source, req)
					want := 1
					if replayable {
						want = 3
						if opens != want {
							t.Fatalf("body opens=%d; want %d", opens, want)
						}
					}
					if calls != want {
						t.Fatalf("calls=%d; want %d", calls, want)
					}
					for _, body := range requestBodies {
						if body.closes != 1 {
							t.Fatalf("request body closed %d times; want 1", body.closes)
						}
					}
					if status == 0 {
						if !errors.Is(err, cause) || !errors.Is(err, ErrRetryExhausted) {
							t.Fatalf("error=%v", err)
						}
					} else {
						if err != nil {
							t.Fatal(err)
						}
						checkRetryResponseOwnership(t, resp, responseBodies)
					}
				})
			}
		}
	}
}

func TestDoGetBodyFailureStopsBeforeSend(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(fmt.Sprintf("open=%d", failAt), func(t *testing.T) {
			cause := errors.New("body reopen failed")
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.invalid", strings.NewReader("payload"))
			if err != nil {
				t.Fatal(err)
			}
			opens, calls := 0, 0
			var requestBodies []*retryTrackedBody
			var responseBodies []*retryTrackedBody
			req.GetBody = func() (io.ReadCloser, error) {
				opens++
				if opens == failAt {
					return nil, cause
				}
				body := &retryTrackedBody{Reader: strings.NewReader("payload")}
				requestBodies = append(requestBodies, body)
				return body, nil
			}
			s, source := retryTestSession(t, Options{RetryMax: 2, RetryMethods: []string{"POST"}}, func(req *http.Request) (*http.Response, error) {
				calls++
				_, _ = io.Copy(io.Discard, req.Body)
				_ = req.Body.Close()
				return retryTestResponse(503, &responseBodies), nil
			})
			resp, err := s.Do(context.Background(), source, req)
			if resp != nil || !errors.Is(err, cause) || calls != failAt-1 || opens != failAt {
				t.Fatalf("response=%v error=%v calls=%d opens=%d", resp, err, calls, opens)
			}
			for _, body := range append(requestBodies, responseBodies...) {
				if body.closes != 1 {
					t.Fatalf("body closes=%d; want 1", body.closes)
				}
			}
		})
	}
}

func TestDoEmptyBodiesAndExactMethods(t *testing.T) {
	for _, tc := range []struct {
		name    string
		method  string
		methods []string
		body    io.ReadCloser
		want    int
	}{
		{name: "GET nil body", method: "GET", want: 2},
		{name: "GET NoBody", method: "GET", body: http.NoBody, want: 2},
		{name: "POST nil opt in", method: "POST", methods: []string{"POST"}, want: 2},
		{name: "POST NoBody opt in", method: "POST", methods: []string{"POST"}, body: http.NoBody, want: 2},
		{name: "lowercase request not uppercased", method: "get", methods: []string{"GET"}, want: 1},
		{name: "lowercase option not accepted", method: "get", methods: []string{"get"}, want: 1},
		{name: "mixed retains valid entries", method: "GET", methods: []string{"get", "GET"}, want: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			var bodies []*retryTrackedBody
			s, source := retryTestSession(t, Options{RetryMax: 1, RetryMethods: tc.methods}, func(*http.Request) (*http.Response, error) {
				calls++
				return retryTestResponse(503, &bodies), nil
			})
			req, err := http.NewRequestWithContext(context.Background(), tc.method, "https://example.invalid", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Body, req.GetBody = tc.body, nil
			resp, err := s.Do(context.Background(), source, req)
			if err != nil || calls != tc.want {
				t.Fatalf("error=%v calls=%d; want %d", err, calls, tc.want)
			}
			checkRetryResponseOwnership(t, resp, bodies)
		})
	}
}

func TestExplicitPostRetryCanceledAfterResponse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	var bodies []*retryTrackedBody
	s, source := retryTestSession(t, Options{RetryMax: 2, RetryMethods: []string{"POST"}}, func(*http.Request) (*http.Response, error) {
		calls++
		cancel()
		return retryTestResponse(429, &bodies), nil
	})
	resp, err := s.Post(ctx, "https://example.invalid", source, []byte("payload"), nil)
	if resp != nil || !errors.Is(err, context.Canceled) || calls != 1 || len(bodies) != 1 || bodies[0].closes != 1 {
		t.Fatalf("response=%v error=%v calls=%d", resp, err, calls)
	}
}
