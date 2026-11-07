package netloom

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

type partialResponseTransport func(context.Context, *Request) (*Response, error)

func (f partialResponseTransport) RoundTrip(ctx context.Context, req *Request) (*Response, error) {
	return f(ctx, req)
}

func TestPartialResponseRetryPreservesEvidence(t *testing.T) {
	beforeHeaders := errors.New("connection failed before headers")
	for _, tc := range []struct {
		name    string
		later   bool
		replace bool
		cancel  bool
		blocked bool
	}{
		{name: "read error"},
		{name: "later attempt without headers", later: true},
		{name: "latest nonnil response", later: true, replace: true},
		{name: "cancellation with response", cancel: true},
		{name: "cancellation after earlier response", later: true, cancel: true},
		{name: "blocked with response", blocked: true},
		{name: "blocked after earlier response", later: true, blocked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			first := &Response{StatusCode: 200, Body: []byte("partial"), Header: http.Header{"X-Evidence": {"first"}}}
			latest := &Response{StatusCode: 206, Body: []byte("new partial")}
			want := first
			wantErr := error(io.ErrUnexpectedEOF)
			calls := 0
			tr := partialResponseTransport(func(context.Context, *Request) (*Response, error) {
				calls++
				resp := first
				if calls > 1 {
					resp = nil
					if tc.replace && calls == 2 {
						resp = latest
						want = latest
					}
				}
				if !tc.later || calls > 1 {
					if tc.cancel {
						cancel()
						wantErr = context.Canceled
						return resp, context.Canceled
					}
					if tc.blocked {
						wantErr = ErrBlockedAddress
						return resp, fmt.Errorf("blocked: %w", ErrBlockedAddress)
					}
					if tc.later {
						wantErr = beforeHeaders
						return resp, beforeHeaders
					}
				}
				return resp, io.ErrUnexpectedEOF
			})
			retries := 0
			if tc.later || tc.cancel || tc.blocked {
				retries = 3
			}
			s := newScheduler(Config{Retries: retries}, tr, tr, nil)
			got, err := s.sendWithRetry(ctx, &Request{URL: "https://example.test"})
			if got != want || !errors.Is(err, wantErr) {
				t.Fatalf("response=%+v error=%v; want response=%+v error=%v", got, err, want, wantErr)
			}
			wantCalls := retries + 1
			if tc.cancel || tc.blocked {
				wantCalls = 1
				if tc.later {
					wantCalls = 2
				}
			}
			if calls != wantCalls {
				t.Fatalf("attempts=%d, want %d", calls, wantCalls)
			}
		})
	}
}

func TestPartialResponseRetrySuccessReturnsSuccessfulAttempt(t *testing.T) {
	partial := &Response{StatusCode: 200, Body: []byte("partial")}
	complete := &Response{StatusCode: 200, Body: []byte("complete")}
	calls := 0
	tr := partialResponseTransport(func(context.Context, *Request) (*Response, error) {
		calls++
		if calls == 1 {
			return partial, io.ErrUnexpectedEOF
		}
		return complete, nil
	})
	s := newScheduler(Config{Retries: 2}, tr, tr, nil)
	resp, err := s.sendWithRetry(context.Background(), &Request{URL: "https://example.test"})
	if resp != complete || err != nil || calls != 2 {
		t.Fatalf("response=%+v error=%v attempts=%d", resp, err, calls)
	}
}

func TestPartialResponseSendReturnsResponseAndError(t *testing.T) {
	e, err := New(Config{Retries: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	partial := &Response{StatusCode: 200, Body: []byte("partial"), Error: io.ErrUnexpectedEOF}
	e.tlsT = partialResponseTransport(func(context.Context, *Request) (*Response, error) {
		return partial, io.ErrUnexpectedEOF
	})
	resp, err := e.Send(context.Background(), &Request{URL: "https://example.test"})
	if resp != partial || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("response=%+v error=%v", resp, err)
	}
}

func TestPartialResponseRunPreservesEvidenceAndFinalError(t *testing.T) {
	for _, evidence := range []bool{false, true} {
		t.Run(fmt.Sprintf("evidence=%v", evidence), func(t *testing.T) {
			e, err := New(Config{Threads: 1, Retries: 1})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			finalErr := errors.New("later connection failure")
			partial := &Response{StatusCode: 200, Body: []byte("partial"), Header: http.Header{"X-Evidence": {"retained"}}, Error: io.ErrUnexpectedEOF}
			calls := 0
			e.tlsT = partialResponseTransport(func(context.Context, *Request) (*Response, error) {
				calls++
				if calls == 1 && evidence {
					return partial, io.ErrUnexpectedEOF
				}
				return nil, finalErr
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			pipelineRan := false
			results, err := e.Run(ctx, []Task{{Req: &Request{URL: "https://example.test"}, Pipeline: []Handler{func(*Context) error {
				pipelineRan = true
				return nil
			}}}})
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for result := range results {
				count++
				resp := result.Ctx.Resp
				if resp == nil || !errors.Is(resp.Error, finalErr) {
					t.Fatalf("response=%+v, want final error %v", resp, finalErr)
				}
				if evidence && (resp != partial || string(resp.Body) != "partial" || resp.Header.Get("X-Evidence") != "retained") {
					t.Fatalf("lost evidence: %+v", resp)
				}
				if !evidence && resp.Scheme != "https" {
					t.Fatalf("missing fallback scheme: %+v", resp)
				}
			}
			if count != 1 || calls != 2 || pipelineRan || ctx.Err() != nil {
				t.Fatalf("results=%d attempts=%d pipelineRan=%v context=%v", count, calls, pipelineRan, ctx.Err())
			}
		})
	}
}

func TestPartialResponseRetryEffectiveTimeoutDoesNotMutateRequest(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		request, config, want time.Duration
	}{
		{name: "request override", request: 45 * time.Second, config: 30 * time.Second, want: 45 * time.Second},
		{name: "config default", config: 30 * time.Second, want: 30 * time.Second},
		{name: "negative request uses config", request: -time.Second, config: 30 * time.Second, want: 30 * time.Second},
		{name: "transport fallback", want: dialTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := &Request{URL: "https://example.test", Timeout: tc.request}
			calls := 0
			tr := partialResponseTransport(func(ctx context.Context, got *Request) (*Response, error) {
				calls++
				if got == request || got.Timeout != tc.want || request.Timeout != tc.request {
					t.Errorf("request copy timeout=%v, original=%v; want %v and %v", got.Timeout, request.Timeout, tc.want, tc.request)
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Error("attempt missing effective deadline")
				}
				return nil, io.ErrUnexpectedEOF
			})
			s := newScheduler(Config{Retries: 1, Timeout: tc.config}, tr, tr, nil)
			_, err := s.sendWithRetry(context.Background(), request)
			if !errors.Is(err, io.ErrUnexpectedEOF) || calls != 2 || request.Timeout != tc.request {
				t.Fatalf("error=%v attempts=%d original timeout=%v", err, calls, request.Timeout)
			}
		})
	}
}
