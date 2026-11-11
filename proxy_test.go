package netloom

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestInvalidProxyEntryPointsFailBeforeAdmission(t *testing.T) {
	invalids := []string{" ", "http://", "proxy.test:8080", "http://user:secret%zz@host", "ftp://user:secret@host:21", "http://host:", "http://host:0", "http://host:65536", "http://host/path", "http://host/?", "http://host/#", "socks5://host"}
	for _, raw := range invalids {
		t.Run(raw, func(t *testing.T) {
			calls := 0
			tr := lifecycleRegressionTransport(func(context.Context, *Request) (*Response, error) { calls++; return &Response{StatusCode: 200}, nil })
			e := lifecycleRegressionEngine(t, 1, tr)
			defer e.Close()
			// A full slot and empty limiter prove the error is returned before either
			// admission path, rather than merely releasing slots after using them.
			e.sendSlots <- struct{}{}
			e.sendLimiter = newRateLimiter(1, 0)
			e.sendLimiter.perSecond.tokens = 0
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			req := &Request{URL: "https://example.invalid/", Proxy: raw}
			_, err := e.Send(ctx, req)
			checkInvalidProxyError(t, err)
			_, err = e.SendStream(ctx, req)
			checkInvalidProxyError(t, err)
			if len(e.sendSlots) != 1 || e.sendLimiter.perSecond.tokens != 0 || len(e.sendHosts.used) != 0 {
				t.Fatal("admission side effects")
			}
			<-e.sendSlots
			s := newScheduler(e.cfg, tr, tr, e.logger)
			_, err = s.sendWithRetry(ctx, req)
			checkInvalidProxyError(t, err)
			if calls != 0 {
				t.Fatalf("sent %d requests", calls)
			}
			for _, direct := range []Transport{newTLSTransport(1024), newRawTransport(1024)} {
				_, err = direct.RoundTrip(ctx, req)
				checkInvalidProxyError(t, err)
			}
		})
	}
	if !permanentRetryError(errors.Join(errors.New("wrapped"), ErrInvalidProxy)) {
		t.Fatal("invalid proxy must be permanent")
	}
}

func checkInvalidProxyError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvalidProxy) {
		t.Fatalf("want ErrInvalidProxy, got %v", err)
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "user:") {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestProxyValidatedAfterMutatorsBeforeHostAccounting(t *testing.T) {
	for _, tc := range []struct {
		name, before, after string
		invalid             bool
	}{
		{"fix", "http://bad/path", "http://proxy.test:8080", false},
		{"direct", "http://bad/path", "", false},
		{"break", "http://proxy.test:8080", "http://user:secret@proxy.test/path", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			tr := lifecycleRegressionTransport(func(_ context.Context, req *Request) (*Response, error) {
				calls++
				if req.Proxy != tc.after {
					t.Fatalf("sent original proxy")
				}
				return &Response{StatusCode: 200}, nil
			})
			cfg := Config{MaxHostErrors: 1, Retries: 3}.withDefaults()
			s := newScheduler(cfg, tr, tr, nil)
			s.results = make(chan *Result, 1)
			s.limiter = newRateLimiter(1, 0)
			original := &Request{URL: "http://target.invalid/", Proxy: tc.before}
			host := hostKey(original.URL)
			s.hostErrorCount[host] = 1
			if tc.invalid {
				s.skipped[host] = true
			} // config errors still surface for skipped hosts
			mutated := 0
			s.process(context.Background(), Task{Req: original, Mutators: []Mutator{taskMutatorFunc(func(r *Request) error { mutated++; r.Proxy = tc.after; return nil })}})
			if len(s.results) != 1 {
				t.Fatal("missing result")
			}
			result := <-s.results
			if tc.invalid {
				checkInvalidProxyError(t, result.Ctx.Resp.Error)
				if calls != 0 || s.limiter.perSecond.tokens != 1 || s.hostErrorCount[host] != 1 || len(s.hostSem.used) != 0 {
					t.Fatal("invalid proxy consumed admission or changed host failure count")
				}
			} else if result.Ctx.Resp.Error != nil || calls != 1 {
				t.Fatalf("fixed proxy failed: calls=%d err=%v", calls, result.Ctx.Resp.Error)
			}
			if mutated != 1 || original.Proxy != tc.before {
				t.Fatal("mutator changed caller or ran more than once")
			}
		})
	}
	// A custom Transport returning the sentinel is also a local error, not a
	// host failure, and must not retry even when configured for several attempts.
	calls := 0
	tr := lifecycleRegressionTransport(func(context.Context, *Request) (*Response, error) { calls++; return nil, ErrInvalidProxy })
	s := newScheduler(Config{Retries: 3}.withDefaults(), tr, tr, nil)
	s.results = make(chan *Result, 1)
	s.process(context.Background(), Task{Req: &Request{URL: "http://target.invalid/"}})
	if calls != 1 || len(s.hostErrorCount) != 0 {
		t.Fatalf("calls=%d hostErrors=%v", calls, s.hostErrorCount)
	}
}

func TestRootProxySupportedSchemes(t *testing.T) {
	for _, raw := range []string{"", "http://proxy.test", "https://proxy.test/", "HTTP://proxy.test", "http://[fe80::1%25eth0]/", "HTTPS://user:secret@[::1]/", "socks4://proxy.test:1080", "socks4a://proxy.test:1080", "socks5://proxy.test:1080", "socks5h://user:secret@[::1]:1080/"} {
		req := &Request{Proxy: raw}
		if err := validateProxy(req); err != nil {
			t.Fatalf("valid proxy %q: %v", raw, err)
		}
		// Client construction is pure: verify the dependency also accepts the
		// normalized schemes and implicit HTTP(S) ports without any dialing.
		client, err := newTLSTransport(1024).buildClient(req, &clientDialScope{})
		if err != nil {
			t.Fatalf("build valid proxy %q: %v", raw, err)
		}
		client.CloseIdleConnections()
	}
}
