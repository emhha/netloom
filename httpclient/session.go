// Package httpclient provides a reusable, credential-agnostic HTTP session for
// API-query workloads (enterprise search, network-space mapping).
//
// It is intentionally distinct from the root netloom package, which drives scanning/probing
// (TLS fingerprinting, pipeline, high concurrency), whereas httpclient targets
// third-party REST APIs and adds per-source rate limiting, retry (including
// 429/Retry-After semantics), timeouts and proxy support.
//
// Credential boundary: httpclient never stores, encrypts or decrypts any
// credential. Callers pass plaintext headers already assembled by the provider
// layer; this package only rate-limits and sends them.
package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/net/proxy"
)

// Sentinel errors exported for callers that need to branch on failure mode.
var (
	// ErrRetryExhausted is returned when all retry attempts failed.
	ErrRetryExhausted = errors.New("httpclient: retry attempts exhausted")
	// ErrUnsupportedProxy is returned when the proxy URL scheme is not handled.
	ErrUnsupportedProxy = errors.New("httpclient: unsupported proxy scheme")
)

const (
	defaultTimeout   = 30 * time.Second
	defaultRetryMax  = 3
	defaultRetryWait = 1 * time.Second
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
	// maxRetryAfter caps how long a Retry-After header may make us wait, so a
	// hostile or buggy server cannot pin a goroutine for an unbounded time.
	maxRetryAfter = 60 * time.Second
)

// Options configures a Session. Zero values fall back to package defaults.
type Options struct {
	Timeout            time.Duration
	RetryMax           int
	DisableRetries     bool
	RetryWait          time.Duration
	Proxy              string // "http://host:port" or "socks5://host:port"; empty disables
	UserAgent          string
	InsecureSkipVerify bool // default false; enable only per provider whitelist
}

// Session is a configured, reusable HTTP client. It is safe for concurrent use.
//
// Rate limiting is NOT held by the Session: it is delegated to a process-level
// per-source registry so that multiple Sessions cannot exceed a source's rate.
type Session struct {
	client    *http.Client
	retryMax  int
	retryWait time.Duration
	userAgent string
}

// NewSession builds a Session from opts. An invalid proxy URL is logged and
// ignored: the session falls back to a direct connection. The constructor has
// no error return; callers requiring fail-closed proxy policy must validate
// configuration before construction.
func NewSession(opts Options) *Session {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	retryMax := opts.RetryMax
	if retryMax < 0 {
		retryMax = 0
	} else if opts.RetryMax == 0 {
		retryMax = defaultRetryMax
	}
	if opts.DisableRetries {
		retryMax = 0
	}
	retryWait := opts.RetryWait
	if retryWait <= 0 {
		retryWait = defaultRetryWait
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}

	if opts.InsecureSkipVerify {
		// Acceptance criterion: enabling InsecureSkipVerify is auditable.
		slog.Warn("httpclient: TLS certificate verification disabled",
			slog.String("event", "tls_insecure_skip_verify"))
	}

	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify}, //nolint:gosec // gated by provider whitelist + audit log
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if err := applyProxy(transport, opts.Proxy); err != nil {
		slog.Warn("httpclient: proxy ignored",
			slog.String("proxy", opts.Proxy), slog.String("error", err.Error()))
	}

	return &Session{
		client: &http.Client{
			Transport:     transport,
			Timeout:       timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		retryMax:  retryMax,
		retryWait: retryWait,
		userAgent: ua,
	}
}

// applyProxy wires an HTTP or SOCKS5 proxy into transport based on the URL
// scheme. An empty proxy string is a no-op (direct connection).
func applyProxy(transport *http.Transport, raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("httpclient.applyProxy: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
		transport.Proxy = http.ProxyURL(u)
		return nil
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		dialer, derr := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
		if derr != nil {
			return fmt.Errorf("httpclient.applyProxy: %w", derr)
		}
		ctxDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return fmt.Errorf("httpclient.applyProxy: socks5 dialer lacks context support")
		}
		transport.DialContext = ctxDialer.DialContext
		return nil
	default:
		return fmt.Errorf("httpclient.applyProxy: %w: %q", ErrUnsupportedProxy, u.Scheme)
	}
}

// Get performs a rate-limited, retrying GET against rawURL under the given
// source's bucket. headers are sent verbatim (plaintext; credential-agnostic).
func (s *Session) Get(ctx context.Context, rawURL, source string, headers map[string]string) (*http.Response, error) {
	return s.do(ctx, http.MethodGet, rawURL, source, nil, headers)
}

// Post performs a rate-limited, retrying POST with the given body.
func (s *Session) Post(ctx context.Context, rawURL, source string, body []byte, headers map[string]string) (*http.Response, error) {
	return s.do(ctx, http.MethodPost, rawURL, source, body, headers)
}

// Do sends an arbitrary caller-built request under source's rate limit and
// retry policy. The request body, if any, must be rewindable across retries;
// callers should set req.GetBody (http.NewRequestWithContext does this for
// byte/string bodies). Provided for enterprise/mapping providers that need
// full control over method, URL and headers.
func (s *Session) Do(ctx context.Context, source string, req *http.Request) (*http.Response, error) {
	return s.execute(ctx, source, req, nil)
}

// do builds a request from primitives then delegates to execute.
func (s *Session) do(ctx context.Context, method, rawURL, source string, body []byte, headers map[string]string) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return nil, fmt.Errorf("httpclient.do: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return s.execute(ctx, source, req, body)
}

// execute runs the rate-limit → send → retry loop. rawBody (may be nil) is used
// to rebuild the request body on each retry when req.GetBody is unavailable.
func (s *Session) execute(ctx context.Context, source string, req *http.Request, rawBody []byte) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", s.userAgent)
	}

	var lastErr error
	// nextWait is the backoff before the next attempt; 429 overrides it with the
	// server's Retry-After so the single wait at the top of the loop is correct
	// for every retry reason (no double-waiting).
	nextWait := s.retryWait
	// attempts = 1 initial try + retryMax retries.
	for attempt := 0; attempt <= s.retryMax; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, nextWait); err != nil {
				return nil, err
			}
			nextWait = s.retryWait
		}

		// Acquire a token from the shared per-source bucket before each send,
		// so retries also count against the rate.
		if err := waitForSource(ctx, source); err != nil {
			return nil, fmt.Errorf("httpclient.execute: %w", err)
		}

		attemptReq, err := cloneRequest(ctx, req, rawBody)
		if err != nil {
			return nil, err
		}

		resp, err := s.client.Do(attemptReq)
		if err != nil {
			// Network error / timeout: retry per policy.
			lastErr = fmt.Errorf("httpclient.execute: %w", err)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}

		switch {
		case resp.StatusCode == http.StatusTooManyRequests:
			if attempt == s.retryMax {
				return resp, nil
			}
			// Honor Retry-After (delta-seconds or HTTP-date) for the next wait.
			nextWait = retryAfter(resp, s.retryWait)
			drainClose(resp)
			lastErr = fmt.Errorf("httpclient.execute: 429 from %s", source)
			continue
		case resp.StatusCode >= 500:
			if attempt == s.retryMax {
				return resp, nil
			}
			drainClose(resp)
			lastErr = fmt.Errorf("httpclient.execute: %d from %s", resp.StatusCode, source)
			continue
		default:
			// 2xx/3xx success, or 4xx (non-429) business error: return as-is.
			return resp, nil
		}
	}

	if lastErr == nil {
		lastErr = ErrRetryExhausted
	}
	return nil, fmt.Errorf("httpclient.execute: %w: %w", ErrRetryExhausted, lastErr)
}

// cloneRequest produces a fresh request for an attempt with a rewound body.
func cloneRequest(ctx context.Context, req *http.Request, rawBody []byte) (*http.Request, error) {
	clone := req.Clone(ctx)
	if rawBody != nil {
		clone.Body = io.NopCloser(bytes.NewReader(rawBody))
		clone.ContentLength = int64(len(rawBody))
		clone.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(rawBody)), nil
		}
	} else if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("httpclient.cloneRequest: %w", err)
		}
		clone.Body = body
	}
	return clone, nil
}

// retryAfter parses the Retry-After header (delta-seconds or HTTP-date),
// clamped to [0, maxRetryAfter]. Falls back to fallback when absent/invalid.
func retryAfter(resp *http.Response, fallback time.Duration) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return fallback
	}
	if secs, err := strconv.Atoi(v); err == nil {
		d := time.Duration(secs) * time.Second
		return clampWait(d)
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		return clampWait(d)
	}
	return fallback
}

func clampWait(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	if d > maxRetryAfter {
		return maxRetryAfter
	}
	return d
}

// sleepCtx waits for d or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// drainClose drains and closes a response body so the connection can be reused.
func drainClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()
}

// ReadBody reads and closes resp.Body, returning the full payload.
func ReadBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if len(data) > 8<<20 {
		return nil, fmt.Errorf("httpclient: API response exceeds 8 MiB")
	}
	if err != nil {
		return nil, fmt.Errorf("httpclient.ReadBody: %w", err)
	}
	return data, nil
}

// Close releases idle connections held by the session's transport.
func (s *Session) Close() {
	if s == nil || s.client == nil {
		return
	}
	if tr, ok := s.client.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}
