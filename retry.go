package netloom

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

// RetryPolicy is opt-in. A non-nil zero value disables retries. Network errors
// and selected statuses can retry only allowed methods with replayable bodies.
// Nil Methods selects GET/HEAD/OPTIONS; adding a non-idempotent method is an
// explicit caller decision. MaxRetries excludes the initial attempt.
// Observer runs synchronously once per attempt; it must be concurrency safe,
// nonblocking and must not synchronously close the originating Engine.
type RetryPolicy struct {
	MaxRetries        int
	Methods           []string
	StatusCodes       []int
	BaseDelay         time.Duration
	MaxDelay          time.Duration
	RespectRetryAfter bool
	Observer          func(AttemptInfo)
}

// AttemptInfo is an immutable attempt summary, not a request/credential capture.
// Duration excludes retry delay. Attempts are 1-based; authentication challenge
// exchanges are part of the same attempt. Streaming observes headers only and
// never retries after handing out the stream.
type AttemptInfo struct {
	Attempt    int
	Method     string
	StatusCode int
	Error      error
	Duration   time.Duration
	WillRetry  bool
	Delay      time.Duration
}

func (p *RetryPolicy) Clone() *RetryPolicy {
	if p == nil {
		return nil
	}
	c := *p
	if p.Methods != nil {
		c.Methods = append(make([]string, 0, len(p.Methods)), p.Methods...)
	}
	c.StatusCodes = append([]int(nil), p.StatusCodes...)
	return &c
}
func (p *RetryPolicy) Validate() error {
	if p == nil {
		return nil
	}
	if p.MaxRetries < 0 || p.MaxRetries > 100 || p.BaseDelay < 0 || p.MaxDelay < 0 || p.BaseDelay > time.Minute || p.MaxDelay > time.Minute {
		return fmt.Errorf("netloom: invalid retry limits")
	}
	if p.MaxDelay > 0 && p.BaseDelay > p.MaxDelay {
		return fmt.Errorf("netloom: retry base delay exceeds maximum")
	}
	if len(p.Methods) > 32 || len(p.StatusCodes) > 64 {
		return fmt.Errorf("netloom: retry policy exceeds entry limits")
	}
	for _, m := range p.Methods {
		if !headerToken(m) || strings.ToUpper(m) != m {
			return fmt.Errorf("netloom: retry methods must be uppercase tokens")
		}
	}
	for _, s := range p.StatusCodes {
		if s < 400 || s > 599 {
			return fmt.Errorf("netloom: retry statuses must be 400..599")
		}
	}
	return nil
}
func retryMethodAllowed(policy *RetryPolicy, method string) bool {
	if method == "" {
		method = "GET"
	}
	methods := []string{"GET", "HEAD", "OPTIONS"}
	if policy != nil && policy.Methods != nil {
		methods = policy.Methods
	}
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}
func retryStatusAllowed(policy *RetryPolicy, status int) bool {
	if policy != nil {
		for _, s := range policy.StatusCodes {
			if status == s {
				return true
			}
		}
	}
	return false
}
func replayableBody(req *Request) bool { return req.Upload == nil || req.Upload.replayable }
func retryDelay(p *RetryPolicy, retry int, resp *Response) time.Duration {
	if p == nil {
		return 0
	}
	max := p.MaxDelay
	if max == 0 {
		max = 30 * time.Second
	}
	d := p.BaseDelay
	for i := 0; i < retry && d < max; i++ {
		if d > max/2 {
			d = max
			break
		}
		d *= 2
	}
	if d > max {
		d = max
	}
	if p.RespectRetryAfter && resp != nil {
		s := resp.Header.Get("Retry-After")
		var after time.Duration
		if n, e := strconv.ParseInt(s, 10, 64); e == nil && n >= 0 {
			if n > int64(max/time.Second) {
				after = max
			} else {
				after = time.Duration(n) * time.Second
			}
		} else if t, e := http.ParseTime(s); e == nil {
			after = time.Until(t)
		}
		if after > d {
			d = after
		}
		if d > max {
			d = max
		}
	}
	return d
}
func permanentRetryError(err error) bool {
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var authority x509.UnknownAuthorityError
	return errors.Is(err, ErrNetworkBinding) || errors.Is(err, ErrNetworkBindingInvalid) || errors.Is(err, ErrNetworkBindingUnsupported) || errors.As(err, &invalid) || errors.As(err, &hostname) || errors.As(err, &authority)
}

func waitRetry(ctx context.Context, d time.Duration) error {
	if err := requestContextError(ctx); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return requestContextError(ctx)
	case <-ctx.Done():
		return requestContextError(ctx)
	}
}
