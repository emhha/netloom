package netloom

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"
)

// PhaseTimeouts configures HTTP attempt phases. Zero disables that phase timer.
// Connect includes DNS, TCP and an HTTP proxy CONNECT exchange. TLSHandshake
// ends when the connection is ready for HTTP; ResponseHeader starts after the
// request has been written and ends only when the final response headers arrive.
// BodyIdle measures a blocked Body.Read, not time spent by a streaming consumer.
// Total spans retries after Send/Run admission, and includes streaming reads.
// Do starts its shared redirect budget at entry, including its Send queue waits.
// Negative durations are invalid. These timers never extend a caller deadline.
type PhaseTimeouts struct {
	Connect        time.Duration
	TLSHandshake   time.Duration
	ResponseHeader time.Duration
	BodyIdle       time.Duration
	Total          time.Duration
}

// Phase identifies the operation that failed, not a guessed TCP/TLS diagnosis.
type Phase string

const (
	PhaseTotal          Phase = "total"
	PhasePool           Phase = "pool"
	PhaseConnect        Phase = "connect"
	PhaseTLS            Phase = "tls"
	PhaseRequest        Phase = "request"
	PhaseResponseHeader Phase = "response_header"
	PhaseBody           Phase = "body"
)

// PhaseError preserves the underlying cause for errors.Is/As. Timeout reports
// both configured stage deadlines and underlying network/context timeouts.
// It adds no URL, proxy credentials or request headers of its own. Underlying
// errors may contain request metadata; this wrapper is not a redaction layer.
type PhaseError struct {
	Phase Phase
	Err   error
}

func (e *PhaseError) Error() string { return fmt.Sprintf("netloom: %s: %v", e.Phase, e.Err) }
func (e *PhaseError) Unwrap() error { return e.Err }
func (e *PhaseError) Timeout() bool {
	var t interface{ Timeout() bool }
	return errors.Is(e.Err, context.DeadlineExceeded) || errors.As(e.Err, &t) && t.Timeout()
}
func (e *PhaseError) Temporary() bool { return false }

func (p PhaseTimeouts) validate() error {
	if p.Connect < 0 || p.TLSHandshake < 0 || p.ResponseHeader < 0 || p.BodyIdle < 0 || p.Total < 0 {
		return errors.New("netloom: phase timeouts must not be negative")
	}
	return nil
}
func (p PhaseTimeouts) enabled() bool { return p != (PhaseTimeouts{}) }
func timeoutPolicy(req *Request) PhaseTimeouts {
	if req.PhaseTimeouts != nil {
		return *req.PhaseTimeouts
	}
	return PhaseTimeouts{}
}

// An explicit Connect budget replaces the legacy per-TCP 10s fallback. Use a
// per-call copy: clients are cached across leases with different phase policies.
func phaseDialer(ctx context.Context, base *net.Dialer) *net.Dialer {
	if clock := phaseClockFrom(ctx); clock != nil && clock.policy.Connect > 0 {
		clone := *base
		clone.Timeout = 0
		return &clone
	}
	return base
}

type totalBudgetKey struct{}

// Socket deadlines can fire before the context timer publishes its cause.
// Remember Total's owning deadline so classification does not race that timer.
func withTotalBudget(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(timeout)
	child, cancel := context.WithDeadlineCause(ctx, deadline, &PhaseError{Phase: PhaseTotal, Err: context.DeadlineExceeded})
	if effective, ok := child.Deadline(); ok && effective.Equal(deadline) {
		child = context.WithValue(child, totalBudgetKey{}, deadline)
	}
	return child, cancel
}

type phaseKey struct{}
type phaseClock struct {
	mu         sync.Mutex
	policy     PhaseTimeouts
	phase      Phase
	secure     bool
	cancel     context.CancelCauseFunc
	timer      *time.Timer
	generation uint64
	stopped    bool
}

func newPhaseClock(ctx context.Context, req *Request) (context.Context, *phaseClock, error) {
	policy := timeoutPolicy(req)
	if err := policy.validate(); err != nil {
		return ctx, nil, err
	}
	if policy.enabled() && req.Proxy != "" {
		proxy, err := url.Parse(req.Proxy)
		if err != nil || proxy.Scheme != "http" {
			return ctx, nil, errors.New("netloom: phase timeouts support only direct connections and http:// proxies")
		}
	}
	ctx, err := withNetworkOptions(ctx, req)
	if err != nil {
		return ctx, nil, err
	}
	ctx, cancel := context.WithCancelCause(ctx)
	u, _ := url.Parse(req.URL)
	secure := u != nil && u.Scheme == "https"
	p := &phaseClock{policy: policy, phase: PhasePool, secure: secure, cancel: cancel}
	return context.WithValue(ctx, phaseKey{}, p), p, nil
}
func phaseClockFrom(ctx context.Context) *phaseClock {
	p, _ := ctx.Value(phaseKey{}).(*phaseClock)
	return p
}
func enterPhase(ctx context.Context, phase Phase) {
	if p := phaseClockFrom(ctx); p != nil {
		p.enter(phase)
	}
}
func (p *phaseClock) enter(phase Phase) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped || p.phase == PhaseBody && phase != PhaseBody {
		return
	}
	if phase == PhaseResponseHeader && p.phase != PhaseRequest {
		return
	}
	p.generation++
	generation := p.generation
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	p.phase = phase
	var d time.Duration
	switch phase {
	case PhaseConnect:
		d = p.policy.Connect
	case PhaseTLS:
		d = p.policy.TLSHandshake
	case PhaseResponseHeader:
		d = p.policy.ResponseHeader
	}
	if d > 0 {
		p.timer = time.AfterFunc(d, func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			if !p.stopped && p.generation == generation {
				p.cancel(&PhaseError{Phase: phase, Err: context.DeadlineExceeded})
			}
		})
	}
}
func (p *phaseClock) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopped = true
	p.generation++
	if p.timer != nil {
		p.timer.Stop()
	}
}
func (p *phaseClock) finish() { p.stop(); p.cancel(context.Canceled) }
func (p *phaseClock) failure(ctx context.Context, err error) error {
	if err == nil || err == io.EOF {
		return err
	}
	if cause := requestContextError(ctx); cause != nil {
		err = cause
	}
	var phaseErr *PhaseError
	if errors.As(err, &phaseErr) {
		return err
	}
	p.mu.Lock()
	phase := p.phase
	p.mu.Unlock()
	return &PhaseError{Phase: phase, Err: err}
}

// phaseBody applies idle timeouts to individual reads only. There is no timer
// while the application is processing bytes.
// A timeout cancels the attempt, closing its raw sockets via clientDialScope.
type phaseBody struct {
	io.ReadCloser
	ctx   context.Context
	clock *phaseClock
}

func (b *phaseBody) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return b.ReadCloser.Read(buf)
	}
	var timer *time.Timer
	done := make(chan struct{})
	var mu sync.Mutex
	finished := false
	if d := b.clock.policy.BodyIdle; d > 0 {
		timer = time.AfterFunc(d, func() {
			defer close(done)
			mu.Lock()
			defer mu.Unlock()
			if !finished {
				b.clock.cancel(&PhaseError{Phase: PhaseBody, Err: context.DeadlineExceeded})
			}
		})
	}
	n, err := b.ReadCloser.Read(buf)
	mu.Lock()
	finished = true
	mu.Unlock()
	if timer != nil && !timer.Stop() {
		<-done
	}
	// A timeout can win even if a simultaneous socket read returns EOF/data.
	if cause := requestContextError(b.ctx); cause != nil {
		return n, b.clock.failure(b.ctx, cause)
	}
	return n, b.clock.failure(b.ctx, err)
}
func wrapPhaseBody(ctx context.Context, body io.ReadCloser) io.ReadCloser {
	if p := phaseClockFrom(ctx); p != nil {
		p.enter(PhaseBody)
		return &phaseBody{ReadCloser: body, ctx: ctx, clock: p}
	}
	return body
}
