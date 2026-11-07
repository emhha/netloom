package netloom

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Runtime is the dynamic, on-demand driving interface (reserved for an AI
// runtime): Send fetches a Response synchronously; Schedule dispatches a Task
// asynchronously. Batch seed scanning uses Engine.Run instead.
type Runtime interface {
	Send(ctx context.Context, req *Request) (*Response, error)
	Schedule(t Task)
}

// Engine is the Layer-4 facade over Transport + Scheduler + rate control.
// It is the public entry point for pkg/probe, pkg/dirscan and pkg/fingerprint.
type Engine struct {
	cfg         Config
	tlsT        Transport
	rawT        Transport
	logger      *slog.Logger
	sendLimiter *rateLimiter
	sendHosts   *hostSemaphore
	sendSlots   chan struct{}

	mu       sync.Mutex
	lifetime context.Context
	stop     context.CancelFunc
	closed   bool
	active   sync.WaitGroup
	sch      *scheduler // active scheduler for an in-flight Run, nil otherwise
}

// EngineOption customizes an Engine at construction.
type EngineOption func(*Engine)

// WithLogger sets the structured logger used for warnings (host skips, pipeline
// errors). Defaults to slog.Default().
func WithLogger(l *slog.Logger) EngineOption {
	return func(e *Engine) {
		if l != nil {
			e.logger = l
		}
	}
}

// New builds an Engine from cfg. It never panics; the only error path is
// reserved for future fingerprint-backend initialization.
func New(cfg Config, opts ...EngineOption) (*Engine, error) {
	cfg = cfg.withDefaults()
	lifetime, stop := context.WithCancel(context.Background())
	e := &Engine{
		cfg:      cfg,
		lifetime: lifetime, stop: stop,
		tlsT:        newTLSTransportWithJar(cfg.MaxBodySize, cfg.CookieJar),
		rawT:        newRawTransport(cfg.MaxBodySize),
		logger:      slog.Default(),
		sendLimiter: newRateLimiter(cfg.RatePerSecond, cfg.RatePerMinute),
		sendHosts:   newHostSemaphore(cfg.MaxConcurrentPerHost),
		sendSlots:   make(chan struct{}, cfg.Threads),
	}
	for _, o := range opts {
		o(e)
	}
	return e, nil
}

// Run processes seed tasks concurrently and streams a Result per completed
// task (including derived tasks emitted via Context.Emit). The returned channel
// closes when all tasks finish or ctx is cancelled. Run is single-flight: a
// second concurrent Run returns an error.
func (e *Engine) Run(ctx context.Context, seeds []Task) (<-chan *Result, error) {
	ctx, release, err := e.begin(ctx)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	if e.sch != nil {
		e.mu.Unlock()
		release()
		return nil, fmt.Errorf("netloom.Engine.Run: %w", ErrEngineBusy)
	}
	sch := newScheduler(e.cfg, e.tlsT, e.rawT, e.logger)
	sch.onDone = func() {
		e.mu.Lock()
		if e.sch == sch {
			e.sch = nil
		}
		e.mu.Unlock()
		release()
	}
	e.sch = sch
	e.mu.Unlock()

	sch.start(ctx)
	// Keep the scheduler alive while a bounded feeder submits seeds. Returning
	// the result channel first prevents producers and workers blocking each other.
	sch.acceptMu.Lock()
	sch.pending++
	sch.acceptMu.Unlock()
	go func() {
		defer sch.finishTask()
		for _, task := range seeds {
			if task.Req == nil {
				continue
			}
			if !sch.submit(task) {
				return
			}
		}
	}()

	// Close the scheduler once every task (and derivative) drains, then clear
	// the active reference.
	go sch.wait()

	return sch.results, nil
}

// Submit schedules a Task into the currently-running Run. It is the imperative
// counterpart to Run's seed slice and the backing of Schedule. Returns false if
// no Run is active, the queue is full, or the scheduler is shutting down.
func (e *Engine) Submit(t Task) bool {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return false
	}
	sch := e.sch
	e.mu.Unlock()
	if sch == nil {
		return false
	}
	return sch.trySubmit(t)
}

// Schedule implements Runtime: fire-and-forget dispatch into the active Run.
func (e *Engine) Schedule(t Task) {
	e.Submit(t)
}

// Send performs a synchronous request with shared rate/concurrency control,
// without requiring an active Run. Response analysis is supplied by callers.
func (e *Engine) Send(ctx context.Context, req *Request) (*Response, error) {
	if req == nil {
		return nil, fmt.Errorf("netloom.Engine.Send: %w", ErrNilRequest)
	}
	ctx, finish, err := e.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	release, err := e.acquireSend(ctx, req)
	if err != nil {
		return nil, err
	}
	defer release()
	cfg := e.cfg
	if req.Method != "" && req.Method != "GET" && req.Method != "HEAD" && req.Method != "OPTIONS" {
		cfg.Retries = 0
	}
	tmp := newScheduler(cfg, e.tlsT, e.rawT, e.logger)
	resp, err := tmp.sendWithRetry(ctx, req)
	if err != nil {
		return resp, fmt.Errorf("netloom.Engine.Send: %w", err)
	}
	return resp, nil
}

func (e *Engine) acquireSend(ctx context.Context, req *Request) (func(), error) {
	select {
	case e.sendSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := e.sendLimiter.wait(ctx); err != nil {
		<-e.sendSlots
		return nil, err
	}
	host := hostKey(req.URL)
	if err := e.sendHosts.acquire(ctx, host); err != nil {
		<-e.sendSlots
		return nil, err
	}
	release := func() { e.sendHosts.release(host); <-e.sendSlots }
	if e.cfg.Delay > 0 {
		timer := time.NewTimer(e.cfg.Delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			release()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return release, nil
}

var (
	// ErrEngineBusy is returned by Run when another Run is already in flight.
	ErrEngineBusy = fmt.Errorf("netloom: engine busy")
	// ErrNilRequest is returned when a nil *Request reaches Send.
	ErrNilRequest = fmt.Errorf("netloom: nil request")
)

// compile-time assertion that Engine satisfies Runtime.
var _ Runtime = (*Engine)(nil)

// ErrEngineClosed is returned when work is submitted after Close.
var ErrEngineClosed = fmt.Errorf("netloom: engine closed")

// begin links caller cancellation to the Engine lifetime and registers work.
func (e *Engine) begin(ctx context.Context) (context.Context, func(), error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, nil, ErrEngineClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(e.lifetime, cancel)
	e.active.Add(1)
	var once sync.Once
	return ctx, func() { once.Do(func() { stop(); cancel(); e.active.Done() }) }, nil
}

// Close cancels all work, closes live streams, and waits for it to stop.
// Do not call Close from a pipeline handler; cancel its context instead.
func (e *Engine) Close() error {
	e.mu.Lock()
	e.closed = true
	e.stop()
	e.mu.Unlock()
	e.active.Wait()
	return nil
}
