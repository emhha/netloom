package netrt

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"sync"
	"time"
)

// scheduler owns the bounded worker pool, the task queue, rate limiting and
// per-host error accounting. Derived tasks (Context.Emit) re-enter through
// submit, avoiding recursive in-handler execution.
type scheduler struct {
	cfg     Config
	tlsT    Transport
	rawT    Transport
	limiter *rateLimiter
	hostSem *hostSemaphore
	logger  *slog.Logger

	results chan *Result

	acceptMu  sync.Mutex
	cond      *sync.Cond
	pending   int
	accepting bool
	runCtx    context.Context
	space     chan struct{}
	queue     chan Task
	workers   sync.WaitGroup // worker goroutines
	onDone    func()

	mu             sync.Mutex
	hostErrorCount map[string]int
	skipped        map[string]bool

	closeOnce sync.Once
	closed    chan struct{}
}

func newScheduler(cfg Config, tlsT, rawT Transport, logger *slog.Logger) *scheduler {
	if logger == nil {
		logger = slog.Default()
	}
	s := &scheduler{
		cfg:            cfg,
		tlsT:           tlsT,
		rawT:           rawT,
		limiter:        newRateLimiter(cfg.RatePerSecond, cfg.RatePerMinute),
		hostSem:        newHostSemaphore(cfg.MaxConcurrentPerHost),
		logger:         logger,
		results:        make(chan *Result, cfg.Threads),
		queue:          make(chan Task, cfg.Threads*4),
		hostErrorCount: map[string]int{},
		skipped:        map[string]bool{},
		closed:         make(chan struct{}),
		accepting:      true, runCtx: context.Background(), space: make(chan struct{}, 1),
	}
	s.cond = sync.NewCond(&s.acceptMu)
	return s
}

// start launches the worker pool. ctx cancellation stops all workers.
func (s *scheduler) start(ctx context.Context) {
	s.runCtx = ctx
	for i := 0; i < s.cfg.Threads; i++ {
		s.workers.Add(1)
		go s.worker(ctx)
	}
}

// submit enqueues a task. Returns false if the scheduler is shutting down.
func (s *scheduler) trySubmit(t Task) bool {
	if t.Req == nil {
		return false
	}
	s.acceptMu.Lock()
	defer s.acceptMu.Unlock()
	if !s.accepting || s.runCtx.Err() != nil {
		return false
	}
	select {
	case s.queue <- t:
		s.pending++
		return true
	default:
		return false
	}
}

func (s *scheduler) submit(t Task) bool {
	if t.Req == nil {
		return false
	}
	for {
		if s.trySubmit(t) {
			return true
		}
		select {
		case <-s.closed:
			return false
		case <-s.runCtx.Done():
			return false
		case <-s.space:
		}
	}
}

func (s *scheduler) finishTask() {
	s.acceptMu.Lock()
	s.pending--
	if s.pending == 0 {
		s.cond.Broadcast()
	}
	s.acceptMu.Unlock()
}

func (s *scheduler) stopAccepting() {
	s.acceptMu.Lock()
	s.accepting = false
	s.acceptMu.Unlock()
}

func (s *scheduler) worker(ctx context.Context) {
	defer s.workers.Done()
	for {
		select {
		case <-ctx.Done():
			// Drain remaining queued tasks' wg counters so wait() unblocks.
			s.stopAccepting()
			s.drainOnCancel()
			return
		case <-s.closed:
			return
		case t := <-s.queue:
			select {
			case s.space <- struct{}{}:
			default:
			}
			s.process(ctx, t)
			s.finishTask()
		}
	}
}

// drainOnCancel decrements wg for any tasks still queued when ctx is cancelled.
func (s *scheduler) drainOnCancel() {
	for {
		select {
		case <-s.queue:
			s.finishTask()
		default:
			return
		}
	}
}

func (s *scheduler) process(ctx context.Context, t Task) {
	host := hostKey(t.Req.URL)

	s.mu.Lock()
	if s.skipped[host] {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	if err := s.limiter.wait(ctx); err != nil {
		return
	}
	if s.cfg.Delay > 0 {
		timer := time.NewTimer(s.cfg.Delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}

	if err := s.hostSem.acquire(ctx, host); err != nil {
		return
	}
	defer s.hostSem.release(host)

	resp, err := s.sendWithRetry(ctx, t.Req)
	if err != nil {
		s.recordHostError(host)
		// Surface the failed Context to consumers with the error attached.
		c := NewContext(ctx, t.Req, t.Pipeline, nil)
		c.Resp = &Response{Error: err, Scheme: schemeOf(t.Req.URL)}
		s.deliver(&Result{Ctx: c})
		return
	}
	s.resetHostError(host)

	c := NewContext(ctx, t.Req, t.Pipeline, nil)
	c.Resp = resp
	c.tryEmit = s.trySubmit
	if perr := c.run(); perr != nil {
		c.Resp.Error = perr
		s.logger.LogAttrs(ctx, slog.LevelWarn, "netrt: pipeline error",
			slog.String("url", t.Req.URL), slog.String("err", perr.Error()))
	}
	s.deliver(&Result{Ctx: c})
}

func (s *scheduler) sendWithRetry(ctx context.Context, req *Request) (*Response, error) {
	tr := route(req, s.tlsT, s.rawT)
	var lastErr error
	for attempt := 0; attempt <= s.cfg.Retries; attempt++ {
		rctx := ctx
		var cancel context.CancelFunc
		timeout := s.cfg.Timeout
		if req.Timeout > 0 {
			timeout = req.Timeout
		}
		if timeout > 0 {
			rctx, cancel = context.WithTimeout(ctx, timeout)
		}
		resp, err := tr.RoundTrip(rctx, req)
		if cancel != nil {
			cancel()
		}
		if err == nil {
			return resp, nil
		}
		// Blocked addresses are permanent; never retry.
		if errors.Is(err, ErrBlockedAddress) {
			return nil, err
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

func (s *scheduler) deliver(r *Result) {
	select {
	case <-s.closed:
	case <-s.runCtx.Done():
	case s.results <- r:
	}
}

func (s *scheduler) recordHostError(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostErrorCount[host]++
	if s.hostErrorCount[host] > s.cfg.MaxHostErrors && !s.skipped[host] {
		s.skipped[host] = true
		s.logger.Warn("netrt: host skipped after error threshold",
			slog.String("host", host), slog.Int("errors", s.hostErrorCount[host]))
	}
}

func (s *scheduler) resetHostError(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostErrorCount[host] = 0
}

// wait blocks until all submitted tasks (and their derived tasks) complete,
// then closes the results channel exactly once.
func (s *scheduler) wait() {
	s.acceptMu.Lock()
	for s.pending > 0 {
		s.cond.Wait()
	}
	s.accepting = false
	s.acceptMu.Unlock()
	s.shutdown()
}

// shutdown stops workers and closes results. Safe to call multiple times.
func (s *scheduler) shutdown() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.workers.Wait()
		if s.onDone != nil {
			s.onDone()
		}
		close(s.results)
	})
}

func hostKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		return host
	}
	return host + ":" + port
}

func schemeOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Scheme
}
