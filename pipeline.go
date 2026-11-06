package netloom

import (
	"context"
	"fmt"
)

// Context flows through the onion Pipeline. Handlers call Next to descend into
// the remaining stages (pre-work before Next, post-work after), Emit to derive
// new Tasks, and Abort to stop the chain without raising an error.
type Context struct {
	Req       *Request
	Resp      *Response
	Meta      map[string]any
	Artifacts []Artifact

	ctx      context.Context
	handlers []Handler
	index    int
	aborted  bool

	// emit is injected by the Scheduler so derived Tasks re-enter the queue
	// instead of recursing. nil when running standalone (Engine.Send).
	emit    func(Task)
	tryEmit func(Task) bool
	emitErr error
}

// NewContext builds a Context for the given request and handler chain. A nil
// emit callback rejects derived tasks unless the scheduler supplies tryEmit.
func NewContext(ctx context.Context, req *Request, handlers []Handler, emit func(Task)) *Context {
	return &Context{
		Req:      req,
		Meta:     map[string]any{},
		ctx:      ctx,
		handlers: handlers,
		index:    -1,
		emit:     emit,
	}
}

// Context returns the request-scoped context.Context for cancellation/deadline.
func (c *Context) Context() context.Context {
	if c.ctx == nil {
		return context.Background()
	}
	return c.ctx
}

// Next invokes the remaining handlers. Calling it inside a handler enables
// nested pre/post work; Abort explicitly terminates the chain.
func (c *Context) Next() error {
	if c.aborted {
		return nil
	}
	c.index++
	for c.index < len(c.handlers) {
		h := c.handlers[c.index]
		current := c.index
		if err := h(c); err != nil {
			return fmt.Errorf("netloom.Context.Next[%d]: %w", current, err)
		}
		if c.aborted {
			return nil
		}
		// If the handler advanced the index itself via Next, the loop body
		// already ran the deeper stages; resume after them.
		if c.index == current {
			c.index++
		}
	}
	return nil
}

// Emit derives a Task without blocking the worker. Rejected tasks surface
// as a pipeline error; use TryEmit to handle queue backpressure explicitly.
func (c *Context) Emit(t Task) {
	if !c.TryEmit(t) {
		c.emitErr = ErrQueueFull
	}
}

// TryEmit reports bounded queue backpressure without blocking a worker.
func (c *Context) TryEmit(t Task) bool {
	if c.tryEmit != nil {
		return c.tryEmit(t)
	}
	if c.emit != nil {
		c.emit(t)
		return true
	}
	return false
}

var ErrQueueFull = fmt.Errorf("netloom: task queue is full or unavailable")

// Abort stops Pipeline execution for the current request without producing an
// error. Use it for "not interested" decisions (e.g. a Matcher miss).
func (c *Context) Abort() {
	c.aborted = true
}

// Aborted reports whether Abort was called.
func (c *Context) Aborted() bool { return c.aborted }

// run executes the full chain from the start. Returns the first handler error.
func (c *Context) run() error {
	c.index = -1
	c.emitErr = nil
	if err := c.Next(); err != nil {
		return err
	}
	return c.emitErr
}

// AsMutator adapts a Mutator into a Handler. It rewrites the request, then
// descends into the rest of the chain.
func AsMutator(m Mutator) Handler {
	return func(c *Context) error {
		if err := m.Mutate(c.Req); err != nil {
			return fmt.Errorf("netloom.AsMutator: %w", err)
		}
		return c.Next()
	}
}

// AsExtractor adapts an Extractor into a Handler. It descends first so the
// Response is populated, then appends extracted Artifacts.
func AsExtractor(e Extractor) Handler {
	return func(c *Context) error {
		if err := c.Next(); err != nil {
			return err
		}
		if c.Resp == nil {
			return nil
		}
		arts, err := e.Extract(c.Resp)
		if err != nil {
			return fmt.Errorf("netloom.AsExtractor[%s]: %w", e.Name(), err)
		}
		c.Artifacts = append(c.Artifacts, arts...)
		return nil
	}
}

// AsMatcher adapts a Matcher into a Handler. It descends first, then aborts the
// chain when the Response is not interesting.
func AsMatcher(m Matcher) Handler {
	return func(c *Context) error {
		if err := c.Next(); err != nil {
			return err
		}
		if c.Resp == nil || !m.Match(c.Resp) {
			c.Abort()
		}
		return nil
	}
}
