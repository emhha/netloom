package netloom

import (
	"context"
	"net"
	"sync"
)

// clientDialScope bridges the dependency's background HTTP/2 reconnects to the
// current exclusive lease. Closing the raw socket also interrupts TLS handshakes
// and synchronous H2 preface writes that otherwise have no request context.
// It must never be shared by concurrent leases.
type clientDialScope struct {
	mu          sync.Mutex
	ctx         context.Context
	generation  uint64
	connections map[*scopedConn]*dialCancellation
	bindings    []*dialCancellation // includes callbacks whose Close is still running
}

type dialCancellation struct {
	stop     func() bool
	done     chan struct{}
	finished sync.Once
}

func (b *dialCancellation) finish() { b.finished.Do(func() { close(b.done) }) }
func (b *dialCancellation) disable() {
	if b.stop() {
		b.finish()
	}
}

func bindDialCancellation(ctx context.Context, conn *scopedConn) *dialCancellation {
	b := &dialCancellation{done: make(chan struct{})}
	b.stop = context.AfterFunc(ctx, func() { defer b.finish(); _ = conn.Close() })
	return b
}

func (s *clientDialScope) begin(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.generation++
	s.ctx = ctx
	if s.connections == nil {
		s.connections = make(map[*scopedConn]*dialCancellation)
	}
	for conn := range s.connections {
		binding := bindDialCancellation(ctx, conn)
		s.connections[conn] = binding
		s.bindings = append(s.bindings, binding)
	}
}

func (s *clientDialScope) end(reuse bool) {
	s.mu.Lock()
	s.ctx = nil
	s.generation++
	bindings := s.bindings
	s.bindings = nil
	var conns []*scopedConn
	for conn := range s.connections {
		s.connections[conn] = nil
		if !reuse {
			conns = append(conns, conn)
		}
	}
	s.mu.Unlock()
	// stop() does not wait for a callback already executing. Finish those before
	// publishing the client as idle, lest an old lease close a new lease's socket.
	for _, binding := range bindings {
		binding.disable()
		<-binding.done
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (s *clientDialScope) wrapDial(base func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, network, addr string) (net.Conn, error) {
		s.mu.Lock()
		ctx, generation := s.ctx, s.generation
		s.mu.Unlock()
		if ctx == nil {
			return nil, context.Canceled
		}
		enterPhase(ctx, PhaseConnect)
		conn, err := base(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if clock := phaseClockFrom(ctx); clock != nil {
			if clock.secure {
				clock.enter(PhaseTLS)
			} else {
				clock.enter(PhaseRequest)
			}
		}
		tracked := &scopedConn{Conn: conn, scope: s}
		s.mu.Lock()
		if s.ctx == nil || generation != s.generation || requestContextError(ctx) != nil {
			s.mu.Unlock()
			_ = conn.Close()
			if err := requestContextError(ctx); err != nil {
				return nil, err
			}
			return nil, context.Canceled
		}
		binding := bindDialCancellation(ctx, tracked)
		s.connections[tracked] = binding
		s.bindings = append(s.bindings, binding)
		s.mu.Unlock()
		return tracked, nil
	}
}

type scopedConn struct {
	net.Conn
	scope *clientDialScope
	once  sync.Once
	err   error
}

func (c *scopedConn) Close() error {
	c.once.Do(func() {
		c.scope.mu.Lock()
		binding := c.scope.connections[c]
		delete(c.scope.connections, c)
		c.scope.mu.Unlock()
		if binding != nil {
			binding.disable()
		}
		c.err = c.Conn.Close()
	})
	return c.err
}
