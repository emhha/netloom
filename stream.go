package netloom

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

// StreamResponse contains immutable header-time metadata and a live body.
// Status returns a synchronized progress/completion snapshot; Response is not
// mutated as the body is read or closed.
type StreamResponse struct {
	Response *Response
	Body     io.ReadCloser
	body     *streamBody
}

// ErrStreamClosedEarly marks an explicitly closed body that did not reach EOF.
var ErrStreamClosedEarly = errors.New("netloom: stream closed before EOF")

// StreamStatus reports application reads, not on-wire byte counts. Complete is
// true only after EOF. Finished also includes read failure and early Close.
// EOF does not release concurrency slots: the caller must still close Body.
type StreamStatus struct {
	Timings   Timings
	BytesRead int64
	Complete  bool
	Finished  bool
	Closed    bool
	Error     error
}

func (s *StreamResponse) Status() StreamStatus {
	if s == nil || s.body == nil {
		return StreamStatus{}
	}
	return s.body.snapshot()
}

// SendStream forwards without buffering or retries. Closing Body releases rate
// slots and the upstream client. Evidence capture limits belong to the caller.
func (e *Engine) SendStream(ctx context.Context, req *Request) (*StreamResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	ctx, finish, err := e.begin(ctx)
	if err != nil {
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			finish()
		}
	}()
	if len(req.Raw) != 0 {
		return nil, fmt.Errorf("netloom.SendStream: raw requests are unsupported")
	}
	transport, ok := e.tlsT.(*tlsTransport)
	if !ok {
		return nil, fmt.Errorf("netloom.SendStream: streaming transport unavailable")
	}
	// Resolve the same request > Engine > default timeout as buffered sends,
	// without mutating the caller's request. The context covers body reads.
	requestCopy := *req
	requestCopy.Network = req.Network.Clone()
	if _, err := withNetworkOptions(ctx, &requestCopy); err != nil {
		return nil, err
	}
	if requestCopy.PhaseTimeouts == nil {
		policy := e.cfg.PhaseTimeouts
		requestCopy.PhaseTimeouts = &policy
	}
	if err := requestCopy.PhaseTimeouts.validate(); err != nil {
		return nil, err
	}
	if requestCopy.Timeout <= 0 {
		requestCopy.Timeout = e.cfg.Timeout
	}
	if requestCopy.Timeout <= 0 {
		requestCopy.Timeout = dialTimeout
	}
	req = &requestCopy
	queued := time.Now()
	release, err := e.acquireSend(ctx, req)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	stopTotal := func() {}
	if total := req.PhaseTimeouts.Total; total > 0 {
		ctx, stopTotal = withTotalBudget(ctx, total)
	}
	ctx, cancelAttempt := context.WithTimeout(ctx, req.Timeout)
	cancelTimeout := func() { cancelAttempt(); stopTotal() }
	ctx, clock, err := newPhaseClock(ctx, req)
	if err != nil {
		cancelTimeout()
		release()
		return nil, err
	}
	defer func() {
		if !owned {
			clock.finish()
			cancelTimeout()
		}
	}()
	ctx, observation := observe(ctx, start)
	observation.proxy = req.Proxy != ""
	lease, err := transport.acquireClient(ctx, req)
	if err != nil {
		release()
		return nil, clock.failure(ctx, err)
	}
	client := lease.client
	defer func() {
		if !owned {
			clock.stop()
			lease.release(false)
		}
	}()
	method := req.Method
	if method == "" {
		method = "GET"
	}
	request, err := http.NewRequestWithContext(ctx, method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		release()
		return nil, err
	}
	request.Header = req.Header.Clone()
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	applyHeaderOrder(request, req.HeaderOrder)
	response, err := transport.doRequest(client, req, request)
	if err != nil {
		release()
		return nil, fmt.Errorf("netloom.SendStream: %w", err)
	}
	meta := &Response{RequestHeaders: request.Header.Clone(), StatusCode: response.StatusCode, Header: response.Header,
		ContentLength: response.ContentLength, ContentType: response.Header.Get("Content-Type"),
		WebServer: response.Header.Get("Server"), Location: response.Header.Get("Location"),
		CSP: response.Header.Get("Content-Security-Policy"), IP: observation.connectedIP(),
		Scheme: request.URL.Scheme, HTTPVersion: response.Proto, ResponseTime: time.Since(start),
	}
	timing, actualTLS := observation.snapshot()
	timing.QueueMS = milliseconds(start.Sub(queued))
	timing.HeadersMS = milliseconds(time.Since(start))
	meta.Timings, meta.TLS = &timing, actualTLS
	delete(meta.RequestHeaders, http.HeaderOrderKey)
	if response.TLS != nil {
		meta.TLS = buildTLSInfo(*response.TLS)
	}
	response.Body = wrapPhaseBody(ctx, response.Body)
	var body *streamBody
	body = &streamBody{ReadCloser: response.Body, ctx: ctx,
		start: start, headersAt: time.Now(), status: StreamStatus{Timings: cloneTimings(timing)},
		cleanup: func() {
			status := body.snapshot()
			clock.stop()
			lease.release(status.Complete && status.Error == nil && body.err == nil)
			clock.finish()
			cancelTimeout()
			release()
			finish()
		}}
	owned = true
	context.AfterFunc(ctx, func() { _ = body.Close() })
	return &StreamResponse{Response: meta, Body: body, body: body}, nil
}

type streamBody struct {
	io.ReadCloser
	once    sync.Once
	cleanup func()
	err     error
	ctx     context.Context

	mu        sync.Mutex
	start     time.Time
	headersAt time.Time
	status    StreamStatus
}

func (b *streamBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		if clock := phaseClockFrom(b.ctx); clock != nil {
			err = clock.failure(b.ctx, err)
		} else if cause := requestContextError(b.ctx); cause != nil {
			err = cause
		}
	}
	b.mu.Lock()
	b.status.BytesRead += int64(n)
	if err != nil {
		b.finishLocked(err)
	}
	b.mu.Unlock()
	return n, err
}

// finishLocked freezes completion times at EOF, error or Close, whichever wins.
func (b *streamBody) finishLocked(err error) {
	if b.status.Finished {
		return
	}
	b.status.Finished = true
	b.status.Complete = err == io.EOF
	if err != io.EOF {
		if clock := phaseClockFrom(b.ctx); clock != nil {
			err = clock.failure(b.ctx, err)
		} else if cause := requestContextError(b.ctx); cause != nil {
			err = cause
		}
		b.status.Error = err
	}
	now := time.Now()
	b.status.Timings.BodyMS = milliseconds(now.Sub(b.headersAt))
	b.status.Timings.TotalMS = milliseconds(now.Sub(b.start))
}

func (b *streamBody) snapshot() StreamStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.status
	out.Timings = cloneTimings(out.Timings)
	return out
}

func (b *streamBody) Close() error {
	b.once.Do(func() {
		b.err = b.ReadCloser.Close()
		b.mu.Lock()
		b.status.Closed = true
		err := requestContextError(b.ctx)
		if err == nil {
			err = b.err
		}
		if err == nil {
			err = ErrStreamClosedEarly
		}
		b.finishLocked(err)
		b.mu.Unlock()
		b.cleanup()
	})
	return b.err
}
