package netloom

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"

	http "github.com/bogdanfinn/fhttp"
)

var ErrBodyNotReplayable = errors.New("netloom: request body is not replayable")
var ErrUploadLength = errors.New("netloom: upload length does not match declared length")

// Upload is an immutable body source. One-shot sources can be opened once even
// across concurrent sends. Close must unblock Read; the SDK closes every opened
// reader on cancellation and completion. Constructors never read or open files.
// A replayable opener must be concurrency safe and reproduce identical bytes.
type Upload struct {
	mu         sync.Mutex
	length     int64
	replayable bool
	used       bool
	open       func(context.Context) (io.ReadCloser, error)
}

func nilUploadReader(reader io.ReadCloser) bool {
	if reader == nil {
		return true
	}
	value := reflect.ValueOf(reader)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// NewUpload transfers reader ownership when first opened by transport. Length
// is -1 for unknown, or the exact byte count (including zero). On preflight
// failure the unopened reader remains caller owned.
func NewUpload(reader io.ReadCloser, length int64) (*Upload, error) {
	if nilUploadReader(reader) || length < -1 {
		return nil, fmt.Errorf("netloom: upload needs a reader and length >= -1")
	}
	return &Upload{length: length, open: func(context.Context) (io.ReadCloser, error) { return reader, nil }}, nil
}

// NewReplayableUpload opens a fresh reader for every wire attempt.
func NewReplayableUpload(length int64, open func(context.Context) (io.ReadCloser, error)) (*Upload, error) {
	if open == nil || length < -1 {
		return nil, fmt.Errorf("netloom: upload needs an opener and length >= -1")
	}
	return &Upload{length: length, replayable: true, open: open}, nil
}

func (u *Upload) openBody(ctx context.Context) (io.ReadCloser, error) {
	if u == nil || u.open == nil || u.length < -1 {
		return nil, fmt.Errorf("netloom: invalid upload source")
	}
	if err := requestContextError(ctx); err != nil {
		return nil, err
	}
	u.mu.Lock()
	if u.used && !u.replayable {
		u.mu.Unlock()
		return nil, ErrBodyNotReplayable
	}
	u.used = true
	u.mu.Unlock()
	body, err := u.open(ctx)
	if err != nil {
		if !nilUploadReader(body) {
			_ = body.Close()
		}
		return nil, err
	}
	if nilUploadReader(body) {
		return nil, fmt.Errorf("netloom: upload opener returned nil reader")
	}
	owned := &uploadReader{body: body, ctx: ctx, remaining: u.length, known: u.length >= 0}
	owned.stopMu.Lock()
	owned.stop = context.AfterFunc(ctx, func() { _ = owned.Close() })
	owned.stopMu.Unlock()
	return owned, nil
}

// uploadReader is close-once and enforces known lengths without reading ahead.
// Excess bytes beyond a known length are not sent or inspected. Short readers
// fail with ErrUploadLength. Unknown length uses chunking for HTTP/1.1.
type uploadReader struct {
	body      io.ReadCloser
	ctx       context.Context
	remaining int64
	known     bool
	once      sync.Once
	stopMu    sync.Mutex
	stop      func() bool
	closeErr  error
}

func (r *uploadReader) Read(p []byte) (int, error) {
	if err := requestContextError(r.ctx); err != nil {
		return 0, err
	}
	if r.known {
		if r.remaining == 0 {
			return 0, io.EOF
		}
		if int64(len(p)) > r.remaining {
			p = p[:r.remaining]
		}
	}
	n, err := r.body.Read(p)
	if r.known {
		r.remaining -= int64(n)
		if err == io.EOF && r.remaining > 0 {
			err = ErrUploadLength
		}
	}
	if cause := requestContextError(r.ctx); cause != nil {
		err = cause
	}
	return n, err
}
func (r *uploadReader) Close() error {
	r.once.Do(func() {
		r.stopMu.Lock()
		stop := r.stop
		r.stopMu.Unlock()
		if stop != nil {
			stop()
		}
		r.closeErr = r.body.Close()
	})
	return r.closeErr
}

func validateRequestBody(req *Request) error {
	if req.CaptureRequestBody < 0 || req.CaptureRequestBody > 1<<20 {
		return fmt.Errorf("netloom: request capture limit must be between 0 and 1048576")
	}
	if req.Upload != nil && (len(req.Body) > 0 || len(req.Raw) > 0) {
		return fmt.Errorf("netloom: Upload cannot be combined with Body or Raw")
	}
	if req.Upload != nil && (req.Upload.open == nil || req.Upload.length < -1) {
		return fmt.Errorf("netloom: invalid upload source")
	}
	if err := validateAuthRequest(req); err != nil {
		return err
	}
	if _, err := HTTPURL(req.URL); err != nil {
		return err
	}
	if len(req.Raw) > 0 {
		if req.CaptureRequestBody != 0 {
			return fmt.Errorf("netloom: Raw does not support upload capture")
		}
		return nil
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}
	h, err := http.NewRequest(method, req.URL, nil)
	if err != nil {
		return err
	}
	h.Header = req.Header.Clone()
	return normalizeWireHeaders(h, req)
}

// buildWireRequest centralizes normalization for buffered and streaming paths.
// Raw never goes through this function. Header framing is owned by the transport.
func buildWireRequest(ctx context.Context, req *Request) (*http.Request, error) {
	if err := validateRequestBody(req); err != nil {
		return nil, err
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	if _, err := HTTPURL(req.URL); err != nil {
		return nil, err
	}
	// Build and validate headers before consuming a one-shot source.
	h, err := http.NewRequestWithContext(ctx, method, req.URL, nil)
	if err != nil {
		return nil, err
	}
	h.Header = req.Header.Clone()
	if h.Header == nil {
		h.Header = make(http.Header)
	}
	if err := normalizeWireHeaders(h, req); err != nil {
		return nil, err
	}
	if req.Upload == nil {
		if len(req.Body) > 0 {
			h.Body = io.NopCloser(bytes.NewReader(req.Body))
			h.ContentLength = int64(len(req.Body))
			h.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(req.Body)), nil }
		}
	} else {
		body, err := req.Upload.openBody(ctx)
		if err != nil {
			return nil, err
		}
		h.Body = body
		h.ContentLength = req.Upload.length
		if req.Upload.length == 0 {
			_ = body.Close()
			h.Body = http.NoBody
		}
		if req.Upload.replayable {
			h.GetBody = func() (io.ReadCloser, error) { return req.Upload.openBody(ctx) }
		}
	}
	applyHeaderOrder(h, req.HeaderOrder)
	return h, nil
}

// UploadEvidence is a bounded application-reader prefix, not a wire capture.
// Captured bytes can include secrets; enable only with caller authorization.
type UploadEvidence struct {
	Prefix    []byte
	BytesRead int64
	Truncated bool
}
type captureUpload struct {
	io.ReadCloser
	mu       sync.Mutex
	limit    int
	evidence UploadEvidence
}

func (c *captureUpload) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.mu.Lock()
	c.evidence.BytesRead += int64(n)
	room := c.limit - len(c.evidence.Prefix)
	if room > n {
		room = n
	}
	if room > 0 {
		c.evidence.Prefix = append(c.evidence.Prefix, p[:room]...)
	}
	c.evidence.Truncated = c.evidence.BytesRead > int64(c.limit)
	c.mu.Unlock()
	return n, err
}
func (c *captureUpload) snapshot() *UploadEvidence {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.evidence
	e.Prefix = append([]byte(nil), e.Prefix...)
	return &e
}
func captureWireUpload(h *http.Request, limit int) *captureUpload {
	if limit == 0 || h.Body == nil || h.Body == http.NoBody {
		return nil
	}
	c := &captureUpload{ReadCloser: h.Body, limit: limit}
	h.Body = c
	return c
}
