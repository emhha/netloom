package traffic

import (
	"io"
	"slices"
	"sync"
)

func (t *Traffic) captureResponse(body io.ReadCloser, o observation) io.ReadCloser {
	return &responseBody{ReadCloser: body, traffic: t, observation: o}
}

type responseBody struct {
	io.ReadCloser
	traffic     *Traffic
	mu          sync.Mutex
	observation observation
	finished    bool
	closeOnce   sync.Once
	closeErr    error
}

func (b *responseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.record(p[:n], err, false)
	return n, err
}

func (b *responseBody) Close() error {
	b.closeOnce.Do(func() {
		b.closeErr = b.ReadCloser.Close()
		b.record(nil, b.closeErr, true)
	})
	return b.closeErr
}

func (b *responseBody) record(data []byte, err error, closed bool) {
	b.mu.Lock()
	if b.finished {
		b.mu.Unlock()
		return
	}
	o := &b.observation
	remaining := b.traffic.cfg.BodyLimit - len(o.resp.Body)
	if len(data) > 0 {
		o.resp.Body = append(o.resp.Body, data[:min(len(data), remaining)]...)
	}
	if len(data) <= remaining && err == nil && !closed {
		b.mu.Unlock()
		return
	}
	o.report.ResponseTruncated = len(data) > remaining
	o.report.ResponseIncomplete = err != io.EOF && (closed || err != nil)
	o.resp.BodyTruncated = o.report.ResponseTruncated || o.report.ResponseIncomplete
	if err != io.EOF {
		o.report.TransportError = err
	}
	completed := *o
	b.observation = observation{}
	b.finished = true
	b.mu.Unlock()
	b.traffic.submit(completed)
}

// requestBody captures bytes consumed by the downstream transport without
// reading ahead or changing the source's Close semantics.
type requestBody struct {
	io.ReadCloser
	limit, size int
	mu          sync.Mutex
	prefix      []byte
	eof         bool
}

func (b *requestBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.mu.Lock()
	b.size += n
	b.prefix = append(b.prefix, p[:min(n, b.limit-len(b.prefix))]...)
	b.eof = b.eof || err == io.EOF
	b.mu.Unlock()
	return n, err
}

func (b *requestBody) snapshot(expected int64) ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	complete := b.eof || (expected > 0 && int64(b.size) == expected)
	return slices.Clone(b.prefix), !complete || b.size > b.limit
}
