package mitm

import (
	"bytes"
	"io"
	"sync"
)

// ObserveBody forwards every byte while retaining only limit bytes of evidence.
// done runs once on Close; truncated also reports incomplete upstream reads.
func ObserveBody(body io.ReadCloser, limit int, expected int64, done func([]byte, bool)) io.ReadCloser {
	if limit < 0 {
		limit = 0
	}
	return &observedBody{ReadCloser: body, limit: limit, expected: expected, done: done}
}

type observedBody struct {
	io.ReadCloser
	buffer          bytes.Buffer
	limit           int
	expected, count int64
	eof, failed     bool
	done            func([]byte, bool)
	once            sync.Once
	err             error
}

func (b *observedBody) Read(data []byte) (int, error) {
	n, err := b.ReadCloser.Read(data)
	b.count += int64(n)
	keep := min(n, max(0, b.limit-b.buffer.Len()))
	_, _ = b.buffer.Write(data[:keep])
	if err == io.EOF {
		b.eof = true
	} else if err != nil {
		b.failed = true
	}
	return n, err
}

func (b *observedBody) Close() error {
	b.once.Do(func() {
		b.err = b.ReadCloser.Close()
		complete := b.eof || (b.expected >= 0 && b.count == b.expected)
		b.done(b.buffer.Bytes(), b.count > int64(b.limit) || b.failed || !complete)
	})
	return b.err
}
