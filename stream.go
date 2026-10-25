package netrt

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

type StreamResponse struct {
	Response *Response
	Body     io.ReadCloser
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
		return nil, fmt.Errorf("netrt.SendStream: raw requests are unsupported")
	}
	transport, ok := e.tlsT.(*tlsTransport)
	if !ok {
		return nil, fmt.Errorf("netrt.SendStream: streaming transport unavailable")
	}
	queued := time.Now()
	release, err := e.acquireSend(ctx, req)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	ctx, observation := observe(ctx, start)
	client, connectedIP, err := transport.buildClient(req)
	if err != nil {
		release()
		return nil, err
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}
	request, err := http.NewRequestWithContext(ctx, method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		client.CloseIdleConnections()
		release()
		return nil, err
	}
	request.Header = req.Header.Clone()
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	applyHeaderOrder(request, req.HeaderOrder)
	response, err := client.Do(request)
	if err != nil {
		client.CloseIdleConnections()
		release()
		return nil, fmt.Errorf("netrt.SendStream: %w", err)
	}
	meta := &Response{RequestHeaders: request.Header.Clone(), StatusCode: response.StatusCode, Header: response.Header,
		ContentLength: response.ContentLength, ContentType: response.Header.Get("Content-Type"),
		WebServer: response.Header.Get("Server"), Location: response.Header.Get("Location"),
		CSP: response.Header.Get("Content-Security-Policy"), IP: *connectedIP,
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
	body := &streamBody{ReadCloser: response.Body,
		cleanup: func() { client.CloseIdleConnections(); release(); finish() }}
	owned = true
	context.AfterFunc(ctx, func() { _ = body.Close() })
	return &StreamResponse{Response: meta, Body: body}, nil
}

type streamBody struct {
	io.ReadCloser
	once    sync.Once
	cleanup func()
	err     error
}

func (b *streamBody) Close() error {
	b.once.Do(func() { b.err = b.ReadCloser.Close(); b.cleanup() })
	return b.err
}
