package traffic

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/emhha/netloom/httpdata"
	"github.com/emhha/netloom/mitm"
)

// MITMBackend is a mitm.Backend backed by an owned standard HTTP transport.
type MITMBackend struct {
	*observedBackend
	transport *http.Transport
}

// CloseIdleConnections releases unused upstream connections. The proxy server
// and any in-flight exchanges are owned by the caller.
func (b *MITMBackend) CloseIdleConnections() { b.transport.CloseIdleConnections() }

// NewMITMBackend creates a single-hop backend and applies the configured MITM
// proxy. If transport is supplied it is cloned, and its Proxy function is kept
// when traffic has no MITM/default proxy setting. With a nil transport, the
// backend connects directly by default, verifies TLS and disables automatic
// decompression on the forwarded response. check is the caller's target policy.
func (t *Traffic) NewMITMBackend(check func(context.Context, *url.URL) error, transport *http.Transport) (*MITMBackend, error) {
	if t.queue == nil || check == nil {
		return nil, fmt.Errorf("traffic: OnReport and a target policy are required for MITM")
	}
	if transport == nil {
		transport = &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			DisableCompression:    true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		}
	} else {
		transport = transport.Clone()
	}
	if t.mitmProxy != nil {
		proxy, err := parseMITMProxy(*t.mitmProxy)
		if err != nil {
			return nil, fmt.Errorf("traffic: MITM proxy: %w", err)
		}
		transport.Proxy = nil
		if proxy != nil {
			transport.Proxy = http.ProxyURL(proxy)
		}
	}
	backend := transportBackend{check: check, transport: transport}
	return &MITMBackend{observedBackend: &observedBackend{traffic: t, Backend: backend}, transport: transport}, nil
}

// WrapMITM adds observation to a caller-owned backend. Configure the upstream
// proxy on the backend itself. Use NewMITMBackend to apply ProxyConfig.MITM.
func (t *Traffic) WrapMITM(backend mitm.Backend) (mitm.Backend, error) {
	if t.queue == nil || backend == nil {
		return nil, fmt.Errorf("traffic: OnReport and a backend are required for MITM")
	}
	if t.mitmProxy != nil {
		return nil, fmt.Errorf("traffic: custom MITM backend owns proxy configuration")
	}
	if _, wrapped := backend.(*observedBackend); wrapped {
		return nil, fmt.Errorf("traffic: MITM backend is already observed")
	}
	if _, wrapped := backend.(*MITMBackend); wrapped {
		return nil, fmt.Errorf("traffic: MITM backend is already observed")
	}
	return &observedBackend{traffic: t, Backend: backend}, nil
}

type transportBackend struct {
	check     func(context.Context, *url.URL) error
	transport *http.Transport
}

func (b transportBackend) CheckTarget(ctx context.Context, target *url.URL) error {
	return b.check(ctx, target)
}

func (b transportBackend) RoundTrip(req *http.Request) (*http.Response, error) {
	return b.transport.RoundTrip(req)
}

type observedBackend struct {
	mitm.Backend
	traffic *Traffic
}

func (b *observedBackend) RoundTrip(req *http.Request) (*http.Response, error) {
	t := b.traffic
	request := &httpdata.Request{URL: req.URL.String(), Method: req.Method, Header: req.Header.Clone()}
	var body *requestBody
	if req.Body != nil && req.Body != http.NoBody {
		body = &requestBody{ReadCloser: req.Body, limit: t.cfg.BodyLimit}
		forwarded := *req
		forwarded.Body = body
		req = &forwarded
	}
	resp, err := b.Backend.RoundTrip(req)
	requestTruncated := false
	if body != nil {
		request.Body, requestTruncated = body.snapshot(req.ContentLength)
	}
	var response *httpdata.Response
	if resp != nil {
		response = &httpdata.Response{
			URL: request.URL, StatusCode: resp.StatusCode, Header: resp.Header.Clone(),
			ContentType: resp.Header.Get("Content-Type"), WebServer: resp.Header.Get("Server"),
		}
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			response.TLS = &httpdata.TLSInfo{Subject: resp.TLS.PeerCertificates[0].Subject.String()}
		}
	}
	o := t.observe(SourceMITM, request, response, err)
	o.report.RequestTruncated = requestTruncated
	if err != nil || resp == nil || resp.Body == nil || resp.Body == http.NoBody || req.Method == http.MethodHead {
		o.report.ResponseIncomplete = resp != nil && err != nil
		t.submit(o)
	} else {
		resp.Body = t.captureResponse(resp.Body, o)
	}
	return resp, err
}
