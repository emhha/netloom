package netloom

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/fhttp/httptrace"
	tls_client "github.com/bogdanfinn/tls-client"
	tls "github.com/bogdanfinn/utls"
)

// ErrHTTP2Unavailable means a strict HTTP/2 request could not use HTTP/2.
// Such requests never fall back to transmitting an HTTP/1.x request. The
// current strict mode requires HTTPS with ALPN; plaintext h2c is unsupported.
var ErrHTTP2Unavailable = errors.New("netloom: HTTP/2 unavailable")

func validateHTTPVersion(version string) error {
	switch version {
	case "", "auto", "1.1", "2", "2-only":
		return nil
	default:
		return fmt.Errorf("netloom: HTTP version must be auto, 1.1, 2 or 2-only")
	}
}

// doHTTPRequest uses tls-client except for strict HTTP/2 and explicit TLS
// controls, which must be enforced on the actual connection before application
// bytes. These paths own one dedicated uTLS connection until the body is closed;
// the connection never enters the reusable client cache.
func doHTTPRequest(client tls_client.HttpClient, req *Request, hreq *http.Request) (_ *http.Response, returnErr error) {
	if err := validateHTTPVersion(req.HTTPVersion); err != nil {
		return nil, err
	}
	if req.HTTPVersion != "2-only" && !req.TLSConfig.controlsEnabled() {
		return client.Do(hreq)
	}
	if hreq.URL.Scheme != "https" {
		return nil, fmt.Errorf("%w: strict mode requires HTTPS with ALPN", ErrHTTP2Unavailable)
	}

	ctx := hreq.Context()
	defer func() {
		if returnErr != nil {
			if cause := requestContextError(ctx); cause != nil {
				returnErr = cause
			}
		}
	}()
	addr := hreq.URL.Host
	if hreq.URL.Port() == "" {
		addr = net.JoinHostPort(hreq.URL.Hostname(), "443")
	}
	profile := profileOrDefault(req.Profile)
	makeTLSConn, err := prepareTLSHandshake(req, hreq.URL.Hostname(), profile, req.HTTPVersion == "1.1")
	if err != nil {
		return nil, err
	}
	var rawConn net.Conn
	enterPhase(ctx, PhaseConnect)
	if req.Proxy == "" {
		rawConn, err = client.GetDialer().DialContext(ctx, "tcp", addr)
	} else {
		rawConn, err = dialHTTPProxy(ctx, req.Proxy, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	enterPhase(ctx, PhaseTLS)
	// NewClientConn below writes its preface synchronously, before RoundTrip's
	// request-context handling exists. Closing the raw connection on cancellation
	// therefore covers initialization as well as the handshake and body reads.
	stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	owned := false
	defer func() {
		if !owned {
			stop()
			_ = rawConn.Close()
		}
	}()

	conn, err := makeTLSConn(rawConn)
	if err != nil {
		return nil, err
	}
	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.TLSHandshakeStart != nil {
		trace.TLSHandshakeStart()
	}
	err = conn.HandshakeContext(ctx)
	state := conn.ConnectionState()
	if trace != nil && trace.TLSHandshakeDone != nil {
		trace.TLSHandshakeDone(state, err)
	}
	if err != nil {
		return nil, err
	}
	if state.NegotiatedProtocol != http2.NextProtoTLS {
		if req.HTTPVersion == "2-only" {
			return nil, fmt.Errorf("%w: negotiated ALPN %q", ErrHTTP2Unavailable, state.NegotiatedProtocol)
		}
		if state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" {
			return nil, fmt.Errorf("netloom: unsupported TLS ALPN %q", state.NegotiatedProtocol)
		}
		var delivered atomic.Bool
		transport := &http.Transport{
			DisableCompression: true, ConnectionFlow: profile.GetConnectionFlow(),
			TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				if !delivered.CompareAndSwap(false, true) {
					return nil, errors.New("netloom: dedicated TLS connection cannot redial")
				}
				return conn, nil
			},
		}
		singleClient := &http.Client{Transport: transport, Jar: client.GetCookieJar(), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := singleClient.Do(hreq)
		if err != nil {
			transport.CloseIdleConnections()
			return nil, err
		}
		response.TLS = &state
		response.Body = &http2DedicatedBody{ReadCloser: response.Body, conn: rawConn, stop: stop, cleanup: transport.CloseIdleConnections}
		owned = true
		return response, nil
	}
	transport := &http2.Transport{
		DisableCompression: true,
		Settings:           profile.GetSettings(), SettingsOrder: profile.GetSettingsOrder(),
		ConnectionFlow: profile.GetConnectionFlow(), HeaderPriority: profile.GetHeaderPriority(),
		PseudoHeaderOrder: profile.GetPseudoHeaderOrder(), Priorities: profile.GetPriorities(),
		InitialStreamID: profile.GetStreamID(), AllowHTTP: profile.GetAllowHTTP(),
		PushHandler: &http2.DefaultPushHandler{},
	}
	if transport.Settings == nil {
		// Match tls-client's HTTP/2 defaults for profiles without a settings map.
		transport.Settings = map[http2.SettingID]uint32{
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingMaxFrameSize:         16384,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingHeaderTableSize:      65536,
		}
		transport.SettingsOrder = []http2.SettingID{http2.SettingMaxConcurrentStreams, http2.SettingMaxFrameSize, http2.SettingInitialWindowSize, http2.SettingHeaderTableSize}
	}
	cc, err := transport.NewClientConn(conn)
	if err != nil {
		return nil, err
	}
	if trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{Conn: conn})
	}
	// Keep the normal client's cookie-jar and URL-userinfo handling without
	// invoking its transport (which could silently negotiate HTTP/1.1).
	strictClient := &http.Client{
		Transport: cc, Jar: client.GetCookieJar(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := strictClient.Do(hreq)
	if err != nil {
		_ = rawConn.Close()
		_ = cc.Close()
		return nil, err
	}
	response.Body = &http2DedicatedBody{ReadCloser: response.Body, conn: rawConn, stop: stop}
	owned = true
	return response, nil
}

// http2DedicatedBody closes the connection before the body: a pending HTTP/2
// writer must not make Body.Close block while trying to send a reset stream.
type http2DedicatedBody struct {
	io.ReadCloser
	conn    net.Conn
	stop    func() bool
	cleanup func()
	once    sync.Once
	err     error
}

func (b *http2DedicatedBody) Close() error {
	b.once.Do(func() {
		b.stop()
		_ = b.conn.Close()
		b.err = b.ReadCloser.Close()
		if b.cleanup != nil {
			b.cleanup()
		}
	})
	return b.err
}
