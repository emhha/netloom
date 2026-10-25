package netrt

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	tls "github.com/bogdanfinn/utls"
)

// Transport sends a Request and returns a Response. tlsTransport handles normal
// HTTP(S) through bogdanfinn/tls-client (browser TLS fingerprint); rawTransport
// writes verbatim bytes for malformed-packet scenarios over a fingerprinted TLS
// connection borrowed from the same tls-client.
type Transport interface {
	RoundTrip(ctx context.Context, req *Request) (*Response, error)
}

// route picks the Transport for a Request: raw bytes go to rawTransport,
// everything else to tlsTransport.
func route(req *Request, tlsT, rawT Transport) Transport {
	if len(req.Raw) > 0 {
		return rawT
	}
	return tlsT
}

// dialTimeout is the per-connection TCP dial timeout for both transports.
const dialTimeout = 10 * time.Second

// --- tlsTransport ---------------------------------------------------------

// tlsTransport issues requests through a bogdanfinn/tls-client HttpClient so the
// TLS handshake, HTTP/2 SETTINGS and header order mimic a real browser
// (JA3/JA4). Request.VerifyTLS controls certificate verification.
type tlsTransport struct {
	maxBody  int
	resolver *net.Resolver

	// noGuard disables the loopback/link-local dial guard. It exists solely so
	// tests can reach a 127.0.0.1 httptest server; production paths never set it.
	noGuard bool

	// cookieEnabled enables per-host session cookies. Each unique host gets its
	// own tls-client CookieJar (RFC 6265 semantics are handled by the library),
	// shared by every concurrent request to that host so login state carries
	// across hops, retries and worker threads. Jars are never shared between
	// different hosts, so scanning many targets cannot leak cookies across
	// sites. When nil (the default) clients are built without a jar, matching
	// the previous stateless behaviour exactly.
	cookies *cookieStore
}

// cookieStore owns the per-host CookieJar map and its guard mutex. It is a
// separate heap object so a tlsTransport can be cheaply cloned for tests (the
// clone shares the store instead of copying a lock).
type cookieStore struct {
	mu   sync.Mutex
	jars map[string]tls_client.CookieJar
}

func newTLSTransport(maxBody int) *tlsTransport {
	return newTLSTransportWithJar(maxBody, false)
}

// newTLSTransportWithJar builds a tlsTransport. When enabled, per-host cookie
// jars are created lazily on first request to each host and kept for the
// transport's lifetime.
func newTLSTransportWithJar(maxBody int, cookieEnabled bool) *tlsTransport {
	if maxBody <= 0 {
		maxBody = defaultMaxBodySize
	}
	t := &tlsTransport{maxBody: maxBody, resolver: net.DefaultResolver}
	if cookieEnabled {
		t.cookies = &cookieStore{jars: make(map[string]tls_client.CookieJar)}
	}
	return t
}

// guardDialer returns the loopback/link-local dial guard for this transport,
// or a plain dialer when noGuard is set (tests only).
func (t *tlsTransport) guardDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	base := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	if t.noGuard {
		return base.DialContext
	}
	return guardedDialContext(base, t.resolver)
}

// buildClient constructs a tls-client HttpClient for a single request. The
// client is short-lived (one request) so per-request Profile/Proxy/Timeout are
// honoured without shared mutable state. connectedIP is updated by the guarded
// dialer on connect so the final hop's IP can be reported.
func (t *tlsTransport) buildClient(req *Request) (tls_client.HttpClient, *string, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = dialTimeout
	}

	var connectedIP string
	guard := t.guardDialer()
	dialCapture := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := guard(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if ra := conn.RemoteAddr(); ra != nil {
			if host, _, e := net.SplitHostPort(ra.String()); e == nil {
				connectedIP = host
			}
		}
		return conn, nil
	}

	transportOptions := &tls_client.TransportOptions{DisableCompression: true}
	if req.TLSConfig != nil {
		transportOptions.RootCAs = req.TLSConfig.Roots
		transportOptions.Certificates = req.TLSConfig.Certificates
	}
	opts := []tls_client.HttpClientOption{
		tls_client.WithTimeoutMilliseconds(int(timeout.Milliseconds())),
		tls_client.WithClientProfile(profileOrDefault(req.Profile)),
		// Redirects are surfaced to the caller (Location header) rather than
		// followed transparently, so the dial guard re-validates each hop and
		// the redirect chain stays observable.
		tls_client.WithNotFollowRedirects(),
		tls_client.WithTransportOptions(transportOptions),
	}
	if !req.VerifyTLS {
		opts = append(opts, tls_client.WithInsecureSkipVerify())
	}
	switch req.HTTPVersion {
	case "", "auto":
		opts = append(opts, tls_client.WithDisableHttp3())
	case "1.1":
		opts = append(opts, tls_client.WithForceHttp1())
	default:
		return nil, nil, fmt.Errorf("netrt: HTTP version must be auto or 1.1")
	}

	if req.Proxy != "" {
		// tls-client forbids combining WithDialContext with WithProxyUrl: the
		// proxy owns the CONNECT handshake and egress resolution. Egress IP
		// filtering is then the proxy's responsibility; the network-layer SSRF
		// guard only applies to direct dials.
		opts = append(opts, tls_client.WithProxyUrl(req.Proxy))
	} else {
		opts = append(opts, tls_client.WithDialContext(dialCapture))
	}

	if jar := t.jarFor(req); jar != nil {
		opts = append(opts, tls_client.WithCookieJar(jar))
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("netrt.tlsTransport: new client: %w", err)
	}
	return client, &connectedIP, nil
}

func (t *tlsTransport) RoundTrip(ctx context.Context, req *Request) (*Response, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = dialTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	client, connectedIP, err := t.buildClient(req)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	hreq, err := http.NewRequestWithContext(ctx, method, req.URL, body)
	if err != nil {
		return nil, fmt.Errorf("netrt.tlsTransport: build request: %w", err)
	}
	if req.Header != nil {
		hreq.Header = req.Header.Clone()
	}
	applyHeaderOrder(hreq, req.HeaderOrder)

	hresp, err := client.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("netrt.tlsTransport: %w", err)
	}
	defer func() { _ = hresp.Body.Close() }()

	resp := &Response{
		RequestHeaders: hreq.Header.Clone(),
		StatusCode:     hresp.StatusCode,
		Header:         hresp.Header,
		ResponseTime:   time.Since(start),
		ContentLength:  hresp.ContentLength,
		Scheme:         hreq.URL.Scheme,
		HTTPVersion:    hresp.Proto,
		WebServer:      hresp.Header.Get("Server"),
		ContentType:    hresp.Header.Get("Content-Type"),
		Location:       hresp.Header.Get("Location"),
		CSP:            hresp.Header.Get("Content-Security-Policy"),
		IP:             *connectedIP,
	}
	delete(resp.RequestHeaders, http.HeaderOrderKey)

	resp.Body, resp.BodyTruncated, err = readCappedResult(hresp.Body, t.maxBody)
	resp.ResponseTime = time.Since(start)
	if err != nil {
		resp.Error = err
		return resp, fmt.Errorf("netrt: read response body: %w", err)
	}

	if hresp.TLS != nil {
		resp.TLS = buildTLSInfo(*hresp.TLS)
	} else if strings.EqualFold(hreq.URL.Scheme, "https") {
		// tls-client surfaces the ConnectionState on the HTTP/2 path but not on
		// HTTP/1.1 (fhttp only fills resp.TLS when the custom-dialed conn is a
		// *tls.Conn, whereas tls-client returns a *utls.UConn). For http/1.1
		// targets, capture the certificate with a best-effort fingerprinted TLS
		// peek so probe's cert extraction keeps working.
		resp.TLS = t.peekTLSInfo(ctx, req, hreq.URL.Hostname(), hreq.URL.Port())
	}
	if cname := lookupCNAME(ctx, t.resolver, hreq.URL.Hostname()); cname != "" {
		resp.CNAME = cname
	}
	// Cookies set during this request were written into the shared per-host jar
	// by the library (fhttp reads/writes http.Client.Jar on every round trip).
	// Surface them on the Response so upper layers can persist or log them.
	if jar := t.jarFor(req); jar != nil {
		if u, err := url.Parse(req.URL); err == nil {
			if cks := jar.Cookies(u); len(cks) > 0 {
				resp.Cookies = cks
			}
		}
	}
	return resp, nil
}

// jarFor returns the shared per-host CookieJar for req, or nil when per-host
// cookies are disabled. It lazily creates a jar on first contact with a host.
// The returned jar is safe for concurrent use (tls-client jar owns an RWMutex).
func (t *tlsTransport) jarFor(req *Request) tls_client.CookieJar {
	if t.cookies == nil {
		return nil
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		return nil
	}
	key := hostKey(req.URL)
	if key == "" {
		key = u.Host
	}
	t.cookies.mu.Lock()
	defer t.cookies.mu.Unlock()
	jar, ok := t.cookies.jars[key]
	if !ok {
		jar = tls_client.NewCookieJar()
		t.cookies.jars[key] = jar
	}
	return jar
}

// peekTLSInfo opens a best-effort fingerprinted TLS connection and reads its
// certificate. It is only used when the main request did not surface a
// ConnectionState (HTTP/1.1). Any error yields nil — the caller treats TLS
// metadata as optional.
func (t *tlsTransport) peekTLSInfo(ctx context.Context, req *Request, host, port string) *TLSInfo {
	if port == "" {
		port = "443"
	}
	opts := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profileOrDefault(req.Profile)),
		tls_client.WithServerNameOverwrite(host),
	}
	if !req.VerifyTLS {
		opts = append(opts, tls_client.WithInsecureSkipVerify())
	}
	if req.Proxy != "" {
		opts = append(opts, tls_client.WithProxyUrl(req.Proxy))
	} else {
		opts = append(opts, tls_client.WithDialContext(t.guardDialer()))
	}
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil
	}
	defer client.CloseIdleConnections()

	conn, err := client.GetTLSDialer()(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()
	if uc, ok := conn.(*tls.UConn); ok {
		return buildTLSInfo(uc.ConnectionState())
	}
	return nil
}

// roundTripNoGuard is a test helper that bypasses the dial guard so loopback
// test servers (httptest) are reachable. Not used by production code.
func (t *tlsTransport) roundTripNoGuard(ctx context.Context, req *Request) (*Response, error) {
	clone := *t
	clone.noGuard = true
	return clone.RoundTrip(ctx, req)
}

// --- rawTransport ---------------------------------------------------------

// rawTransport writes Request.Raw verbatim over a connection, enabling malformed
// packets, request smuggling and CRLF injection. For https it borrows a
// fingerprinted TLS connection from a tls-client (GetTLSDialer) so even raw
// probing keeps the browser JA3/JA4; for http it dials directly. Both paths run
// through the dial guard so loopback/link-local remain blocked.
type rawTransport struct {
	maxBody  int
	resolver *net.Resolver

	// noGuard disables the dial guard for tests only (see tlsTransport.noGuard).
	noGuard bool
}

func newRawTransport(maxBody int) *rawTransport {
	if maxBody <= 0 {
		maxBody = defaultMaxBodySize
	}
	return &rawTransport{maxBody: maxBody, resolver: net.DefaultResolver}
}

func (t *rawTransport) RoundTrip(ctx context.Context, req *Request) (*Response, error) {
	if req.Proxy != "" {
		return nil, fmt.Errorf("netrt.rawTransport: proxy is unsupported for raw requests")
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = dialTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("netrt.rawTransport: parse url: %w", err)
	}
	if _, err := HTTPURL(req.URL); err != nil {
		return nil, err
	}
	host := u.Hostname()
	port := u.Port()
	useTLS := strings.EqualFold(u.Scheme, "https")
	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)

	base := &net.Dialer{Timeout: dialTimeout}
	var guard func(ctx context.Context, network, addr string) (net.Conn, error)
	if t.noGuard {
		guard = base.DialContext
	} else {
		guard = guardedDialContext(base, t.resolver)
	}

	var conn net.Conn
	var tlsInfo *TLSInfo

	if useTLS {
		// Borrow the tls-client fingerprinted TLS dialer, but layer it on top of
		// the guarded raw dialer so the SSRF guard still runs before connect.
		opts := []tls_client.HttpClientOption{
			tls_client.WithClientProfile(profileOrDefault(req.Profile)),
			tls_client.WithForceHttp1(),
			tls_client.WithServerNameOverwrite(host),
			tls_client.WithDialContext(guard),
		}
		if req.TLSConfig != nil {
			opts = append(opts, tls_client.WithTransportOptions(&tls_client.TransportOptions{RootCAs: req.TLSConfig.Roots, Certificates: req.TLSConfig.Certificates}))
		}
		if !req.VerifyTLS {
			opts = append(opts, tls_client.WithInsecureSkipVerify())
		}
		client, cerr := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
		if cerr != nil {
			return nil, fmt.Errorf("netrt.rawTransport: new client: %w", cerr)
		}
		defer client.CloseIdleConnections()

		tlsConn, derr := client.GetTLSDialer()(ctx, "tcp", addr)
		if derr != nil {
			return nil, fmt.Errorf("netrt.rawTransport: tls dial: %w", derr)
		}
		conn = tlsConn
		if uc, ok := tlsConn.(*tls.UConn); ok {
			tlsInfo = buildTLSInfo(uc.ConnectionState())
		}
	} else {
		plainConn, derr := guard(ctx, "tcp", addr)
		if derr != nil {
			return nil, fmt.Errorf("netrt.rawTransport: dial: %w", derr)
		}
		conn = plainConn
	}
	defer func() { _ = conn.Close() }()

	connectedIP := ""
	if ra := conn.RemoteAddr(); ra != nil {
		if h, _, e := net.SplitHostPort(ra.String()); e == nil {
			connectedIP = h
		}
	}

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	if _, err := conn.Write(req.Raw); err != nil {
		return nil, fmt.Errorf("netrt.rawTransport: write: %w", err)
	}

	br := bufio.NewReader(io.LimitReader(conn, int64(t.maxBody)+8192))
	resp := &Response{
		ResponseTime: time.Since(start),
		Scheme:       u.Scheme,
		IP:           connectedIP,
		TLS:          tlsInfo,
	}

	// Best-effort parse: malformed responses still yield raw bytes in Body.
	if hresp, perr := http.ReadResponse(br, nil); perr == nil {
		resp.StatusCode = hresp.StatusCode
		resp.Header = hresp.Header
		resp.HTTPVersion = hresp.Proto
		resp.ContentLength = hresp.ContentLength
		resp.WebServer = hresp.Header.Get("Server")
		resp.ContentType = hresp.Header.Get("Content-Type")
		resp.Location = hresp.Header.Get("Location")
		resp.Body, resp.BodyTruncated, err = readCappedResult(hresp.Body, t.maxBody)
		_ = hresp.Body.Close()
	} else {
		resp.Body, resp.BodyTruncated, err = readCappedResult(br, t.maxBody)
	}
	resp.ResponseTime = time.Since(start)
	if err != nil {
		resp.Error = err
		return resp, fmt.Errorf("netrt: read raw response: %w", err)
	}
	return resp, nil
}

// roundTripNoGuard is a test helper: builds a raw Request and bypasses the dial
// guard so loopback listeners are reachable. Not used by production code.
func (t *rawTransport) roundTripNoGuard(ctx context.Context, rawURL string, raw []byte) (*Response, error) {
	clone := *t
	clone.noGuard = true
	return clone.RoundTrip(ctx, &Request{URL: rawURL, Raw: raw})
}

// --- helpers --------------------------------------------------------------

// applyHeaderOrder wires the browser header order into the fhttp request via
// the magic HeaderOrderKey so the on-wire order matches the TLS fingerprint.
func applyHeaderOrder(hreq *http.Request, order []string) {
	if len(order) == 0 {
		return
	}
	if hreq.Header == nil {
		hreq.Header = http.Header{}
	}
	hreq.Header[http.HeaderOrderKey] = append([]string(nil), order...)
}

func readCappedResult(r io.Reader, max int) ([]byte, bool, error) {
	if max <= 0 {
		max = defaultMaxBodySize
	}
	b, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if len(b) > max {
		return b[:max], true, err
	}
	return b, false, err
}

func lookupCNAME(ctx context.Context, r *net.Resolver, host string) string {
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	if r == nil {
		r = net.DefaultResolver
	}
	cname, err := r.LookupCNAME(ctx, host)
	if err != nil {
		return ""
	}
	cname = strings.TrimSuffix(cname, ".")
	if strings.EqualFold(cname, host) {
		return ""
	}
	return cname
}

func buildTLSInfo(state tlsConnState) *TLSInfo {
	info := &TLSInfo{
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		Version:     tls.VersionName(state.Version),
	}
	if len(state.PeerCertificates) == 0 {
		return info
	}
	leaf := state.PeerCertificates[0]
	info.Subject = leaf.Subject.String()
	info.Issuer = leaf.Issuer.String()
	info.SANs = leaf.DNSNames
	info.NotBefore = leaf.NotBefore
	info.NotAfter = leaf.NotAfter
	sum := sha256.Sum256(leaf.Raw)
	info.FingerprintSHA256 = hex.EncodeToString(sum[:])
	return info
}
