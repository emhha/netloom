package netloom

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
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
	cookies        *cookieStore
	pool           *clientPool
	defaultProfile profiles.ClientProfile
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
	t := &tlsTransport{maxBody: maxBody, resolver: net.DefaultResolver, defaultProfile: cloneClientProfile(profiles.DefaultClientProfile)}
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
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			return phaseDialer(ctx, base).DialContext(ctx, network, addr)
		}
	}
	return guardedDialContext(base, t.resolver)
}

// buildClient constructs an immutable-config client, leased to one request at
// a time. Connection evidence is recorded per request, never in a client closure.
func (t *tlsTransport) buildClient(req *Request, scope *clientDialScope) (tls_client.HttpClient, error) {
	guard := mappedDialContext(t.guardDialer(), t.resolver, t.noGuard)
	dialCapture := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := guard(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		recordConnectedIP(ctx, conn)
		return conn, nil
	}

	transportOptions := &tls_client.TransportOptions{DisableCompression: true}
	if t.pool != nil {
		idleTimeout := t.pool.idleTimeout
		transportOptions.IdleConnTimeout = &idleTimeout
		transportOptions.MaxIdleConns = 1
		transportOptions.MaxIdleConnsPerHost = 1
		transportOptions.MaxConnsPerHost = 1
	}
	if req.TLSConfig != nil {
		transportOptions.RootCAs = req.TLSConfig.Roots
		transportOptions.Certificates = req.TLSConfig.Certificates
	}
	// The context owns the precise request deadline. For direct requests we
	// disable the client's independent timer. tls-client's CONNECT dialer,
	// however, treats a zero timeout as an already-expired socket deadline,
	// so proxy clients need a positive (rounded-up) fallback as well.
	var clientTimeoutMS int
	if req.Proxy != "" {
		clientTimeoutMS = proxyTimeoutMilliseconds(req.Timeout)
	}
	profile := req.Profile
	id := profile.GetClientHelloId()
	if id.IsSet() {
		profile = profileOrDefault(t.defaultProfile)
	}
	opts := []tls_client.HttpClientOption{
		tls_client.WithTimeoutMilliseconds(clientTimeoutMS),
		tls_client.WithClientProfile(profile),
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
	case "", "auto", "2", "2-only":
		opts = append(opts, tls_client.WithDisableHttp3())
	case "1.1":
		opts = append(opts, tls_client.WithForceHttp1())
	default:
		return nil, fmt.Errorf("netloom: HTTP version must be auto, 1.1, 2 or 2-only")
	}

	if req.Proxy != "" {
		// The proxy owns egress resolution/filtering; direct-dial guarding does
		// not apply to its tunnel. For HTTP proxies replace the dependency's
		// CONNECT exchange, which otherwise ignores cancellation while reading
		// its response. Use only WithDialContext for this case: tls-client rejects
		// combining it (or a proxy factory) with WithProxyUrl. The request/key
		// retain the actual proxy URL; this private client never exports GetProxy.
		if u, err := url.Parse(req.Proxy); err == nil && u.Scheme == "http" {
			dialer := &httpProxyContextDialer{proxyURL: req.Proxy}
			opts = append(opts, tls_client.WithDialContext(scope.wrapDial(dialer.DialContext)))
		} else {
			opts = append(opts, tls_client.WithProxyUrl(req.Proxy))
		}
	} else {
		opts = append(opts, tls_client.WithDialContext(scope.wrapDial(dialCapture)))
	}

	if jar := t.jarFor(req); jar != nil {
		opts = append(opts, tls_client.WithCookieJar(jar))
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil, fmt.Errorf("netloom.tlsTransport: new client: %w", err)
	}
	return client, nil
}

// doRequest pins the Engine's default profile snapshot for strict H2 too.
func (t *tlsTransport) doRequest(client tls_client.HttpClient, req *Request, hreq *http.Request) (_ *http.Response, returnErr error) {
	defer func() {
		if clock := phaseClockFrom(hreq.Context()); clock != nil {
			returnErr = clock.failure(hreq.Context(), returnErr)
		} else if returnErr != nil {
			if cause := requestContextError(hreq.Context()); cause != nil {
				returnErr = cause
			}
		}
	}()
	if req.HTTPVersion == "2-only" {
		requestCopy := *req
		id := requestCopy.Profile.GetClientHelloId()
		if id.IsSet() {
			requestCopy.Profile = profileOrDefault(t.defaultProfile)
		}
		req = &requestCopy
	}
	response, err := doHTTPRequest(client, req, hreq)
	if err == nil && response != nil {
		enterPhase(hreq.Context(), PhaseBody)
	}
	return response, err
}

func (t *tlsTransport) RoundTrip(ctx context.Context, req *Request) (*Response, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = dialTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	ctx, clock, err := newPhaseClock(ctx, req)
	if err != nil {
		return nil, err
	}
	defer clock.finish()
	ctx, observation := observe(ctx, start)
	observation.proxy = req.Proxy != ""
	lease, err := t.acquireClient(ctx, req)
	if err != nil {
		return nil, clock.failure(ctx, err)
	}
	reusable := false
	defer func() { clock.stop(); lease.release(reusable) }()
	client := lease.client

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
		return nil, fmt.Errorf("netloom.tlsTransport: build request: %w", err)
	}
	if req.Header != nil {
		hreq.Header = req.Header.Clone()
	}
	applyHeaderOrder(hreq, req.HeaderOrder)

	hresp, err := t.doRequest(client, req, hreq)
	if err != nil {
		return nil, fmt.Errorf("netloom.tlsTransport: %w", err)
	}
	hresp.Body = wrapPhaseBody(ctx, hresp.Body)
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
		IP:             observation.connectedIP(),
	}
	delete(resp.RequestHeaders, http.HeaderOrderKey)

	headersAt := time.Now()
	resp.Body, resp.BodyTruncated, err = readCappedResult(hresp.Body, t.maxBody)
	finishedAt := time.Now()
	resp.ResponseTime = finishedAt.Sub(start)
	timing, actualTLS := observation.snapshot()
	timing.HeadersMS = milliseconds(headersAt.Sub(start))
	timing.BodyMS = milliseconds(finishedAt.Sub(headersAt))
	timing.TotalMS = milliseconds(finishedAt.Sub(start))
	resp.Timings, resp.TLS = &timing, actualTLS
	if hresp.TLS != nil {
		resp.TLS = buildTLSInfo(*hresp.TLS)
	}
	if err != nil {
		err = clock.failure(ctx, err)
		resp.Error = err
		return resp, fmt.Errorf("netloom: read response body: %w", err)
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
	reusable = !resp.BodyTruncated
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

func (t *rawTransport) RoundTrip(ctx context.Context, req *Request) (_ *Response, returnErr error) {
	if req.Proxy != "" {
		if _, err := withNetworkOptions(ctx, req); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("netloom.rawTransport: proxy is unsupported for raw requests")
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
		return nil, fmt.Errorf("netloom.rawTransport: parse url: %w", err)
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

	ctx, clock, err := newPhaseClock(ctx, req)
	if err != nil {
		return nil, err
	}
	defer clock.finish()
	defer func() { returnErr = clock.failure(ctx, returnErr) }()
	if err := validateNetworkLogicalTarget(ctx, req, t.noGuard); err != nil {
		return nil, err
	}
	scope := &clientDialScope{}
	scope.begin(ctx)
	// Stop phase timers before detaching cancellation; finish only after all
	// raw sockets (including ones still in TLS setup) have been cleaned up.
	defer func() { clock.stop(); scope.end(false) }()

	base := &net.Dialer{Timeout: dialTimeout}
	var guard func(ctx context.Context, network, addr string) (net.Conn, error)
	if t.noGuard {
		guard = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return phaseDialer(ctx, base).DialContext(ctx, network, addr)
		}
	} else {
		guard = guardedDialContext(base, t.resolver)
	}

	guard = scope.wrapDial(mappedDialContext(guard, t.resolver, t.noGuard))
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
			return nil, fmt.Errorf("netloom.rawTransport: new client: %w", cerr)
		}
		defer client.CloseIdleConnections()

		tlsConn, derr := client.GetTLSDialer()(ctx, "tcp", addr)
		if derr != nil {
			return nil, fmt.Errorf("netloom.rawTransport: tls dial: %w", derr)
		}
		conn = tlsConn
		if uc, ok := tlsConn.(*tls.UConn); ok {
			tlsInfo = buildTLSInfo(uc.ConnectionState())
		}
	} else {
		plainConn, derr := guard(ctx, "tcp", addr)
		if derr != nil {
			return nil, fmt.Errorf("netloom.rawTransport: dial: %w", derr)
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
	enterPhase(ctx, PhaseRequest)
	if _, err := conn.Write(req.Raw); err != nil {
		return nil, fmt.Errorf("netloom.rawTransport: write: %w", err)
	}
	enterPhase(ctx, PhaseResponseHeader)

	br := bufio.NewReader(io.LimitReader(conn, int64(t.maxBody)+8192))
	resp := &Response{
		ResponseTime: time.Since(start),
		Scheme:       u.Scheme,
		IP:           connectedIP,
		TLS:          tlsInfo,
	}

	// Best-effort parse: malformed responses still yield raw bytes in Body.
	hresp, perr := http.ReadResponse(br, nil)
	for perr == nil && hresp.StatusCode >= 100 && hresp.StatusCode < 200 && hresp.StatusCode != 101 {
		_ = hresp.Body.Close()
		hresp, perr = http.ReadResponse(br, nil)
	}
	if perr == nil {
		enterPhase(ctx, PhaseBody)
		resp.StatusCode = hresp.StatusCode
		resp.Header = hresp.Header
		resp.HTTPVersion = hresp.Proto
		resp.ContentLength = hresp.ContentLength
		resp.WebServer = hresp.Header.Get("Server")
		resp.ContentType = hresp.Header.Get("Content-Type")
		resp.Location = hresp.Header.Get("Location")
		hresp.Body = wrapPhaseBody(ctx, hresp.Body)
		resp.Body, resp.BodyTruncated, err = readCappedResult(hresp.Body, t.maxBody)
		_ = hresp.Body.Close()
	} else {
		// Malformed protocol bytes remain best-effort evidence, but a failed
		// header read must not turn cancellation or a timeout into success.
		resp.Body, resp.BodyTruncated, err = readCappedResult(br, t.maxBody)
		var timeoutErr net.Error
		if cause := requestContextError(ctx); cause != nil {
			err = cause
		} else if errors.Is(perr, context.Canceled) || errors.Is(perr, context.DeadlineExceeded) || errors.As(perr, &timeoutErr) && timeoutErr.Timeout() {
			err = perr
		}
	}
	resp.ResponseTime = time.Since(start)
	if err != nil {
		err = clock.failure(ctx, err)
		resp.Error = err
		return resp, fmt.Errorf("netloom: read raw response: %w", err)
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

// requestContextError also handles a dependency's timer firing after the
// effective deadline but before the context timer goroutine has been scheduled.
// It is only used to classify an existing read/close failure, not successful IO.
func requestContextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		var phaseErr *PhaseError
		if cause := context.Cause(ctx); errors.As(cause, &phaseErr) {
			return cause
		} else if cause != nil && cause != err {
			return errors.Join(err, cause)
		}
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		if total, ok := ctx.Value(totalBudgetKey{}).(time.Time); ok && total.Equal(deadline) {
			return &PhaseError{Phase: PhaseTotal, Err: context.DeadlineExceeded}
		}
		return context.DeadlineExceeded
	}
	return nil
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
	// Mapping must not trigger a second lookup of the logical origin merely
	// for enrichment; it may be intentionally absent from local DNS.
	if plan, _ := ctx.Value(networkPlanKey{}).(*networkPlan); plan.enabled() {
		return ""
	}
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
