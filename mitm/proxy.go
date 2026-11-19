package mitm

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Backend interface {
	CheckTarget(context.Context, *url.URL) error
	RoundTrip(*http.Request) (*http.Response, error)
}

var ErrBusy = errors.New("mitm: capture queue full")

type Proxy struct {
	authority   *Authority
	backend     Backend
	username    string
	realm       string
	password    [32]byte
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closed      bool
}

// Options supplies proxy authentication. An empty username disables authentication.
type Options struct{ Username, Password, Realm string }

func New(authority *Authority, backend Backend, opts Options) *Proxy {
	realm := opts.Realm
	if realm == "" {
		realm = "netloom"
	}
	realm = strings.NewReplacer("\r", "", "\n", "", "\"", "", "\\", "").Replace(realm)
	return &Proxy{authority: authority, backend: backend, username: opts.Username, realm: realm, password: sha256.Sum256([]byte(opts.Password)), connections: make(map[net.Conn]struct{})}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		http.Error(w, "proxy stopped", http.StatusServiceUnavailable)
		return
	}
	encoded := strings.TrimPrefix(r.Header.Get("Proxy-Authorization"), "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	user, password, ok := strings.Cut(string(decoded), ":")
	actual := sha256.Sum256([]byte(password))
	if p.username != "" && (!strings.HasPrefix(r.Header.Get("Proxy-Authorization"), "Basic ") || err != nil || !ok || user != p.username || subtle.ConstantTimeCompare(actual[:], p.password[:]) != 1) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="`+p.realm+`"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	p.forward(w, r, "")
}

func authority(host, scheme string) string {
	u, err := url.Parse(scheme + "://" + host)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse("https://" + r.Host)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		http.Error(w, "invalid CONNECT target", http.StatusBadRequest)
		return
	}
	if err := p.backend.CheckTarget(r.Context(), u); err != nil {
		http.Error(w, "target rejected by backend", http.StatusForbidden)
		return
	}
	cert, err := p.authority.Certificate(u.Hostname())
	if err != nil {
		http.Error(w, "certificate unavailable", http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT requires HTTP/1.1", http.StatusNotImplemented)
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	p.mu.Lock()
	if p.closed || len(p.connections) >= 32 {
		p.mu.Unlock()
		_ = conn.Close()
		return
	}
	p.connections[conn] = struct{}{}
	p.mu.Unlock()
	defer func() { _ = conn.Close(); p.mu.Lock(); delete(p.connections, conn); p.mu.Unlock() }()
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	// Preserve bytes already read before Hijack. Once those bytes are used,
	// read directly from the tunnel. The outer HTTP reader can cancel the
	// CONNECT context when the inner server interrupts a pending read.
	bufferedPrefix := io.LimitReader(buffered.Reader, int64(buffered.Reader.Buffered()))
	tlsConn := tls.Server(&bufferedConn{Conn: conn, reader: io.MultiReader(bufferedPrefix, conn)}, &tls.Config{
		MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" && !strings.EqualFold(hello.ServerName, u.Hostname()) {
				return nil, fmt.Errorf("mitm: SNI differs from CONNECT target")
			}
			return cert, nil
		},
	})
	handshakeCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	err = tlsConn.HandshakeContext(handshakeCtx)
	cancel()
	if err != nil {
		return
	}
	listener := newSingleListener(tlsConn)
	defer func() { _ = listener.Close() }()
	server := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, inner *http.Request) { p.forward(w, inner, u.Host) }),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10,
		BaseContext: func(net.Listener) context.Context { return r.Context() },
	}
	_ = server.Serve(listener)
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, tunnel string) {
	request := r.Clone(r.Context())
	if tunnel != "" {
		if authority(r.Host, "https") != authority(tunnel, "https") ||
			(r.URL.IsAbs() && (r.URL.Scheme != "https" || authority(r.URL.Host, "https") != authority(tunnel, "https"))) {
			http.Error(w, "request differs from CONNECT target", http.StatusForbidden)
			return
		}
		request.URL.Scheme, request.URL.Host = "https", tunnel
	} else if !request.URL.IsAbs() || request.URL.Scheme != "http" {
		http.Error(w, "absolute HTTP URL or HTTPS CONNECT required", http.StatusBadRequest)
		return
	}
	if request.URL.User != nil || request.URL.Fragment != "" || len(request.URL.String()) > 8192 ||
		authority(request.Host, request.URL.Scheme) != authority(request.URL.Host, request.URL.Scheme) {
		http.Error(w, "invalid proxy URL or Host", http.StatusBadRequest)
		return
	}
	if err := p.backend.CheckTarget(r.Context(), request.URL); err != nil {
		http.Error(w, "target rejected by backend", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" {
		http.Error(w, "nested CONNECT and protocol upgrades are unsupported", http.StatusNotImplemented)
		return
	}
	if len(request.Header) > 64 {
		http.Error(w, "too many headers", http.StatusRequestHeaderFieldsTooLarge)
		return
	}
	request.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	defer func() { _ = request.Body.Close() }()
	stripHopHeaders(request.Header)
	request.RequestURI = ""
	response, err := p.backend.RoundTrip(request)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request body exceeds 256KB", http.StatusRequestEntityTooLarge)
			return
		}
		if errors.Is(err, ErrBusy) {
			http.Error(w, "capture queue full; retry later", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "proxy upstream request unavailable", http.StatusBadGateway)
		return
	}
	defer func() { _ = response.Body.Close() }()
	stripHopHeaders(response.Header)
	for name, values := range response.Header {
		w.Header()[name] = append([]string(nil), values...)
	}
	w.WriteHeader(response.StatusCode)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(flushingWriter{w}, response.Body)
	}
}

func stripHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}

type flushingWriter struct{ http.ResponseWriter }

func (w flushingWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}

func (p *Proxy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for conn := range p.connections {
		_ = conn.Close()
	}
}

type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

type singleListener struct {
	conn     net.Conn
	accepted bool
	done     chan struct{}
	once     sync.Once
}

func newSingleListener(conn net.Conn) *singleListener {
	l := &singleListener{done: make(chan struct{})}
	l.conn = &notifyingConn{Conn: conn, notify: l.Close}
	return l
}
func (l *singleListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *singleListener) Close() error {
	l.once.Do(func() { close(l.done); _ = l.conn.(*notifyingConn).Conn.Close() })
	return nil
}
func (l *singleListener) Addr() net.Addr { return l.conn.LocalAddr() }

type notifyingConn struct {
	net.Conn
	notify func() error
}

func (c *notifyingConn) Close() error { return c.notify() }
