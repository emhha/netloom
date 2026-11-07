package netloom

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

// dialHTTPProxy deliberately supports HTTP CONNECT only. tls-client's
// HTTP/1 CONNECT exchange uses a fixed socket timeout rather than cancellation
// of the request context. Owning this socket lets strict requests honor caller
// cancellation even while waiting for the proxy's CONNECT response.
func dialHTTPProxy(ctx context.Context, proxyURL, network, target string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("netloom: HTTP CONNECT requires a TCP network")
	}
	u, err := url.Parse(proxyURL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("netloom: invalid HTTP proxy URL")
	}
	if u.Scheme != "http" {
		return nil, fmt.Errorf("netloom: this proxy dialer supports only http:// proxies")
	}
	if u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("netloom: HTTP proxy URL cannot contain a path, query or fragment")
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "80")
	}
	raw, err := phaseDialer(ctx, &net.Dialer{Timeout: dialTimeout}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	owned := false
	defer func() {
		stop()
		if !owned {
			_ = raw.Close()
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: target}, Host: target, Header: make(http.Header)}
	if u.User != nil {
		password, _ := u.User.Password()
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+password)))
	}
	if err := request.Write(raw); err != nil {
		return nil, err
	}
	limited := &io.LimitedReader{R: raw, N: 64 << 10}
	reader := bufio.NewReader(limited)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		if limited.N == 0 {
			return nil, fmt.Errorf("netloom: HTTP proxy CONNECT response headers exceed 64 KiB")
		}
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("netloom: HTTP proxy CONNECT returned status %d", response.StatusCode)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	// Retain any bytes buffered beyond the CONNECT headers without imposing the
	// header limit on the subsequent TLS/H2 tunnel.
	limited.N = math.MaxInt64
	owned = true
	return &http2ProxyReaderConn{Conn: raw, reader: reader}, nil
}

// httpProxyContextDialer can also be supplied to tls-client's proxy factory.
// Unlike the dependency's HTTP/1 CONNECT dialer it honors cancellation during
// the CONNECT exchange, not just the initial TCP dial.
type httpProxyContextDialer struct{ proxyURL string }

func (d *httpProxyContextDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return dialHTTPProxy(ctx, d.proxyURL, network, addr)
}

func (d *httpProxyContextDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

type http2ProxyReaderConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *http2ProxyReaderConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
