package netloom

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestNetworkBindingValidation(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "::", "::ffff:0.0.0.0", "224.0.0.1", "ff02::1", "255.255.255.255", "localhost", "127.0.0.1:80", "[::1]", "::1%lo", " 127.0.0.1", "127.0.0.1\n"} {
		t.Run(s, func(t *testing.T) {
			if err := (NetworkOptions{LocalAddress: s}).Validate(); !errors.Is(err, ErrNetworkBindingInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	for _, s := range []string{".", "..", "a/b", "a:b", "a b", "a\tb", "a\x00b", "a\nb", "网卡", strings.Repeat("x", 16)} {
		if err := (NetworkOptions{Interface: s}).Validate(); !errors.Is(err, ErrNetworkBindingInvalid) {
			t.Errorf("interface=%q err=%v", s, err)
		}
	}
	for _, s := range []string{"127.0.0.1", "192.0.2.2", "::1", "2001:db8::1", "::ffff:192.0.2.2", "fe80::1"} {
		if err := (NetworkOptions{LocalAddress: s}).Validate(); err != nil {
			t.Errorf("source=%q err=%v", s, err)
		}
	}
	for _, o := range []NetworkOptions{{LocalAddress: "127.0.0.1", AddressFamily: AddressFamilyIPv6}, {LocalAddress: "::1", AddressFamily: AddressFamilyIPv4}} {
		if err := o.Validate(); !errors.Is(err, ErrNetworkBindingInvalid) {
			t.Errorf("conflict err=%v", err)
		}
	}
	for _, name := range []string{"lo", "eth0.100", strings.Repeat("z", 15)} {
		err := (NetworkOptions{Interface: name}).Validate()
		if runtime.GOOS == "linux" {
			if err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(err, ErrNetworkBindingUnsupported) {
			t.Fatalf("nonLinux err=%v", err)
		}
	}
}

func TestNetworkBindingPlanAndDialerCopy(t *testing.T) {
	var first string
	for _, o := range []*NetworkOptions{{LocalAddress: "127.0.0.1"}, {LocalAddress: "::ffff:127.0.0.1"}, {LocalAddress: "127.0.0.1", AddressFamily: AddressFamilyIPv4}} {
		p, err := compileNetworkOptions(o)
		if err != nil {
			t.Fatal(err)
		}
		if !p.enabled() || !p.bindingEnabled() || p.family != AddressFamilyIPv4 || p.localAddress.String() != "127.0.0.1" {
			t.Fatalf("plan=%+v", p)
		}
		if first == "" {
			first = p.identity
		} else if first != p.identity {
			t.Fatal("equivalent source identities differ")
		}
	}
	source := &NetworkOptions{LocalAddress: "127.0.0.1"}
	ctx := networkContext(t, source)
	base := &net.Dialer{Timeout: time.Second, KeepAlive: 23 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 9), Port: 1234}}
	bound := networkDialer(ctx, base)
	if bound == base || bound.Timeout != base.Timeout || bound.KeepAlive != base.KeepAlive {
		t.Fatal("dialer not copied")
	}
	local := bound.LocalAddr.(*net.TCPAddr)
	if local.IP.String() != "127.0.0.1" || local.Port != 0 {
		t.Fatalf("local=%v", local)
	}
	local.IP[0] = 99
	if base.LocalAddr.String() != "127.0.0.9:1234" || networkDialer(ctx, base).LocalAddr.String() != "127.0.0.1:0" {
		t.Fatal("dialer mutation leaked")
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := dialWithNetworkBinding(cancelCtx, base, "tcp", "127.0.0.1:1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel err=%v", err)
	}
	if !permanentRetryError(errors.Join(ErrNetworkBinding, syscall.EADDRNOTAVAIL)) || !permanentRetryError(ErrNetworkBindingUnsupported) || !permanentRetryError(ErrNetworkBindingInvalid) {
		t.Fatal("binding errors retried")
	}
}

func TestNetworkBindingPlatformErrors(t *testing.T) {
	for _, code := range []syscall.Errno{10013, 10047, 10049} {
		if got := isPlatformBindingError(&net.OpError{Op: "dial", Net: "tcp", Err: code}); got != (runtime.GOOS == "windows") {
			t.Fatalf("platform code=%d classified=%t", code, got)
		}
	}
	if isPlatformBindingError(context.Canceled) {
		t.Fatal("cancellation is not a binding failure")
	}
}

func TestNetworkBindingIPv6Transport(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) {
			t.Skipf("IPv6 loopback unavailable; actual IPv6 binding not tested: %v", err)
		}
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		_, _ = io.WriteString(w, host+"|"+r.Proto)
	}))
	_ = server.Listener.Close()
	server.Listener = listener
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	engine := pooledEngine(t, 4)
	engine.rawT.(*rawTransport).noGuard = true // controlled local IPv6 server only
	for _, mode := range []string{"1.1/buffer", "1.1/stream", "2/buffer", "2/stream", "2-only/buffer", "2-only/stream", "raw"} {
		t.Run(mode, func(t *testing.T) {
			version, operation, _ := strings.Cut(mode, "/")
			if mode == "raw" {
				version, operation = "1.1", "raw"
			}
			req := &Request{URL: server.URL, HTTPVersion: version, Timeout: 2 * time.Second, Network: &NetworkOptions{LocalAddress: "::1"}}
			response, err := tlsControlSend(engine, req, operation)
			if err != nil {
				t.Fatal(err)
			}
			proto := "HTTP/1.1"
			if version != "1.1" {
				proto = "HTTP/2.0"
			}
			if string(response.Body) != "::1|"+proto || response.IP != "::1" {
				t.Fatalf("IPv6 response=%+v body=%q", response, response.Body)
			}
		})
	}
}

func TestNetworkBindingControlComposition(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux control composition not exercised; unsupported-platform validation is tested separately")
	}
	ctx := networkContext(t, &NetworkOptions{Interface: "lo"})
	marker := errors.New("existing control error")
	for _, useContext := range []bool{false, true} {
		var calls atomic.Int32
		base := &net.Dialer{Control: func(string, string, syscall.RawConn) error { calls.Add(1); return marker }}
		if useContext {
			base.ControlContext = func(context.Context, string, string, syscall.RawConn) error { calls.Add(10); return marker }
		}
		bound := networkDialer(ctx, base)
		if err := bound.ControlContext(ctx, "tcp4", "127.0.0.1:80", nil); !errors.Is(err, marker) {
			t.Fatalf("control err=%v", err)
		}
		want := int32(1)
		if useContext {
			want = 10
		}
		if calls.Load() != want {
			t.Fatalf("calls=%d want=%d", calls.Load(), want)
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if err := bound.ControlContext(canceled, "tcp4", "127.0.0.1:80", nil); !errors.Is(err, context.Canceled) || calls.Load() != want {
			t.Fatalf("cancel control err=%v calls=%d", err, calls.Load())
		}
	}
}

func TestNetworkBindingFamilyGuardAndNoFallback(t *testing.T) {
	for _, source := range []string{"192.0.2.3", "2001:db8::3"} {
		opts := &NetworkOptions{LocalAddress: source, Resolve: []ResolveRule{{Host: "logical.test", Port: 443, Addresses: []string{"2001:db8::2", "192.0.2.2", "2001:db8::4", "192.0.2.4"}}}}
		var calls atomic.Int32
		dial := mappedDialContext(func(_ context.Context, _, addr string) (net.Conn, error) {
			calls.Add(1)
			host, _, _ := net.SplitHostPort(addr)
			if netip.MustParseAddr(host).Is4() != netip.MustParseAddr(source).Is4() {
				t.Errorf("cross-family dial %s", addr)
			}
			return nil, ErrNetworkBinding
		}, nil, true)
		if _, err := dial(networkContext(t, opts), "tcp", "logical.test:443"); !errors.Is(err, ErrNetworkBinding) || calls.Load() != 1 {
			t.Fatalf("err=%v calls=%d", err, calls.Load())
		}
	}
	for _, guarded := range []bool{false, true} {
		opts := &NetworkOptions{LocalAddress: "127.0.0.1"}
		ctx := networkContext(t, opts)
		var dial func(context.Context, string, string) (net.Conn, error)
		if guarded {
			dial = guardedDialContext(&net.Dialer{}, nil)
		} else {
			dial = mappedDialContext(func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("blocked target dialed")
				return nil, nil
			}, nil, false)
		}
		if _, err := dial(ctx, "tcp", "127.0.0.1:80"); !errors.Is(err, ErrBlockedAddress) {
			t.Fatalf("guard err=%v", err)
		}
	}
}

func TestNetworkBindingPreflightAndProxy(t *testing.T) {
	engine := pooledEngine(t, 1)
	for _, stream := range []bool{false, true} {
		for _, opts := range []*NetworkOptions{{LocalAddress: "0.0.0.0"}, {LocalAddress: "127.0.0.1", AddressFamily: AddressFamilyIPv6}, {Interface: "invalid/name"}, {LocalAddress: "127.0.0.1"}} {
			var opens atomic.Int32
			upload, _ := NewReplayableUpload(0, func(context.Context) (io.ReadCloser, error) {
				opens.Add(1)
				return io.NopCloser(strings.NewReader("")), nil
			})
			req := &Request{URL: "https://logical.test", Method: "POST", Network: opts, Upload: upload}
			want := ErrNetworkBindingInvalid
			if opts.LocalAddress == "127.0.0.1" && opts.AddressFamily == "" {
				req.Proxy = "http://127.0.0.1:1"
				want = ErrNetworkProxyUnsupported
			}
			var err error
			if stream {
				_, err = engine.SendStream(context.Background(), req)
			} else {
				_, err = engine.Send(context.Background(), req)
			}
			if !errors.Is(err, want) || opens.Load() != 0 {
				t.Fatalf("stream=%t err=%v opens=%d", stream, err, opens.Load())
			}
		}
	}
}

func TestNetworkBindingUnavailableSourceNoRetry(t *testing.T) {
	// Pick an unassigned documentation IP; never configure an interface or contact
	// that IP as a destination. A local listener proves bind failure sends no HTTP.
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	assigned := map[string]bool{}
	for _, a := range addresses {
		prefix, err := netip.ParsePrefix(a.String())
		if err == nil {
			assigned[prefix.Addr().Unmap().String()] = true
		}
	}
	source := ""
	for _, ip := range []string{"192.0.2.254", "198.51.100.254", "203.0.113.254"} {
		if !assigned[ip] {
			source = ip
			break
		}
	}
	if source == "" {
		t.Skip("all documentation source candidates assigned; unassigned-source failure not tested")
	}
	probe, probeErr := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(source)})
	if probeErr == nil {
		_ = probe.Close()
		t.Skip("kernel permits nonlocal source binding; unavailable-source failure not tested")
	}
	var kernelCause syscall.Errno
	if !errors.As(probeErr, &kernelCause) {
		t.Fatalf("unavailable-source probe lost kernel error: %v", probeErr)
	}
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer server.Close()
	engine := pooledEngine(t, 1)
	for _, stream := range []bool{false, true} {
		var observed atomic.Int32
		req := &Request{URL: server.URL, Network: &NetworkOptions{LocalAddress: source}, RetryPolicy: &RetryPolicy{MaxRetries: 3, Observer: func(info AttemptInfo) {
			observed.Add(1)
			if info.WillRetry {
				t.Error("permanent source failure retried")
			}
		}}}
		var err error
		if stream {
			_, err = engine.SendStream(context.Background(), req)
		} else {
			_, err = engine.Send(context.Background(), req)
		}
		var op *net.OpError
		if !errors.Is(err, ErrNetworkBinding) || !errors.As(err, &op) || !errors.Is(err, kernelCause) || observed.Load() != 1 || hits.Load() != 0 {
			t.Fatalf("stream=%t err=%v observed=%d hits=%d", stream, err, observed.Load(), hits.Load())
		}
	}
	// A failed binding must release the exclusive client slot.
	r, err := engine.Send(context.Background(), &Request{URL: server.URL, Network: &NetworkOptions{LocalAddress: "127.0.0.1"}, Timeout: time.Second})
	if err != nil || r.StatusCode != 200 || hits.Load() != 1 {
		t.Fatalf("recovery=%+v err=%v hits=%d", r, err, hits.Load())
	}
}
