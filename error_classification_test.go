package netloom

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func classifyFailDNSResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("test resolver unavailable")
		},
	}
}

func classifyClosedPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func classifyConnectTimeout(t *testing.T) error {
	t.Helper()
	ctx, clock, err := newPhaseClock(context.Background(), &Request{
		URL:           "http://connect-timeout.invalid",
		PhaseTimeouts: &PhaseTimeouts{Connect: 30 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clock.finish()
	var scope clientDialScope
	scope.begin(ctx)
	defer scope.end(false)
	dial := scope.wrapDial(func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	_, err = dial(context.Background(), "tcp", "connect-timeout.invalid:80")
	return clock.failure(ctx, err)
}

func classifyTLSHandshakeFailure(t *testing.T) error {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	e := phaseEngine(t, PhaseTimeouts{}, false)
	_, err = e.Send(context.Background(), &Request{
		URL:     "https://" + listener.Addr().String() + "/",
		Timeout: 2 * time.Second,
	})
	return err
}

func maxBytesError(t *testing.T) error {
	t.Helper()
	body := http.MaxBytesReader(httptest.NewRecorder(), io.NopCloser(strings.NewReader("0123456789")), 4)
	defer body.Close()
	_, err := io.ReadAll(body)
	if err == nil {
		t.Fatal("expected a response body limit error")
	}
	return err
}

func TestClassifyAndMessage(t *testing.T) {
	const secret = "s3cr3t-proxy-password"

	cases := []struct {
		name        string
		err         func(t *testing.T) error
		wantKind    ErrorKind
		wantPhase   Phase
		wantTimeout bool
	}{
		{
			name: "dns",
			err: func(t *testing.T) error {
				e := phaseEngine(t, PhaseTimeouts{}, false)
				e.tlsT.(*tlsTransport).resolver = classifyFailDNSResolver()
				_, err := e.Send(context.Background(), &Request{URL: "http://dns.invalid/", Timeout: 2 * time.Second})
				return err
			},
			wantKind:  ErrorKindDNS,
			wantPhase: PhaseConnect,
		},
		{
			name: "connect-refused",
			err: func(t *testing.T) error {
				e := phaseEngine(t, PhaseTimeouts{}, false)
				_, err := e.Send(context.Background(), &Request{URL: "http://" + classifyClosedPort(t) + "/", Timeout: 2 * time.Second})
				return err
			},
			wantKind:  ErrorKindConnectRefused,
			wantPhase: PhaseConnect,
		},
		{
			name:        "connect-timeout",
			err:         classifyConnectTimeout,
			wantKind:    ErrorKindConnectTimeout,
			wantPhase:   PhaseConnect,
			wantTimeout: true,
		},
		{
			name: "tls-verify",
			err: func(t *testing.T) error {
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
				server.Config.ErrorLog = log.New(io.Discard, "", 0)
				server.StartTLS()
				t.Cleanup(server.Close)
				e := phaseEngine(t, PhaseTimeouts{}, false)
				_, err := e.Send(context.Background(), &Request{URL: server.URL, VerifyTLS: true, Timeout: 2 * time.Second})
				return err
			},
			wantKind:  ErrorKindTLSVerify,
			wantPhase: PhaseTLS,
		},
		{
			name:      "tls-handshake",
			err:       classifyTLSHandshakeFailure,
			wantKind:  ErrorKindTLSHandshake,
			wantPhase: PhaseTLS,
		},
		{
			name: "response-header-timeout",
			err: func(t *testing.T) error {
				server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					<-r.Context().Done()
				}))
				t.Cleanup(server.Close)
				e := phaseEngine(t, PhaseTimeouts{ResponseHeader: 50 * time.Millisecond}, false)
				_, err := e.Send(context.Background(), &Request{URL: server.URL, Timeout: 2 * time.Second})
				return err
			},
			wantKind:    ErrorKindResponseHeaderTimeout,
			wantPhase:   PhaseResponseHeader,
			wantTimeout: true,
		},
		{
			name: "body-idle-timeout",
			err: func(t *testing.T) error {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Length", "10")
					_, _ = io.WriteString(w, "a")
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				}))
				t.Cleanup(server.Close)
				e := phaseEngine(t, PhaseTimeouts{BodyIdle: 50 * time.Millisecond}, false)
				_, err := e.Send(context.Background(), &Request{URL: server.URL, Timeout: 2 * time.Second})
				return err
			},
			wantKind:    ErrorKindBodyTimeout,
			wantPhase:   PhaseBody,
			wantTimeout: true,
		},
		{
			name: "body-read-interrupted",
			err: func(t *testing.T) error {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Length", "10")
					_, _ = io.WriteString(w, "abc")
					w.(http.Flusher).Flush()
				}))
				t.Cleanup(server.Close)
				e := phaseEngine(t, PhaseTimeouts{}, false)
				_, err := e.Send(context.Background(), &Request{URL: server.URL, Timeout: 2 * time.Second})
				return err
			},
			wantKind:  ErrorKindBodyRead,
			wantPhase: PhaseBody,
		},
		{
			name: "body-limit",
			err: func(t *testing.T) error {
				return &PhaseError{Phase: PhaseBody, Err: maxBytesError(t)}
			},
			wantKind:  ErrorKindBodyLimit,
			wantPhase: PhaseBody,
		},
		{
			name: "redirect-limit",
			err: func(t *testing.T) error {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, "/next", http.StatusFound)
				}))
				t.Cleanup(server.Close)
				e := phaseEngine(t, PhaseTimeouts{}, false)
				_, err := Do(context.Background(), e, &Request{URL: server.URL, Timeout: 2 * time.Second}, RedirectPolicy{Follow: true, MaxHops: 2})
				return err
			},
			wantKind: ErrorKindRedirectLimit,
		},
		{
			name: "blocked-address",
			err: func(t *testing.T) error {
				e, err := New(Config{Retries: -1, RatePerSecond: 10000})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = e.Close() })
				_, err = e.Send(context.Background(), &Request{URL: "http://127.0.0.1:1/", Timeout: 2 * time.Second})
				return err
			},
			wantKind:  ErrorKindBlockedAddress,
			wantPhase: PhaseConnect,
		},
		{
			name: "invalid-proxy",
			err: func(t *testing.T) error {
				e := phaseEngine(t, PhaseTimeouts{}, false)
				_, err := e.Send(context.Background(), &Request{
					URL:     "http://proxy-target.invalid/",
					Proxy:   "http://user:" + secret + "@127.0.0.1:8080/path",
					Timeout: 2 * time.Second,
				})
				return err
			},
			wantKind: ErrorKindProxy,
		},
		{
			name: "engine-closed",
			err: func(t *testing.T) error {
				e, err := New(Config{Retries: -1, RatePerSecond: 10000})
				if err != nil {
					t.Fatal(err)
				}
				if err := e.Close(); err != nil {
					t.Fatal(err)
				}
				_, err = e.Send(context.Background(), &Request{URL: "http://closed.invalid/"})
				return err
			},
			wantKind: ErrorKindEngineClosed,
		},
		{
			name: "invalid-request",
			err: func(t *testing.T) error {
				e := phaseEngine(t, PhaseTimeouts{}, false)
				_, err := e.Send(context.Background(), nil)
				return err
			},
			wantKind: ErrorKindInvalidRequest,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.err(t)
			if err == nil {
				t.Fatal("expected an error")
			}
			kind, phase, timeout := Classify(err)
			if kind != tc.wantKind || phase != tc.wantPhase || timeout != tc.wantTimeout {
				t.Fatalf("Classify = (%s, %q, %v), want (%s, %q, %v); err=%v",
					kind, phase, timeout, tc.wantKind, tc.wantPhase, tc.wantTimeout, err)
			}

			msg := Message(err)
			if msg == "" {
				t.Fatal("Message returned an empty string")
			}
			if strings.ContainsAny(msg, "\r\n") {
				t.Fatalf("Message is not single-line: %q", msg)
			}
			if strings.Contains(msg, "netloom: ") {
				t.Fatalf("Message retained a library prefix: %q", msg)
			}
			if strings.HasPrefix(msg, "netloom") {
				t.Fatalf("Message starts with the library name: %q", msg)
			}
			if strings.Contains(msg, secret) {
				t.Fatalf("Message leaked a credential: %q", msg)
			}
			if tc.wantPhase != "" && !strings.HasPrefix(msg, string(tc.wantPhase)+": ") {
				t.Fatalf("Message lost phase %q: %q", tc.wantPhase, msg)
			}
			if tc.name == "invalid-proxy" && strings.Contains(msg, "127.0.0.1") {
				t.Fatalf("Message echoed the proxy endpoint: %q", msg)
			}
		})
	}
}

func TestClassifyNilAndUnprovenErrors(t *testing.T) {
	if kind, phase, timeout := Classify(nil); kind != ErrorKindUnknown || phase != "" || timeout {
		t.Fatalf("Classify(nil) = (%s, %q, %v)", kind, phase, timeout)
	}
	if msg := Message(nil); msg != "" {
		t.Fatalf("Message(nil) = %q", msg)
	}

	plain := errors.New("boom")
	if kind, phase, timeout := Classify(plain); kind != ErrorKindUnknown || phase != "" || timeout {
		t.Fatalf("unproven error classified as (%s, %q, %v)", kind, phase, timeout)
	}
	if msg := Message(plain); msg != "boom" {
		t.Fatalf("Message(plain) = %q", msg)
	}

	// A phase alone is not proof of a more specific failure.
	unproven := &PhaseError{Phase: PhaseConnect, Err: errors.New("opaque failure")}
	if kind, phase, timeout := Classify(unproven); kind != ErrorKindUnknown || phase != PhaseConnect || timeout {
		t.Fatalf("unproven phased error classified as (%s, %q, %v)", kind, phase, timeout)
	}
	if msg := Message(unproven); msg != "connect: opaque failure" {
		t.Fatalf("Message(unproven) = %q", msg)
	}

	// Caller cancellation is not turned into a body or handshake diagnosis.
	canceled := &PhaseError{Phase: PhaseBody, Err: context.Canceled}
	if kind, phase, timeout := Classify(canceled); kind != ErrorKindUnknown || phase != PhaseBody || timeout {
		t.Fatalf("canceled error classified as (%s, %q, %v)", kind, phase, timeout)
	}
}

func TestClassifyPrecedence(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		wantKind    ErrorKind
		wantPhase   Phase
		wantTimeout bool
	}{
		{
			name:        "dns-timeout-stays-dns",
			err:         &PhaseError{Phase: PhaseConnect, Err: &net.DNSError{Err: "timeout", Name: "dns.invalid", IsTimeout: true}},
			wantKind:    ErrorKindDNS,
			wantPhase:   PhaseConnect,
			wantTimeout: true,
		},
		{
			name:        "tls-timeout-is-handshake",
			err:         &PhaseError{Phase: PhaseTLS, Err: context.DeadlineExceeded},
			wantKind:    ErrorKindTLSHandshake,
			wantPhase:   PhaseTLS,
			wantTimeout: true,
		},
		{
			name:        "blocked-beats-connect",
			err:         &PhaseError{Phase: PhaseConnect, Err: fmt.Errorf("dial: %w", ErrBlockedAddress)},
			wantKind:    ErrorKindBlockedAddress,
			wantPhase:   PhaseConnect,
			wantTimeout: false,
		},
		{
			name:        "body-limit-beats-body-read",
			err:         &PhaseError{Phase: PhaseBody, Err: &http.MaxBytesError{Limit: 1}},
			wantKind:    ErrorKindBodyLimit,
			wantPhase:   PhaseBody,
			wantTimeout: false,
		},
		{
			name:        "generic-timeout",
			err:         &PhaseError{Phase: PhaseTotal, Err: context.DeadlineExceeded},
			wantKind:    ErrorKindTimeout,
			wantPhase:   PhaseTotal,
			wantTimeout: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, phase, timeout := Classify(tc.err)
			if kind != tc.wantKind || phase != tc.wantPhase || timeout != tc.wantTimeout {
				t.Fatalf("Classify = (%s, %q, %v), want (%s, %q, %v)",
					kind, phase, timeout, tc.wantKind, tc.wantPhase, tc.wantTimeout)
			}
		})
	}
}

func TestMessageFormatting(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "phase-and-multiline",
			err:  &PhaseError{Phase: PhaseConnect, Err: errors.New("netloom: first line\nsecond\r\nthird")},
			want: "connect: first line; second; third",
		},
		{
			name: "wrapped-sentinel",
			err:  fmt.Errorf("netloom.Engine.Send: %w", ErrNilRequest),
			want: "nil request",
		},
		{
			name: "known-sentinel",
			err:  ErrEngineClosed,
			want: "engine closed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Message(tc.err); got != tc.want {
				t.Fatalf("Message = %q, want %q", got, tc.want)
			}
		})
	}
}
