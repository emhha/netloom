package netloom

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func phaseRawServer(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		handler(conn)
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	return listener.Addr().String()
}

func requireRawPhase(t *testing.T, err error, phase Phase) {
	t.Helper()
	var failure *PhaseError
	if !errors.As(err, &failure) || failure.Phase != phase || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want %s deadline, got %v", phase, err)
	}
}

func TestPhaseRawStalls(t *testing.T) {
	for _, phase := range []Phase{PhaseTLS, PhaseResponseHeader, PhaseBody} {
		t.Run(string(phase), func(t *testing.T) {
			addr := phaseRawServer(t, func(conn net.Conn) {
				if phase == PhaseTLS {
					_, _ = io.Copy(io.Discard, conn)
					return
				}
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				if phase == PhaseBody {
					_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\npartial")
				}
				_, _ = io.Copy(io.Discard, reader)
			})
			scheme := "http://"
			phases := &PhaseTimeouts{}
			switch phase {
			case PhaseTLS:
				scheme = "https://"
				phases.TLSHandshake = 60 * time.Millisecond
			case PhaseResponseHeader:
				phases.ResponseHeader = 60 * time.Millisecond
			case PhaseBody:
				phases.BodyIdle = 60 * time.Millisecond
			}
			transport := newRawTransport(1024)
			transport.noGuard = true
			start := time.Now()
			response, err := transport.RoundTrip(context.Background(), &Request{URL: scheme + addr, Raw: []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"), Timeout: 2 * time.Second, PhaseTimeouts: phases})
			requireRawPhase(t, err, phase)
			if time.Since(start) > time.Second {
				t.Fatal("phase deadline did not interrupt socket promptly")
			}
			if phase == PhaseBody {
				if response == nil || response.StatusCode != 200 || string(response.Body) != "partial" || response.Error == nil {
					t.Fatalf("lost partial evidence: %#v", response)
				}
			}
		})
	}
}

func TestPhaseRawTruncatedBody(t *testing.T) {
	addr := phaseRawServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\npartial")
	})
	transport := newRawTransport(1024)
	transport.noGuard = true
	response, err := transport.RoundTrip(context.Background(), &Request{URL: "http://" + addr, Raw: []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")})
	var failure *PhaseError
	if !errors.Is(err, io.ErrUnexpectedEOF) || !errors.As(err, &failure) || failure.Phase != PhaseBody || response == nil || string(response.Body) != "partial" {
		t.Fatalf("lost failed-body evidence: %#v %v", response, err)
	}
}

func TestPhaseRawTotal(t *testing.T) {
	addr := phaseRawServer(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\npartial")
		_, _ = io.Copy(io.Discard, reader)
	})
	transport := newRawTransport(1024)
	transport.noGuard = true
	scheduler := &scheduler{cfg: Config{Timeout: 2 * time.Second, Retries: 2, PhaseTimeouts: PhaseTimeouts{Total: 60 * time.Millisecond}}, rawT: transport}
	response, err := scheduler.sendWithRetry(context.Background(), &Request{URL: "http://" + addr, Raw: []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")})
	requireRawPhase(t, err, PhaseTotal)
	if response == nil || response.StatusCode != 200 || string(response.Body) != "partial" {
		t.Fatalf("lost total timeout evidence: %#v", response)
	}
}

func TestPhaseDoTotalRedirectChain(t *testing.T) {
	calls := 0
	var firstDeadline time.Time
	sender := redirectSender(func(ctx context.Context, req *Request) (*Response, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("missing total deadline")
		}
		if calls == 1 {
			firstDeadline = deadline
			select {
			case <-time.After(50 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return &Response{StatusCode: 302, Location: "/next"}, nil
		}
		if !deadline.Equal(firstDeadline) {
			t.Fatal("redirect reset total budget")
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	input := &Request{URL: "http://example.test/", PhaseTimeouts: &PhaseTimeouts{Total: 120 * time.Millisecond}}
	exchange, err := Do(context.Background(), sender, input, RedirectPolicy{Follow: true})
	requireRawPhase(t, err, PhaseTotal)
	if calls != 2 || exchange == nil || exchange.Response.StatusCode != 302 || len(exchange.Hops) != 1 {
		t.Fatalf("lost redirect evidence: calls=%d %#v", calls, exchange)
	}
	if input.URL != "http://example.test/" || input.PhaseTimeouts.Total != 120*time.Millisecond {
		t.Fatal("mutated caller request")
	}
}

func TestPhaseDoTotalPolicy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sender   Sender
		phases   *PhaseTimeouts
		deadline bool
	}{
		{"engine inheritance", &Engine{cfg: Config{PhaseTimeouts: PhaseTimeouts{Total: time.Second}}}, nil, true},
		{"zero override", &Engine{cfg: Config{PhaseTimeouts: PhaseTimeouts{Total: time.Second}}}, &PhaseTimeouts{}, false},
		{"custom sender", redirectSender(nil), nil, false},
		{"custom request policy", redirectSender(nil), &PhaseTimeouts{Total: time.Second}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sentinel := errors.New("validation stops send")
			input := &Request{URL: "http://example.test/", PhaseTimeouts: tc.phases}
			_, err := Do(context.Background(), tc.sender, input, RedirectPolicy{ValidateURL: func(ctx context.Context, _ string) error {
				_, ok := ctx.Deadline()
				if ok != tc.deadline {
					t.Fatalf("deadline=%v, want %v", ok, tc.deadline)
				}
				return sentinel
			}})
			if !errors.Is(err, sentinel) {
				t.Fatal(err)
			}
			if input.PhaseTimeouts != tc.phases {
				t.Fatal("mutated caller policy")
			}
		})
	}
}
