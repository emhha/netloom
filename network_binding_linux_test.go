//go:build linux

package netloom

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/bogdanfinn/fhttp/httptrace"
	"golang.org/x/sys/unix"
)

// Probe only the requested kernel socket option, independently of production
// code. EPERM/EACCES are explicit missing coverage, not successful bind evidence.
func networkBindingProbeLoopbackDevice(t *testing.T) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("create SO_BINDTODEVICE capability probe: %v", err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "lo"); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("Linux SO_BINDTODEVICE lo probe failed: %v; current process lacks permission, actual interface binding NOT tested", err)
		}
		t.Fatalf("Linux SO_BINDTODEVICE lo probe failed (not a permission skip): %v", err)
	}
}

func TestNetworkBindingInterfaceTLS(t *testing.T) {
	networkBindingProbeLoopbackDevice(t)
	networkBindingTLSMatrix(t, "lo")
}

func TestNetworkBindingInterfaceActualSocketAndPoolIdentity(t *testing.T) {
	networkBindingProbeLoopbackDevice(t)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		_, _ = io.WriteString(w, host)
	}))
	defer s.Close()
	e := pooledEngine(t, 2)
	type evidence struct {
		local, device string
		err           error
	}
	observed := make(chan evidence, 1)
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		conn := info.Conn
		// The lease scope intentionally wraps the actual TCP socket.
		if scoped, ok := conn.(*scopedConn); ok {
			conn = scoped.Conn
		}
		ev := evidence{local: conn.LocalAddr().String()}
		raw, ok := conn.(syscall.Conn)
		if !ok {
			ev.err = fmt.Errorf("actual HTTP socket %T does not expose syscall.Conn", conn)
			observed <- ev
			return
		}
		rc, err := raw.SyscallConn()
		if err != nil {
			ev.err = err
			observed <- ev
			return
		}
		err = rc.Control(func(fd uintptr) {
			ev.device, ev.err = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
		})
		if err != nil {
			ev.err = err
		}
		observed <- ev
	}})
	send := func(device string) evidence {
		t.Helper()
		r, err := e.Send(ctx, &Request{URL: s.URL, HTTPVersion: "1.1", Timeout: 2 * time.Second, Network: &NetworkOptions{LocalAddress: "127.0.0.2", Interface: device}})
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Body) != "127.0.0.2" {
			t.Fatalf("actual source=%q", r.Body)
		}
		select {
		case ev := <-observed:
			if ev.err != nil {
				t.Fatal(ev.err)
			}
			if ev.device != device {
				t.Fatalf("actual socket SO_BINDTODEVICE=%q want %q", ev.device, device)
			}
			return ev
		case <-time.After(time.Second):
			t.Fatal("missing actual socket trace")
			return evidence{}
		}
	}
	a := send("")
	b := send("lo")
	c := send("lo")
	d := send("")
	if a.local == b.local {
		t.Fatalf("different interface policies reused socket: %q", a.local)
	}
	if a.local != d.local || b.local != c.local {
		t.Fatalf("same-interface policy did not reuse: %+v %+v %+v %+v", a, b, c, d)
	}
}

func TestNetworkBindingInterfaceMissingNoFallback(t *testing.T) {
	// A short valid name known not to exist; do not alter interface configuration.
	const missing = "netloom-missing"
	if _, err := net.InterfaceByName(missing); err == nil {
		t.Fatalf("test requires nonexistent interface %q", missing)
	}
	var calls atomic.Int32
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, "must not arrive")
	}))
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	for _, mode := range []string{"1.1/buffer", "1.1/stream", "2/buffer", "2/stream", "2-only/buffer", "2-only/stream", "raw"} {
		t.Run(mode, func(t *testing.T) {
			e := pooledEngine(t, 1)
			e.rawT.(*rawTransport).noGuard = true
			req := &Request{URL: s.URL, Timeout: time.Second, Network: &NetworkOptions{Interface: missing, LocalAddress: "127.0.0.1"}}
			version, operation := "1.1", "buffer"
			switch mode {
			case "1.1/stream":
				operation = "stream"
			case "2/buffer":
				version = "2"
			case "2/stream":
				version, operation = "2", "stream"
			case "2-only/buffer":
				version = "2-only"
			case "2-only/stream":
				version, operation = "2-only", "stream"
			case "raw":
				operation = "raw"
			}
			req.HTTPVersion = version
			if _, err := tlsControlSend(e, req, operation); !errors.Is(err, ErrNetworkBinding) {
				t.Fatalf("missing interface must fail applying binding, got %v", err)
			} else if !errors.Is(err, unix.ENODEV) && !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EACCES) {
				t.Fatalf("missing interface lost kernel device/permission cause: %v", err)
			}
			if calls.Load() != 0 {
				t.Fatalf("missing interface reached HTTP handler: %d", calls.Load())
			}
			// The failed bind must not strand the one available pool slot.
			req.Network.Interface = ""
			r, err := tlsControlSend(e, req, operation)
			if err != nil || r == nil {
				t.Fatalf("pool did not recover after bind failure: response=%+v err=%v", r, err)
			}
			calls.Store(0)
		})
	}
}
