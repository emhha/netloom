package netloom

import (
	"context"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

func tlsControlPins(cert *x509.Certificate) (good, bad string) {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	good = "sha256//" + base64.StdEncoding.EncodeToString(sum[:])
	sum[0] ^= 0x80
	bad = "sha256//" + base64.StdEncoding.EncodeToString(sum[:])
	return
}

func tlsControlRequest(t *testing.T, s *httptest.Server, logical string) *Request {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	return &Request{URL: "https://" + logical + "/probe", HTTPVersion: "1.1", VerifyTLS: true, Timeout: 2 * time.Second, TLSConfig: &TLSOptions{Roots: roots}, Network: &NetworkOptions{ConnectTo: []ConnectToRule{{Host: logical, Port: 443, ConnectHost: "127.0.0.1", ConnectPort: networkTransportPort(t, s.Listener.Addr())}}}}
}

func tlsControlSend(e *Engine, req *Request, mode string) (*Response, error) {
	if mode == "raw" {
		req.Raw = []byte("GET /probe HTTP/1.1\r\nHost: logical.test\r\nConnection: close\r\n\r\n")
	}
	if mode != "stream" {
		return e.Send(context.Background(), req)
	}
	stream, err := e.SendStream(context.Background(), req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(stream.Body)
	closeErr := stream.Body.Close()
	if err != nil {
		return stream.Response, err
	}
	if closeErr != nil {
		return stream.Response, closeErr
	}
	response := *stream.Response
	response.Body = body
	return &response, nil
}

func TestTLSControlsTransportVersionsAndIdentity(t *testing.T) {
	for _, version := range []struct {
		name TLSVersion
		wire uint16
	}{{TLSVersion12, stdtls.VersionTLS12}, {TLSVersion13, stdtls.VersionTLS13}} {
		for _, mode := range []string{"1.1/buffer", "1.1/stream", "2/buffer", "2/stream", "2-only/buffer", "2-only/stream", "raw"} {
			t.Run(string(version.name)+"/"+mode, func(t *testing.T) {
				var connections, hits atomic.Int32
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					_, _ = fmt.Fprintf(w, "%x|%s|%s|%s", r.TLS.Version, r.Host, r.TLS.ServerName, r.Proto)
				}))
				server.EnableHTTP2 = true
				server.TLS = &stdtls.Config{MinVersion: version.wire, MaxVersion: version.wire}
				server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateNew {
						connections.Add(1)
					}
				}
				server.StartTLS()
				defer server.Close()
				e := pooledEngine(t, 2)
				e.rawT.(*rawTransport).noGuard = true
				var dns atomic.Int32
				e.tlsT.(*tlsTransport).resolver = networkTransportNoDNS(&dns)
				e.rawT.(*rawTransport).resolver = networkTransportNoDNS(&dns)
				req := tlsControlRequest(t, server, "logical.test")
				req.TLSConfig.MinVersion = version.name
				req.TLSConfig.MaxVersion = version.name
				req.TLSConfig.ServerName = "example.com"
				good, _ := tlsControlPins(server.Certificate())
				req.TLSConfig.PinnedPublicKeys = []string{good}
				protocol, operation, _ := strings.Cut(mode, "/")
				if mode == "raw" {
					protocol = "1.1"
					operation = "raw"
				}
				req.HTTPVersion = protocol
				response, err := tlsControlSend(e, req, operation)
				if err != nil {
					t.Fatal(err)
				}
				wantProto := "HTTP/1.1"
				if protocol != "1.1" {
					wantProto = "HTTP/2.0"
				}
				want := fmt.Sprintf("%x|logical.test|example.com|%s", version.wire, wantProto)
				if string(response.Body) != want {
					t.Fatalf("identity/version: got %q want %q", response.Body, want)
				}
				if response.TLS == nil || response.TLS.Version != utls.VersionName(version.wire) {
					t.Fatalf("actual TLS metadata=%+v", response.TLS)
				}
				if hits.Load() != 1 || connections.Load() != 1 || dns.Load() != 0 {
					t.Fatalf("hits=%d sockets=%d DNS=%d; no probe or logical DNS permitted", hits.Load(), connections.Load(), dns.Load())
				}
				if req.URL != "https://logical.test/probe" || req.TLSConfig.ServerName != "example.com" || req.TLSConfig.PinnedPublicKeys[0] != good {
					t.Fatal("controls mutated caller request")
				}
			})
		}
	}
}

func TestTLSControlsTransportPinsAndPKIAreIndependent(t *testing.T) {
	for _, mode := range []string{"1.1/buffer", "2/stream", "2-only/buffer", "raw"} {
		for _, failure := range []string{"wrong-pin-insecure", "wrong-pin-verified", "wrong-name", "wrong-ca"} {
			t.Run(mode+"/"+failure, func(t *testing.T) {
				var hits atomic.Int32
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
				server.EnableHTTP2 = true
				server.StartTLS()
				defer server.Close()
				e := pooledEngine(t, 2)
				e.rawT.(*rawTransport).noGuard = true
				req := tlsControlRequest(t, server, "logical.test")
				req.TLSConfig.ServerName = "example.com"
				good, bad := tlsControlPins(server.Certificate())
				req.TLSConfig.PinnedPublicKeys = []string{good}
				switch failure {
				case "wrong-pin-insecure":
					req.VerifyTLS = false
					req.TLSConfig.PinnedPublicKeys = []string{bad}
				case "wrong-pin-verified":
					req.TLSConfig.PinnedPublicKeys = []string{bad}
				case "wrong-name":
					req.TLSConfig.ServerName = "wrong.test"
				case "wrong-ca":
					req.TLSConfig.Roots = x509.NewCertPool()
				}
				protocol, operation, _ := strings.Cut(mode, "/")
				if mode == "raw" {
					protocol = "1.1"
					operation = "raw"
				}
				req.HTTPVersion = protocol
				_, err := tlsControlSend(e, req, operation)
				if err == nil {
					t.Fatal("accepted invalid TLS trust/pin policy")
				}
				if strings.HasPrefix(failure, "wrong-pin") && !errors.Is(err, ErrTLSPinMismatch) {
					t.Fatalf("pin failure lost identity: %v", err)
				}
				if failure == "wrong-name" {
					var mismatch x509.HostnameError
					if !errors.As(err, &mismatch) || mismatch.Host != "wrong.test" {
						t.Fatalf("explicit name was not verified: %v", err)
					}
				}
				if failure == "wrong-ca" {
					var unknown x509.UnknownAuthorityError
					if !errors.As(err, &unknown) {
						t.Fatalf("pin bypassed CA verification: %v", err)
					}
				}
				if hits.Load() != 0 {
					t.Fatalf("HTTP bytes sent before controls accepted: hits=%d", hits.Load())
				}
			})
		}
	}
}

func TestTLSControlsTransportPinIsolation(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); _, _ = io.WriteString(w, "ok") }))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	e := pooledEngine(t, 16)
	good, bad := tlsControlPins(server.Certificate())
	send := func(valid bool) error {
		req := tlsControlRequest(t, server, "example.com")
		req.VerifyTLS = false
		req.HTTPVersion = "2"
		pin := bad
		if valid {
			pin = good
		}
		req.TLSConfig.PinnedPublicKeys = []string{pin}
		response, err := e.Send(context.Background(), req)
		if valid {
			if err != nil {
				return fmt.Errorf("valid pin: %w", err)
			}
			if string(response.Body) != "ok" {
				return fmt.Errorf("body=%q", response.Body)
			}
			return nil
		}
		if !errors.Is(err, ErrTLSPinMismatch) {
			return fmt.Errorf("wrong pin accepted or identity lost: %v", err)
		}
		return nil
	}
	for _, valid := range []bool{true, false, true, false} {
		if err := send(valid); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	failures := make(chan error, 12)
	for i := range 12 {
		wg.Add(1)
		go func(valid bool) {
			defer wg.Done()
			if err := send(valid); err != nil {
				failures <- err
			}
		}(i%2 == 0)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if hits.Load() != 8 {
		t.Fatalf("same-host pin instances interfered: HTTP hits=%d want 8", hits.Load())
	}
}

func TestTLSControlsTransportVersionCannotSilentlyFallback(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	server.TLS = &stdtls.Config{MinVersion: stdtls.VersionTLS13, MaxVersion: stdtls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	e := pooledEngine(t, 2)
	for _, mode := range []string{"1.1/buffer", "2/stream", "2-only/buffer", "raw"} {
		t.Run(mode, func(t *testing.T) {
			e.rawT.(*rawTransport).noGuard = true
			req := tlsControlRequest(t, server, "example.com")
			req.TLSConfig.MaxVersion = TLSVersion12
			protocol, operation, _ := strings.Cut(mode, "/")
			if mode == "raw" {
				protocol = "1.1"
				operation = "raw"
			}
			req.HTTPVersion = protocol
			if _, err := tlsControlSend(e, req, operation); err == nil {
				t.Fatal("TLS 1.3 server accepted with maximum TLS 1.2")
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("version fallback sent HTTP: hits=%d", hits.Load())
	}
}

func TestTLSControlsTransportHTTPConnect(t *testing.T) {
	for _, mode := range []string{"1.1/buffer", "2/stream", "2-only/buffer"} {
		for _, valid := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/pin=%t", mode, valid), func(t *testing.T) {
				var hits, tunnels atomic.Int32
				target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					if r.Header.Get("Proxy-Authorization") != "" {
						t.Error("proxy credential reached origin")
					}
					_, _ = fmt.Fprintf(w, "%x|%s|%s", r.TLS.Version, r.Host, r.TLS.ServerName)
				}))
				target.EnableHTTP2 = true
				target.StartTLS()
				defer target.Close()
				proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodConnect || r.Host != "logical.test:443" {
						t.Errorf("CONNECT routed wrong logical origin: %s %s", r.Method, r.Host)
						http.Error(w, "CONNECT required", 400)
						return
					}
					tunnels.Add(1)
					upstream, err := net.DialTimeout("tcp", target.Listener.Addr().String(), time.Second)
					if err != nil {
						t.Error(err)
						http.Error(w, "dial failed", 502)
						return
					}
					defer upstream.Close()
					conn, rw, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
					if err := rw.Flush(); err != nil {
						return
					}
					done := make(chan struct{})
					go func() { _, _ = io.Copy(upstream, rw); _ = upstream.Close(); close(done) }()
					_, _ = io.Copy(conn, upstream)
					_ = conn.Close()
					<-done
				}))
				defer proxy.Close()
				e := pooledEngine(t, 2)
				e.rawT.(*rawTransport).noGuard = true
				req := tlsControlRequest(t, target, "logical.test")
				req.Network = nil
				req.Proxy = proxy.URL
				req.TLSConfig.ServerName = "example.com"
				req.TLSConfig.MaxVersion = TLSVersion12
				good, bad := tlsControlPins(target.Certificate())
				pin := bad
				if valid {
					pin = good
				}
				req.TLSConfig.PinnedPublicKeys = []string{pin}
				protocol, operation, _ := strings.Cut(mode, "/")
				if mode == "raw" {
					protocol = "1.1"
					operation = "raw"
				}
				req.HTTPVersion = protocol
				response, err := tlsControlSend(e, req, operation)
				if valid {
					if err != nil {
						t.Fatal(err)
					}
					if string(response.Body) != "303|logical.test|example.com" {
						t.Fatalf("proxy TLS controls hit wrong scope: %q", response.Body)
					}
					if hits.Load() != 1 {
						t.Fatalf("HTTP hits=%d", hits.Load())
					}
				} else {
					if !errors.Is(err, ErrTLSPinMismatch) {
						t.Fatalf("proxy pin error=%v", err)
					}
					if hits.Load() != 0 {
						t.Fatalf("wrong pin sent HTTP over tunnel: %d", hits.Load())
					}
				}
				if tunnels.Load() != 1 {
					t.Fatalf("CONNECT count=%d want one", tunnels.Load())
				}
			})
		}
	}
}

func TestTLSControlsTransportRawProxyRejectedBeforeConnect(t *testing.T) {
	var sockets atomic.Int32
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("Raw request connected to unsupported proxy") }))
	proxy.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			sockets.Add(1)
		}
	}
	proxy.Start()
	defer proxy.Close()
	e := pooledEngine(t, 2)
	e.rawT.(*rawTransport).noGuard = true
	req := &Request{URL: "https://example.com/", Proxy: proxy.URL, Raw: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), Timeout: time.Second, TLSConfig: &TLSOptions{ServerName: "example.com"}}
	if _, err := e.Send(context.Background(), req); err == nil {
		t.Fatal("Raw proxy unexpectedly accepted")
	}
	if sockets.Load() != 0 {
		t.Fatalf("unsupported Raw proxy opened %d sockets", sockets.Load())
	}
}

func tlsControlCustomSNIProfile(removeSNI bool) profiles.ClientProfile {
	base := profiles.Chrome_146
	id := base.GetClientHelloId()
	factory := id.SpecFactory
	originalID := id
	id.SpecFactory = func() (utls.ClientHelloSpec, error) {
		var spec utls.ClientHelloSpec
		var err error
		if factory != nil {
			spec, err = factory()
		} else {
			spec, err = utls.UTLSIdToSpec(originalID)
		}
		if err != nil {
			return spec, err
		}
		extensions := make([]utls.TLSExtension, 0, len(spec.Extensions))
		for _, ext := range spec.Extensions {
			if _, ok := ext.(*utls.SNIExtension); ok {
				if !removeSNI {
					extensions = append(extensions, &utls.SNIExtension{ServerName: "wrong.test"})
				}
				continue
			}
			extensions = append(extensions, ext)
		}
		spec.Extensions = extensions
		return spec, nil
	}
	return profiles.NewClientProfile(id, base.GetSettings(), base.GetSettingsOrder(), base.GetPseudoHeaderOrder(), base.GetConnectionFlow(), base.GetPriorities(), base.GetHeaderPriority(), base.GetStreamID(), base.GetAllowHTTP(), base.GetHttp3Settings(), base.GetHttp3SettingsOrder(), base.GetHttp3PriorityParam(), base.GetHttp3PseudoHeaderOrder(), base.GetHttp3SendGreaseFrames())
}

func TestTLSControlsTransportCustomProfileExplicitName(t *testing.T) {
	for _, mode := range []string{"1.1/buffer", "2/stream", "2-only/buffer", "raw"} {
		for _, name := range []string{"example.com", "127.0.0.1", "192.0.2.1", "missing-sni"} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				var hits atomic.Int32
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
					_, _ = fmt.Fprintf(w, "%s|%s", r.Host, r.TLS.ServerName)
				}))
				server.EnableHTTP2 = true
				server.StartTLS()
				defer server.Close()
				if err := server.Certificate().VerifyHostname("127.0.0.1"); err != nil {
					t.Fatalf("fixture must include IP SAN: %v", err)
				}
				e := pooledEngine(t, 2)
				e.rawT.(*rawTransport).noGuard = true
				req := tlsControlRequest(t, server, "logical.test")
				req.Profile = tlsControlCustomSNIProfile(name == "missing-sni")
				req.TLSConfig.ServerName = name
				if name == "missing-sni" {
					req.TLSConfig.ServerName = "example.com"
				}
				good, _ := tlsControlPins(server.Certificate())
				req.TLSConfig.PinnedPublicKeys = []string{good}
				protocol, operation, _ := strings.Cut(mode, "/")
				if mode == "raw" {
					protocol = "1.1"
					operation = "raw"
				}
				req.HTTPVersion = protocol
				response, err := tlsControlSend(e, req, operation)
				switch name {
				case "192.0.2.1":
					var mismatch x509.HostnameError
					if !errors.As(err, &mismatch) || mismatch.Host != name {
						t.Fatalf("IP verification name lost: %v", err)
					}
					if hits.Load() != 0 {
						t.Fatal("invalid IP certificate sent HTTP")
					}
				case "missing-sni":
					if !errors.Is(err, ErrTLSProfileConflict) {
						t.Fatalf("profile without SNI silently accepted: %v", err)
					}
					if hits.Load() != 0 {
						t.Fatal("conflicting profile sent HTTP")
					}
				default:
					if err != nil {
						t.Fatal(err)
					}
					wantSNI := name
					if net.ParseIP(name) != nil {
						wantSNI = ""
					}
					if string(response.Body) != "logical.test|"+wantSNI {
						t.Fatalf("profile name overrode explicit controls: body=%q", response.Body)
					}
					if hits.Load() != 1 {
						t.Fatalf("HTTP hits=%d", hits.Load())
					}
				}
			})
		}
	}
}

func TestTLSControlsTransportRedirectClearsControls(t *testing.T) {
	var finalHits atomic.Int32
	final := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalHits.Add(1)
		_, _ = io.WriteString(w, r.TLS.ServerName)
	}))
	final.StartTLS()
	defer final.Close()
	first := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://second.test/final")
		w.WriteHeader(http.StatusFound)
	}))
	first.StartTLS()
	defer first.Close()
	e := pooledEngine(t, 4)
	req := tlsControlRequest(t, first, "first.test")
	req.VerifyTLS = false
	req.TLSConfig.ServerName = "explicit.test"
	good, _ := tlsControlPins(first.Certificate())
	req.TLSConfig.PinnedPublicKeys = []string{good}
	req.TLSConfig.MinVersion = TLSVersion12
	req.Network.ConnectTo = append(req.Network.ConnectTo, ConnectToRule{Host: "second.test", Port: 443, ConnectHost: "127.0.0.1", ConnectPort: networkTransportPort(t, final.Listener.Addr())})
	exchange, err := Do(context.Background(), e, req, RedirectPolicy{Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	if exchange.Request.TLSConfig != nil || string(exchange.Response.Body) != "second.test" || finalHits.Load() != 1 {
		t.Fatalf("cross-origin controls retained: options=%+v body=%q hits=%d", exchange.Request.TLSConfig, exchange.Response.Body, finalHits.Load())
	}
	if req.TLSConfig == nil || req.TLSConfig.ServerName != "explicit.test" || len(req.TLSConfig.PinnedPublicKeys) != 1 {
		t.Fatal("redirect mutated caller TLS options")
	}
}
