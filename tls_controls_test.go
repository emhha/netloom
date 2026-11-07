package netloom

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

func tlsPolicyProfile(id tls.ClientHelloID) profiles.ClientProfile {
	return profiles.NewClientProfile(id, nil, nil, nil, 0, nil, nil, 0, false, nil, nil, 0, nil, false)
}

func TestTLSControlsBounds(t *testing.T) {
	source := &tls.SupportedVersionsExtension{Versions: []uint16{tls.GREASE_PLACEHOLDER, tls.VersionTLS13, tls.VersionTLS12}}
	id := tls.ClientHelloID{Client: "bounds-test", Version: "1", SpecFactory: func() (tls.ClientHelloSpec, error) {
		return tls.ClientHelloSpec{Extensions: []tls.TLSExtension{source}}, nil
	}}
	for _, tc := range []struct {
		name     string
		options  TLSOptions
		want     []uint16
		min, max uint16
	}{
		{"exact12", TLSOptions{MinVersion: TLSVersion12, MaxVersion: TLSVersion12}, []uint16{tls.GREASE_PLACEHOLDER, tls.VersionTLS12}, tls.VersionTLS12, tls.VersionTLS12},
		{"minimum13", TLSOptions{MinVersion: TLSVersion13}, []uint16{tls.GREASE_PLACEHOLDER, tls.VersionTLS13}, tls.VersionTLS13, tls.VersionTLS13},
		{"no-broadening", TLSOptions{MinVersion: TLSVersion10}, []uint16{tls.GREASE_PLACEHOLDER, tls.VersionTLS13, tls.VersionTLS12}, tls.VersionTLS12, tls.VersionTLS13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := boundedTLSHello(tlsPolicyProfile(id), &tc.options)
			if err != nil {
				t.Fatal(err)
			}
			got := spec.Extensions[0].(*tls.SupportedVersionsExtension)
			if !reflect.DeepEqual(got.Versions, tc.want) || spec.TLSVersMin != tc.min || spec.TLSVersMax != tc.max {
				t.Fatalf("bounds=%x..%x wire=%x", spec.TLSVersMin, spec.TLSVersMax, got.Versions)
			}
			got.Versions[0] = 0
			if source.Versions[0] != tls.GREASE_PLACEHOLDER || len(source.Versions) != 3 {
				t.Fatal("mutated source profile extension")
			}
		})
	}
	if _, err := boundedTLSHello(tlsPolicyProfile(id), &TLSOptions{MaxVersion: TLSVersion11}); !errors.Is(err, ErrTLSProfileConflict) {
		t.Fatalf("no overlap: %v", err)
	}
	// Built-ins can have nil or placeholder factories; neither may panic/fail.
	for _, builtin := range []tls.ClientHelloID{tls.HelloChrome_120, func() tls.ClientHelloID { id := tls.HelloChrome_120; id.SpecFactory = nil; return id }()} {
		if _, err := boundedTLSHello(tlsPolicyProfile(builtin), &TLSOptions{MaxVersion: TLSVersion12}); err != nil {
			t.Fatal(err)
		}
	}
	// Bounds in the source spec are constraints too, even with a broader wire list.
	id.SpecFactory = func() (tls.ClientHelloSpec, error) {
		return tls.ClientHelloSpec{TLSVersMin: tls.VersionTLS12, TLSVersMax: tls.VersionTLS12, Extensions: []tls.TLSExtension{source}}, nil
	}
	if _, err := boundedTLSHello(tlsPolicyProfile(id), &TLSOptions{MinVersion: TLSVersion13}); !errors.Is(err, ErrTLSProfileConflict) {
		t.Fatalf("source bound broadened: %v", err)
	}
	id.SpecFactory = func() (tls.ClientHelloSpec, error) {
		return tls.ClientHelloSpec{TLSVersMin: tls.VersionTLS10, TLSVersMax: tls.VersionTLS12}, nil
	}
	spec, err := boundedTLSHello(tlsPolicyProfile(id), &TLSOptions{MinVersion: TLSVersion11})
	if err != nil || spec.TLSVersMin != tls.VersionTLS11 || spec.TLSVersMax != tls.VersionTLS12 {
		t.Fatalf("legacy bounds=%+v error=%v", spec, err)
	}
	id.SpecFactory = func() (tls.ClientHelloSpec, error) {
		return tls.ClientHelloSpec{Extensions: []tls.TLSExtension{source, source}}, nil
	}
	if _, err := boundedTLSHello(tlsPolicyProfile(id), &TLSOptions{MaxVersion: TLSVersion12}); !errors.Is(err, ErrTLSProfileConflict) {
		t.Fatalf("duplicate supported versions: %v", err)
	}
}

func TestTLSControlsPolicyEarlyRejection(t *testing.T) {
	e := pooledEngine(t, 1)
	var dns atomic.Int32
	e.tlsT.(*tlsTransport).resolver = networkTransportNoDNS(&dns)
	for _, tc := range []struct {
		name, url, proxy string
		options          TLSOptions
		profile          profiles.ClientProfile
		want             error
	}{
		{name: "http", url: "http://example.com", options: TLSOptions{ServerName: "example.com"}, want: ErrTLSOptionsUnsupported},
		{name: "https-proxy", proxy: "https://proxy.example:443", options: TLSOptions{MinVersion: TLSVersion12}, want: ErrTLSOptionsUnsupported},
		{name: "socks", proxy: "socks5://proxy.example:1080", options: TLSOptions{ServerName: "example.com"}, want: ErrTLSOptionsUnsupported},
		{name: "explicit-profile", options: TLSOptions{MinVersion: TLSVersion12}, profile: profiles.Chrome_120, want: ErrTLSProfileConflict},
		{name: "no-default-overlap", options: TLSOptions{MaxVersion: TLSVersion11}, want: ErrTLSProfileConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := tc.url
			if u == "" {
				u = "https://example.com"
			}
			_, err := e.Send(context.Background(), &Request{URL: u, Proxy: tc.proxy, Profile: tc.profile, TLSConfig: &tc.options})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want %v", err, tc.want)
			}
		})
	}
	if dns.Load() != 0 {
		t.Fatalf("invalid TLS policy performed DNS: %d", dns.Load())
	}
	if err := validateTLSRequest(&Request{URL: "http://example.com", TLSConfig: &TLSOptions{}}); err != nil {
		t.Fatal("empty options changed HTTP defaults:", err)
	}
	if err := validateTLSRequest(&Request{URL: "https://example.com", Profile: profiles.Chrome_120, TLSConfig: &TLSOptions{ServerName: "example.com"}}); err != nil {
		t.Fatal("SNI alone must accept explicit profile:", err)
	}
}

func TestTLSControlsPinsLeafOnlyAndSnapshot(t *testing.T) {
	leaf := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("leaf")}
	issuer := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("issuer")}
	pin := func(cert *x509.Certificate) string {
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		return "sha256//" + base64.StdEncoding.EncodeToString(sum[:])
	}
	for _, verify := range []bool{false, true} {
		req := &Request{VerifyTLS: verify, TLSConfig: &TLSOptions{PinnedPublicKeys: []string{pin(issuer), pin(leaf)}}}
		config, err := tlsControlConfig(req, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		req.TLSConfig.PinnedPublicKeys[1] = pin(issuer)
		if err := config.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, issuer}}); err != nil {
			t.Fatalf("callback did not snapshot alternatives: %v", err)
		}
		if _, err = tlsControlConfig(req, "example.com"); err == nil {
			t.Fatal("duplicate options must be rejected")
		}
		req.TLSConfig.PinnedPublicKeys = []string{pin(issuer)}
		config, err = tlsControlConfig(req, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		if !errors.Is(config.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, issuer}}), ErrTLSPinMismatch) {
			t.Fatal("issuer pin accepted for leaf")
		}
		if !errors.Is(config.VerifyConnection(tls.ConnectionState{}), ErrTLSPinMismatch) {
			t.Fatal("absent leaf accepted")
		}
		if config.InsecureSkipVerify == verify {
			t.Fatal("pinning changed certificate verification flag")
		}
	}
}

func TestTLSControlsBuiltinNilFactory(t *testing.T) {
	id := tls.HelloChrome_120
	id.SpecFactory = nil
	makeConn, err := prepareTLSHandshake(&Request{TLSConfig: &TLSOptions{ServerName: "example.com"}}, "logical.test", tlsPolicyProfile(id), true)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	conn, err := makeConn(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	if conn.HandshakeState.Hello.ServerName != "example.com" {
		t.Fatal("explicit name was not applied")
	}
}

func TestTLSControlsImplicitNameCannotBeOverriddenByProfile(t *testing.T) {
	// Inspect the exact pre-handshake state without opening any network socket.
	req := &Request{TLSConfig: &TLSOptions{PinnedPublicKeys: []string{"sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}}
	makeConn, err := prepareTLSHandshake(req, "logical.test", tlsControlCustomSNIProfile(false), false)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	conn, err := makeConn(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	if conn.HandshakeState.Hello.ServerName != "logical.test" {
		t.Fatalf("wire SNI=%q", conn.HandshakeState.Hello.ServerName)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("invalid URL certificate identity reached HTTP") }))
	defer server.Close()
	e := pooledEngine(t, 1)
	request := tlsControlRequest(t, server, "logical.test")
	request.Profile = tlsControlCustomSNIProfile(false)
	good, _ := tlsControlPins(server.Certificate())
	request.TLSConfig.PinnedPublicKeys = []string{good}
	_, err = e.Send(context.Background(), request)
	var nameErr x509.HostnameError
	if !errors.As(err, &nameErr) || nameErr.Host != "logical.test" {
		t.Fatalf("certificate verification identity changed by profile: %v", err)
	}
}
