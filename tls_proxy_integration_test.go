//go:build integration

package netrt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testCertificates(t *testing.T, ip net.IP) (caPEM, serverCert, serverKey, clientCert, clientKey string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "netrt test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	issue := func(serial int64, usage x509.ExtKeyUsage) (string, string) {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test identity"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, IPAddresses: []net.IP{ip}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, e := x509.CreateCertificate(rand.Reader, template, ca, &k.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := x509.MarshalPKCS8PrivateKey(k)
		if e != nil {
			t.Fatal(e)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
	}
	serverCert, serverKey = issue(2, x509.ExtKeyUsageServerAuth)
	clientCert, clientKey = issue(3, x509.ExtKeyUsageClientAuth)
	return
}

func TestCustomTrustAndMTLSTransports(t *testing.T) {
	ca, serverPEM, serverKey, clientPEM, clientKey := testCertificates(t, net.ParseIP("127.0.0.1"))
	certificate, err := tls.X509KeyPair([]byte(serverPEM), []byte(serverKey))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(ca))
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			t.Error("missing client identity")
		}
		_, _ = io.WriteString(w, "mtls-ok")
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	options, err := ParseTLSOptions(ca, clientPEM, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := New(Config{Retries: -1})
	defer engine.Close()
	engine.tlsT.(*tlsTransport).noGuard = true
	engine.rawT.(*rawTransport).noGuard = true
	request := &Request{URL: server.URL, VerifyTLS: true, TLSConfig: options}
	response, err := engine.Send(context.Background(), request)
	if err != nil || string(response.Body) != "mtls-ok" {
		t.Fatalf("Send: %v", err)
	}
	stream, err := engine.SendStream(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(stream.Body)
	_ = stream.Body.Close()
	if err != nil || string(payload) != "mtls-ok" {
		t.Fatalf("stream: %q %v", payload, err)
	}
	raw := *request
	raw.Raw = []byte("GET / HTTP/1.1\r\nHost: " + strings.TrimPrefix(server.URL, "https://") + "\r\nConnection: close\r\n\r\n")
	response, err = engine.Send(context.Background(), &raw)
	if err != nil || string(response.Body) != "mtls-ok" {
		t.Fatalf("Raw: %v", err)
	}
	untrusted := *request
	untrusted.TLSConfig = nil
	if _, err = engine.Send(context.Background(), &untrusted); err == nil {
		t.Fatal("untrusted client accepted")
	}
}

func TestProxyIsUsedBySendAndStream(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "example.invalid" {
			t.Errorf("unexpected proxy target %s", r.URL)
		}
		_, _ = io.WriteString(w, "via-proxy")
	}))
	defer proxy.Close()
	engine, _ := New(Config{Retries: -1})
	defer engine.Close()
	request := &Request{URL: "http://example.invalid/path", Proxy: proxy.URL}
	response, err := engine.Send(context.Background(), request)
	if err != nil || string(response.Body) != "via-proxy" {
		t.Fatalf("Send: %v", err)
	}
	stream, err := engine.SendStream(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(stream.Body)
	_ = stream.Body.Close()
	if err != nil || string(payload) != "via-proxy" {
		t.Fatalf("stream: %q %v", payload, err)
	}
}

func TestCloseInterruptsLiveStream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	engine, _ := New(Config{Threads: 1, Retries: -1})
	engine.tlsT.(*tlsTransport).noGuard = true
	stream, err := engine.SendStream(context.Background(), &Request{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = engine.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close blocked on stream")
	}
	if _, err = io.ReadAll(stream.Body); err == nil {
		t.Fatal("closed stream remained readable")
	}
	_ = stream.Body.Close()
}
