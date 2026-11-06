// Package mitm accepts explicit HTTP proxies and terminates HTTPS CONNECT tunnels.
package mitm

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

type Authority struct {
	cert           *x509.Certificate
	key            ed25519.PrivateKey
	certificatePEM []byte
	keyPEM         []byte
	mu             sync.Mutex
	leaves         map[string]*tls.Certificate
	capacity       int
	order          []string
}

func serialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

type AuthorityOptions struct {
	CommonName    string
	CacheCapacity int
}

func NewAuthority(options ...AuthorityOptions) (*Authority, error) {
	opts := AuthorityOptions{CommonName: "netloom MITM CA", CacheCapacity: 256}
	if len(options) > 0 {
		opts = options[0]
	}
	if opts.CommonName == "" {
		opts.CommonName = "netloom MITM CA"
	}
	if opts.CacheCapacity <= 0 {
		opts.CacheCapacity = 256
	}

	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mitm.NewAuthority: %w", err)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: opts.CommonName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		return nil, fmt.Errorf("mitm.NewAuthority: certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	a, err := LoadAuthority(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err == nil {
		a.capacity = opts.CacheCapacity
	}
	return a, err
}

func LoadAuthority(certificatePEM, keyPEM []byte) (*Authority, error) {
	pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("mitm.LoadAuthority: %w", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	key, ok := pair.PrivateKey.(ed25519.PrivateKey)
	if !ok || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("mitm.LoadAuthority: invalid or expired CA")
	}
	return &Authority{cert: cert, key: key, certificatePEM: append([]byte(nil), certificatePEM...),
		keyPEM: append([]byte(nil), keyPEM...), capacity: 256, leaves: make(map[string]*tls.Certificate)}, nil
}

// PEM returns copies for encrypted persistence; only the certificate is public.
func (a *Authority) PEM() (certificate, privateKey []byte) {
	return append([]byte(nil), a.certificatePEM...), append([]byte(nil), a.keyPEM...)
}

func (a *Authority) CertificatePEM() []byte { return append([]byte(nil), a.certificatePEM...) }

func (a *Authority) Certificate(host string) (*tls.Certificate, error) {
	host = strings.ToLower(host)
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\\x00\r\n") {
		return nil, fmt.Errorf("mitm.Certificate: invalid hostname")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if cert := a.leaves[host]; cert != nil && time.Now().Before(cert.Leaf.NotAfter.Add(-time.Minute)) {
		return cert, nil
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	expiry := now.Add(24 * time.Hour)
	if a.cert.NotAfter.Before(expiry) {
		expiry = a.cert.NotAfter
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host},
		NotBefore: now.Add(-time.Hour), NotAfter: expiry,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, public, a.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, a.cert.Raw}, PrivateKey: key, Leaf: leaf}
	if _, exists := a.leaves[host]; !exists {
		a.order = append(a.order, host)
	}
	a.leaves[host] = cert
	for len(a.leaves) > a.capacity {
		delete(a.leaves, a.order[0])
		a.order = a.order[1:]
	}
	return cert, nil
}
