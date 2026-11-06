package netloom

import (
	"crypto/x509"
	"errors"
	tls "github.com/bogdanfinn/utls"
)

// TLSOptions contains in-memory credential material supplied by the host. It is
// never part of captured request bytes or serialized network results.
type TLSOptions struct {
	Roots        *x509.CertPool
	Certificates []tls.Certificate
}

func ParseTLSOptions(caPEM, certificatePEM, keyPEM string) (*TLSOptions, error) {
	out := &TLSOptions{}
	if caPEM != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, errors.New("invalid CA certificate PEM")
		}
		out.Roots = roots
	}
	if (certificatePEM == "") != (keyPEM == "") {
		return nil, errors.New("client certificate and private key must be supplied together")
	}
	if certificatePEM != "" {
		cert, err := tls.X509KeyPair([]byte(certificatePEM), []byte(keyPEM))
		if err != nil {
			return nil, errors.New("invalid client certificate/private key pair")
		}
		out.Certificates = []tls.Certificate{cert}
	}
	return out, nil
}
