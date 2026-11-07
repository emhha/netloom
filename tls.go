package netloom

import (
	"crypto/x509"
	"errors"
	tls "github.com/bogdanfinn/utls"
)

// TLSOptions contains in-memory trust, credentials and explicit TLS controls.
// It is never part of captured request bytes or serialized network results.
// Callers must keep Roots, Certificates and private keys immutable while in use.
type TLSOptions struct {
	Roots        *x509.CertPool
	Certificates []tls.Certificate
	// Version bounds narrow the implicit default browser profile; zero inherits.
	// Explicit Request.Profile and nonzero version bounds conflict.
	MinVersion TLSVersion
	MaxVersion TLSVersion
	// ServerName overrides both TLS SNI and the certificate verification name,
	// not the logical URL, HTTP Host, dialing target or cookie origin.
	ServerName string
	// PinnedPublicKeys are alternative leaf SPKI SHA256 pins, sha256//BASE64.
	// Pins are enforced even when VerifyTLS is false; they never disable PKI checks.
	PinnedPublicKeys []string
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
