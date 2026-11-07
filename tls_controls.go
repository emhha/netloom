package netloom

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

// TLSVersion is a TLS protocol version; the empty value inherits the profile.
type TLSVersion string

const (
	TLSVersion10 TLSVersion = "1.0"
	TLSVersion11 TLSVersion = "1.1"
	TLSVersion12 TLSVersion = "1.2"
	TLSVersion13 TLSVersion = "1.3"
)

// ErrTLSPinMismatch means the actual peer's leaf public key matched no pin.
var ErrTLSPinMismatch = errors.New("netloom: TLS leaf public key pin mismatch")

// ErrTLSProfileConflict means TLS controls cannot be honored by the profile,
// including explicit-profile version bounds or an absent required SNI extension.
var ErrTLSProfileConflict = errors.New("netloom: TLS policy conflicts with browser profile")

// ErrTLSOptionsUnsupported means active TLS controls cannot be safely applied to
// this scheme or proxy. They are never silently ignored.
var ErrTLSOptionsUnsupported = errors.New("netloom: explicit TLS controls require HTTPS and direct or HTTP CONNECT transport")

func tlsVersionNumber(v TLSVersion) (uint16, error) {
	switch v {
	case "":
		return 0, nil
	case TLSVersion10:
		return tls.VersionTLS10, nil
	case TLSVersion11:
		return tls.VersionTLS11, nil
	case TLSVersion12:
		return tls.VersionTLS12, nil
	case TLSVersion13:
		return tls.VersionTLS13, nil
	}
	return 0, fmt.Errorf("netloom: TLS version must be 1.0, 1.1, 1.2, 1.3 or empty")
}
func (o *TLSOptions) controlsEnabled() bool {
	return o != nil && (o.MinVersion != "" || o.MaxVersion != "" || o.ServerName != "" || len(o.PinnedPublicKeys) > 0)
}

// Validate checks TLS controls without IO. Version availability also depends on
// the selected default profile and is checked before opening the TLS socket.
func (o *TLSOptions) Validate() error {
	if o == nil {
		return nil
	}
	min, err := tlsVersionNumber(o.MinVersion)
	if err != nil {
		return err
	}
	max, err := tlsVersionNumber(o.MaxVersion)
	if err != nil {
		return err
	}
	if min != 0 && max != 0 && min > max {
		return errors.New("netloom: minimum TLS version exceeds maximum")
	}
	if o.ServerName != "" {
		if _, err := canonicalNetworkHost(o.ServerName); err != nil {
			return fmt.Errorf("netloom: invalid TLS ServerName: %w", err)
		}
	}
	if len(o.PinnedPublicKeys) > 16 {
		return errors.New("netloom: at most 16 TLS public key pins are allowed")
	}
	seen := map[string]bool{}
	for _, pin := range o.PinnedPublicKeys {
		if !strings.HasPrefix(pin, "sha256//") {
			return errors.New("netloom: public key pin must use sha256//BASE64")
		}
		b, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(pin, "sha256//"))
		if err != nil || len(b) != sha256.Size || "sha256//"+base64.StdEncoding.EncodeToString(b) != pin {
			return errors.New("netloom: public key pin must contain a canonical base64 SHA256 digest")
		}
		if seen[pin] {
			return errors.New("netloom: duplicate TLS public key pin")
		}
		seen[pin] = true
	}
	return nil
}

// Clone copies controls and the pin list. Trust pools, certificate material and
// private keys remain shared immutable caller-owned credential references.
func (o *TLSOptions) Clone() *TLSOptions {
	if o == nil {
		return nil
	}
	c := *o
	c.PinnedPublicKeys = append([]string(nil), o.PinnedPublicKeys...)
	return &c
}

func validateTLSRequest(req *Request) error {
	o := req.TLSConfig
	if err := o.Validate(); err != nil {
		return err
	}
	if !o.controlsEnabled() {
		return nil
	}
	u, err := url.Parse(req.URL)
	if err != nil || !strings.EqualFold(u.Scheme, "https") {
		return ErrTLSOptionsUnsupported
	}
	if req.Proxy != "" {
		p, err := url.Parse(req.Proxy)
		if err != nil || p.Scheme != "http" {
			return ErrTLSOptionsUnsupported
		}
	}
	if (o.MinVersion != "" || o.MaxVersion != "") && !reflect.ValueOf(req.Profile).IsZero() {
		return ErrTLSProfileConflict
	}
	return nil
}

// tlsControlConfig is shared by the dedicated HTTP and Raw handshakes. The
// callback is connection-local, unlike the backend's process-global pin store.
func tlsControlConfig(req *Request, logicalHost string) (*tls.Config, error) {
	c := &tls.Config{ServerName: logicalHost, InsecureSkipVerify: !req.VerifyTLS, OmitEmptyPsk: true}
	o := req.TLSConfig
	if o == nil {
		return c, nil
	}
	if err := o.Validate(); err != nil {
		return nil, err
	}
	c.RootCAs = o.Roots
	c.Certificates = o.Certificates
	if o.ServerName != "" {
		c.ServerName, _ = canonicalNetworkHost(o.ServerName)
	}
	c.MinVersion, _ = tlsVersionNumber(o.MinVersion)
	c.MaxVersion, _ = tlsVersionNumber(o.MaxVersion)
	if len(o.PinnedPublicKeys) > 0 {
		pins := make([][]byte, len(o.PinnedPublicKeys))
		for i, pin := range o.PinnedPublicKeys {
			pins[i], _ = base64.StdEncoding.DecodeString(strings.TrimPrefix(pin, "sha256//"))
		}
		c.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return ErrTLSPinMismatch
			}
			sum := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			matched := 0
			for _, pin := range pins {
				matched |= subtle.ConstantTimeCompare(pin, sum[:])
			}
			if matched != 1 {
				return ErrTLSPinMismatch
			}
			return nil
		}
	}
	return c, nil
}

// boundedTLSHello narrows a fresh profile spec. Config bounds alone are not
// enough: uTLS ApplyPreset overwrites them and SupportedVersions writes the wire.
func boundedTLSHello(profile profiles.ClientProfile, o *TLSOptions) (*tls.ClientHelloSpec, error) {
	if o == nil || (o.MinVersion == "" && o.MaxVersion == "") {
		return nil, nil
	}
	id := profile.GetClientHelloId()
	var spec tls.ClientHelloSpec
	var err error
	if id.SpecFactory != nil {
		spec, err = id.ToSpec()
	}
	if id.SpecFactory == nil || err != nil {
		// Built-ins may carry either nil or the backend's placeholder factory.
		// Match uTLS applyPresetByID's factory-to-built-in fallback.
		spec, err = tls.UTLSIdToSpec(id)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTLSProfileConflict, err)
	}
	min, _ := tlsVersionNumber(o.MinVersion)
	max, _ := tlsVersionNumber(o.MaxVersion)
	if min == 0 {
		min = tls.VersionTLS10
	}
	if max == 0 {
		max = tls.VersionTLS13
	}
	if (spec.TLSVersMin == 0) != (spec.TLSVersMax == 0) {
		return nil, fmt.Errorf("%w: incomplete profile version bounds", ErrTLSProfileConflict)
	}
	if spec.TLSVersMin != 0 && spec.TLSVersMin > min {
		min = spec.TLSVersMin
	}
	if spec.TLSVersMax != 0 && spec.TLSVersMax < max {
		max = spec.TLSVersMax
	}
	spec.Extensions = append([]tls.TLSExtension(nil), spec.Extensions...)
	var real []uint16
	found := false
	for i, extension := range spec.Extensions {
		ext, ok := extension.(*tls.SupportedVersionsExtension)
		if !ok {
			continue
		}
		if found {
			return nil, fmt.Errorf("%w: duplicate supported versions extensions", ErrTLSProfileConflict)
		}
		found = true
		versions := make([]uint16, 0, len(ext.Versions))
		for _, v := range ext.Versions {
			if v&0x0f0f == 0x0a0a && byte(v) == byte(v>>8) {
				versions = append(versions, v)
				continue
			}
			if v >= min && v <= max {
				versions = append(versions, v)
				real = append(real, v)
			}
		}
		spec.Extensions[i] = &tls.SupportedVersionsExtension{Versions: versions}
	}
	if !found {
		low, high := spec.TLSVersMin, spec.TLSVersMax
		if low == 0 {
			low = tls.VersionTLS10
		}
		if high == 0 {
			high = tls.VersionTLS12
		}
		for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {
			if v >= low && v <= high && v >= min && v <= max {
				real = append(real, v)
			}
		}
	}
	if len(real) == 0 {
		return nil, fmt.Errorf("%w: no advertised version within requested bounds", ErrTLSProfileConflict)
	}
	low, high := real[0], real[0]
	for _, v := range real {
		if v < low {
			low = v
		}
		if v > high {
			high = v
		}
	}
	spec.TLSVersMin = low
	spec.TLSVersMax = high
	return &spec, nil
}
