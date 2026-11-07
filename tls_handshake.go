package netloom

import (
	"fmt"
	"net"

	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

// prepareTLSHandshake validates and builds the one-connection handshake before
// dialing. In particular an impossible version/profile intersection sends no TCP
// or HTTP bytes. Profile factories must supply fresh specs, as required by uTLS.
func prepareTLSHandshake(req *Request, host string, profile profiles.ClientProfile, forceHTTP1 bool) (func(net.Conn) (*tls.UConn, error), error) {
	config, err := tlsControlConfig(req, host)
	if err != nil {
		return nil, err
	}
	spec, err := boundedTLSHello(profile, req.TLSConfig)
	if err != nil {
		return nil, err
	}
	if spec != nil {
		for i, extension := range spec.Extensions {
			switch ext := extension.(type) {
			case *tls.ALPNExtension:
				protocols := make([]string, 0, len(ext.AlpnProtocols))
				for _, p := range ext.AlpnProtocols {
					if p != "h3" && (!forceHTTP1 || p == "http/1.1") {
						protocols = append(protocols, p)
					}
				}
				spec.Extensions[i] = &tls.ALPNExtension{AlpnProtocols: protocols}
			case *tls.ApplicationSettingsExtension:
				protocols := make([]string, 0, len(ext.SupportedProtocols))
				for _, p := range ext.SupportedProtocols {
					if p != "h3" && !forceHTTP1 {
						protocols = append(protocols, p)
					}
				}
				spec.Extensions[i] = &tls.ApplicationSettingsExtension{SupportedProtocols: protocols}
			case *tls.ApplicationSettingsExtensionNew:
				protocols := make([]string, 0, len(ext.SupportedProtocols))
				for _, p := range ext.SupportedProtocols {
					if p != "h3" && !forceHTTP1 {
						protocols = append(protocols, p)
					}
				}
				spec.Extensions[i] = &tls.ApplicationSettingsExtensionNew{SupportedProtocols: protocols}
			}
		}
	}
	return func(raw net.Conn) (*tls.UConn, error) {
		id := profile.GetClientHelloId()
		if spec != nil {
			id = tls.HelloCustom
		} else if id.SpecFactory == nil {
			// This fork calls ToSpec without a nil check, even for built-in IDs.
			builtin := id
			id.SpecFactory = func() (tls.ClientHelloSpec, error) { return tls.UTLSIdToSpec(builtin) }
		}
		conn := tls.UClient(raw, config, id, false, forceHTTP1, true)
		if spec != nil {
			if err := conn.ApplyPreset(spec); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrTLSProfileConflict, err)
			}
		}
		if req.TLSConfig.controlsEnabled() {
			desired := config.ServerName
			if err := conn.BuildHandshakeState(); err != nil {
				return nil, err
			}
			found := false
			for i, ext := range conn.Extensions {
				if _, ok := ext.(*tls.SNIExtension); ok {
					conn.Extensions[i] = &tls.SNIExtension{ServerName: desired}
					found = true
				}
			}
			if !found && req.TLSConfig.ServerName != "" && net.ParseIP(desired) == nil {
				return nil, fmt.Errorf("%w: explicit ServerName requires a profile SNI extension", ErrTLSProfileConflict)
			}
			// SNIExtension serializes IPs as absent but retains the IP verification name.
			config.ServerName = desired
		}
		return conn, nil
	}, nil
}
