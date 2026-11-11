// Package proxyconfig validates proxy URLs without DNS or network access.
// Errors deliberately never retain input URLs or user information.
package proxyconfig

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

var ErrInvalid = errors.New("invalid proxy configuration")
var ErrUnsupported = errors.New("unsupported proxy scheme")

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrInvalid, reason) }

// Parse returns nil for explicit direct mode (raw == ""). Nonempty input is
// never trimmed into direct mode. Schemes are matched case-insensitively, as
// URL schemes require; the returned URL is normalized for downstream dialers.
func Parse(raw string, schemes ...string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}
	if strings.ContainsFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return nil, invalid("whitespace or control character")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, invalid("malformed URL")
	}
	if u.Scheme == "" || u.Host == "" || u.Opaque != "" {
		return nil, invalid("scheme and host are required")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	supported := false
	for _, scheme := range schemes {
		if u.Scheme == scheme {
			supported = true
			break
		}
	}
	if !supported {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, ErrUnsupported)
	}
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return nil, invalid("path, query or fragment is not supported")
	}
	host := u.Hostname()
	if host == "" || host == "." || host == ".." || strings.ContainsAny(host, "\\/?#@") || strings.ContainsFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return nil, invalid("invalid host")
	}
	if strings.ContainsAny(u.Host, "[]") || strings.Contains(host, ":") {
		if !strings.HasPrefix(u.Host, "[") {
			return nil, invalid("IPv6 host must be bracketed")
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() {
			return nil, invalid("invalid IPv6 host")
		}
	} else if strings.Contains(host, "%") {
		return nil, invalid("invalid host")
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return nil, invalid("empty port")
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, invalid("port must be 1–65535")
		}
	} else if strings.HasPrefix(u.Scheme, "socks") {
		return nil, invalid("SOCKS requires an explicit port")
	}
	if u.User != nil {
		password, _ := u.User.Password()
		if strings.ContainsFunc(u.User.Username()+password, unicode.IsControl) {
			return nil, invalid("control character in user information")
		}
	}
	return u, nil
}
