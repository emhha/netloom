package netrt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// ErrBlockedAddress is returned by the dial guard when a connection target
// resolves to a permanently forbidden address class (loopback / link-local).
// It is a network-layer SSRF primitive: it fires regardless of any upper-layer
// scope configuration, and is independent of business authorization.
var ErrBlockedAddress = errors.New("netrt: blocked address (loopback/link-local)")

// isBlockedIP reports whether ip belongs to a permanently rejected class.
//
// Zero-business-dependency guarantee: this only inspects net.IP address class.
// Private ranges (RFC1918 10/8, 172.16/12, 192.168/16) are deliberately NOT
// blocked here — internal-asset probing is a legitimate scenario whose
// authorization is decided by the service-layer scope, not by this primitive.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// 127.0.0.0/8, ::1
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	// 169.254.0.0/16, fe80::/10
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return false
}

// guardedDialContext wraps a base dialer so that every resolved target IP is
// checked immediately before the TCP connection is established.
//
// DNS-rebinding defence: the guard resolves the host itself and dials a fixed
// IP literal, so the address validated is exactly the address connected to —
// there is no resolve-then-reconnect window for a rebind to slip through. The
// transport re-invokes this guard for every redirect hop, so each hop is
// re-resolved and re-validated.
func guardedDialContext(base *net.Dialer, resolver *net.Resolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if base == nil {
		base = &net.Dialer{}
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("netrt.dial: %w", err)
		}

		// If addr is already an IP literal, validate and dial it directly.
		if ip := net.ParseIP(host); ip != nil {
			if isBlockedIP(ip) {
				return nil, fmt.Errorf("netrt.dial %s: %w", addr, ErrBlockedAddress)
			}
			start := time.Now()
			conn, err := base.DialContext(ctx, network, addr)
			recordMeasured(ctx, "connect", start)
			return conn, err
		}

		start := time.Now()
		ips, err := resolver.LookupIPAddr(ctx, host)
		recordMeasured(ctx, "dns", start)
		if err != nil {
			return nil, fmt.Errorf("netrt.dial resolve %s: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("netrt.dial resolve %s: no addresses", host)
		}

		// Validate every candidate, then dial the first allowed literal so the
		// connected IP is exactly the validated one.
		var firstErr error
		for _, ipa := range ips {
			if isBlockedIP(ipa.IP) {
				if firstErr == nil {
					firstErr = fmt.Errorf("netrt.dial %s -> %s: %w", host, ipa.IP, ErrBlockedAddress)
				}
				continue
			}
			start := time.Now()
			conn, derr := base.DialContext(ctx, network, net.JoinHostPort(ipa.IP.String(), port))
			recordMeasured(ctx, "connect", start)
			if derr != nil {
				if firstErr == nil {
					firstErr = derr
				}
				continue
			}
			return conn, nil
		}
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, fmt.Errorf("netrt.dial %s: no dialable address", host)
	}
}
