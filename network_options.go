package netloom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// AddressFamily constrains the destination IP family, not TLS or HTTP identity.
type AddressFamily string

const (
	AddressFamilyAuto AddressFamily = "auto"
	AddressFamilyIPv4 AddressFamily = "ipv4"
	AddressFamilyIPv6 AddressFamily = "ipv6"
)

// ResolveRule supplies ordered IP literals for an exact dial host and port.
// Host is an ASCII DNS name or an unbracketed IP; Port is required (1..65535).
type ResolveRule struct {
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	Addresses []string `json:"addresses"`
}

// ConnectToRule replaces an exact dial host/port, once, before Resolve matching.
// It never changes the logical URL, HTTP Host, TLS SNI or certificate identity.
type ConnectToRule struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	ConnectHost string `json:"connect_host"`
	ConnectPort int    `json:"connect_port"`
}

// NetworkOptions configures bounded per-request, direct-only network mapping.
// Nil/zero preserves legacy dialing. Rules are exact, without wildcards or
// recursive rewrites. At most 64 rules of each kind and 16 IPs per Resolve rule
// are accepted. DNS candidates are tried sequentially, not Happy Eyeballs.
// A nonzero policy with a proxy is rejected, never silently ignored.
type NetworkOptions struct {
	Resolve       []ResolveRule   `json:"resolve,omitempty"`
	ConnectTo     []ConnectToRule `json:"connect_to,omitempty"`
	AddressFamily AddressFamily   `json:"address_family,omitempty"`
}

// Validate checks syntax, bounds and duplicate canonical keys, without DNS/IO.
func (o NetworkOptions) Validate() error { _, err := compileNetworkOptions(&o); return err }

// Clone returns an independent copy, including each rule's address slice.
func (o *NetworkOptions) Clone() *NetworkOptions {
	if o == nil {
		return nil
	}
	c := *o
	c.Resolve = append([]ResolveRule(nil), o.Resolve...)
	for i := range c.Resolve {
		c.Resolve[i].Addresses = append([]string(nil), o.Resolve[i].Addresses...)
	}
	c.ConnectTo = append([]ConnectToRule(nil), o.ConnectTo...)
	return &c
}

// ErrNetworkProxyUnsupported means a nonzero Network policy was combined with
// a proxy; proxy-side DNS/mapping/family semantics are not silently approximated.
var ErrNetworkProxyUnsupported = errors.New("netloom: network mapping/address-family policy requires a direct connection")

type networkPlan struct {
	resolve  map[string][]netip.Addr
	connect  map[string]string
	family   AddressFamily
	identity string
}

func (p *networkPlan) enabled() bool {
	return p != nil && (len(p.resolve) > 0 || len(p.connect) > 0 || p.family != AddressFamilyAuto)
}

type networkPlanKey struct{}

func canonicalNetworkHost(host string) (string, error) {
	for _, c := range host {
		if c > 127 {
			return "", fmt.Errorf("netloom: network hosts require ASCII/punycode")
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return "", fmt.Errorf("netloom: network host cannot contain an IPv6 zone")
		}
		return ip.Unmap().String(), nil
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || len(host) > 253 {
		return "", fmt.Errorf("netloom: invalid network host")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("netloom: invalid network host label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", fmt.Errorf("netloom: network hosts must be ASCII names or unbracketed IP literals")
			}
		}
	}
	return host, nil
}
func networkRuleKey(host string, port int) (string, error) {
	host, err := canonicalNetworkHost(host)
	if err != nil {
		return "", err
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("netloom: network rule port must be 1..65535")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
func compileNetworkOptions(o *NetworkOptions) (*networkPlan, error) {
	p := &networkPlan{family: AddressFamilyAuto, resolve: make(map[string][]netip.Addr), connect: make(map[string]string)}
	if o == nil {
		return p, nil
	}
	switch o.AddressFamily {
	case "", AddressFamilyAuto:
	case AddressFamilyIPv4, AddressFamilyIPv6:
		p.family = o.AddressFamily
	default:
		return nil, fmt.Errorf("netloom: address family must be auto, ipv4 or ipv6")
	}
	if len(o.Resolve) > 64 || len(o.ConnectTo) > 64 {
		return nil, fmt.Errorf("netloom: network mapping exceeds 64 rules per kind")
	}
	for _, r := range o.Resolve {
		key, err := networkRuleKey(r.Host, r.Port)
		if err != nil {
			return nil, err
		}
		if _, exists := p.resolve[key]; exists {
			return nil, fmt.Errorf("netloom: duplicate Resolve rule for %s", key)
		}
		if len(r.Addresses) < 1 || len(r.Addresses) > 16 {
			return nil, fmt.Errorf("netloom: Resolve requires 1..16 IP literals")
		}
		ips := make([]netip.Addr, 0, len(r.Addresses))
		seen := make(map[netip.Addr]bool)
		for _, s := range r.Addresses {
			ip, err := netip.ParseAddr(s)
			if err != nil || ip.Zone() != "" {
				return nil, fmt.Errorf("netloom: Resolve addresses must be unzoned IP literals")
			}
			ip = ip.Unmap()
			if seen[ip] {
				return nil, fmt.Errorf("netloom: duplicate Resolve address")
			}
			seen[ip] = true
			ips = append(ips, ip)
		}
		p.resolve[key] = ips
	}
	for _, r := range o.ConnectTo {
		key, err := networkRuleKey(r.Host, r.Port)
		if err != nil {
			return nil, err
		}
		target, err := networkRuleKey(r.ConnectHost, r.ConnectPort)
		if err != nil {
			return nil, err
		}
		if _, exists := p.connect[key]; exists {
			return nil, fmt.Errorf("netloom: duplicate ConnectTo rule for %s", key)
		}
		p.connect[key] = target
	}
	if p.enabled() {
		// JSON map keys are sorted; retain candidate order because fallback order is
		// observable. This identity is private and never logged or used as evidence.
		b, err := json.Marshal(struct {
			Family  AddressFamily
			Resolve map[string][]netip.Addr
			Connect map[string]string
		}{p.family, p.resolve, p.connect})
		if err != nil {
			return nil, err
		}
		p.identity = string(b)
	}
	return p, nil
}
func withNetworkOptions(ctx context.Context, req *Request) (context.Context, error) {
	p, err := compileNetworkOptions(req.Network)
	if err != nil {
		return ctx, err
	}
	if p.enabled() {
		if req.Proxy != "" {
			return ctx, ErrNetworkProxyUnsupported
		}
		u, err := url.Parse(req.URL)
		if err != nil || u.Hostname() == "" {
			return ctx, fmt.Errorf("netloom: network policy requires a valid URL host")
		}
		if _, err := canonicalNetworkHost(u.Hostname()); err != nil {
			return ctx, err
		}
	}
	return context.WithValue(ctx, networkPlanKey{}, p), nil
}

// Check before pool acquisition as well as dialing: reuse must not skip the
// logical-literal guard. DNS names are deliberately not resolved here.
func validateNetworkLogicalTarget(ctx context.Context, req *Request, noGuard bool) error {
	p, _ := ctx.Value(networkPlanKey{}).(*networkPlan)
	if !p.enabled() || noGuard {
		return nil
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		return err
	}
	host, err := canonicalNetworkHost(u.Hostname())
	if err != nil {
		return err
	}
	if ip, err := netip.ParseAddr(host); err == nil && isBlockedIP(net.IP(ip.AsSlice())) {
		return fmt.Errorf("netloom.dial logical target: %w", ErrBlockedAddress)
	}
	return nil
}

// mappedDialContext resolves only the effective dial destination. The original
// request address stays untouched in tls-client, preserving Host/SNI/verification.
// It reads the current lease context, not a client-build-time request closure.
func mappedDialContext(base func(context.Context, string, string) (net.Conn, error), resolver *net.Resolver, noGuard bool) func(context.Context, string, string) (net.Conn, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		p, _ := ctx.Value(networkPlanKey{}).(*networkPlan)
		if !p.enabled() {
			return base(ctx, network, addr)
		}
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("netloom: network mapping requires TCP")
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil {
			return nil, err
		}
		key, err := networkRuleKey(host, portNumber)
		if err != nil {
			return nil, err
		}
		logicalHost, _, _ := net.SplitHostPort(key) // key has already been canonicalized
		if ip, err := netip.ParseAddr(logicalHost); err == nil && !noGuard && isBlockedIP(net.IP(ip.AsSlice())) {
			return nil, fmt.Errorf("netloom.dial logical target: %w", ErrBlockedAddress)
		}
		if target, ok := p.connect[key]; ok {
			key = target
		}
		host, port, err = net.SplitHostPort(key)
		if err != nil {
			return nil, err
		}
		family := p.family
		if network == "tcp4" {
			if family == AddressFamilyIPv6 {
				return nil, fmt.Errorf("netloom: conflicting TCP/address family")
			}
			family = AddressFamilyIPv4
		}
		if network == "tcp6" {
			if family == AddressFamilyIPv4 {
				return nil, fmt.Errorf("netloom: conflicting TCP/address family")
			}
			family = AddressFamilyIPv6
		}
		ips := p.resolve[key]
		if len(ips) == 0 {
			if ip, err := netip.ParseAddr(host); err == nil {
				ips = []netip.Addr{ip.Unmap()}
			} else {
				start := time.Now()
				resolved, err := resolver.LookupIPAddr(ctx, host)
				recordMeasured(ctx, "dns", start)
				if err != nil {
					return nil, fmt.Errorf("netloom.dial resolve %s: %w", host, err)
				}
				for _, ip := range resolved {
					if ip.Zone != "" {
						continue
					}
					if a, ok := netip.AddrFromSlice(ip.IP); ok {
						ips = append(ips, a.Unmap())
					}
				}
			}
		}
		var failures []error
		var blocked error
		for _, ip := range ips {
			if family == AddressFamilyIPv4 && !ip.Is4() || family == AddressFamilyIPv6 && !ip.Is6() {
				continue
			}
			if !noGuard && isBlockedIP(net.IP(ip.AsSlice())) {
				blocked = fmt.Errorf("netloom.dial %s: %w", ip, ErrBlockedAddress)
				continue
			}
			if cause := requestContextError(ctx); cause != nil {
				return nil, cause
			}
			conn, err := base(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			failures = append(failures, err)
		}
		if cause := requestContextError(ctx); cause != nil {
			return nil, cause
		}
		if len(failures) > 0 {
			// Skipped forbidden IPs must not make a transient failure of an
			// allowed candidate permanent in the scheduler's retry policy.
			return nil, errors.Join(failures...)
		}
		if blocked != nil {
			return nil, blocked
		}
		return nil, fmt.Errorf("netloom.dial %s: no addresses for family %s", key, family)
	}
}
