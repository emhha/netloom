package netloom

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// ErrNetworkBindingInvalid identifies an invalid explicit source IP/device or
// a source/destination address-family conflict. Validation performs no DNS/IO.
var ErrNetworkBindingInvalid = errors.New("netloom: invalid network binding")

// ErrNetworkBindingUnsupported means device binding is not implemented on the
// current OS. Explicit device binding is never silently reduced to IP binding.
var ErrNetworkBindingUnsupported = errors.New("netloom: interface binding requires Linux")

// ErrNetworkBinding identifies a failure to apply an explicit binding. The
// underlying device, permission or address error remains available to errors.Is.
// These errors are permanent for automatic retries; no unbound fallback occurs.
var ErrNetworkBinding = errors.New("netloom: cannot apply network binding")

func (p *networkPlan) bindingEnabled() bool {
	return p != nil && (p.localAddress.IsValid() || p.device != "")
}

func compileNetworkBinding(p *networkPlan, o *NetworkOptions) error {
	if o.LocalAddress != "" {
		ip, err := netip.ParseAddr(o.LocalAddress)
		if err != nil || ip.Zone() != "" {
			return fmt.Errorf("%w: local_address must be an unzoned IP literal", ErrNetworkBindingInvalid)
		}
		ip = ip.Unmap()
		if !ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return fmt.Errorf("%w: local_address must be a specific unicast IP", ErrNetworkBindingInvalid)
		}
		family := AddressFamilyIPv6
		if ip.Is4() {
			family = AddressFamilyIPv4
		}
		if p.family != AddressFamilyAuto && p.family != family {
			return fmt.Errorf("%w: local_address conflicts with address_family", ErrNetworkBindingInvalid)
		}
		p.localAddress = ip
		p.family = family
	}
	if o.Interface != "" {
		if len(o.Interface) > 15 || o.Interface == "." || o.Interface == ".." {
			return fmt.Errorf("%w: interface must be a Linux device name of 1..15 ASCII bytes", ErrNetworkBindingInvalid)
		}
		for _, c := range o.Interface {
			if c <= 32 || c >= 127 || c == '/' || c == ':' {
				return fmt.Errorf("%w: invalid interface name", ErrNetworkBindingInvalid)
			}
		}
		if !interfaceBindingSupported {
			return ErrNetworkBindingUnsupported
		}
		p.device = o.Interface
	}
	return nil
}

// networkDialer makes a fresh per-dial copy, including phase budgets and source
// binding. Cached clients must never retain an earlier lease's mutable dialer.
func networkDialer(ctx context.Context, base *net.Dialer) *net.Dialer {
	phase := phaseDialer(ctx, base)
	p, _ := ctx.Value(networkPlanKey{}).(*networkPlan)
	if !p.bindingEnabled() {
		return phase
	}
	bound := *phase
	if p.localAddress.IsValid() {
		bound.LocalAddr = &net.TCPAddr{IP: net.IP(p.localAddress.AsSlice())}
	}
	if p.device != "" {
		prior, legacy := bound.ControlContext, bound.Control
		bound.ControlContext = func(ctx context.Context, network, address string, raw syscall.RawConn) error {
			if err := requestContextError(ctx); err != nil {
				return err
			}
			if prior != nil {
				if err := prior(ctx, network, address, raw); err != nil {
					return err
				}
			} else if legacy != nil {
				if err := legacy(network, address, raw); err != nil {
					return err
				}
			}
			if err := bindNetworkInterface(ctx, raw, p.device); err != nil {
				return fmt.Errorf("%w: interface %q: %w", ErrNetworkBinding, p.device, err)
			}
			return nil
		}
	}
	return &bound
}

func dialWithNetworkBinding(ctx context.Context, base *net.Dialer, network, address string) (net.Conn, error) {
	conn, err := networkDialer(ctx, base).DialContext(ctx, network, address)
	if err != nil {
		p, _ := ctx.Value(networkPlanKey{}).(*networkPlan)
		if p.bindingEnabled() && (errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || isPlatformBindingError(err)) {
			return nil, fmt.Errorf("%w: %w", ErrNetworkBinding, err)
		}
	}
	return conn, err
}
