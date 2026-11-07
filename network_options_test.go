package netloom

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func networkContext(t *testing.T, o *NetworkOptions) context.Context {
	t.Helper()
	ctx, err := withNetworkOptions(context.Background(), &Request{URL: "https://logical.test", Network: o})
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}
func networkIPs(ips ...string) *NetworkOptions {
	return &NetworkOptions{Resolve: []ResolveRule{{Host: "logical.test", Port: 443, Addresses: ips}}}
}
func noNetworkDNS(calls *atomic.Int32) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("unexpected DNS")
	}}
}

func TestNetworkMappingCandidatesAndGuard(t *testing.T) {
	for _, tc := range []struct {
		name          string
		o             *NetworkOptions
		addr, network string
		guard         bool
		want          []string
		blocked       bool
		fail          bool
	}{
		{name: "ordered-filter", o: &NetworkOptions{AddressFamily: AddressFamilyIPv4, Resolve: []ResolveRule{{Host: "logical.test", Port: 443, Addresses: []string{"2001:db8::1", "192.0.2.1", "192.0.2.2"}}}}, want: []string{"192.0.2.1:443", "192.0.2.2:443"}},
		{name: "ipv4-mapped", o: networkIPs("::ffff:192.0.2.2"), want: []string{"192.0.2.2:443"}},
		{name: "blocked-candidates", o: networkIPs("127.0.0.1", "::1", "0.0.0.0", "169.254.1.1"), guard: true, blocked: true, fail: true},
		{name: "skip-blocked", o: networkIPs("127.0.0.1", "192.0.2.2"), guard: true, want: []string{"192.0.2.2:443"}},
		{name: "private-not-blocked", o: networkIPs("10.1.2.3"), guard: true, want: []string{"10.1.2.3:443"}},
		{name: "logical-blocked", o: &NetworkOptions{ConnectTo: []ConnectToRule{{Host: "127.0.0.1", Port: 443, ConnectHost: "192.0.2.2", ConnectPort: 443}}}, addr: "127.0.0.1:443", guard: true, blocked: true, fail: true},
		{name: "dotted-logical-blocked", o: &NetworkOptions{ConnectTo: []ConnectToRule{{Host: "127.0.0.1", Port: 443, ConnectHost: "192.0.2.2", ConnectPort: 443}}}, addr: "127.0.0.1.:443", guard: true, blocked: true, fail: true},
		{name: "v6-no-v4-fallback", o: &NetworkOptions{AddressFamily: AddressFamilyIPv6, Resolve: networkIPs("192.0.2.2").Resolve}, fail: true},
		{name: "network-conflict", o: &NetworkOptions{AddressFamily: AddressFamilyIPv6}, network: "tcp4", fail: true},
		{name: "no-recursive-connect", o: &NetworkOptions{ConnectTo: []ConnectToRule{{Host: "logical.test", Port: 443, ConnectHost: "first.test", ConnectPort: 8443}, {Host: "first.test", Port: 8443, ConnectHost: "192.0.2.99", ConnectPort: 443}}, Resolve: []ResolveRule{{Host: "first.test", Port: 8443, Addresses: []string{"192.0.2.2"}}}}, want: []string{"192.0.2.2:8443"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			var dns atomic.Int32
			base := func(ctx context.Context, n, a string) (net.Conn, error) {
				got = append(got, a)
				if a == "192.0.2.1:443" {
					return nil, errors.New("candidate failed")
				}
				aConn, bConn := net.Pipe()
				_ = bConn.Close()
				return aConn, nil
			}
			network, addr := tc.network, tc.addr
			if network == "" {
				network = "tcp"
			}
			if addr == "" {
				addr = "logical.test:443"
			}
			conn, err := mappedDialContext(base, noNetworkDNS(&dns), !tc.guard)(networkContext(t, tc.o), network, addr)
			if conn != nil {
				_ = conn.Close()
			}
			if (err != nil) != tc.fail {
				t.Fatalf("err=%v fail=%v", err, tc.fail)
			}
			if errors.Is(err, ErrBlockedAddress) != tc.blocked {
				t.Fatalf("blocked=%v error=%v", tc.blocked, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("dialed %v want %v", got, tc.want)
			}
			if dns.Load() != 0 {
				t.Fatalf("Resolve/conflict leaked DNS: %d", dns.Load())
			}
		})
	}
}

func TestNetworkMappingNoFallbackAndBudget(t *testing.T) {
	var dns atomic.Int32
	sentinel := errors.New("fixed candidate failed")
	calls := 0
	dial := mappedDialContext(func(context.Context, string, string) (net.Conn, error) { calls++; return nil, sentinel }, noNetworkDNS(&dns), false)
	_, err := dial(networkContext(t, networkIPs("192.0.2.1", "192.0.2.2")), "tcp", "logical.test:443")
	if !errors.Is(err, sentinel) || calls != 2 || dns.Load() != 0 {
		t.Fatalf("err=%v calls=%d DNS=%d", err, calls, dns.Load())
	}
	ctx, cancel := context.WithTimeout(networkContext(t, networkIPs("192.0.2.1", "192.0.2.2")), 20*time.Millisecond)
	defer cancel()
	calls = 0
	dial = mappedDialContext(func(ctx context.Context, _, _ string) (net.Conn, error) { calls++; <-ctx.Done(); return nil, ctx.Err() }, noNetworkDNS(&dns), false)
	_, err = dial(ctx, "tcp", "logical.test:443")
	if !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatalf("renewed budget: %v calls=%d", err, calls)
	}
}

func TestNetworkCanonicalIdentityAndClone(t *testing.T) {
	compile := func(o *NetworkOptions) string {
		p, err := compileNetworkOptions(o)
		if err != nil {
			t.Fatal(err)
		}
		return p.identity
	}
	for _, o := range []*NetworkOptions{nil, {}, {AddressFamily: AddressFamilyAuto}} {
		if compile(o) != "" {
			t.Fatal("zero policy has nonzero identity")
		}
	}
	original := &NetworkOptions{Resolve: []ResolveRule{{Host: "B.TEST.", Port: 443, Addresses: []string{"::ffff:192.0.2.2", "192.0.2.3"}}, {Host: "a.test", Port: 80, Addresses: []string{"2001:db8::1"}}}, ConnectTo: []ConnectToRule{{Host: "LOGICAL.TEST.", Port: 443, ConnectHost: "B.Test", ConnectPort: 443}}}
	clone := original.Clone()
	clone.Resolve[0].Host = "b.test"
	clone.Resolve[0].Addresses[0] = "192.0.2.2"
	clone.ConnectTo[0].Host = "logical.test"
	clone.ConnectTo[0].ConnectHost = "b.test"
	clone.Resolve[0], clone.Resolve[1] = clone.Resolve[1], clone.Resolve[0]
	if compile(original) != compile(clone) {
		t.Fatal("equivalent policies have different identities")
	}
	clone.Resolve[1].Addresses[0], clone.Resolve[1].Addresses[1] = clone.Resolve[1].Addresses[1], clone.Resolve[1].Addresses[0]
	if compile(original) == compile(clone) {
		t.Fatal("address preference order missing from identity")
	}
	req := &Request{Network: original}
	copied := cloneRequest(req)
	copied.Network.Resolve[0].Addresses[0] = "192.0.2.99"
	if original.Resolve[0].Addresses[0] != "::ffff:192.0.2.2" {
		t.Fatal("redirect clone aliases network policy")
	}
}

func TestNetworkProxyAndLogicalValidation(t *testing.T) {
	for _, proxy := range []string{"http://127.0.0.1:1", "socks5://127.0.0.1:1"} {
		for _, o := range []*NetworkOptions{networkIPs("192.0.2.2"), {AddressFamily: AddressFamilyIPv4}, {ConnectTo: []ConnectToRule{{Host: "unused.test", Port: 443, ConnectHost: "192.0.2.2", ConnectPort: 443}}}} {
			_, err := withNetworkOptions(context.Background(), &Request{URL: "https://logical.test", Proxy: proxy, Network: o})
			if !errors.Is(err, ErrNetworkProxyUnsupported) {
				t.Fatalf("proxy policy silently ignored: %v", err)
			}
		}
		for _, o := range []*NetworkOptions{nil, {}, {AddressFamily: AddressFamilyAuto}} {
			if _, err := withNetworkOptions(context.Background(), &Request{URL: "https://logical.test", Proxy: proxy, Network: o}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, host := range []string{"tést.test", "K.test", "[fe80::1%25eth0]"} {
		if _, err := withNetworkOptions(context.Background(), &Request{URL: "https://" + host, Network: networkIPs("192.0.2.2")}); err == nil {
			t.Fatalf("unsupported logical host accepted: %s", host)
		}
	}
	tr := newTLSTransport(1024)
	pool, err := newClientPool(ConnectionPoolConfig{})
	if err != nil {
		t.Fatal(err)
	}
	tr.pool = pool
	defer pool.close()
	req := &Request{URL: "https://127.0.0.1", Network: &NetworkOptions{ConnectTo: []ConnectToRule{{Host: "127.0.0.1", Port: 443, ConnectHost: "192.0.2.2", ConnectPort: 443}}}}
	ctx, err := withNetworkOptions(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := tr.acquireClient(ctx, req)
	if lease != nil || !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("logical guard skipped: %v", err)
	}
	if n, _ := poolSize(pool); n != 0 {
		t.Fatal("guard checked after allocating client")
	}
}

// Controlled DNS verifies production guard/family filtering without external IO.
func networkDNS(t *testing.T) (*net.Resolver, *atomic.Int32) {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	calls := new(atomic.Int32)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := socket.ReadFrom(buf)
			if err != nil {
				return
			}
			var parser dnsmessage.Parser
			header, err := parser.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := parser.Question()
			if err != nil {
				continue
			}
			calls.Add(1)
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true})
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			h := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 30}
			if q.Type == dnsmessage.TypeA {
				_ = b.AResource(h, dnsmessage.AResource{A: [4]byte{192, 0, 2, 2}})
			} else if q.Type == dnsmessage.TypeAAAA {
				_ = b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}})
			}
			response, err := b.Finish()
			if err == nil {
				_, _ = socket.WriteTo(response, peer)
			}
		}
	}()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", socket.LocalAddr().String())
	}}, calls
}
func TestNetworkGuardedDNSFamilyAndCNAME(t *testing.T) {
	for _, family := range []AddressFamily{AddressFamilyIPv4, AddressFamilyIPv6} {
		t.Run(string(family), func(t *testing.T) {
			resolver, calls := networkDNS(t)
			var got string
			dial := mappedDialContext(func(_ context.Context, _, addr string) (net.Conn, error) {
				got = addr
				a, b := net.Pipe()
				_ = b.Close()
				return a, nil
			}, resolver, false)
			ctx := networkContext(t, &NetworkOptions{AddressFamily: family})
			conn, err := dial(ctx, "tcp", "logical.test:443")
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			want := "192.0.2.2:443"
			if family == AddressFamilyIPv6 {
				want = "[2001:db8::2]:443"
			}
			if got != want {
				t.Fatalf("dialed %s want %s", got, want)
			}
			if calls.Load() == 0 {
				t.Fatal("controlled DNS not consulted")
			}
			before := calls.Load()
			if cname := lookupCNAME(ctx, resolver, "logical.test"); cname != "" {
				t.Fatalf("unexpected CNAME %s", cname)
			}
			if calls.Load() != before {
				t.Fatal("metadata triggered logical DNS")
			}
		})
	}
}

func TestNetworkHostValidation(t *testing.T) {
	for _, host := range []string{"", "*.test", "a..test", "host:443", "a/b", "user@host", "[::1]", "fe80::1%eth0", "tést.test", "K.test", " host", "a.test.."} {
		if _, err := canonicalNetworkHost(host); err == nil {
			t.Fatalf("accepted %q", host)
		}
	}
	for _, tc := range []struct{ in, want string }{{"EXAMPLE.TEST.", "example.test"}, {"2001:0db8::1", "2001:db8::1"}, {"::ffff:192.0.2.2", "192.0.2.2"}} {
		got, err := canonicalNetworkHost(tc.in)
		if err != nil || got != tc.want {
			t.Fatal(fmt.Sprint(tc, got, err))
		}
	}
}
