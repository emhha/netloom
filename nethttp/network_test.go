package nethttp

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/emhha/netloom"
)

func TestBuildRequestNetworkJSON(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        *netloom.NetworkOptions
	}{
		{name: "omitted", input: `{"url":"https://example.test"}`},
		{name: "null", input: `{"url":"https://example.test","network":null}`},
		{name: "empty", input: `{"url":"https://example.test","network":{}}`, want: &netloom.NetworkOptions{}},
		{name: "auto", input: `{"url":"https://example.test","network":{"address_family":"auto"}}`, want: &netloom.NetworkOptions{AddressFamily: netloom.AddressFamilyAuto}},
		{name: "ipv4", input: `{"url":"https://example.test","network":{"address_family":"ipv4"}}`, want: &netloom.NetworkOptions{AddressFamily: netloom.AddressFamilyIPv4}},
		{name: "ipv6", input: `{"url":"https://example.test","network":{"address_family":"ipv6"}}`, want: &netloom.NetworkOptions{AddressFamily: netloom.AddressFamilyIPv6}},
		{name: "resolve-and-connect", input: `{"url":"https://example.test","network":{"address_family":"ipv4","resolve":[{"host":"origin.test","port":8443,"addresses":["192.0.2.10","192.0.2.11"]}],"connect_to":[{"host":"example.test","port":443,"connect_host":"origin.test","connect_port":8443}]}}`, want: &netloom.NetworkOptions{AddressFamily: netloom.AddressFamilyIPv4, Resolve: []netloom.ResolveRule{{Host: "origin.test", Port: 8443, Addresses: []string{"192.0.2.10", "192.0.2.11"}}}, ConnectTo: []netloom.ConnectToRule{{Host: "example.test", Port: 443, ConnectHost: "origin.test", ConnectPort: 8443}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var in RequestInput
			if err := json.Unmarshal([]byte(tc.input), &in); err != nil {
				t.Fatal(err)
			}
			request, err := BuildRequest(in)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(request.Network, tc.want) {
				t.Fatalf("network=%+v want=%+v", request.Network, tc.want)
			}
			if request.URL != "https://example.test" {
				t.Fatalf("mapping changed logical URL: %s", request.URL)
			}
			encoded, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == nil && strings.Contains(string(encoded), `"network"`) {
				t.Fatalf("nil network not omitted: %s", encoded)
			}
		})
	}
}

func TestBuildRequestNetworkDeepCopy(t *testing.T) {
	input := RequestInput{URL: "https://example.test", Network: &netloom.NetworkOptions{
		AddressFamily: netloom.AddressFamilyIPv4,
		Resolve:       []netloom.ResolveRule{{Host: "origin.test", Port: 8443, Addresses: []string{"192.0.2.10", "192.0.2.11"}}},
		ConnectTo:     []netloom.ConnectToRule{{Host: "example.test", Port: 443, ConnectHost: "origin.test", ConnectPort: 8443}},
	}}
	original := input.Network.Clone()
	request, err := BuildRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(input.Network, original) {
		t.Fatal("BuildRequest mutated network input")
	}
	if request.Network == input.Network {
		t.Fatal("network pointer aliases input")
	}
	input.Network.AddressFamily = netloom.AddressFamilyIPv6
	input.Network.Resolve[0].Host = "changed.test"
	input.Network.Resolve[0].Port = 80
	input.Network.Resolve[0].Addresses[0] = "192.0.2.99"
	input.Network.ConnectTo[0].Host = "changed.test"
	input.Network.ConnectTo[0].ConnectHost = "changed-origin.test"
	input.Network.ConnectTo[0].ConnectPort = 9443
	if !reflect.DeepEqual(request.Network, original) {
		t.Fatalf("input mutation changed built request: %+v", request.Network)
	}
	mutated := input.Network.Clone()
	request.Network.Resolve[0].Addresses[1] = "192.0.2.98"
	request.Network.ConnectTo[0].ConnectHost = "request-only.test"
	if !reflect.DeepEqual(input.Network, mutated) {
		t.Fatal("built request mutation changed input")
	}
}

func TestBuildRequestNetworkValidation(t *testing.T) {
	resolve := func(host string, port int, addresses ...string) netloom.ResolveRule {
		return netloom.ResolveRule{Host: host, Port: port, Addresses: addresses}
	}
	connect := func(host string, port int, target string, targetPort int) netloom.ConnectToRule {
		return netloom.ConnectToRule{Host: host, Port: port, ConnectHost: target, ConnectPort: targetPort}
	}
	manyResolve := make([]netloom.ResolveRule, 65)
	manyConnect := make([]netloom.ConnectToRule, 65)
	for i := range manyResolve {
		manyResolve[i] = resolve("example.test", i+1, "192.0.2.10")
		manyConnect[i] = connect("example.test", i+1, "origin.test", 443)
	}
	manyIPs := make([]string, 17)
	for i := range manyIPs {
		manyIPs[i] = fmt.Sprintf("192.0.2.%d", i+1)
	}
	for _, tc := range []struct {
		name    string
		network netloom.NetworkOptions
	}{
		{"invalid-family", netloom.NetworkOptions{AddressFamily: "IPv4"}},
		{"resolve-host", netloom.NetworkOptions{Resolve: []netloom.ResolveRule{resolve("https://example.test", 443, "192.0.2.10")}}},
		{"resolve-port-zero", netloom.NetworkOptions{Resolve: []netloom.ResolveRule{resolve("example.test", 0, "192.0.2.10")}}},
		{"resolve-port-overflow", netloom.NetworkOptions{Resolve: []netloom.ResolveRule{resolve("example.test", 65536, "192.0.2.10")}}},
		{"resolve-empty-addresses", netloom.NetworkOptions{Resolve: []netloom.ResolveRule{resolve("example.test", 443)}}},
		{"resolve-dns-address", netloom.NetworkOptions{Resolve: []netloom.ResolveRule{resolve("example.test", 443, "origin.test")}}},
		{"resolve-zoned-address", netloom.NetworkOptions{Resolve: []netloom.ResolveRule{resolve("example.test", 443, "fe80::1%eth0")}}},
		{"resolve-duplicate-address", netloom.NetworkOptions{Resolve: []netloom.ResolveRule{resolve("example.test", 443, "192.0.2.10", "::ffff:192.0.2.10")}}},
		{"resolve-duplicate-key", netloom.NetworkOptions{Resolve: []netloom.ResolveRule{resolve("Example.TEST.", 443, "192.0.2.10"), resolve("example.test", 443, "192.0.2.11")}}},
		{"resolve-overlimit", netloom.NetworkOptions{Resolve: manyResolve}},
		{"resolve-addresses-overlimit", netloom.NetworkOptions{Resolve: []netloom.ResolveRule{resolve("example.test", 443, manyIPs...)}}},
		{"connect-host", netloom.NetworkOptions{ConnectTo: []netloom.ConnectToRule{connect("*.example.test", 443, "origin.test", 443)}}},
		{"connect-port", netloom.NetworkOptions{ConnectTo: []netloom.ConnectToRule{connect("example.test", -1, "origin.test", 443)}}},
		{"connect-target-host", netloom.NetworkOptions{ConnectTo: []netloom.ConnectToRule{connect("example.test", 443, "origin.test/path", 443)}}},
		{"connect-target-port", netloom.NetworkOptions{ConnectTo: []netloom.ConnectToRule{connect("example.test", 443, "origin.test", 65536)}}},
		{"connect-duplicate-key", netloom.NetworkOptions{ConnectTo: []netloom.ConnectToRule{connect("Example.TEST.", 443, "one.test", 443), connect("example.test", 443, "two.test", 8443)}}},
		{"connect-overlimit", netloom.NetworkOptions{ConnectTo: manyConnect}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := RequestInput{URL: "https://example.test", Network: &tc.network}
			before := input.Network.Clone()
			request, err := BuildRequest(input)
			if err == nil || request != nil {
				t.Fatalf("accepted invalid network: %+v err=%v", request, err)
			}
			if !reflect.DeepEqual(input.Network, before) {
				t.Fatal("validation mutated input")
			}
		})
	}
	for _, network := range []*netloom.NetworkOptions{{Resolve: manyResolve[:64], ConnectTo: manyConnect[:64]}, {Resolve: []netloom.ResolveRule{resolve("example.test", 65535, manyIPs[:16]...)}}} {
		if _, err := BuildRequest(RequestInput{URL: "https://example.test", Network: network}); err != nil {
			t.Fatalf("valid boundary rejected: %v", err)
		}
	}
}
