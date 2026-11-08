package nethttp

import (
	"encoding/json"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/emhha/netloom"
)

// These adapter tests deliberately perform no DNS, interface lookup or dialing.
func TestBuildRequestNetworkBindingJSON(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        *netloom.NetworkOptions
	}{
		{"omitted", `{"url":"https://example.test"}`, nil},
		{"null", `{"url":"https://example.test","network":null}`, nil},
		{"empty", `{"url":"https://example.test","network":{}}`, &netloom.NetworkOptions{}},
		{"explicit-empty-fields", `{"url":"https://example.test","network":{"local_address":"","interface":""}}`, &netloom.NetworkOptions{}},
		{"null-fields", `{"url":"https://example.test","network":{"local_address":null,"interface":null}}`, &netloom.NetworkOptions{}},
		{"ipv4-source", `{"url":"https://example.test","network":{"local_address":"192.0.2.10"}}`, &netloom.NetworkOptions{LocalAddress: "192.0.2.10"}},
		{"ipv6-source", `{"url":"https://example.test","network":{"local_address":"2001:db8::10","address_family":"ipv6"}}`, &netloom.NetworkOptions{LocalAddress: "2001:db8::10", AddressFamily: netloom.AddressFamilyIPv6}},
		{"mapped-source", `{"url":"https://example.test","network":{"local_address":"::ffff:192.0.2.10","address_family":"ipv4"}}`, &netloom.NetworkOptions{LocalAddress: "::ffff:192.0.2.10", AddressFamily: netloom.AddressFamilyIPv4}},
		{"interface", `{"url":"https://example.test","network":{"interface":"eth0"}}`, &netloom.NetworkOptions{Interface: "eth0"}},
		{"source-and-interface", `{"url":"https://example.test","network":{"local_address":"192.0.2.10","interface":"eth0"}}`, &netloom.NetworkOptions{LocalAddress: "192.0.2.10", Interface: "eth0"}},
		{"interface-name-boundary", `{"url":"https://example.test","network":{"interface":"abcdefghijklmno"}}`, &netloom.NetworkOptions{Interface: "abcdefghijklmno"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var input RequestInput
			if err := json.Unmarshal([]byte(tc.input), &input); err != nil {
				t.Fatal(err)
			}
			before := input.Network.Clone()
			request, err := BuildRequest(input)
			if tc.want != nil && tc.want.Interface != "" && runtime.GOOS != "linux" {
				if request != nil || !errors.Is(err, netloom.ErrNetworkBindingUnsupported) {
					t.Fatalf("unsupported interface: request=%+v err=%v", request, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(request.Network, tc.want) {
					t.Fatalf("network=%+v want=%+v", request.Network, tc.want)
				}
				if request.URL != "https://example.test" || !request.VerifyTLS {
					t.Fatalf("binding changed logical URL or TLS verification: %+v", request)
				}
			}
			if !reflect.DeepEqual(input.Network, before) {
				t.Fatal("BuildRequest mutated input, including source spelling")
			}
			encoded, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			var roundTrip RequestInput
			if err := json.Unmarshal(encoded, &roundTrip); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(roundTrip.Network, tc.want) {
				t.Fatalf("round trip network=%+v want=%+v", roundTrip.Network, tc.want)
			}
			if tc.want == nil && strings.Contains(string(encoded), `"network"`) {
				t.Fatalf("nil network not omitted: %s", encoded)
			}
			if tc.want != nil && !strings.Contains(string(encoded), `"network":`) {
				t.Fatalf("explicit network omitted: %s", encoded)
			}
		})
	}
}

func TestBuildRequestNetworkBindingJSONTypes(t *testing.T) {
	for _, payload := range []string{
		`{"network":{"local_address":123}}`,
		`{"network":{"local_address":true}}`,
		`{"network":{"local_address":[]}}`,
		`{"network":{"interface":123}}`,
		`{"network":{"interface":false}}`,
		`{"network":{"interface":{}}}`,
	} {
		var input RequestInput
		if err := json.Unmarshal([]byte(payload), &input); err == nil {
			t.Fatalf("accepted non-string binding field: %s", payload)
		}
	}
}

func TestBuildRequestNetworkBindingCloneIndependence(t *testing.T) {
	policy := &netloom.NetworkOptions{
		LocalAddress: "::ffff:192.0.2.10", AddressFamily: netloom.AddressFamilyIPv4,
		Resolve:   []netloom.ResolveRule{{Host: "origin.test", Port: 443, Addresses: []string{"192.0.2.20"}}},
		ConnectTo: []netloom.ConnectToRule{{Host: "example.test", Port: 443, ConnectHost: "origin.test", ConnectPort: 443}},
	}
	if runtime.GOOS == "linux" {
		policy.Interface = "eth0"
	}
	original := policy.Clone()
	clone := policy.Clone()
	input := RequestInput{URL: "https://example.test", Network: policy}
	first, err := BuildRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	if clone == policy || first.Network == policy || second.Network == first.Network {
		t.Fatal("native clone or adapter shares network pointers")
	}
	if !reflect.DeepEqual(policy, original) || !reflect.DeepEqual(clone, original) || !reflect.DeepEqual(first.Network, original) {
		t.Fatal("clone or BuildRequest changed policy")
	}
	policy.LocalAddress, policy.Interface = "192.0.2.99", "input-only"
	policy.Resolve[0].Addresses[0] = "192.0.2.98"
	policy.ConnectTo[0].ConnectHost = "input-only.test"
	for _, copied := range []*netloom.NetworkOptions{clone, first.Network, second.Network} {
		if !reflect.DeepEqual(copied, original) {
			t.Fatalf("input mutation leaked into independent copy: %+v", copied)
		}
	}
	inputSnapshot := policy.Clone()
	clone.LocalAddress, clone.Interface = "192.0.2.97", "clone-only"
	clone.Resolve[0].Addresses[0] = "192.0.2.96"
	first.Network.LocalAddress, first.Network.Interface = "192.0.2.95", "request-only"
	first.Network.Resolve[0].Addresses[0] = "192.0.2.94"
	first.Network.ConnectTo[0].ConnectHost = "request-only.test"
	if !reflect.DeepEqual(policy, inputSnapshot) || !reflect.DeepEqual(second.Network, original) {
		t.Fatal("copy mutation changed caller or another built request")
	}
	var nilPolicy *netloom.NetworkOptions
	if nilPolicy.Clone() != nil {
		t.Fatal("nil clone is not nil")
	}
}

func TestBuildRequestNetworkBindingValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network netloom.NetworkOptions
	}{
		{"source-hostname", netloom.NetworkOptions{LocalAddress: "source.test"}},
		{"source-port", netloom.NetworkOptions{LocalAddress: "192.0.2.10:1234"}},
		{"source-brackets", netloom.NetworkOptions{LocalAddress: "[2001:db8::10]"}},
		{"source-zone", netloom.NetworkOptions{LocalAddress: "fe80::1%eth0"}},
		{"source-whitespace", netloom.NetworkOptions{LocalAddress: " 192.0.2.10"}},
		{"source-unspecified-v4", netloom.NetworkOptions{LocalAddress: "0.0.0.0"}},
		{"source-unspecified-v6", netloom.NetworkOptions{LocalAddress: "::"}},
		{"source-unspecified-mapped", netloom.NetworkOptions{LocalAddress: "::ffff:0.0.0.0"}},
		{"source-multicast-v4", netloom.NetworkOptions{LocalAddress: "224.0.0.1"}},
		{"source-multicast-v6", netloom.NetworkOptions{LocalAddress: "ff02::1"}},
		{"source-multicast-mapped", netloom.NetworkOptions{LocalAddress: "::ffff:224.0.0.1"}},
		{"source-v4-family-conflict", netloom.NetworkOptions{LocalAddress: "192.0.2.10", AddressFamily: netloom.AddressFamilyIPv6}},
		{"source-v6-family-conflict", netloom.NetworkOptions{LocalAddress: "2001:db8::10", AddressFamily: netloom.AddressFamilyIPv4}},
		{"source-mapped-family-conflict", netloom.NetworkOptions{LocalAddress: "::ffff:192.0.2.10", AddressFamily: netloom.AddressFamilyIPv6}},
		{"interface-too-long", netloom.NetworkOptions{Interface: "abcdefghijklmnop"}},
		{"interface-space", netloom.NetworkOptions{Interface: "eth 0"}},
		{"interface-tab", netloom.NetworkOptions{Interface: "eth\t0"}},
		{"interface-slash", netloom.NetworkOptions{Interface: "eth/0"}},
		{"interface-colon", netloom.NetworkOptions{Interface: "eth0:1"}},
		{"interface-dot", netloom.NetworkOptions{Interface: "."}},
		{"interface-dot-dot", netloom.NetworkOptions{Interface: ".."}},
		{"interface-nul", netloom.NetworkOptions{Interface: "eth\x000"}},
		{"interface-del", netloom.NetworkOptions{Interface: "eth\x7f0"}},
		{"interface-unicode", netloom.NetworkOptions{Interface: "网卡"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.network.Clone()
			nativeErr := tc.network.Validate()
			request, err := BuildRequest(RequestInput{URL: "https://example.test", Network: &tc.network})
			if nativeErr == nil || err == nil || request != nil {
				t.Fatalf("invalid policy accepted: native=%v adapter=%v request=%+v", nativeErr, err, request)
			}
			if err.Error() != nativeErr.Error() {
				t.Fatalf("adapter lost native validation error: native=%v adapter=%v", nativeErr, err)
			}
			if tc.network.Interface == "" || runtime.GOOS == "linux" {
				if !errors.Is(err, netloom.ErrNetworkBindingInvalid) {
					t.Fatalf("adapter lost binding-invalid identity: %v", err)
				}
			}
			if !reflect.DeepEqual(&tc.network, before) {
				t.Fatal("validation mutated caller policy")
			}
		})
	}
}
