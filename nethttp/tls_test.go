package nethttp

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/emhha/netloom"
)

func adapterTLSPin(seed byte) string {
	digest := make([]byte, 32)
	digest[0] = seed
	return "sha256//" + base64.StdEncoding.EncodeToString(digest)
}

func TestBuildRequestTLSJSON(t *testing.T) {
	pin := adapterTLSPin(1)
	for _, tc := range []struct {
		name, input string
		want        *netloom.TLSOptions
	}{
		{"omitted", `{"url":"https://example.test"}`, nil},
		{"null", `{"url":"https://example.test","tls":null}`, nil},
		{"empty", `{"url":"https://example.test","tls":{}}`, &netloom.TLSOptions{}},
		{"explicit-zero", `{"url":"https://example.test","tls":{"min_version":"","max_version":"","server_name":"","pinned_public_keys":[]}}`, &netloom.TLSOptions{}},
		{"tls10", `{"url":"https://example.test","tls":{"min_version":"1.0"}}`, &netloom.TLSOptions{MinVersion: netloom.TLSVersion10}},
		{"tls11", `{"url":"https://example.test","tls":{"min_version":"1.1"}}`, &netloom.TLSOptions{MinVersion: netloom.TLSVersion11}},
		{"tls12", `{"url":"https://example.test","tls":{"min_version":"1.2","max_version":"1.2"}}`, &netloom.TLSOptions{MinVersion: netloom.TLSVersion12, MaxVersion: netloom.TLSVersion12}},
		{"tls13", `{"url":"https://example.test","tls":{"min_version":"1.3","max_version":"1.3"}}`, &netloom.TLSOptions{MinVersion: netloom.TLSVersion13, MaxVersion: netloom.TLSVersion13}},
		{"sni", `{"url":"https://example.test","tls":{"server_name":"Alternate.EXAMPLE."}}`, &netloom.TLSOptions{ServerName: "Alternate.EXAMPLE."}},
		{"punycode", `{"url":"https://example.test","tls":{"server_name":"xn--bcher-kva.example"}}`, &netloom.TLSOptions{ServerName: "xn--bcher-kva.example"}},
		{"ipv4", `{"url":"https://example.test","tls":{"server_name":"192.0.2.10"}}`, &netloom.TLSOptions{ServerName: "192.0.2.10"}},
		{"ipv6", `{"url":"https://example.test","tls":{"server_name":"2001:db8::1"}}`, &netloom.TLSOptions{ServerName: "2001:db8::1"}},
		{"pins", `{"url":"https://example.test","tls":{"pinned_public_keys":["` + pin + `"]}}`, &netloom.TLSOptions{PinnedPublicKeys: []string{pin}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var input RequestInput
			if err := json.Unmarshal([]byte(tc.input), &input); err != nil {
				t.Fatal(err)
			}
			request, err := BuildRequest(input)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(request.TLSConfig, tc.want) {
				t.Fatalf("TLS=%+v want=%+v", request.TLSConfig, tc.want)
			}
			if !request.VerifyTLS || request.URL != "https://example.test" {
				t.Fatalf("TLS controls changed verification or logical URL: %+v", request)
			}
			encoded, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == nil && strings.Contains(string(encoded), `"tls"`) {
				t.Fatalf("nil TLS not omitted: %s", encoded)
			}
			if tc.want != nil && !strings.Contains(string(encoded), `"tls":`) {
				t.Fatalf("explicit TLS omitted: %s", encoded)
			}
		})
	}
}

func TestBuildRequestTLSDeepCopy(t *testing.T) {
	input := RequestInput{URL: "https://example.test", TLS: &TLSInput{
		MinVersion: netloom.TLSVersion12, MaxVersion: netloom.TLSVersion13,
		ServerName: "alternate.test", PinnedPublicKeys: []string{adapterTLSPin(1), adapterTLSPin(2)},
	}}
	before, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	first, err := BuildRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("BuildRequest mutated input")
	}
	if first.TLSConfig == second.TLSConfig {
		t.Fatal("BuildRequest shares TLS configuration between requests")
	}
	input.TLS.MinVersion = netloom.TLSVersion10
	input.TLS.MaxVersion = netloom.TLSVersion11
	input.TLS.ServerName = "input-only.test"
	input.TLS.PinnedPublicKeys[0] = adapterTLSPin(3)
	if first.TLSConfig.MinVersion != netloom.TLSVersion12 || first.TLSConfig.MaxVersion != netloom.TLSVersion13 || first.TLSConfig.ServerName != "alternate.test" || first.TLSConfig.PinnedPublicKeys[0] != adapterTLSPin(1) {
		t.Fatalf("input mutation changed built TLS config: %+v", first.TLSConfig)
	}
	first.TLSConfig.ServerName = "request-only.test"
	first.TLSConfig.PinnedPublicKeys[1] = adapterTLSPin(4)
	if input.TLS.ServerName != "input-only.test" || input.TLS.PinnedPublicKeys[1] != adapterTLSPin(2) || second.TLSConfig.PinnedPublicKeys[1] != adapterTLSPin(2) {
		t.Fatal("request mutation changed input or other request")
	}
}

func TestBuildRequestTLSValidation(t *testing.T) {
	pin := adapterTLSPin(1)
	many := make([]string, 17)
	for i := range many {
		many[i] = adapterTLSPin(byte(i))
	}
	for _, tc := range []struct {
		name string
		tls  TLSInput
	}{
		{"invalid-min", TLSInput{MinVersion: "TLS1.2"}},
		{"invalid-max", TLSInput{MaxVersion: "1.4"}},
		{"inverted-range", TLSInput{MinVersion: netloom.TLSVersion13, MaxVersion: netloom.TLSVersion12}},
		{"pin-prefix", TLSInput{PinnedPublicKeys: []string{"sha1//" + strings.TrimPrefix(pin, "sha256//")}}},
		{"pin-invalid-base64", TLSInput{PinnedPublicKeys: []string{"sha256//!"}}},
		{"pin-short", TLSInput{PinnedPublicKeys: []string{"sha256//" + base64.StdEncoding.EncodeToString([]byte("short"))}}},
		{"pin-no-padding", TLSInput{PinnedPublicKeys: []string{strings.TrimRight(pin, "=")}}},
		{"pin-newline", TLSInput{PinnedPublicKeys: []string{pin + "\n"}}},
		{"pin-duplicate", TLSInput{PinnedPublicKeys: []string{pin, pin}}},
		{"pin-over-limit", TLSInput{PinnedPublicKeys: many}},
		{"unicode-server-name", TLSInput{ServerName: "bücher.example"}},
		{"unicode-fold-server-name", TLSInput{ServerName: "K.example"}},
		{"bracketed-server-name", TLSInput{ServerName: "[2001:db8::1]"}},
		{"zoned-server-name", TLSInput{ServerName: "fe80::1%eth0"}},
		{"url-server-name", TLSInput{ServerName: "https://example.test"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := RequestInput{URL: "https://example.test", TLS: &tc.tls}
			before, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			request, err := BuildRequest(input)
			if err == nil || request != nil {
				t.Fatalf("accepted invalid TLS: request=%+v error=%v", request, err)
			}
			after, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("validation mutated input")
			}
		})
	}
	if _, err := BuildRequest(RequestInput{URL: "https://example.test", TLS: &TLSInput{PinnedPublicKeys: many[:16]}}); err != nil {
		t.Fatalf("valid pin count boundary rejected: %v", err)
	}
}

func TestBuildRequestTLSVerificationAndExecutionBoundaries(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		for _, tls := range []*TLSInput{nil, {}, {ServerName: "alternate.test", PinnedPublicKeys: []string{adapterTLSPin(1)}}} {
			request, err := BuildRequest(RequestInput{URL: "https://example.test", InsecureTLS: insecure, TLS: tls})
			if err != nil {
				t.Fatal(err)
			}
			if request.VerifyTLS == insecure {
				t.Fatalf("explicit TLS changed InsecureTLS=%v policy", insecure)
			}
		}
	}
	// Conversion validates syntax only. Engine owns unsupported scheme/profile
	// combinations and the concrete profile's advertised protocol versions.
	for _, input := range []RequestInput{
		{URL: "http://example.test", TLS: &TLSInput{MinVersion: netloom.TLSVersion12}},
		{URL: "https://example.test", TLSProfile: "chrome_120", TLS: &TLSInput{MaxVersion: netloom.TLSVersion12}},
	} {
		if _, err := BuildRequest(input); err != nil {
			t.Fatalf("adapter incorrectly applied execution policy: %v", err)
		}
	}
	encoded, err := json.Marshal(TLSInput{MinVersion: netloom.TLSVersion12, ServerName: "alternate.test", PinnedPublicKeys: []string{adapterTLSPin(1)}})
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	for key := range object {
		switch key {
		case "min_version", "max_version", "server_name", "pinned_public_keys":
		default:
			t.Fatalf("unexpected credential or unsupported TLS JSON field %q", key)
		}
	}
}
