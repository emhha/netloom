package serialization

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/emhha/netloom/httpdata"
	"github.com/emhha/netloom/passive"
)

func serialInput(body []byte) passive.Input {
	return passive.Input{Request: &httpdata.Request{URL: "https://example.test/", Body: body}, Response: &httpdata.Response{}}
}
func serialFindings(t *testing.T, result passive.Result) []Finding {
	t.Helper()
	var data struct {
		Findings    []Finding `json:"findings"`
		PassiveOnly bool      `json:"passive_only"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatal(err)
	}
	if !data.PassiveOnly {
		t.Fatal("missing passive-only marker")
	}
	return data.Findings
}
func serialHas(findings []Finding, rule, strength, scope, encoding string) bool {
	for _, f := range findings {
		if f.Rule == rule && f.Strength == strength && f.Scope == scope && f.Encoding == encoding {
			return true
		}
	}
	return false
}
func TestSerializationMagic(t *testing.T) {
	for _, magic := range serializationMagics {
		t.Run(magic.rule, func(t *testing.T) {
			result, err := (Plugin{}).Analyze(context.Background(), serialInput(magic.prefix))
			if err != nil {
				t.Fatal(err)
			}
			if !serialHas(serialFindings(t, result), magic.rule, magic.strength, "request.body", "raw") {
				t.Fatalf("missing magic: %s", result.Data)
			}
		})
	}
}
func TestSerializationLocationsAndEncodings(t *testing.T) {
	java := []byte{0xac, 0xed, 0, 5, 0x73, 0x72, 0xfb, 0xff}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		token := enc.EncodeToString(java)
		for _, location := range []string{"request.body", "request.url", "request.header.cookie", "response.body"} {
			in := serialInput(nil)
			switch location {
			case "request.body":
				in.Request.Body = []byte(`{"data":"` + token + `"}`)
			case "request.url":
				in.Request.URL += "?data=" + url.QueryEscape(token)
			case "request.header.cookie":
				in.Request.Header = http.Header{"Cookie": {"payload=" + token}}
			case "response.body":
				in.Response.Body = []byte(token)
			}
			result, err := (Plugin{}).Analyze(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			strength := "strong"
			if location == "response.body" {
				strength = "medium"
			}
			found := false
			for _, f := range serialFindings(t, result) {
				if f.Rule == "magic.java" && f.Scope == location && f.Strength == strength {
					found = true
				}
			}
			if !found {
				t.Fatalf("location %s token %s: %s", location, token, result.Data)
			}
		}
	}
	for _, test := range []struct{ token, rule string }{{"/wEP", "magic.viewstate"}, {"gAQ=", "magic.pickle4"}, {"gAWVAAAAAAAAAAA=", "magic.pickle5"}} {
		result, err := (Plugin{}).Analyze(context.Background(), serialInput([]byte(test.token)))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range serialFindings(t, result) {
			if f.Rule == test.rule && f.Encoding == "base64" {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing short token %s: %s", test.token, result.Data)
		}
	}
}
func TestSerializationTextAndErrors(t *testing.T) {
	tests := []struct{ body, rule, strength string }{
		{`O:4:"Demo":0:{}`, "text.php-object", "strong"},
		{`C:4:"Demo":0:{}`, "text.php-object", "strong"},
		{`a:1:{s:1:"x";i:1;}`, "text.php-array", "medium"},
		{`!!python/object/apply:os.system []`, "text.python-yaml", "strong"},
		{`_$$ND_FUNC$$_function(){}`, "text.node-function", "strong"},
		{`{"@type":"business","@class":"ordinary","$type":"item"}`, "text.java-json-type", "weak"},
		{`rememberMe=ordinary-session`, "context.remember-me", "weak"},
		{`<dynamic-proxy>`, "text.xstream", "medium"},
		{"cposix\nsystem\n", "text.pickle-global", "strong"},
	}
	for _, test := range tests {
		result, err := (Plugin{}).Analyze(context.Background(), serialInput([]byte(test.body)))
		if err != nil {
			t.Fatal(err)
		}
		if !serialHas(serialFindings(t, result), test.rule, test.strength, "request.body", "raw") {
			t.Fatalf("missing %s: %s", test.rule, result.Data)
		}
	}
	in := serialInput([]byte("StreamCorruptedException"))
	result, _ := (Plugin{}).Analyze(context.Background(), in)
	for _, f := range serialFindings(t, result) {
		if strings.HasPrefix(f.Rule, "error.") {
			t.Fatal("request treated as response error")
		}
	}
	in.Response.Body = []byte("java.io.StreamCorruptedException: invalid stream header")
	result, _ = (Plugin{}).Analyze(context.Background(), in)
	if !serialHas(serialFindings(t, result), "error.java", "medium", "response.body", "raw") {
		t.Fatalf("missing error: %s", result.Data)
	}
}
func TestSerializationNegativeAndPrivacy(t *testing.T) {
	for _, body := range []string{"rO0AB", "AC ED 00 05", "eJ", "O: hello", "java.example.Business", "plain text", "my-secret-credential"} {
		result, err := (Plugin{}).Analyze(context.Background(), serialInput([]byte(body)))
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Artifacts) != 0 {
			t.Fatalf("false positive for %q: %s", body, result.Data)
		}
	}
	secret := `O:25:"SuperSecretCredentialName":0:{}`
	in := serialInput([]byte(secret))
	before, _ := json.Marshal(in)
	result, _ := (Plugin{}).Analyze(context.Background(), in)
	after, _ := json.Marshal(in)
	if string(before) != string(after) {
		t.Fatal("input mutated")
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "SuperSecret") {
		t.Fatal("payload leaked into findings")
	}
	// Deliberately do not decode nested Base64.
	nested := base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte{0xac, 0xed, 0, 5})))
	result, _ = (Plugin{}).Analyze(context.Background(), serialInput([]byte(nested)))
	if len(result.Artifacts) != 0 {
		t.Fatalf("recursive decode: %s", result.Data)
	}
}
func TestSerializationLimitsCancellationAndRegistry(t *testing.T) {
	p := Plugin{}
	in := serialInput([]byte(strings.Repeat("!", serializationBytes+1)))
	result, err := p.Analyze(context.Background(), in)
	if err != nil || !result.Truncated {
		t.Fatalf("byte bound: %+v %v", result, err)
	}
	in = serialInput(nil)
	in.Response.BodyTruncated = true
	result, _ = p.Analyze(context.Background(), in)
	if !result.Truncated {
		t.Fatal("capture truncation lost")
	}
	in = serialInput(nil)
	in.Request.Header = http.Header{"X-Many": make([]string, serializationSurfaces+1)}
	for i := range in.Request.Header["X-Many"] {
		in.Request.Header["X-Many"][i] = "!"
	}
	result, _ = p.Analyze(context.Background(), in)
	if !result.Truncated {
		t.Fatal("surface bound not enforced")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Analyze(ctx, in); err != context.Canceled {
		t.Fatalf("cancellation: %v", err)
	}
	if _, err := p.Analyze(context.Background(), passive.Input{}); err == nil {
		t.Fatal("nil input accepted")
	}
	r, err := passive.New([]passive.Plugin{p}, 8)
	if err != nil {
		t.Fatal(err)
	}
	in = serialInput([]byte{0xac, 0xed, 0, 5})
	first, err := r.Analyze(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.Analyze(context.Background(), in, nil)
	if err != nil || !reflect.DeepEqual(first, second) || second[0].CacheHit || first[0].PluginID != "serialization" || first[0].Status != "completed" {
		t.Fatalf("registry: %+v %+v %v", first, second, err)
	}
}

func TestSerializationFormValuesAndGenericErrors(t *testing.T) {
	for _, query := range []bool{false, true} {
		for _, test := range []struct{ value, rule, strength string }{
			{"%AC%ED%00%05", "magic.java", "strong"},
			{"%3Cjava+version%3D%221.8%22%3E", "text.java-xml", "medium"},
		} {
			in := serialInput(nil)
			scope := "request.body"
			if query {
				in.Request.URL += "?payload=" + test.value
				scope = "request.url"
			} else {
				in.Request.Header = http.Header{"Content-Type": {"application/x-www-form-urlencoded; charset=UTF-8"}}
				in.Request.Body = []byte("payload=" + test.value)
			}
			result, err := (Plugin{}).Analyze(context.Background(), in)
			if err != nil || !serialHas(serialFindings(t, result), test.rule, test.strength, scope, "url") {
				t.Fatalf("form %t %s: %s %v", query, test.value, result.Data, err)
			}
		}
	}
	for _, message := range []string{"ModuleNotFoundError: No module named 'requests'", "java.lang.ClassNotFoundException: com.mysql.cj.jdbc.Driver"} {
		in := serialInput(nil)
		in.Response.Body = []byte(message)
		result, _ := (Plugin{}).Analyze(context.Background(), in)
		if len(result.Artifacts) != 0 {
			t.Fatalf("generic error misclassified: %s", result.Data)
		}
	}
	for _, invalid := range []string{"gAQ==", "gAQ===", "gAQ=A", "rO0AB===", "gAR="} {
		result, _ := (Plugin{}).Analyze(context.Background(), serialInput([]byte(invalid)))
		if len(result.Artifacts) != 0 {
			t.Fatalf("invalid Base64 %q: %s", invalid, result.Data)
		}
	}
}

func TestSerializationHeaderPreprocessingLimits(t *testing.T) {
	for _, kind := range []string{"map", "name", "empty-values"} {
		in := serialInput(nil)
		in.Request.Header = make(http.Header)
		switch kind {
		case "map":
			for i := 0; i < serializationSurfaces+1; i++ {
				in.Request.Header[strings.Repeat("x", i+1)] = nil
			}
		case "name":
			in.Request.Header[strings.Repeat("x", serializationBytes+1)] = []string{""}
		case "empty-values":
			in.Request.Header["X-Test"] = make([]string, serializationSurfaces+1)
		}
		result, err := (Plugin{}).Analyze(context.Background(), in)
		if err != nil || !result.Truncated {
			t.Fatalf("header limit %s: %+v %v", kind, result, err)
		}
	}
	s := serializationScan{ctx: context.Background(), remaining: serializationBytes, seen: make(map[string]bool)}
	for i := 0; i < serializationFindings+1; i++ {
		s.add("test", strings.Repeat("x", i+1), "weak", "request.body", "raw")
	}
	if len(s.findings) != serializationFindings || !s.result.Truncated {
		t.Fatal("finding cap not enforced")
	}
}

func FuzzSerialization(f *testing.F) {
	for _, seed := range []string{"rO0ABXNy", "%2FwEP", "_$$ND_FUNC$$_", "!!python/object/apply:", "O:1:\"X\":0:{}"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		result, err := (Plugin{}).Analyze(context.Background(), serialInput(body))
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Artifacts) > serializationFindings || len(result.Data) > 64<<10 {
			t.Fatal("unbounded output")
		}
		serialFindings(t, result)
	})
}
