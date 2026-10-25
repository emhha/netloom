package plugins

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"net/http"
	"netrt.local/netrt/httpdata"
	"netrt.local/netrt/passive"
)

func TestHTTPPolicyUsesHeadersWithoutLeakingCookieValues(t *testing.T) {
	registry, err := passive.New([]passive.Plugin{HTTPPolicy{}}, 8)
	if err != nil {
		t.Fatal(err)
	}
	in := passive.Input{Site: "p:https://example.com", Request: &httpdata.Request{URL: "https://example.com/"}, Response: &httpdata.Response{StatusCode: 200, ContentType: "text/html", Header: http.Header{"Set-Cookie": {"session=do-not-expose; Path=/; SameSite=None"}}}}
	results, err := registry.Analyze(context.Background(), in, nil)
	if err != nil || len(results) != 1 || len(results[0].Artifacts) < 5 {
		t.Fatalf("missing policy observations: %+v %v", results, err)
	}
	data, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "do-not-expose") {
		t.Fatal("cookie value leaked into policy artifacts")
	}
	in.Response.Body = []byte("different body")
	in.Response.Header["Date"] = []string{"changed"}
	results, err = registry.Analyze(context.Background(), in, nil)
	if err != nil || !results[0].CacheHit {
		t.Fatal("irrelevant body/date invalidated header analysis")
	}
	in.Response.Header["Set-Cookie"] = []string{"session=do-not-expose; Secure; HttpOnly; SameSite=Lax; Path=/"}
	results, err = registry.Analyze(context.Background(), in, nil)
	if err != nil || results[0].CacheHit {
		t.Fatal("cookie policy change reused stale analysis")
	}
	for _, a := range results[0].Artifacts {
		if strings.Contains(a.Rule, "cookie") {
			t.Fatalf("safe cookie flagged: %+v", a)
		}
	}
	in.Site = "another-project:https://example.com"
	results, err = registry.Analyze(context.Background(), in, nil)
	if err != nil || results[0].CacheHit {
		t.Fatal("analysis cache crossed project boundary")
	}
}

func TestHTTPPolicySkipsHTMLChecksForJSONAndAcceptsPolicies(t *testing.T) {
	in := passive.Input{Request: &httpdata.Request{URL: "https://example.com"}, Response: &httpdata.Response{StatusCode: 200, ContentType: "application/json", Header: http.Header{"Strict-Transport-Security": {"max-age=31536000"}}}}
	result, err := (HTTPPolicy{}).Analyze(context.Background(), in)
	if err != nil || len(result.Artifacts) != 0 {
		t.Fatalf("JSON should not require HTML policies: %+v %v", result, err)
	}
	in.Response.ContentType = "text/html"
	in.Response.Header["Content-Security-Policy"] = []string{"default-src 'self'; frame-ancestors 'none'"}
	in.Response.Header["X-Content-Type-Options"] = []string{"nosniff"}
	result, err = (HTTPPolicy{}).Analyze(context.Background(), in)
	if err != nil || len(result.Artifacts) != 0 {
		t.Fatalf("configured policies flagged: %+v %v", result, err)
	}
}
