package plugins

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"netrt.local/netrt/httpdata"
	"netrt.local/netrt/infoextract"
	"netrt.local/netrt/passive"
)

func TestInformationReusesBodyWhileExtractingChangedHeaders(t *testing.T) {
	extractor := infoextract.New()
	for _, rule := range []infoextract.Rule{
		{Name: "test_body", Pattern: `secret=([a-z]+)`, Scope: "body"},
		{Name: "test_header", Pattern: `(?i)x-token: ([a-z]+)`, Scope: "header"},
	} {
		if err := extractor.AddRule(rule); err != nil {
			t.Fatal(err)
		}
	}
	registry, err := passive.New([]passive.Plugin{&Information{Extractor: extractor}}, 8)
	if err != nil {
		t.Fatal(err)
	}
	in := passive.Input{Site: "p:https://example.com", SessionID: "s",
		Request: &httpdata.Request{URL: "https://example.com/app.js"},
		Response: &httpdata.Response{Body: []byte("secret=first"), ContentType: "application/javascript",
			Header: map[string][]string{"Date": {"first date"}, "X-Token": {"one"}}},
	}
	analyze := func() (passive.Result, bool, bool) {
		t.Helper()
		results, err := registry.Analyze(context.Background(), in, nil)
		if err != nil || len(results) != 1 || results[0].Status != "completed" {
			t.Fatalf("analysis: %+v %v", results, err)
		}
		var hits struct {
			Body   bool `json:"body_cache_hit"`
			Header bool `json:"header_cache_hit"`
		}
		if err := json.Unmarshal(results[0].Data, &hits); err != nil {
			t.Fatal(err)
		}
		return results[0], hits.Body, hits.Header
	}
	_, bodyHit, _ := analyze()
	if bodyHit {
		t.Fatal("first analysis was cached")
	}
	in.Response.Header["Date"] = []string{"second date"}
	in.Response.Header["X-Token"] = []string{"two"}
	result, bodyHit, headerHit := analyze()
	if !bodyHit || headerHit {
		t.Fatal("header change caused body analysis or reused stale headers")
	}
	foundNewHeader := false
	for _, artifact := range result.Artifacts {
		if artifact.Rule == "test_header" && strings.Contains(artifact.Value, "two") {
			foundNewHeader = true
		}
		if artifact.Rule == "test_header" && strings.Contains(artifact.Value, "one") {
			t.Fatal("stale header finding returned")
		}
	}
	if !foundNewHeader {
		t.Fatal("new header finding missing")
	}
	in.Response.Body = []byte("secret=second")
	_, bodyHit, headerHit = analyze()
	if bodyHit || !headerHit {
		t.Fatal("body change did not isolate body analysis")
	}
	result, _, _ = analyze()
	if !result.CacheHit {
		t.Fatal("identical response did not reuse both results")
	}
	in.SessionID = "other-session"
	_, bodyHit, _ = analyze()
	if bodyHit {
		t.Fatal("body cache crossed a session boundary")
	}
}

func TestInformationPreservesEntireMatchWithCaptureGroups(t *testing.T) {
	const token = "sk_live_abcdefghijklmnopqrstuvwx"
	p := &Information{Extractor: infoextract.New()}
	result, err := p.Analyze(context.Background(), passive.Input{Site: "https://example.test", Request: &httpdata.Request{URL: "https://example.test"}, Response: &httpdata.Response{Body: []byte(token), ContentType: "text/html"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range result.Artifacts {
		if a.Rule == "stripe_key" {
			if a.Value != token {
				t.Fatalf("partial match: %q", a.Value)
			}
			return
		}
	}
	t.Fatal("missing token match")
}
