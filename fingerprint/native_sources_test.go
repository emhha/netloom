package fingerprint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/emhha/netloom/httpdata"
)

func TestNativeRuleCorpora(t *testing.T) {
	provenance, err := os.ReadFile(filepath.Join("rules", "native-sources.upstream.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sources map[string]struct {
		File   string `json:"file"`
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(provenance, &sources); err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 {
		t.Fatal("missing native rule provenance")
	}
	for _, source := range sources {
		data, err := os.ReadFile(filepath.Join("rules", source.File))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != source.SHA256 {
			t.Fatal("native rules changed without provenance update", source.File)
		}
	}
	e, err := New(context.Background(), Config{RulesDir: "rules"})
	if err != nil {
		t.Fatal(err)
	}
	if e.webfinger.Len() != 0 {
		t.Fatal("disabled webfinger was loaded")
	}
	if e.ehole == nil || e.ehole.Len() != 958 {
		t.Fatalf("EHole corpus not loaded: %+v", e.ehole)
	}
	if e.fingerprinthub == nil || e.fingerprinthub.Len() != 3425 {
		t.Fatal("FingerprintHub corpus not loaded")
	}
	if e.wappalyzer == nil || len(e.wappalyzer.techs) == 0 {
		t.Fatal("existing Wappalyzer source disabled")
	}
	// The first upstream EHole keyword and FingerprintHub favicon rule.
	r := &httpdata.Response{Body: []byte("/seeyon/USER-DATA/IMAGES/LOGIN/login.gif"), FaviconHash: 617142232}
	found := map[string]bool{}
	for _, a := range e.Match(context.Background(), r) {
		found[a.Source+":"+a.Name] = true
		if a.Source == "webfinger" || a.Source == "custom" {
			t.Fatal("disabled source produced a match")
		}
	}
	if !found["ehole:致远OA"] || !found["fingerprinthub:moticdsm"] {
		t.Fatalf("real native rules did not match: %v", found)
	}
}

func TestEHoleNativeSemantics(t *testing.T) {
	data := []byte(`{"fingerprint":[
	 {"cms":"and-body","method":"keyword","location":"body","keyword":["ONE","two"]},
	 {"cms":"regex","method":"regular","location":"body","keyword":["[0-9]+","two"]},
	 {"cms":"header","method":"keyword","location":"header","keyword":["x-product","portal"]},
	 {"cms":"title","method":"keyword","location":"title","keyword":["login"]},
	 {"cms":"icon","method":"faviconhash","location":"body","keyword":["-123"]}
	]}`)
	m, err := LoadEHoleJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := New(context.Background(), Config{})
	e.ehole = m
	r := &httpdata.Response{Body: []byte("<title>LOGIN</title>one two 42"), Header: http.Header{"X-Product": {"Portal"}}, FaviconHash: -123}
	if got := e.Match(context.Background(), r); len(got) != 5 {
		t.Fatalf("matches=%v", got)
	}
	r.Body = []byte("<title>LOGIN</title>one 42")
	r.FaviconHash = 0
	for _, a := range e.Match(context.Background(), r) {
		if a.Name == "and-body" || a.Name == "regex" || a.Name == "icon" {
			t.Fatalf("partial/absent evidence matched: %v", a)
		}
	}
	if r.Title != "" {
		t.Fatal("input mutated")
	}
	for _, bad := range []string{`null`, `{"fingerprint":[]}`, `{"fingerprint":[{"cms":"x","method":"keyword","location":"body","keyword":[]}]}`, `{"fingerprint":[{"cms":"x","method":"regular","location":"body","keyword":["["]}]}`, `{"fingerprint":[{"cms":"x","method":"unknown","location":"body","keyword":["x"]}]}`} {
		if _, err := LoadEHoleJSON([]byte(bad)); err == nil {
			t.Fatalf("invalid rules accepted: %s", bad)
		}
	}
}

func TestFingerprintHubConditionsAndFavicon(t *testing.T) {
	data := []byte(`[{"id":"conditions","http":[{"matchers-condition":"and","matchers":[
	 {"type":"word","words":["one","TWO"],"condition":"and","case-insensitive":true},
	 {"type":"regex","regex":["X-[0-9]+"],"part":"header","case-insensitive":true},
	 {"type":"word","words":["denied"],"negative":true}]}]},
	 {"id":"md5","http":[{"matchers":[{"type":"favicon","hash":["0123456789abcdef0123456789abcdef"]}]}]},
	 {"id":"mmh3","http":[{"matchers":[{"type":"favicon","hash":["-123"]}]}]},
	 {"id":"negative-icon","http":[{"matchers":[{"type":"favicon","hash":["-456"],"negative":true}]}]}
	]`)
	m, err := LoadFingerprintHubJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := New(context.Background(), Config{})
	e.fingerprinthub = m
	r := &httpdata.Response{Body: []byte("ONE two"), Header: http.Header{"X-Product": {"X-42"}}, FaviconMD5: "0123456789abcdef0123456789abcdef", FaviconHash: -123}
	if got := e.Match(context.Background(), r); len(got) != 4 {
		t.Fatalf("matches=%v", got)
	}
	r.Body = []byte("one denied")
	r.FaviconMD5 = ""
	r.FaviconHash = 0
	if got := e.Match(context.Background(), r); len(got) != 0 {
		t.Fatalf("AND/negative/unknown icon evidence: %v", got)
	}
	for _, bad := range []string{`{}`, `[]`, `[{"id":"x","http":[{"matchers":[{"type":"dsl","dsl":["true"]}]}]}]`, `[{"id":"x","http":[{"matchers":[{"type":"regex","regex":["["]}]}]}]`} {
		if _, err := LoadFingerprintHubJSON([]byte(bad)); err == nil {
			t.Fatalf("unsupported rules accepted: %s", bad)
		}
	}
}

func TestFingerprintHubRequestConstraints(t *testing.T) {
	data := []byte(`[{"id":"probe","http":[{"method":"POST","path":["{{BaseURL}}/admin"],"headers":{"X-Probe":"yes"},"matchers":[{"type":"word","words":["marker"]}]}]}]`)
	m, err := LoadFingerprintHubJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := New(context.Background(), Config{})
	e.fingerprinthub = m
	r := &httpdata.Response{Body: []byte("marker")}
	if len(e.Match(context.Background(), r)) != 0 {
		t.Fatal("active-style probe matched without captured request")
	}
	q := &httpdata.Request{URL: "https://example.test/admin", Method: "POST", Header: http.Header{"X-Probe": {"yes"}}}
	if len(e.MatchExchange(context.Background(), q, r)) != 1 {
		t.Fatal("captured matching request rejected")
	}
	for _, change := range []func(*httpdata.Request){func(q *httpdata.Request) { q.Method = "GET" }, func(q *httpdata.Request) { q.URL = "https://example.test/" }, func(q *httpdata.Request) { q.Header = nil }} {
		copy := *q
		change(&copy)
		if len(e.MatchExchange(context.Background(), &copy, r)) != 0 {
			t.Fatal("probe constraints ignored")
		}
	}
}

func TestSourceProfileSwitchesAndValidation(t *testing.T) {
	dir := t.TempDir()
	profile := map[string]SourceSetting{"webfinger": {Enabled: false, File: "invalid.yaml"}, "ehole": {Enabled: true, File: "ehole.json"}, "fingerprinthub": {Enabled: false, File: "missing.json"}}
	write := func() {
		b, _ := json.Marshal(profile)
		if err := os.WriteFile(filepath.Join(dir, "sources.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if err := os.WriteFile(filepath.Join(dir, "ehole.json"), []byte(`{"fingerprint":[{"cms":"x","method":"keyword","location":"body","keyword":["marker"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := New(context.Background(), Config{RulesDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	r := &httpdata.Response{Body: []byte("marker")}
	if got := e.Match(context.Background(), r); len(got) != 1 || got[0].Source != "ehole" {
		t.Fatal(got)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if len(e.Match(context.Background(), r)) != 1 {
					t.Error("concurrent matching failed")
				}
			}
		}()
	}
	wg.Wait()
	profile["ehole"] = SourceSetting{Enabled: false, File: "ehole.json"}
	write()
	off, err := New(context.Background(), Config{RulesDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(off.Match(context.Background(), r)) != 0 {
		t.Fatal("disabled source matched")
	}
	profile["ehole"] = SourceSetting{Enabled: true, File: "../ehole.json"}
	write()
	if _, err := New(context.Background(), Config{RulesDir: dir}); err == nil {
		t.Fatal("escaping source path accepted")
	}
	if _, err := New(context.Background(), Config{RulesDir: dir, CustomRulesDir: dir}); err == nil {
		t.Fatal("legacy input bypassed source switches")
	}
}

func TestFingerprintHubRealPathAndVersion(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("rules", "fingerprinthub_v4.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := LoadFingerprintHubJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := New(context.Background(), Config{})
	e.fingerprinthub = m
	q := &httpdata.Request{URL: "https://example.test/", Method: "GET"}
	r := &httpdata.Response{Header: http.Header{"Server": {"nginx/1.26.0"}}}
	found := false
	for _, a := range e.MatchExchange(context.Background(), q, r) {
		if a.Name == "nginx" {
			found = true
			if a.Version != "1.26.0" {
				t.Fatal("version extractor failed", a)
			}
		}
	}
	if !found {
		t.Fatal("real nginx rule did not match")
	}
}

func TestEnabledSourceMissingIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sources.json"), []byte(`{"ehole":{"enabled":true,"file":"missing.json"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), Config{RulesDir: dir}); err == nil {
		t.Fatal("missing enabled source silently ignored")
	}
}
