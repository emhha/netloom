package fingerprint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emhha/netloom/httpdata"

	"net/http"
)

// ---------------------------------------------------------------------------
// Lexer tests
// ---------------------------------------------------------------------------

func TestLexer_BasicBody(t *testing.T) {
	l := newLexer(`body="wp-content"`)
	toks, err := l.Tokenize()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Expect: [tokBody("body"), tokEq, tokString("wp-content"), tokEOF]
	if len(toks) != 4 {
		t.Fatalf("want 4 tokens, got %d: %v", len(toks), toks)
	}
	if toks[0].Type != tokBody {
		t.Errorf("want tokBody, got %v", toks[0].Type)
	}
	if toks[1].Type != tokEq {
		t.Errorf("want tokEq, got %v", toks[1].Type)
	}
	if toks[2].Type != tokString || toks[2].Value != "wp-content" {
		t.Errorf("want tokString(wp-content), got %v %q", toks[2].Type, toks[2].Value)
	}
	if toks[3].Type != tokEOF {
		t.Errorf("want tokEOF, got %v", toks[3].Type)
	}
}

func TestLexer_IconHash(t *testing.T) {
	l := newLexer(`icon_hash="116323821"`)
	toks, err := l.Tokenize()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(toks) != 4 {
		t.Fatalf("want 4 tokens, got %d", len(toks))
	}
	// icon_hash is mapped to tokBody with Value="icon_hash"
	if toks[0].Value != "icon_hash" {
		t.Errorf("want Value=icon_hash, got %q", toks[0].Value)
	}
}

func TestLexer_ANDExpression(t *testing.T) {
	l := newLexer(`body="a" && header="b"`)
	toks, err := l.Tokenize()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// [body, eq, str, and, header, eq, str, eof]
	if len(toks) != 8 {
		t.Fatalf("want 8 tokens, got %d: %v", len(toks), toks)
	}
	if toks[3].Type != tokAnd {
		t.Errorf("want tokAnd at pos 3, got %v", toks[3].Type)
	}
}

func TestLexer_NEQ(t *testing.T) {
	l := newLexer(`header!="couchdb"`)
	toks, err := l.Tokenize()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// [tokHeader(header), tokNeq, tokString(couchdb), tokEOF]
	if len(toks) != 4 {
		t.Fatalf("want 4 tokens, got %d: %v", len(toks), toks)
	}
	if toks[1].Type != tokNeq {
		t.Errorf("want tokNeq, got %v", toks[1].Type)
	}
}

func TestLexer_Not(t *testing.T) {
	l := newLexer(`!header="drupal"`)
	toks, err := l.Tokenize()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// [tokNot, tokHeader, tokEq, tokString, tokEOF]
	if len(toks) != 5 {
		t.Fatalf("want 5 tokens, got %d: %v", len(toks), toks)
	}
	if toks[0].Type != tokNot {
		t.Errorf("want tokNot at pos 0, got %v", toks[0].Type)
	}
}

// ---------------------------------------------------------------------------
// Parser tests
// ---------------------------------------------------------------------------

func mustParse(t *testing.T, expr string) Node {
	t.Helper()
	node, isHash, _, err := parseRule(expr)
	if err != nil {
		t.Fatalf("parseRule(%q): %v", expr, err)
	}
	if isHash {
		t.Fatalf("parseRule(%q): unexpectedly detected as icon_hash rule", expr)
	}
	return node
}

func TestParser_SimpleBody(t *testing.T) {
	node := mustParse(t, `body="wp-content"`)
	b, ok := node.(BodyNode)
	if !ok {
		t.Fatalf("want BodyNode, got %T", node)
	}
	if b.Value != "wp-content" {
		t.Errorf("want Value=wp-content, got %q", b.Value)
	}
}

func TestParser_NotNode(t *testing.T) {
	node := mustParse(t, `!header="couchdb"`)
	nn, ok := node.(NotNode)
	if !ok {
		t.Fatalf("want NotNode, got %T", node)
	}
	if _, ok2 := nn.Child.(HeaderNode); !ok2 {
		t.Errorf("want NotNode{Child: HeaderNode}, got %T", nn.Child)
	}
}

func TestParser_NEQEquivalence(t *testing.T) {
	// header!="couchdb" should produce the same AST as !header="couchdb"
	node := mustParse(t, `header!="couchdb"`)
	nn, ok := node.(NotNode)
	if !ok {
		t.Fatalf("want NotNode, got %T", node)
	}
	if _, ok2 := nn.Child.(HeaderNode); !ok2 {
		t.Errorf("want NotNode{Child: HeaderNode}, got %T", nn.Child)
	}
}

func TestParser_AndNode(t *testing.T) {
	node := mustParse(t, `body="a" && body="b"`)
	an, ok := node.(AndNode)
	if !ok {
		t.Fatalf("want AndNode, got %T", node)
	}
	if _, ok2 := an.Left.(BodyNode); !ok2 {
		t.Errorf("want Left=BodyNode, got %T", an.Left)
	}
	if _, ok2 := an.Right.(BodyNode); !ok2 {
		t.Errorf("want Right=BodyNode, got %T", an.Right)
	}
}

func TestParser_Complex(t *testing.T) {
	// (server="3S_WebServer" && !header="couchdb" && !header="drupal")
	node := mustParse(t, `(server="3S_WebServer" && !header="couchdb" && !header="drupal")`)
	if node == nil {
		t.Fatal("expected non-nil node")
	}
	// Root should be AndNode with NotNode{HeaderNode} on right.
	an, ok := node.(AndNode)
	if !ok {
		t.Fatalf("want AndNode at root, got %T", node)
	}
	if _, ok2 := an.Right.(NotNode); !ok2 {
		t.Errorf("want NotNode on right, got %T", an.Right)
	}
}

func TestParser_OrNode(t *testing.T) {
	node := mustParse(t, `body="a" || title="b"`)
	on, ok := node.(OrNode)
	if !ok {
		t.Fatalf("want OrNode, got %T", node)
	}
	if _, ok2 := on.Left.(BodyNode); !ok2 {
		t.Errorf("want Left=BodyNode, got %T", on.Left)
	}
	if _, ok2 := on.Right.(TitleNode); !ok2 {
		t.Errorf("want Right=TitleNode, got %T", on.Right)
	}
}

func TestParser_IconHashDetection(t *testing.T) {
	_, isHash, val, err := parseRule(`icon_hash="116323821"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isHash {
		t.Error("want isHash=true")
	}
	if val != "116323821" {
		t.Errorf("want val=116323821, got %q", val)
	}
}

// ---------------------------------------------------------------------------
// AST Match tests
// ---------------------------------------------------------------------------

func makeCtx(body, header, title, server string) *MatchContext {
	resp := &httpdata.Response{
		Body:      []byte(body),
		Header:    make(http.Header),
		Title:     title,
		WebServer: server,
	}
	// Add header blob manually via serializeHeader.
	if header != "" {
		// Parse "Key: Value" lines.
		for _, line := range strings.Split(header, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				resp.Header.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
	}

	// Build a simple index from the body/header/title/server.
	idx := buildACIndex([]*Fingerprint{})
	mc := &MatchContext{
		Response: resp,
		Hits:     make(map[Field]map[string]bool),
	}
	mc.BodyUTF8 = []byte(body)
	mc.HeaderBlob = serializeHeader(resp.Header)

	// Manually run AC scan on keywords.
	_ = idx // no keywords in empty index, so we fill manually
	mc.Hits[FieldBody] = scanHits([]byte(body))
	mc.Hits[FieldHeader] = scanHits(mc.HeaderBlob)
	mc.Hits[FieldTitle] = scanHits([]byte(title))
	mc.Hits[FieldServer] = scanHits([]byte(server))

	return mc
}

// scanHits builds a trivial "every substring is a hit" map using strings.Contains.
// This is NOT how the real ACIndex works but is sufficient for unit tests where
// we need to verify specific keywords match.
func scanHits(text []byte) map[string]bool {
	// We return a special map that returns true for any key that is in the text.
	// Since Go maps don't support that, we build a real map with all possible
	// substrings — but that's O(n^2). Instead, let's abuse the test fixtures by
	// returning a proxy-like approach with test-specific keywords.
	//
	// For tests we simply return a map where each byte-range that matches is
	// checked dynamically via a custom approach. Since we can't override map
	// lookup, we use a wrapper struct approach for tests only.
	//
	// Simplest solution: pre-populate Hits with the specific values we test.
	// This is fine since tests construct the context directly.
	return nil // filled per test below
}

func TestBodyNodeMatch(t *testing.T) {
	mc := &MatchContext{
		Hits: map[Field]map[string]bool{
			FieldBody: {"wp-content": true},
		},
		Response: &httpdata.Response{},
	}
	node := BodyNode{Value: "wp-content"}
	if !node.Match(mc) {
		t.Error("BodyNode should match")
	}
	node2 := BodyNode{Value: "joomla"}
	if node2.Match(mc) {
		t.Error("BodyNode should not match joomla")
	}
}

func TestHeaderNodeMatch(t *testing.T) {
	mc := &MatchContext{
		Hits: map[Field]map[string]bool{
			FieldHeader: {"x-powered-by: php": true},
		},
		Response: &httpdata.Response{},
	}
	node := HeaderNode{Value: "x-powered-by: php"}
	if !node.Match(mc) {
		t.Error("HeaderNode should match")
	}
}

func TestNotNodeMatch(t *testing.T) {
	mc := &MatchContext{
		Hits: map[Field]map[string]bool{
			FieldHeader: {},
		},
		Response: &httpdata.Response{},
	}
	node := NotNode{Child: HeaderNode{Value: "couchdb"}}
	if !node.Match(mc) {
		t.Error("NotNode should match when child does not match")
	}

	mc.Hits[FieldHeader]["couchdb"] = true
	if node.Match(mc) {
		t.Error("NotNode should not match when child matches")
	}
}

func TestCertNodeMatch(t *testing.T) {
	mc := &MatchContext{
		Hits: make(map[Field]map[string]bool),
		Response: &httpdata.Response{
			TLS: &httpdata.TLSInfo{
				Subject: "CN=example.com, O=Example Inc.",
			},
		},
	}
	node := CertNode{Value: "example.com"}
	if !node.Match(mc) {
		t.Error("CertNode should match")
	}
	node2 := CertNode{Value: "google.com"}
	if node2.Match(mc) {
		t.Error("CertNode should not match google.com")
	}
}

func TestCertNodeNilTLS(t *testing.T) {
	mc := &MatchContext{
		Hits:     make(map[Field]map[string]bool),
		Response: &httpdata.Response{},
	}
	node := CertNode{Value: "anything"}
	if node.Match(mc) {
		t.Error("CertNode should not match when TLS is nil")
	}
}

func TestAndOrNodes(t *testing.T) {
	mc := &MatchContext{
		Hits: map[Field]map[string]bool{
			FieldBody:  {"a": true},
			FieldTitle: {"b": true},
		},
		Response: &httpdata.Response{},
	}

	and := AndNode{Left: BodyNode{Value: "a"}, Right: TitleNode{Value: "b"}}
	if !and.Match(mc) {
		t.Error("AndNode should match")
	}

	and2 := AndNode{Left: BodyNode{Value: "a"}, Right: TitleNode{Value: "missing"}}
	if and2.Match(mc) {
		t.Error("AndNode should not match when right is missing")
	}

	or := OrNode{Left: BodyNode{Value: "missing"}, Right: TitleNode{Value: "b"}}
	if !or.Match(mc) {
		t.Error("OrNode should match when right matches")
	}

	or2 := OrNode{Left: BodyNode{Value: "missing"}, Right: TitleNode{Value: "alsomissing"}}
	if or2.Match(mc) {
		t.Error("OrNode should not match when both are missing")
	}
}

// ---------------------------------------------------------------------------
// Compiler tests
// ---------------------------------------------------------------------------

func TestCompileWebfingerYAML_Basic(t *testing.T) {
	yaml := []byte(`
WordPress:
    - body="wp-content"
    - body="wp-includes"
    - icon_hash="116323821"
`)
	res, err := compileWebfingerYAML(yaml, "webfinger")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Fingerprints) != 1 {
		t.Fatalf("want 1 fingerprint, got %d", len(res.Fingerprints))
	}
	fp := res.Fingerprints[0]
	if fp.Name != "WordPress" {
		t.Errorf("want Name=WordPress, got %q", fp.Name)
	}
	if len(fp.Rules) != 2 {
		t.Errorf("want 2 AST rules (icon_hash excluded), got %d", len(fp.Rules))
	}

	// Verify HashMatcher has the icon_hash entry.
	if matches := res.HashMatcher.Match(116323821); len(matches) != 1 {
		t.Errorf("want 1 hash match for 116323821, got %d", len(matches))
	}
}

func TestCompileWebfingerYAML_Complex(t *testing.T) {
	yaml := []byte(`
3s_webserver:
    - (server="3S_WebServer" && !header="couchdb" && !header="drupal")
`)
	res, err := compileWebfingerYAML(yaml, "webfinger")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Fingerprints) != 1 {
		t.Fatalf("want 1 fingerprint, got %d", len(res.Fingerprints))
	}
	fp := res.Fingerprints[0]
	if len(fp.Rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(fp.Rules))
	}
}

func TestCompileWebfingerYAML_EmptyData(t *testing.T) {
	res, err := compileWebfingerYAML([]byte(""), "webfinger")
	if err != nil {
		t.Fatalf("unexpected error on empty YAML: %v", err)
	}
	if len(res.Fingerprints) != 0 {
		t.Errorf("want 0 fingerprints for empty YAML, got %d", len(res.Fingerprints))
	}
}

// ---------------------------------------------------------------------------
// Aho-Corasick tests
// ---------------------------------------------------------------------------

func TestAutomaton_Basic(t *testing.T) {
	a := newAutomaton([]string{"wp-content", "joomla", "drupal"})

	hits := a.Match([]byte("this site has wp-content/themes and more"))
	if !hits["wp-content"] {
		t.Error("expected wp-content to match")
	}
	if hits["joomla"] {
		t.Error("did not expect joomla to match")
	}
}

func TestAutomaton_Empty(t *testing.T) {
	a := newAutomaton(nil)
	hits := a.Match([]byte("some body text"))
	if len(hits) != 0 {
		t.Errorf("want no hits on empty automaton, got %v", hits)
	}
}

func TestAutomaton_Dedup(t *testing.T) {
	a := newAutomaton([]string{"abc", "abc", "def"})
	hits := a.Match([]byte("abc def"))
	if !hits["abc"] || !hits["def"] {
		t.Errorf("expected abc and def in hits, got %v", hits)
	}
}

// ---------------------------------------------------------------------------
// MMH3 / FaviconHash tests
// ---------------------------------------------------------------------------

func TestFaviconHash_Empty(t *testing.T) {
	h := FaviconHash([]byte{})
	// Empty bytes → specific hash value (test that it doesn't panic).
	_ = h
}

func TestFaviconHash_Consistent(t *testing.T) {
	data := []byte("fake favicon data")
	h1 := FaviconHash(data)
	h2 := FaviconHash(data)
	if h1 != h2 {
		t.Errorf("FaviconHash not consistent: %d != %d", h1, h2)
	}
}

// ---------------------------------------------------------------------------
// Encoding tests
// ---------------------------------------------------------------------------

func TestDecodeBodyToUTF8_UTF8(t *testing.T) {
	resp := &httpdata.Response{
		Body:   []byte("hello world"),
		Header: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
	}
	result := decodeBodyToUTF8(resp)
	if string(result) != "hello world" {
		t.Errorf("unexpected result: %q", result)
	}
}

func TestDecodeBodyToUTF8_Empty(t *testing.T) {
	resp := &httpdata.Response{Body: nil}
	result := decodeBodyToUTF8(resp)
	if result != nil {
		t.Errorf("expected nil result for empty body, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// Wappalyzer tests
// ---------------------------------------------------------------------------

func TestWappalyzerMatcher_BasicHeader(t *testing.T) {
	jsonData := []byte(`{
		"apps": {
			"TestTech": {
				"cats": [1],
				"headers": { "X-Powered-By": "TestTech" }
			}
		}
	}`)

	wm, err := LoadWappalyzerJSON(jsonData)
	if err != nil {
		t.Fatalf("LoadWappalyzerJSON: %v", err)
	}

	mc := &MatchContext{
		Hits: make(map[Field]map[string]bool),
		Response: &httpdata.Response{
			Header: http.Header{
				"X-Powered-By": []string{"TestTech/1.0"},
			},
		},
		BodyUTF8: []byte(""),
	}

	arts := wm.match(mc)
	if len(arts) == 0 {
		t.Fatal("expected at least one artifact")
	}
	found := false
	for _, a := range arts {
		if a.Name == "TestTech" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected TestTech in artifacts, got %v", arts)
	}
}

func TestWappalyzerMatcher_EmptyJSON(t *testing.T) {
	wm, err := LoadWappalyzerJSON(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wm == nil {
		t.Fatal("expected non-nil WappalyzerMatcher")
	}
}

func TestWappalyzerMatcher_HTMLPattern(t *testing.T) {
	jsonData := []byte(`{
		"apps": {
			"WordPress": {
				"cats": [1],
				"html": ["wp-content/"]
			}
		}
	}`)

	wm, err := LoadWappalyzerJSON(jsonData)
	if err != nil {
		t.Fatalf("LoadWappalyzerJSON: %v", err)
	}

	mc := &MatchContext{
		Hits: make(map[Field]map[string]bool),
		Response: &httpdata.Response{
			Header: http.Header{},
		},
		BodyUTF8: []byte(`<html><body><a href="/wp-content/themes/test">test</a></body></html>`),
	}

	arts := wm.match(mc)
	if len(arts) == 0 {
		t.Fatal("expected at least one artifact")
	}
	if arts[0].Name != "WordPress" {
		t.Errorf("want WordPress, got %q", arts[0].Name)
	}
}

func TestWappalyzerPattern_VersionExtraction(t *testing.T) {
	jsonData := []byte(`{
		"apps": {
			"jQuery": {
				"cats": [12],
				"html": ["jquery[.-](\\d+\\.\\d+\\.\\d+)[^\"']*\\.js\\;version:\\1"]
			}
		}
	}`)

	wm, err := LoadWappalyzerJSON(jsonData)
	if err != nil {
		t.Fatalf("LoadWappalyzerJSON: %v", err)
	}

	mc := &MatchContext{
		Hits: make(map[Field]map[string]bool),
		Response: &httpdata.Response{
			Header: http.Header{},
		},
		BodyUTF8: []byte(`<script src="jquery-3.6.0.min.js"></script>`),
	}

	arts := wm.match(mc)
	found := false
	for _, a := range arts {
		if a.Name == "jQuery" {
			found = true
			if a.Version != "3.6.0" {
				t.Errorf("want version 3.6.0, got %q", a.Version)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected jQuery in artifacts, got %v", arts)
	}
}

// ---------------------------------------------------------------------------
// Engine integration tests
// ---------------------------------------------------------------------------

func TestEngine_New(t *testing.T) {
	e, err := New(context.Background(), Config{})
	if err != nil {
		t.Fatalf("Engine.New: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil Engine")
	}
}

func TestEngine_MatchNilResponse(t *testing.T) {
	e, _ := New(context.Background(), Config{})
	arts := e.Match(context.Background(), nil)
	if arts != nil {
		t.Errorf("expected nil for nil response, got %v", arts)
	}
}

func TestEngine_MatchWithYAML(t *testing.T) {
	// Override embedded YAML by using compileWebfingerYAML directly and building
	// an engine from scratch for this test.
	yaml := []byte(`
WordPress:
    - body="wp-content"
    - body="wp-includes"
`)
	res, err := compileWebfingerYAML(yaml, "webfinger")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	e := &Engine{
		webfinger:  &WebfingerMatcher{fps: res.Fingerprints, hashMatcher: res.HashMatcher, acIndex: res.ACIndex},
		wappalyzer: &WappalyzerMatcher{},
	}

	resp := &httpdata.Response{
		Body:   []byte("<html><body>look ma, wp-content/themes here</body></html>"),
		Header: http.Header{},
	}
	arts := e.Match(context.Background(), resp)
	if len(arts) == 0 {
		t.Fatal("expected at least one artifact")
	}
	if arts[0].Name != "WordPress" {
		t.Errorf("want WordPress, got %q", arts[0].Name)
	}
}

func TestEngine_HashMatcherIntegration(t *testing.T) {
	yaml := []byte(`
WordPress:
    - icon_hash="116323821"
`)
	res, err := compileWebfingerYAML(yaml, "webfinger")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	e := &Engine{
		webfinger:  &WebfingerMatcher{fps: res.Fingerprints, hashMatcher: res.HashMatcher, acIndex: res.ACIndex},
		wappalyzer: &WappalyzerMatcher{},
	}

	resp := &httpdata.Response{
		Body:        []byte("<html></html>"),
		Header:      http.Header{},
		FaviconHash: 116323821,
	}
	arts := e.Match(context.Background(), resp)
	if len(arts) == 0 {
		t.Fatal("expected at least one artifact from hash match")
	}
	if arts[0].Name != "WordPress" {
		t.Errorf("want WordPress, got %q", arts[0].Name)
	}
}

func TestExplicitRulesRecognizeCapturedHTTP(t *testing.T) {
	e, err := New(context.Background(), Config{WebfingerYAML: []byte(`nginx:
  - header="nginx"
`)})
	if err != nil {
		t.Fatal(err)
	}
	if e.webfinger.Len() == 0 {
		t.Fatalf("explicit rules missing: %d", e.webfinger.Len())
	}
	response := &httpdata.Response{Header: http.Header{"Server": {"nginx"}}, WebServer: "nginx", Body: []byte(`<html><title>Example</title><link href="/wp-content/themes/test/style.css"></html>`), ContentType: "text/html"}
	found := map[string]bool{}
	for _, art := range e.Match(context.Background(), response) {
		found[art.Name] = true
	}
	if !found["nginx"] {
		t.Fatalf("missing explicit detections: %v", found)
	}
	if response.Title != "" {
		t.Fatal("matcher mutated its immutable input")
	}
}

func TestDirectoryRulesRecognizeCapturedHTTP(t *testing.T) {
	base := "rules"
	manifest, err := os.ReadFile(filepath.Join(base, "upstream.json"))
	if err != nil {
		t.Fatal(err)
	}
	var source struct {
		Files map[string]struct {
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	if err := json.Unmarshal(manifest, &source); err != nil {
		t.Fatal(err)
	}
	if len(source.Files) == 0 {
		t.Fatal("missing rule source inventory")
	}
	for name, file := range source.Files {
		data, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != file.SHA256 {
			t.Fatalf("source changed without updating provenance: %s", name)
		}
	}
	e, err := New(context.Background(), Config{CustomRulesDir: base})
	if err != nil {
		t.Fatal(err)
	}
	if e.webfinger.Len() < 100 {
		t.Fatalf("production rules failed to load: %d", e.webfinger.Len())
	}
	response := &httpdata.Response{Header: http.Header{"Server": {"nginx"}}, WebServer: "nginx", Body: []byte(`<html><title>Example</title><link href="/wp-content/themes/test/style.css"></html>`), ContentType: "text/html"}
	found := map[string]bool{}
	for _, artifact := range e.Match(context.Background(), response) {
		found[artifact.Name] = true
	}
	if !found["nginx"] || !found["wordpress"] {
		t.Fatalf("missing detections from rule directory: %v", found)
	}
	if response.Title != "" {
		t.Fatal("matcher mutated its input")
	}
	zero, err := New(context.Background(), Config{})
	if err != nil || zero.webfinger.Len() != 0 {
		t.Fatal("zero configuration loaded rules implicitly", err)
	}
}

func TestWappalyzerCorpusRecognizesCapturedHTTP(t *testing.T) {
	base := "rules"
	data, err := os.ReadFile(filepath.Join(base, "wappalyzer.upstream.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		TechnologyCount int `json:"technology_count"`
		Files           map[string]struct {
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.TechnologyCount < 100 || len(manifest.Files) == 0 {
		t.Fatal("missing Wappalyzer corpus provenance")
	}
	for name, file := range manifest.Files {
		data, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != file.SHA256 {
			t.Fatalf("Wappalyzer source changed: %s", name)
		}
	}
	e, err := New(context.Background(), Config{WappalyzerJSONPath: filepath.Join(base, "wappalyzer.json")})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.wappalyzer.techs) != manifest.TechnologyCount {
		t.Fatalf("loaded %d technologies, expected %d", len(e.wappalyzer.techs), manifest.TechnologyCount)
	}
	response := &httpdata.Response{
		Header:      http.Header{"Server": {"nginx/1.26.0"}},
		ContentType: "text/html",
		Body:        []byte(`<html><head><meta name="generator" content="WordPress 6.8"><script src="https://cdn.example.test/jquery-3.7.1.min.js"></script></head></html>`),
	}
	found := map[string]bool{}
	for _, artifact := range e.Match(context.Background(), response) {
		if artifact.Source == "wappalyzer" {
			found[artifact.Name] = true
		}
	}
	for _, name := range []string{"Nginx", "WordPress", "jQuery"} {
		if !found[name] {
			t.Errorf("missing %s detection", name)
		}
	}
}
