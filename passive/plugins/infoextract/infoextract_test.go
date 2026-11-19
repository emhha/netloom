package infoextract

import (
	"net/http"
	"testing"
)

func newExtractor() *extractor {
	e := &extractor{}
	e.loadDefaults()
	return e
}

// TestTwoPhaseAC verifies that Phase 1 (AC) correctly gates Phase 2 (regex).
func TestTwoPhaseAC(t *testing.T) {
	e := newExtractor()

	// Body that contains the AWS trigger but no actual key.
	body := []byte("some content with AKIA prefix but not a real key")
	findings := e.extract(body, nil, "text/html")

	// aws_access_key requires AKIA + exactly 16 uppercase alphanum chars.
	// "AKIA prefix" does not match the full pattern, so no finding expected.
	for _, f := range findings {
		if f.RuleName == "aws_access_key" {
			t.Errorf("unexpected aws_access_key finding: %+v", f)
		}
	}
}

// TestFallbackRulesAlwaysRun verifies that rules with no Triggers run
// unconditionally even without an AC hit.
func TestFallbackRulesAlwaysRun(t *testing.T) {
	e := newExtractor()
	if err := e.addRule(Rule{
		Name: "email", Pattern: `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
		Scope: "all", Sensitivity: "low",
	}); err != nil {
		t.Fatalf("addRule: %v", err)
	}

	body := []byte("contact us at admin@example.com for more info")
	findings := e.extract(body, nil, "text/html")

	found := false
	for _, f := range findings {
		if f.RuleName == "email" && f.Value == "admin@example.com" {
			found = true
		}
	}
	if !found {
		t.Error("expected email fallback rule to fire")
	}
}

// TestAWSKey checks that a real AWS access key is detected.
func TestAWSKey(t *testing.T) {
	e := newExtractor()

	body := []byte("key=AKIAIOSFODNN7EXAMPLE other stuff")
	findings := e.extract(body, nil, "text/html")

	found := false
	for _, f := range findings {
		if f.RuleName == "aws_access_key" {
			found = true
			if f.Sensitivity != "high" {
				t.Errorf("expected high sensitivity, got %q", f.Sensitivity)
			}
		}
	}
	if !found {
		t.Error("expected aws_access_key finding")
	}
}

// TestBinaryContentTypeSkipped verifies image/* returns nil.
func TestBinaryContentTypeSkipped(t *testing.T) {
	e := newExtractor()
	body := []byte("AKIAIOSFODNN7EXAMPLE")
	findings := e.extract(body, nil, "image/png")
	if findings != nil {
		t.Errorf("expected nil for binary content-type, got %v", findings)
	}
}

// TestHeaderScan verifies header-scope rules fire on serialized headers.
func TestHeaderScan(t *testing.T) {
	e := newExtractor()

	// Add a header-scoped rule for testing.
	err := e.addRule(Rule{
		Name:        "test_header_bearer",
		Pattern:     `Bearer\s+([A-Za-z0-9._\-]+)`,
		Color:       "red",
		Scope:       "header",
		Sensitivity: "high",
		Triggers:    []string{"Bearer "},
	})
	if err != nil {
		t.Fatalf("addRule: %v", err)
	}

	h := http.Header{"Authorization": []string{"Bearer mytoken123"}}
	findings := e.extract(nil, h, "text/html")

	found := false
	for _, f := range findings {
		if f.RuleName == "test_header_bearer" && f.Scope == "header" {
			found = true
		}
	}
	if !found {
		t.Error("expected bearer token found in header")
	}
}

// TestSpecialCategoryJSOnly verifies linkfinder only runs for JS/JSON content.
func TestSpecialCategoryJSOnly(t *testing.T) {
	e := newExtractor()
	if err := e.addRule(Rule{
		Name: "linkfinder", Pattern: `(?:"|')(/(?:api|v[0-9]+|graphql)/[a-zA-Z0-9_/\-?=&]{1,200})(?:"|')`,
		Scope: "body", Sensitivity: "low", Category: "special",
		Triggers: []string{"/api/", "/v1/", "/v2/", "/graphql"},
	}); err != nil {
		t.Fatalf("addRule: %v", err)
	}

	jsBody := []byte(`"/api/v1/users" some js content`)

	// Should fire for JS content-type.
	jsFindings := e.extract(jsBody, nil, "application/javascript")
	foundInJS := false
	for _, f := range jsFindings {
		if f.RuleName == "linkfinder" {
			foundInJS = true
		}
	}
	if !foundInJS {
		t.Error("expected linkfinder to fire for JS content-type")
	}

	// Should NOT fire for HTML content-type.
	htmlFindings := e.extract(jsBody, nil, "text/html")
	for _, f := range htmlFindings {
		if f.RuleName == "linkfinder" {
			t.Error("linkfinder should not fire for HTML content-type")
		}
	}
}

// TestHeadOnlyJS verifies that JS bodies larger than 100KB are truncated.
func TestHeadOnlyJS(t *testing.T) {
	e := newExtractor()

	// Build a 200KB body: first 1KB has a valid JWT, rest is junk.
	jwtToken := []byte(`eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`)
	body := make([]byte, 200*1024)
	copy(body, jwtToken)

	findings := e.extract(body, nil, "application/javascript")
	found := false
	for _, f := range findings {
		if f.RuleName == "jwt_token" {
			found = true
		}
	}
	if !found {
		t.Error("expected JWT finding in first 100KB of JS body")
	}
}

// TestAddRuleSameNameOverwrite verifies same-name rules are deduplicated.
func TestAddRuleSameNameOverwrite(t *testing.T) {
	e := newExtractor()

	// Add custom rule with same name as built-in; it uses a different pattern.
	err := e.addRule(Rule{
		Name:        "aws_access_key",
		Pattern:     `CUSTOM_([a-z]+)`,
		Color:       "green",
		Scope:       "body",
		Sensitivity: "high",
		Triggers:    []string{"CUSTOM_"},
	})
	if err != nil {
		t.Fatalf("addRule: %v", err)
	}

	// Count how many "aws_access_key" rules exist (should be exactly 1).
	e.mu.RLock()
	count := 0
	for _, cr := range e.rules {
		if cr.Name == "aws_access_key" {
			count++
		}
	}
	e.mu.RUnlock()

	if count != 1 {
		t.Errorf("expected exactly 1 rule named 'aws_access_key', got %d", count)
	}

	findings := e.extract([]byte("CUSTOM_replacement AKIAIOSFODNN7EXAMPLE"), nil, "text/html")
	count = 0
	for _, f := range findings {
		if f.RuleName == "aws_access_key" {
			count++
			if f.Value != "CUSTOM_replacement" {
				t.Errorf("overwritten rule matched old pattern: %+v", f)
			}
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 replacement finding, got %d", count)
	}
}

// TestAddRuleInvalidPattern verifies addRule returns error without mutation.
func TestAddRuleInvalidPattern(t *testing.T) {
	e := newExtractor()
	countBefore := func() int {
		e.mu.RLock()
		defer e.mu.RUnlock()
		return len(e.rules)
	}
	before := countBefore()

	err := e.addRule(Rule{
		Name:    "bad_rule",
		Pattern: `[invalid(`,
	})
	if err == nil {
		t.Error("expected error for invalid pattern")
	}
	if countBefore() != before {
		t.Error("rule count changed on error")
	}
}

// TestInternalIPFallback checks that internal IPs are detected without triggers.
func TestInternalIPFallback(t *testing.T) {
	e := newExtractor()
	if err := e.addRule(Rule{
		Name: "internal_ip", Pattern: `(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)`,
		Scope: "all", Sensitivity: "medium",
	}); err != nil {
		t.Fatalf("addRule: %v", err)
	}
	body := []byte("connect to 192.168.1.100 for service")
	findings := e.extract(body, nil, "text/html")

	found := false
	for _, f := range findings {
		if f.RuleName == "internal_ip" {
			found = true
		}
	}
	if !found {
		t.Error("expected internal_ip finding")
	}
}

// TestDefaultRulesHighSensitivityOnly preserves the intentionally narrow defaults.
func TestDefaultRulesHighSensitivityOnly(t *testing.T) {
	removed := map[string]bool{
		"password_field": true, "internal_ip": true, "id_card_cn": true,
		"wechat_appid": true, "email": true, "ipv4": true, "url": true,
		"phone_cn": true, "linkfinder": true,
	}
	rules := defaultRules()
	if len(rules) == 0 {
		t.Fatal("expected high-sensitivity built-in rules")
	}
	for _, rule := range rules {
		if rule.Sensitivity != "high" {
			t.Errorf("default rule %q has sensitivity %q, want high", rule.Name, rule.Sensitivity)
		}
		if removed[rule.Name] {
			t.Errorf("removed rule %q returned to defaults", rule.Name)
		}
	}
	for _, rule := range newExtractor().rules {
		if removed[rule.Name] {
			t.Errorf("removed rule %q registered by New", rule.Name)
		}
	}
}
