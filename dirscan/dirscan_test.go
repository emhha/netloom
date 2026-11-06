package dirscan

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emhha/netloom"

	http "github.com/bogdanfinn/fhttp"
)

func TestExpandTemplate_EXT(t *testing.T) {
	vars := map[string][]string{
		"EXT": {"php", "html"},
	}
	got := ExpandTemplate("index.%EXT%", vars)
	want := map[string]bool{"index.php": true, "index.html": true}
	if len(got) != 2 {
		t.Fatalf("want 2 results, got %d: %v", len(got), got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected result %q", g)
		}
	}
}

func TestExpandTemplate_CartesianProduct(t *testing.T) {
	vars := map[string][]string{
		"ENV": {"dev", "prod"},
		"EXT": {"php", "html"},
	}
	got := ExpandTemplate("config/%ENV%.%EXT%", vars)
	// 2*2 = 4 results.
	if len(got) != 4 {
		t.Fatalf("want 4 results, got %d: %v", len(got), got)
	}
}

func TestExpandTemplate_NoPlaceholder(t *testing.T) {
	vars := map[string][]string{"EXT": {"php"}}
	got := ExpandTemplate("admin/", vars)
	if len(got) != 1 || got[0] != "admin/" {
		t.Errorf("want [admin/], got %v", got)
	}
}

func TestNormalizePath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/Admin/", "admin"},
		{"ADMIN", "admin"},
		{"/api/v1/", "api/v1"},
	}
	for _, c := range cases {
		got := normalizePath(c.in)
		if got != c.want {
			t.Errorf("normalizePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFileExt(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"admin.php", "php"},
		{"config.json", "json"},
		{"dir/", ""},
		{"noext", ""},
		{".hidden", ""},
		{"file.tar.gz", "gz"},
	}
	for _, c := range cases {
		got := fileExt(c.path)
		if got != c.want {
			t.Errorf("fileExt(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestBuildWordlist_SizeLimit(t *testing.T) {
	// Build a wordlist that exceeds WordlistMaxSize with unique entries.
	large := make([]string, 101)
	for i := range large {
		large[i] = fmt.Sprintf("path%d", i)
	}
	cfg := &Config{
		Wordlist:        large,
		WordlistMaxSize: 100,
	}
	_, err := BuildWordlist(cfg)
	if err == nil {
		t.Fatal("expected error for oversized wordlist")
	}
}

func TestBuildWordlist_CustomPathTraversal(t *testing.T) {
	cfg := &Config{
		Preset:          PresetCustom,
		CustomWordlists: []string{"../etc/passwd"},
	}
	_, err := BuildWordlist(cfg)
	if err == nil {
		t.Fatal("expected error for path traversal in custom wordlist name")
	}
}

func TestBuildWordlist_CustomAbsolute(t *testing.T) {
	cfg := &Config{
		Preset:          PresetCustom,
		CustomWordlists: []string{"/etc/passwd"},
	}
	_, err := BuildWordlist(cfg)
	if err == nil {
		t.Fatal("expected error for absolute path in custom wordlist name")
	}
}

func TestApplyExtensions_Default(t *testing.T) {
	paths := []string{"admin", "dir/", "page.html"}
	cfg := &Config{}
	exts := []string{"php", "asp"}
	got := applyExtensions(paths, cfg, exts)
	// admin → admin, admin.php, admin.asp
	// dir/ → dir/
	// page.html → page.html (has extension, not overwriting)
	wantContains := map[string]bool{
		"admin":     true,
		"admin.php": true,
		"admin.asp": true,
		"dir/":      true,
		"page.html": true,
	}
	for _, p := range got {
		delete(wantContains, p)
	}
	if len(wantContains) > 0 {
		t.Errorf("missing expected paths: %v; got: %v", wantContains, got)
	}
}

func TestApplyExtensions_Force(t *testing.T) {
	paths := []string{"admin"}
	cfg := &Config{ForceExtensions: true}
	exts := []string{"php"}
	got := applyExtensions(paths, cfg, exts)
	wantContains := map[string]bool{
		"admin":     true,
		"admin/":    true,
		"admin.php": true,
	}
	for _, p := range got {
		delete(wantContains, p)
	}
	if len(wantContains) > 0 {
		t.Errorf("missing with ForceExtensions: %v; got: %v", wantContains, got)
	}
}

func TestApplyExtensions_Overwrite(t *testing.T) {
	paths := []string{"index.html"}
	cfg := &Config{OverwriteExtensions: true}
	exts := []string{"php"}
	got := applyExtensions(paths, cfg, exts)
	found := false
	for _, p := range got {
		if p == "index.php" {
			found = true
		}
	}
	if !found {
		t.Errorf("OverwriteExtensions should produce index.php; got: %v", got)
	}
}

func TestCategorizeResult(t *testing.T) {
	cases := []struct {
		path string
		want ResultCategory
	}{
		{".git/HEAD", CategoryVCS},
		{".svn/entries", CategoryVCS},
		{".env", CategoryConfig},
		{"web.config", CategoryConfig},
		{"backup.sql", CategoryConfig},
		{"file.bak", CategoryBackup},
		{"archive.zip", CategoryBackup},
		{"test/", CategoryLeak},
		{"staging/", CategoryLeak},
		{"admin", CategoryCommon},
	}
	for _, c := range cases {
		got := categorizeResult(c.path)
		if got != c.want {
			t.Errorf("categorizeResult(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestGenerateBackupNames(t *testing.T) {
	cfg := &Config{}
	names := GenerateBackupNames("config.php", cfg)
	if len(names) == 0 {
		t.Fatal("expected backup names for config.php")
	}
	found := false
	for _, n := range names {
		if n == "config.php.bak" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected config.php.bak in backup names; got: %v", names)
	}
}

func TestResponseFingerprint_Deterministic(t *testing.T) {
	resp := mockResp(200, "text/html", "hello world")
	fp1 := ResponseFingerprint(resp)
	fp2 := ResponseFingerprint(resp)
	if fp1 != fp2 {
		t.Errorf("fingerprint should be deterministic: %q vs %q", fp1, fp2)
	}
}

func TestResponseFingerprint_Distinguishes(t *testing.T) {
	r1 := mockResp(200, "text/html", "hello world")
	r2 := mockResp(200, "text/html", "completely different body content here")
	fp1 := ResponseFingerprint(r1)
	fp2 := ResponseFingerprint(r2)
	if fp1 == fp2 {
		t.Errorf("different bodies should have different fingerprints")
	}
}

func TestJoinURL(t *testing.T) {
	got := joinURL("https://example.com/app/", "/app/", "admin")
	if got != "https://example.com/app/admin" {
		t.Errorf("joinURL = %q, want https://example.com/app/admin", got)
	}
}

func TestDepthOf(t *testing.T) {
	cases := []struct {
		newDir  string
		baseDir string
		want    int
	}{
		{"/app/api/v1/", "/app/", 2},
		{"/app/admin/", "/app/", 1},
		{"/app/", "/app/", 0},
	}
	for _, c := range cases {
		got := depthOf(c.newDir, c.baseDir)
		if got != c.want {
			t.Errorf("depthOf(%q, %q) = %d, want %d", c.newDir, c.baseDir, got, c.want)
		}
	}
}

func TestCommonPrefix(t *testing.T) {
	got := commonPrefix("/redirect?r=abc123", "/redirect?r=xyz789")
	if got != "/redirect?r=" {
		t.Errorf("commonPrefix = %q, want /redirect?r=", got)
	}
}

func TestNormalizeBody(t *testing.T) {
	input := `token="abc123def456" nonce="abc123" uuid="550e8400-e29b-41d4-a716-446655440000"`
	got := normalizeBody(input)
	if strings.Contains(got, "550e8400") {
		t.Errorf("normalizeBody should remove UUID, got: %s", got)
	}
}

func TestExtractLinks_HTML(t *testing.T) {
	body := `<html><body><a href="/admin">Admin</a><a href="/api/v1/users">Users</a><a href="https://other.com/page">External</a></body></html>`
	resp := mockRespWithContentType(200, "text/html", body, "")
	links := ExtractLinks(resp, "https://example.com/")
	foundAdmin, foundUsers := false, false
	for _, l := range links {
		if l == "/admin" {
			foundAdmin = true
		}
		if l == "/api/v1/users" {
			foundUsers = true
		}
		if strings.Contains(l, "other.com") {
			t.Errorf("external link should not be included: %q", l)
		}
	}
	if !foundAdmin {
		t.Error("expected /admin in links")
	}
	if !foundUsers {
		t.Error("expected /api/v1/users in links")
	}
}

func TestFilterChain_ExcludeStatus(t *testing.T) {
	cfg := &Config{ExcludeStatusCodes: []int{404, 403}}
	fc, err := buildFilterChain(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resp404 := mockResp(404, "text/html", "not found")
	if fc.Keep(resp404) {
		t.Error("404 should be excluded")
	}
	resp200 := mockResp(200, "text/html", "found")
	if !fc.Keep(resp200) {
		t.Error("200 should be kept")
	}
}

func TestFilterChain_ExcludeText(t *testing.T) {
	cfg := &Config{
		ExcludeStatusCodes: []int{},
		ExcludeTexts:       []string{"Not Found"},
	}
	fc, err := buildFilterChain(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resp := mockResp(200, "text/html", "Not Found")
	if fc.Keep(resp) {
		t.Error("response containing ExcludeText should be excluded")
	}
}

func TestFilterChain_MatchStatus(t *testing.T) {
	cfg := &Config{
		ExcludeStatusCodes: []int{},
		MatchStatus:        "200-299",
		MatcherMode:        "and",
	}
	fc, err := buildFilterChain(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resp301 := mockResp(301, "text/html", "redirect")
	if fc.Keep(resp301) {
		t.Error("301 should not match MatchStatus 200-299")
	}
	resp200 := mockResp(200, "text/html", "ok")
	if !fc.Keep(resp200) {
		t.Error("200 should match MatchStatus 200-299")
	}
}

func TestWildcardProfile_Classify_UniqueStatus(t *testing.T) {
	wp := &WildcardProfile{
		BaseStatus:        404,
		FingerprintCounts: make(map[string]int),
		Threshold:         8,
	}
	resp := mockResp(200, "text/html", "admin panel")
	got := wp.Classify("/admin", resp)
	if got != "unique" {
		t.Errorf("status differs from base should be unique, got %q", got)
	}
}

func TestWildcardProfile_Classify_WildcardThreshold(t *testing.T) {
	wp := &WildcardProfile{
		BaseStatus:        200,
		FingerprintCounts: make(map[string]int),
		Threshold:         3,
	}
	resp := mockResp(200, "text/html", "not found page")
	// First two hits: unique.
	for i := 0; i < 2; i++ {
		got := wp.Classify("/path"+string(rune('0'+i)), resp)
		if got != "unique" {
			t.Errorf("iteration %d: expected unique before threshold, got %q", i, got)
		}
	}
	// Third hit with same fingerprint: should be wildcard.
	got := wp.Classify("/path3", resp)
	if got != "wildcard" {
		t.Errorf("expected wildcard at threshold, got %q", got)
	}
}

// --- Test helpers ---

func mockResp(status int, ct, body string) *netloom.Response {
	return mockRespWithContentType(status, ct, body, "")
}

func mockRespWithContentType(status int, ct, body, location string) *netloom.Response {
	return &netloom.Response{
		StatusCode:   status,
		ContentType:  ct,
		Body:         []byte(body),
		Location:     location,
		ResponseTime: 100 * time.Millisecond,
		Header:       make(http.Header),
	}
}
