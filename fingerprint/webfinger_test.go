package fingerprint

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/emhha/netloom/httpdata"
)

func TestWebfingerMatcherFacade(t *testing.T) {
	m, err := LoadWebfingerYAML([]byte(`page:
  - body="marker"
  - icon_hash="123"
icon-only:
  - icon_hash="456"
`))
	if err != nil {
		t.Fatal(err)
	}
	if m.Len() != 2 {
		t.Fatalf("icon-only rules missing from Len: %d", m.Len())
	}
	r := &httpdata.Response{Body: []byte("marker"), FaviconHash: 456}
	mc := NewMatchContext(r, nil)
	got := m.match(context.Background(), mc)
	if len(got) != 2 || got[0].Name != "icon-only" || got[1].Name != "page" {
		t.Fatal(got)
	}
	if len(mc.Hits) != 0 {
		t.Fatal("matcher changed the shared context's hit set")
	}
	for _, a := range got {
		if a.Source != "webfinger" {
			t.Fatal(a)
		}
	}
}

func TestWebfingerProfileEnableAndDisable(t *testing.T) {
	dir := t.TempDir()
	write := func(name, contents string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("rules.yaml", "portal:\n  - title=\"Portal Login\"\n")
	write("sources.json", `{"webfinger":{"enabled":true,"file":"rules.yaml"}}`)
	e, err := New(context.Background(), Config{RulesDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	r := &httpdata.Response{Body: []byte("<title>Portal Login</title>")}
	got := e.Match(context.Background(), r)
	if len(got) != 1 || got[0].Name != "portal" || got[0].Source != "webfinger" {
		t.Fatal(got)
	}
	if r.Title != "" {
		t.Fatal("title extraction mutated input")
	}
	write("sources.json", `{"webfinger":{"enabled":false,"file":"rules.yaml"}}`)
	off, err := New(context.Background(), Config{RulesDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if off.webfinger != nil || len(off.Match(context.Background(), r)) != 0 {
		t.Fatal("disabled source loaded")
	}
	write("sources.json", `{"webfinger":{"enabled":true,"file":"rules.yaml"}}`)
	write("rules.yaml", "# no valid rules\n")
	if _, err := New(context.Background(), Config{RulesDir: dir}); err == nil {
		t.Fatal("empty enabled source accepted")
	}
}
