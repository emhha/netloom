package fingerprint

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/emhha/netloom/httpdata"
)

func TestBuiltinSelectedSourcesWithoutResourceDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	e, err := NewBuiltin(t.Context(), SourceEHole, SourceWappalyzer)
	if err != nil {
		t.Fatal(err)
	}
	if e.webfinger != nil || e.fingerprinthub != nil || e.ehole == nil || e.wappalyzer == nil {
		t.Fatal("explicit source selection was not respected")
	}
	r := &httpdata.Response{Header: http.Header{"Server": {"nginx/1.24.0"}}, Body: []byte("/seeyon/USER-DATA/IMAGES/LOGIN/login.gif")}
	found := map[string]bool{}
	for _, a := range e.Match(t.Context(), r) {
		found[a.Source+":"+a.Name] = true
		if a.Source != "ehole" && a.Source != "wappalyzer" {
			t.Fatalf("unselected source returned a match: %s", a.Source)
		}
	}
	if !found["ehole:致远OA"] || !found["wappalyzer:Nginx"] {
		t.Fatalf("built-in rules did not match: %v", found)
	}
}

func TestBuiltinDefaultMatchesSourceProfile(t *testing.T) {
	builtin, err := NewBuiltin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	external, err := New(t.Context(), Config{RulesDir: "rules"})
	if err != nil {
		t.Fatal(err)
	}
	if builtin.webfinger != nil || builtin.ehole == nil || builtin.fingerprinthub == nil || builtin.wappalyzer == nil {
		t.Fatal("default source profile was not respected")
	}
	r := &httpdata.Response{Header: http.Header{"Server": {"nginx"}}, Body: []byte("/seeyon/USER-DATA/IMAGES/LOGIN/login.gif"), FaviconHash: 617142232}
	if a, b := builtin.Match(t.Context(), r), external.Match(t.Context(), r); !reflect.DeepEqual(a, b) {
		t.Fatalf("embedded and external source profile disagree:\n%+v\n%+v", a, b)
	}
}

func TestBuiltinRejectsUnknownSourceAndCancelledContext(t *testing.T) {
	if _, err := NewBuiltin(t.Context(), Source("unknown")); err == nil {
		t.Fatal("unknown source accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := NewBuiltin(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: %v", err)
	}
}
