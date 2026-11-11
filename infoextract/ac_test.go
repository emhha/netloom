package infoextract

import (
	"reflect"
	"testing"

	"github.com/emhha/netloom/ac"
)

func TestAutomatonCompatibility(t *testing.T) {
	var shared *ac.Matcher = newAutomaton([]string{"", "he", "she", "he", "\x00\xff"})
	want := map[string]struct{}{"he": {}, "she": {}, "\x00\xff": {}}
	if got := shared.Search([]byte("ushers\x00\xff")); !reflect.DeepEqual(got, want) {
		t.Fatalf("compatibility Search = %q, want %q", got, want)
	}
	var zero automaton
	if got := zero.Search([]byte("anything")); got == nil || len(got) != 0 {
		t.Fatalf("zero automaton Search = %v", got)
	}
}

func TestSharedACTriggerCompatibility(t *testing.T) {
	e := &InfoExtractor{}
	for _, rule := range []Rule{
		{Name: "suffix", Pattern: "value", Triggers: []string{"", "he", "he"}},
		{Name: "overlap", Pattern: "value", Triggers: []string{"she"}},
		{Name: "shared", Pattern: "value", Triggers: []string{"she", "she"}},
		{Name: "bytes", Pattern: "value", Triggers: []string{"\x00\xff"}},
		{Name: "case", Pattern: "value", Triggers: []string{"SHE"}},
		{Name: "empty-only", Pattern: "value", Triggers: []string{"", ""}},
		{Name: "fallback", Pattern: "value"},
	} {
		if err := e.AddRule(rule); err != nil {
			t.Fatal(err)
		}
	}
	for _, scope := range []string{"body", "header"} {
		t.Run(scope, func(t *testing.T) {
			var findings []Finding
			if scope == "body" {
				findings = e.ExtractWithContentType([]byte("she\x00\xff value"), nil, "text/plain")
			} else {
				findings = e.ExtractWithContentType(nil, map[string][]string{"X-Test": {"she\x00\xff value"}}, "text/plain")
			}
			var got []string
			for _, finding := range findings {
				if finding.Scope != scope {
					t.Errorf("finding scope = %q, want %q", finding.Scope, scope)
				}
				got = append(got, finding.RuleName)
			}
			want := []string{"suffix", "overlap", "shared", "bytes", "fallback"}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("rules = %v, want %v", got, want)
			}
		})
	}
	// Rebuilding replaces the matcher rather than mutating published snapshots.
	old := e.ac
	if err := e.AddRule(Rule{Name: "suffix", Pattern: "value", Triggers: []string{"new-trigger"}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := old.Search([]byte("he"))["he"]; !ok {
		t.Fatal("rebuild changed a previously published matcher")
	}
	if _, ok := e.ac.Search([]byte("he"))["he"]; ok {
		t.Fatal("rebuild retained removed trigger")
	}
}
