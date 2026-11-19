package infoextract

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func TestRuleSnapshotsSurviveReplacementAndAppend(t *testing.T) {
	e := &extractor{}
	oldRule := Rule{Name: "replace", Pattern: "old-value", Scope: "body", Triggers: []string{"old-trigger"}}
	if err := e.addRule(oldRule); err != nil {
		t.Fatal(err)
	}
	// These are exactly the two values readers retain after unlocking.
	oldRules, oldMatcher := e.rules, e.ac
	wantOld := oldRules[0].Rule
	if err := e.addRule(Rule{Name: "replace", Pattern: "new-value", Scope: "body", Triggers: []string{"new-trigger"}}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(oldRules[0].Rule, wantOld) {
		t.Fatalf("replacement mutated published rule: %+v", oldRules[0].Rule)
	}
	if hits := oldMatcher.Search([]byte("old-trigger new-trigger")); len(hits) != 1 {
		t.Fatalf("old matcher snapshot changed: %v", hits)
	} else if _, ok := hits["old-trigger"]; !ok {
		t.Fatalf("old matcher lost old trigger: %v", hits)
	}
	if got := e.extract([]byte("old-trigger old-value"), nil, "text/plain"); len(got) != 0 {
		t.Fatalf("replaced rule still runs: %+v", got)
	}
	want := e.extract([]byte("new-trigger new-value"), nil, "text/plain")
	if len(want) != 1 || want[0].Value != "new-value" {
		t.Fatalf("new rule/matcher snapshot inconsistent: %+v", want)
	}
	currentRules, currentMatcher := e.rules, e.ac
	if err := e.addRule(Rule{Name: "replace", Pattern: "[", Triggers: []string{"bad"}}); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	if e.ac != currentMatcher || !reflect.DeepEqual(e.rules, currentRules) {
		t.Fatal("invalid replacement changed published state")
	}
	if err := e.addRule(Rule{Name: "tail", Pattern: "tail", Scope: "body"}); err != nil {
		t.Fatal(err)
	}
	if len(currentRules) != 1 || currentRules[0].Name != "replace" {
		t.Fatalf("append mutated previous snapshot: %+v", currentRules)
	}
	got := e.extract([]byte("new-trigger new-value tail"), nil, "text/plain")
	if len(got) != 2 || got[0].RuleName != "replace" || got[1].RuleName != "tail" {
		t.Fatalf("replacement/append changed business rule order: %+v", got)
	}
}

func TestRuleOwnsTriggerSlice(t *testing.T) {
	e := &extractor{}
	triggers := []string{"old-trigger"}
	if err := e.addRule(Rule{Name: "owned", Pattern: "value", Scope: "body", Triggers: triggers}); err != nil {
		t.Fatal(err)
	}
	triggers[0] = "caller-reused"
	// Force a rebuild: the rule's triggerSet and the new AC must still agree.
	if err := e.addRule(Rule{Name: "unrelated", Pattern: "absent", Scope: "body", Triggers: []string{"absent"}}); err != nil {
		t.Fatal(err)
	}
	if got := e.extract([]byte("old-trigger value"), nil, "text/plain"); len(got) != 1 || got[0].RuleName != "owned" {
		t.Fatalf("caller mutation changed registered trigger: %+v", got)
	}
	if got := e.extract([]byte("caller-reused value"), nil, "text/plain"); len(got) != 0 {
		t.Fatalf("caller mutation enabled a different trigger: %+v", got)
	}
}

func TestTriggerEmptySliceAndEmptyKeywordRemainDistinct(t *testing.T) {
	for _, tc := range []struct {
		name     string
		triggers []string
		want     bool
	}{
		{"nil-fallback", nil, true},
		{"empty-slice-fallback", []string{}, true},
		{"empty-keyword-disabled", []string{""}, false},
		{"duplicate-empty-disabled", []string{"", ""}, false},
		{"mixed-keywords-hit", []string{"", "value"}, true},
		{"mixed-keywords-miss", []string{"", "absent"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &extractor{}
			if err := e.addRule(Rule{Name: tc.name, Pattern: "value", Triggers: tc.triggers}); err != nil {
				t.Fatal(err)
			}
			for _, scope := range []string{"body", "header"} {
				got := e.extractScope([]byte("value"), scope)
				if (len(got) == 1) != tc.want {
					t.Fatalf("%s: findings = %+v, want hit %v", scope, got, tc.want)
				}
			}
			if got := e.extract([]byte("value"), nil, "text/plain"); (len(got) == 1) != tc.want {
				t.Fatalf("body routing: findings = %+v, want hit %v", got, tc.want)
			}
		})
	}
}

func TestConcurrentAddRuleAndExtraction(t *testing.T) {
	e := &extractor{}
	borrowed := []string{"old-trigger"}
	if err := e.addRule(Rule{Name: "replace", Pattern: "value-one", Scope: "body", Triggers: borrowed}); err != nil {
		t.Fatal(err)
	}
	body := []byte("old-trigger new-trigger value-one value-two")
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 150; i++ {
				got := e.extract(body, nil, "text/plain")
				// Every published version matches exactly once, regardless of
				// which coherent rules/matcher snapshot the reader acquired.
				if len(got) != 1 || got[0].RuleName != "replace" || (got[0].Value != "value-one" && got[0].Value != "value-two") {
					t.Errorf("inconsistent concurrent snapshot: %+v", got)
					return
				}
			}
		}()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 100; i++ {
			rule := Rule{Name: "replace", Pattern: "value-two", Scope: "body", Triggers: []string{"new-trigger"}}
			if i%2 == 0 {
				rule.Pattern = "value-one"
				rule.Triggers = []string{"old-trigger"}
			}
			if err := e.addRule(rule); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 30; i++ {
			// Reusing a previously registered caller slice must not race with
			// rebuildAC, including its first rebuild before replacement.
			borrowed[0] = fmt.Sprintf("caller-reused-%d", i)
			if err := e.addRule(Rule{Name: fmt.Sprintf("append-%d", i), Pattern: "not-present", Scope: "body", Triggers: []string{"not-present"}}); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	close(start)
	wg.Wait()
}
