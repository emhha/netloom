package infoextract

import (
	"sync"
	"testing"
)

func TestSnapshotIdentityAndLifetime(t *testing.T) {
	e, other := &extractor{}, &extractor{}
	empty := e.snapshot()
	if empty.identity == 0 || empty.identity != e.snapshot().identity {
		t.Fatal("initial identity must be nonzero and stable")
	}
	if empty.identity == other.snapshot().identity {
		t.Fatal("different zero-value extractors share an identity")
	}
	oldRule := Rule{Name: "versioned", Pattern: "old-value", Triggers: []string{"old-trigger"}}
	if err := e.addRule(oldRule); err != nil {
		t.Fatal(err)
	}
	old := e.snapshot()
	if old.identity == empty.identity {
		t.Fatal("successful append did not change identity")
	}
	if err := e.addRule(Rule{Name: "versioned", Pattern: "new-value", Triggers: []string{"new-trigger"}}); err != nil {
		t.Fatal(err)
	}
	current := e.snapshot()
	if old.identity == current.identity {
		t.Fatal("successful replacement did not change identity")
	}
	if err := e.addRule(Rule{Name: "versioned", Pattern: "["}); err == nil {
		t.Fatal("invalid rule accepted")
	}
	if current.identity != e.snapshot().identity {
		t.Fatal("failed update changed identity")
	}
	body := []byte("old-trigger new-trigger old-value new-value")
	headers := map[string][]string{"X-Value": {string(body)}}
	for _, tc := range []struct {
		snapshot snapshot
		want     string
	}{{old, "old-value"}, {current, "new-value"}} {
		got := tc.snapshot.extract(body, headers, "text/plain")
		if len(got) != 2 || got[0].Value != tc.want || got[1].Value != tc.want || got[0].Scope != "body" || got[1].Scope != "header" {
			t.Fatalf("snapshot %d is not immutable/coherent: %+v", tc.snapshot.identity, got)
		}
	}
	if got := empty.extract(body, headers, "text/plain"); len(got) != 0 {
		t.Fatalf("empty snapshot acquired later rules: %+v", got)
	}
	var zero snapshot
	if zero.identity != 0 || len(zero.extract(body, headers, "text/plain")) != 0 {
		t.Fatal("zero snapshot is not an empty ruleset")
	}
}

func TestConcurrentExtractionPinsBodyAndHeaderGeneration(t *testing.T) {
	e := &extractor{}
	makeRule := func(i int) Rule {
		value, trigger := "old-value", "old-trigger"
		if i%2 != 0 {
			value, trigger = "new-value", "new-trigger"
		}
		return Rule{Name: "versioned", Pattern: value, Triggers: []string{trigger}}
	}
	if err := e.addRule(makeRule(0)); err != nil {
		t.Fatal(err)
	}
	body := []byte("old-trigger new-trigger old-value new-value")
	headers := map[string][]string{"X-Value": {string(body)}}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 150; i++ {
				got := e.extract(body, headers, "text/plain")
				if len(got) != 2 || got[0].Value != got[1].Value {
					t.Errorf("mixed body/header generations: %+v", got)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 100; i++ {
			if err := e.addRule(makeRule(i)); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	close(start)
	wg.Wait()
}
