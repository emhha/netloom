package infoextract

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/emhha/netloom/httpdata"
	"github.com/emhha/netloom/passive"
)

func informationGenerationInput() passive.Input {
	const text = "old-trigger new-trigger old-value new-value added-value"
	return passive.Input{Site: "https://example.test", SessionID: "session",
		Request:  &httpdata.Request{URL: "https://example.test/app"},
		Response: &httpdata.Response{Body: []byte(text), ContentType: "text/plain", Header: map[string][]string{"X-Value": {text}}},
	}
}

func informationGenerationRule(value, trigger string) Rule {
	return Rule{Name: "versioned", Pattern: value, Triggers: []string{trigger}}
}

func checkInformationValues(t *testing.T, result passive.Result, want string, count int) {
	t.Helper()
	if len(result.Artifacts) != count {
		t.Fatalf("artifacts = %+v, want %d", result.Artifacts, count)
	}
	for _, a := range result.Artifacts {
		if a.Rule == "versioned" && a.Value != want {
			t.Fatalf("stale/mixed generation: %+v, want %q", result.Artifacts, want)
		}
	}
}

func TestInformationInvalidatesCacheOnRuleAppendAndReplacement(t *testing.T) {
	p := &Plugin{}
	registry, err := passive.New([]passive.Plugin{p}, 8)
	if err != nil {
		t.Fatal(err)
	}
	in := informationGenerationInput()
	analyze := func() passive.Result {
		t.Helper()
		results, err := registry.Analyze(context.Background(), in, nil)
		if err != nil || len(results) != 1 || results[0].Status != "completed" {
			t.Fatalf("analysis: %+v %v", results, err)
		}
		return results[0]
	}
	if got := analyze(); len(got.Artifacts) != 0 || got.CacheHit {
		t.Fatalf("unexpected empty first analysis: %+v", got)
	}
	if !analyze().CacheHit {
		t.Fatal("unchanged empty generation was not cached")
	}
	if err := p.AddRule(informationGenerationRule("old-value", "old-trigger")); err != nil {
		t.Fatal(err)
	}
	got := analyze()
	checkInformationValues(t, got, "old-value", 2)
	if got.CacheHit || !analyze().CacheHit {
		t.Fatal("append did not invalidate then reuse the new generation")
	}
	if err := p.AddRule(informationGenerationRule("new-value", "new-trigger")); err != nil {
		t.Fatal(err)
	}
	got = analyze()
	checkInformationValues(t, got, "new-value", 2)
	if got.CacheHit || !analyze().CacheHit {
		t.Fatal("replacement did not invalidate then reuse the new generation")
	}
	if err := p.AddRule(Rule{Name: "added", Pattern: "added-value", Scope: "body"}); err != nil {
		t.Fatal(err)
	}
	got = analyze()
	checkInformationValues(t, got, "new-value", 3)
	foundAdded := false
	for _, a := range got.Artifacts {
		foundAdded = foundAdded || a.Rule == "added" && a.Value == "added-value"
	}
	if !foundAdded || got.CacheHit {
		t.Fatalf("appended rule absent or stale cache reused: %+v", got)
	}
	if err := p.AddRule(Rule{Name: "added", Pattern: "["}); err == nil {
		t.Fatal("invalid rule accepted")
	}
	if !analyze().CacheHit {
		t.Fatal("failed update invalidated unchanged generation")
	}
}

func TestInformationPinsRegistryAcrossUpdatesAndExtractorInstances(t *testing.T) {
	first, other := &Plugin{}, &Plugin{}
	if err := first.AddRule(informationGenerationRule("old-value", "old-trigger")); err != nil {
		t.Fatal(err)
	}
	if err := other.AddRule(informationGenerationRule("new-value", "new-trigger")); err != nil {
		t.Fatal(err)
	}
	oldCache, err := first.registry()
	if err != nil {
		t.Fatal(err)
	}
	// Both extractors have had one AddRule call; object identity must also be
	// part of the generation identity.
	newCache, err := other.registry()
	if err != nil {
		t.Fatal(err)
	}
	if oldCache == newCache {
		t.Fatal("different plugin instances shared a cache")
	}
	p := other
	in := informationGenerationInput()
	// Simulate an old in-flight call completing after the new registry exists.
	oldResults, err := oldCache.Analyze(context.Background(), in, nil)
	if err != nil || len(oldResults) != 2 {
		t.Fatalf("old analysis: %+v %v", oldResults, err)
	}
	for _, result := range oldResults {
		checkInformationValues(t, result, "old-value", 1)
	}
	got, err := p.Analyze(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	checkInformationValues(t, got, "new-value", 2)
	if got.CacheHit {
		t.Fatal("old registry populated the new generation cache")
	}
	if err := other.AddRule(informationGenerationRule("old-value", "old-trigger")); err != nil {
		t.Fatal(err)
	}
	// The previous registry remains immutable, not only its cache identity.
	in.Request.URL += "/fresh"
	results, err := newCache.Analyze(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		checkInformationValues(t, result, "new-value", 1)
	}
	got, err = p.Analyze(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	checkInformationValues(t, got, "old-value", 2)
}

func TestPluginZeroValueUsesAnEmptyRuleSet(t *testing.T) {
	in := informationGenerationInput()
	in.Response.Body = []byte("key=AKIAIOSFODNN7EXAMPLE")
	var p Plugin
	got, err := p.Analyze(t.Context(), in)
	if err != nil || len(got.Artifacts) != 0 {
		t.Fatalf("zero-value analysis: %+v %v", got, err)
	}
}

func TestInformationConcurrentRuleUpdatesKeepOneGeneration(t *testing.T) {
	p := &Plugin{}
	if err := p.AddRule(informationGenerationRule("old-value", "old-trigger")); err != nil {
		t.Fatal(err)
	}
	in := informationGenerationInput()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 100; i++ {
				input := in
				request := *in.Request
				request.URL = fmt.Sprintf("%s/%d/%d", request.URL, worker, i)
				input.Request = &request
				got, err := p.Analyze(context.Background(), input)
				if err != nil || len(got.Artifacts) != 2 || got.Artifacts[0].Value != got.Artifacts[1].Value {
					t.Errorf("inconsistent body/header snapshot: %+v %v", got, err)
					return
				}
				for _, artifact := range got.Artifacts {
					if artifact.Value != "old-value" && artifact.Value != "new-value" {
						t.Errorf("unexpected rule value: %+v", artifact)
						return
					}
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 100; i++ {
			value, trigger := "old-value", "old-trigger"
			if i%2 != 0 {
				value, trigger = "new-value", "new-trigger"
			}
			if err := p.AddRule(informationGenerationRule(value, trigger)); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	close(start)
	wg.Wait()
	got, err := p.Analyze(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	checkInformationValues(t, got, "new-value", 2)
	got, err = p.Analyze(context.Background(), in)
	if err != nil || !got.CacheHit {
		t.Fatalf("stable final generation not cached: %+v %v", got, err)
	}
}
