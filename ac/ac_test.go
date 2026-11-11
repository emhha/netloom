package ac_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/emhha/netloom/ac"
)

func TestSearch(t *testing.T) {
	keywords := []string{"", "he", "she", "hers", "his", "he", "a", "aa", "aaa", "A", "\x00\xff", "\xff"}
	m := ac.New(keywords)
	text := []byte("ushers his aaaa\x00\xff")
	want := map[string]struct{}{"he": {}, "she": {}, "hers": {}, "his": {}, "a": {}, "aa": {}, "aaa": {}, "\x00\xff": {}, "\xff": {}}
	if got := m.Search(text); !reflect.DeepEqual(got, want) {
		t.Fatalf("Search = %q, want %q", got, want)
	}
	// Mutation of either the constructor slice or a result cannot alter m.
	keywords[1] = "changed"
	got := m.Search([]byte("he"))
	delete(got, "he")
	got["invented"] = struct{}{}
	if got := m.Search([]byte("he")); !reflect.DeepEqual(got, map[string]struct{}{"he": {}}) {
		t.Fatalf("matcher changed through external mutation: %v", got)
	}
}

func TestMatchUniqueOriginalIndices(t *testing.T) {
	m := ac.New([]string{"", "a", "aa", "a", "ba", "aba", "aa", "b"})
	var got []int
	m.Match([]byte("abaa"), func(index int) { got = append(got, index) })
	sort.Ints(got)
	// Every matching unique keyword appears once, using its first original ID.
	want := []int{1, 2, 4, 5, 7}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Match = %v, want %v", got, want)
	}
	m.Match([]byte("abaa"), nil)
}

func TestEmptyAndZero(t *testing.T) {
	var zero ac.Matcher
	var nilMatcher *ac.Matcher
	for _, m := range []*ac.Matcher{&zero, nilMatcher, ac.New(nil), ac.New([]string{"", ""})} {
		for _, text := range [][]byte{nil, {}, []byte("anything\x00\xff")} {
			if got := m.Search(text); got == nil || len(got) != 0 {
				t.Errorf("empty matcher Search = %v, want non-nil empty map", got)
			}
			m.Match(text, func(index int) { t.Errorf("unexpected hit %d", index) })
			m.Match(text, nil)
		}
	}
	ac.New([]string{"a"}).Match(nil, func(index int) { t.Errorf("empty text hit %d", index) })
}

func expectedIndices(keywords []string, text []byte) []int {
	seen := make(map[string]bool)
	var hits []int
	for index, keyword := range keywords {
		if keyword != "" && !seen[keyword] {
			seen[keyword] = true
			if bytes.Contains(text, []byte(keyword)) {
				hits = append(hits, index)
			}
		}
	}
	return hits
}

func TestRandomArbitraryBytesEquivalent(t *testing.T) {
	rng := rand.New(rand.NewSource(0xAC2026))
	for trial := 0; trial < 400; trial++ {
		text := make([]byte, rng.Intn(180))
		_, _ = rng.Read(text)
		keywords := []string{"", "\x00", "\xff", "\x80\x00", "a", "A"}
		for i := 0; i < 30; i++ {
			keyword := make([]byte, rng.Intn(12))
			_, _ = rng.Read(keyword)
			if len(text) > 0 && i%2 == 0 {
				start := rng.Intn(len(text))
				end := start + rng.Intn(len(text)-start+1)
				keyword = text[start:end]
			}
			keywords = append(keywords, string(keyword))
			if i%5 == 0 {
				keywords = append(keywords, string(keyword))
			}
		}
		m := ac.New(keywords)
		want := make(map[string]struct{})
		for _, keyword := range keywords {
			if keyword != "" && bytes.Contains(text, []byte(keyword)) {
				want[keyword] = struct{}{}
			}
		}
		if got := m.Search(text); !reflect.DeepEqual(got, want) {
			t.Fatalf("trial %d: Search = %q, want %q (text %x)", trial, got, want, text)
		}
		var got []int
		m.Match(text, func(index int) { got = append(got, index) })
		sort.Ints(got)
		if want := expectedIndices(keywords, text); !reflect.DeepEqual(got, want) {
			t.Fatalf("trial %d: Match = %v, want %v", trial, got, want)
		}
	}
}

func TestDenseSuffixesAndFallback(t *testing.T) {
	var keywords []string
	for length := 1; length <= 64; length++ {
		keywords = append(keywords, string(bytes.Repeat([]byte{'a'}, length)))
	}
	keywords = append(keywords, "aaab", "ab", "b", "baaaaa")
	text := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabaaaaaxaaab")
	var got []int
	ac.New(keywords).Match(text, func(index int) { got = append(got, index) })
	sort.Ints(got)
	if want := expectedIndices(keywords, text); !reflect.DeepEqual(got, want) {
		t.Fatalf("suffix/fallback hits = %v, want %v", got, want)
	}
}

func TestConcurrentReads(t *testing.T) {
	keywords := []string{"he", "she", "hers", "a", "aa", "\x00\xff", "he", ""}
	text := []byte("ushers aaaa\x00\xff")
	m := ac.New(keywords)
	wantSet := m.Search(text)
	wantIndices := expectedIndices(keywords, text)
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if got := m.Search(text); !reflect.DeepEqual(got, wantSet) {
					t.Errorf("concurrent Search = %v, want %v", got, wantSet)
					return
				}
				var got []int
				m.Match(text, func(index int) { got = append(got, index) })
				sort.Ints(got)
				if !reflect.DeepEqual(got, wantIndices) {
					t.Errorf("concurrent Match = %v, want %v", got, wantIndices)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func benchmarkKeywords() []string {
	keywords := []string{"AKIA", "Bearer ", "secret", "token", "password", "key", "\x00\xff"}
	for i := 0; i < 100; i++ {
		keywords = append(keywords, fmt.Sprintf("keyword-%03d", i))
	}
	return keywords
}

func BenchmarkNew(b *testing.B) {
	keywords := benchmarkKeywords()
	b.ReportAllocs()
	for b.Loop() {
		ac.New(keywords)
	}
}

var benchmarkCount int
var benchmarkHits map[string]struct{}

func BenchmarkScan(b *testing.B) {
	keywords := benchmarkKeywords()
	patterns := make([][]byte, len(keywords))
	for i, keyword := range keywords {
		patterns[i] = []byte(keyword)
	}
	m := ac.New(keywords)
	for _, tc := range []struct {
		name string
		text []byte
	}{
		{"NoHit", bytes.Repeat([]byte("ordinary response body without matches\n"), 1024)},
		{"SparseHit", bytes.Repeat([]byte("ordinary response body followed by Bearer value keyword-099\n"), 512)},
		{"DenseHit", bytes.Repeat([]byte("AKIA secret token password key\x00\xff"), 1024)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.Run("Match", func(b *testing.B) {
				b.SetBytes(int64(len(tc.text)))
				b.ReportAllocs()
				count := 0
				for b.Loop() {
					m.Match(tc.text, func(int) { count++ })
				}
				benchmarkCount = count
			})
			b.Run("Search", func(b *testing.B) {
				b.SetBytes(int64(len(tc.text)))
				b.ReportAllocs()
				for b.Loop() {
					benchmarkHits = m.Search(tc.text)
				}
			})
			b.Run("BytesContains", func(b *testing.B) {
				b.SetBytes(int64(len(tc.text)))
				b.ReportAllocs()
				count := 0
				for b.Loop() {
					for _, pattern := range patterns {
						if bytes.Contains(tc.text, pattern) {
							count++
						}
					}
				}
				benchmarkCount = count
			})
		})
	}
}
