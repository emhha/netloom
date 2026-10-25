package fingerprint

import (
	"maps"
	"math/rand"
	"strings"
	"testing"
)

func TestNativeAutomatonMatchesSubstringSearch(t *testing.T) {
	random := rand.New(rand.NewSource(18421))
	for iteration := 0; iteration < 60; iteration++ {
		patterns := []string{"he", "she", "hers", "his", "a", "aa", "aaa", "中文", "\x00a", "", "he"}
		for range 100 {
			word := make([]byte, 1+random.Intn(14))
			for i := range word {
				word[i] = byte(random.Intn(256))
			}
			patterns = append(patterns, string(word))
		}
		ac := newNativeAutomaton(patterns)
		input := []byte("ushers aaaa 中文\x00a")
		for range 40 {
			input = append(input, patterns[random.Intn(len(patterns))]...)
			input = append(input, byte(random.Intn(256)))
		}
		text := string(input)
		want := map[string]bool{}
		for _, word := range patterns {
			if word != "" && strings.Contains(text, word) {
				want[word] = true
			}
		}
		if got := ac.matchString(text); !maps.Equal(got, want) {
			t.Fatalf("iteration %d: got=%v want=%v", iteration, got, want)
		}
	}
	if got := newNativeAutomaton(nil).matchString("anything"); len(got) != 0 {
		t.Fatal(got)
	}
}
