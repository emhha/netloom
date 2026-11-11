// Package ac provides byte-oriented Aho-Corasick keyword-set matching.
// It adapts github.com/cloudflare/ahocorasick without implementing an automaton.
package ac

import "github.com/cloudflare/ahocorasick"

// Matcher matches case-sensitive byte strings, including invalid UTF-8 and NUL.
// Its zero value matches nothing. After New returns, its dictionary is fixed and
// Search and Match are safe for concurrent use. Each Search result is independent.
type Matcher struct {
	engine   *ahocorasick.Matcher
	keywords []string // normalized unique dictionary, not the caller's slice
	indices  []int    // normalized index -> first original keyword index
}

// New compiles keywords. Empty keywords are ignored, and duplicate strings use
// only their first index in keywords. The input slice is not retained.
func New(keywords []string) *Matcher {
	m := &Matcher{}
	seen := make(map[string]struct{}, len(keywords))
	for index, keyword := range keywords {
		if keyword == "" {
			continue
		}
		if _, exists := seen[keyword]; exists {
			continue
		}
		seen[keyword] = struct{}{}
		m.keywords = append(m.keywords, keyword)
		m.indices = append(m.indices, index)
	}
	if len(m.keywords) > 0 {
		m.engine = ahocorasick.NewStringMatcher(m.keywords)
	}
	return m
}

// Match synchronously calls hit with the original index of each matching unique
// keyword, at most once per call. Overlaps and suffix matches are included, but
// callback order and occurrence counts are not part of the contract. Duplicate
// keywords report only their first original index. A nil hit is a no-op.
// The caller must synchronize any shared callback state.
func (m *Matcher) Match(text []byte, hit func(index int)) {
	if hit == nil {
		return
	}
	for _, index := range m.matches(text) {
		hit(m.indices[index])
	}
}

// Search returns a non-nil set of the keywords occurring in text. Empty and
// duplicate keywords are ignored. The caller may freely modify the result.
func (m *Matcher) Search(text []byte) map[string]struct{} {
	hits := make(map[string]struct{})
	for _, index := range m.matches(text) {
		hits[m.keywords[index]] = struct{}{}
	}
	return hits
}

func (m *Matcher) matches(text []byte) []int {
	if m == nil || m.engine == nil || len(text) == 0 {
		return nil
	}
	// Never mix the upstream non-thread-safe Match method with this path.
	return m.engine.MatchThreadSafe(text)
}
