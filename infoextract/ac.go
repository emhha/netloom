// Package infoextract implements two-phase (Aho-Corasick + regex) sensitive
// information extraction from HTTP responses, modelled after HaE.
package infoextract

// automaton is a minimal Aho-Corasick automaton built over a set of byte-string
// keywords. It uses a slice-based trie with failure links (BFS construction).
// Only Search is exposed; the automaton is immutable after Build.
type automaton struct {
	// goto_[state][byte] = next state; 0 = root; -1 = not set
	goto_ []map[byte]int
	// fail[state] = failure link state
	fail []int
	// output[state] = keywords that end at this state (via match or suffix chain)
	output [][]string
}

// newAutomaton builds an Aho-Corasick automaton from the given keywords.
// Duplicate keywords are silently ignored. An empty keyword slice returns a
// no-op automaton (Search always returns an empty set).
func newAutomaton(keywords []string) *automaton {
	a := &automaton{}
	a.goto_ = []map[byte]int{make(map[byte]int)} // root = 0
	a.fail = []int{0}
	a.output = [][]string{nil}

	// Phase 1: build goto function
	for _, kw := range keywords {
		if len(kw) == 0 {
			continue
		}
		cur := 0
		for i := 0; i < len(kw); i++ {
			b := kw[i]
			if next, ok := a.goto_[cur][b]; ok {
				cur = next
			} else {
				newState := len(a.goto_)
				a.goto_ = append(a.goto_, make(map[byte]int))
				a.fail = append(a.fail, 0)
				a.output = append(a.output, nil)
				a.goto_[cur][b] = newState
				cur = newState
			}
		}
		a.output[cur] = append(a.output[cur], kw)
	}

	// Phase 2: build failure links via BFS
	queue := make([]int, 0, 64)
	for _, s := range a.goto_[0] {
		a.fail[s] = 0
		queue = append(queue, s)
	}
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		for b, u := range a.goto_[r] {
			// follow failure links from r to find suffix match for b
			f := a.fail[r]
			for f != 0 {
				if _, ok := a.goto_[f][b]; ok {
					break
				}
				f = a.fail[f]
			}
			if next, ok := a.goto_[f][b]; ok && next != u {
				a.fail[u] = next
			} else {
				a.fail[u] = 0
			}
			// inherit output from failure link
			a.output[u] = append(a.output[u], a.output[a.fail[u]]...)
			queue = append(queue, u)
		}
	}

	return a
}

// Search scans text and returns all keywords (from the set passed to Build)
// that appear as substrings. The returned set de-duplicates matches.
func (a *automaton) Search(text []byte) map[string]struct{} {
	hits := make(map[string]struct{})
	if len(a.goto_) == 0 {
		return hits
	}
	state := 0
	for _, b := range text {
		for state != 0 {
			if _, ok := a.goto_[state][b]; ok {
				break
			}
			state = a.fail[state]
		}
		if next, ok := a.goto_[state][b]; ok {
			state = next
		}
		for _, kw := range a.output[state] {
			hits[kw] = struct{}{}
		}
	}
	return hits
}
