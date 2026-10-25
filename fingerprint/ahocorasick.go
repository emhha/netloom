package fingerprint

// Automaton is a compiled Aho-Corasick automaton for multi-pattern substring
// search. It supports case-sensitive matching over byte strings.
//
// Construction: O(total pattern length).
// Searching:    O(text length + number of matches).
type Automaton struct {
	// goto table: goto[state][byte] = next state
	// state 0 is the root (failure state for unmatched input at root = 0)
	goto_  []map[byte]int
	fail   []int
	output [][]string // patterns that end at each state
}

// newAutomaton builds an Aho-Corasick automaton from the given set of patterns.
// Duplicate patterns are deduplicated. Empty patterns are ignored.
func newAutomaton(patterns []string) *Automaton {
	a := &Automaton{}
	a.goto_ = []map[byte]int{make(map[byte]int)}
	a.fail = []int{0}
	a.output = [][]string{nil}

	// Phase 1: build goto table (trie insertion).
	seen := make(map[string]struct{}, len(patterns))
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}

		cur := 0
		for i := 0; i < len(p); i++ {
			b := p[i]
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
		a.output[cur] = append(a.output[cur], p)
	}

	// Phase 2: compute failure links (BFS from root's children).
	queue := make([]int, 0, len(a.goto_))
	for _, s := range a.goto_[0] {
		a.fail[s] = 0
		queue = append(queue, s)
	}
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		for b, s := range a.goto_[r] {
			queue = append(queue, s)
			// Follow fail links from r's parent to find s's fail state.
			f := a.fail[r]
			for f != 0 {
				if _, ok := a.goto_[f][b]; ok {
					break
				}
				f = a.fail[f]
			}
			if next, ok := a.goto_[f][b]; ok && next != s {
				a.fail[s] = next
			} else {
				a.fail[s] = 0
			}
			// Merge output of fail state.
			a.output[s] = append(a.output[s], a.output[a.fail[s]]...)
		}
	}

	return a
}

// Match returns the set of patterns found in text.
func (a *Automaton) Match(text []byte) map[string]bool {
	if len(a.goto_) == 0 {
		return nil
	}
	result := make(map[string]bool)
	cur := 0
	for _, b := range text {
		// Follow fail links until we find a transition or reach root.
		for cur != 0 {
			if _, ok := a.goto_[cur][b]; ok {
				break
			}
			cur = a.fail[cur]
		}
		if next, ok := a.goto_[cur][b]; ok {
			cur = next
		}
		for _, p := range a.output[cur] {
			result[p] = true
		}
	}
	return result
}

// MatchString is a convenience wrapper over Match.
func (a *Automaton) MatchString(text string) map[string]bool {
	return a.Match([]byte(text))
}
