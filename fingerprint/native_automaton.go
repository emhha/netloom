package fingerprint

import "sort"

// nativeAutomaton is a compact double-array representation of the existing AC
// trie. Transition checks use arrays instead of a Go map lookup per input byte.
// It retains sparse transitions/failure links rather than a 256-column DFA.
type nativeAutomaton struct {
	base   []int
	check  []int // parent slot + 1; zero means unoccupied
	fail   []int
	output [][]string
	root   [256]int
}

func newNativeAutomaton(patterns []string) *nativeAutomaton {
	trie := newAutomaton(patterns)
	a := &nativeAutomaton{}
	ensure := func(size int) {
		if size <= len(a.base) {
			return
		}
		add := size - len(a.base)
		a.base = append(a.base, make([]int, add)...)
		a.check = append(a.check, make([]int, add)...)
		a.fail = append(a.fail, make([]int, add)...)
		a.output = append(a.output, make([][]string, add)...)
	}
	ensure(256)
	a.check[0] = -1
	slots := make([]int, len(trie.goto_))
	queue := []int{0}
	firstFree := 1
	for head := 0; head < len(queue); head++ {
		old := queue[head]
		slot := slots[old]
		a.output[slot] = trie.output[old]
		if len(trie.goto_[old]) == 0 {
			continue
		}
		keys := make([]int, 0, len(trie.goto_[old]))
		for b := range trie.goto_[old] {
			keys = append(keys, int(b))
		}
		sort.Ints(keys)
		for {
			ensure(firstFree + 1)
			if a.check[firstFree] == 0 {
				break
			}
			firstFree++
		}
		free := firstFree
		var offset int
		for {
			offset = free - keys[0]
			ensure(offset + keys[len(keys)-1] + 1)
			available := true
			for _, key := range keys {
				if a.check[offset+key] != 0 {
					available = false
					break
				}
			}
			if available {
				break
			}
			free++
			for {
				ensure(free + 1)
				if a.check[free] == 0 {
					break
				}
				free++
			}
		}
		a.base[slot] = offset
		for _, key := range keys {
			child := trie.goto_[old][byte(key)]
			next := offset + key
			a.check[next] = slot + 1
			slots[child] = next
			queue = append(queue, child)
			if old == 0 {
				a.root[key] = next
			}
		}
	}
	for old, slot := range slots {
		a.fail[slot] = slots[trie.fail[old]]
	}
	return a
}

func (a *nativeAutomaton) matchString(text string) map[string]bool {
	var hits map[string]bool
	state := 0
	for i := 0; i < len(text); i++ {
		b := int(text[i])
		for {
			if state == 0 {
				state = a.root[b]
				break
			}
			next := a.base[state] + b
			if next >= 0 && next < len(a.check) && a.check[next] == state+1 {
				state = next
				break
			}
			state = a.fail[state]
		}
		for _, pattern := range a.output[state] {
			if hits == nil {
				hits = map[string]bool{}
			}
			hits[pattern] = true
		}
	}
	return hits
}
