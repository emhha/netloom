// Package infoextract implements two-phase (Aho-Corasick + regex) sensitive
// information extraction from HTTP responses, modelled after HaE.
package infoextract

import "github.com/emhha/netloom/ac"

// automaton preserves compatibility with package-local callers and tests.
// The implementation lives in the shared ac package.
type automaton = ac.Matcher

func newAutomaton(keywords []string) *automaton {
	return ac.New(keywords)
}
