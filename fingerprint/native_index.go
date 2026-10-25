package fingerprint

import (
	"encoding/json"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode"
)

type nativePart uint8

const (
	nativeBody nativePart = iota
	nativeHeader
	nativeTitle
	nativeAll
	nativeEHoleHeader
)

type nativeMode uint8

const (
	nativeExact nativeMode = iota
	nativeLower
	nativeFold
	nativeLowerFold
)

type nativeField struct {
	part nativePart
	mode nativeMode
}
type nativeWord struct {
	field nativeField
	word  string
}
type nativeIcon struct {
	md5   bool
	value string
}

func formatIconHash(value int32) string { return strconv.FormatInt(int64(value), 10) }

type nativeGate struct {
	words []nativeWord
	icons []nativeIcon
}

// A gate contains alternatives. At least one must occur for a rule to match.
// An empty gate means no safe prefilter is available, so the rule is evaluated.
type nativeGroup struct {
	patterns []string
	ac       *nativeAutomaton
	anchors  map[string][]int
}
type nativeIndex struct {
	groups map[nativeField]*nativeGroup
	icons  map[nativeIcon][]int
	always []int
	count  int
}

func newNativeIndex(count int) *nativeIndex {
	return &nativeIndex{groups: map[nativeField]*nativeGroup{}, icons: map[nativeIcon][]int{}, count: count}
}

func (idx *nativeIndex) word(field nativeField, word string) nativeWord {
	g := idx.groups[field]
	if g == nil {
		g = &nativeGroup{anchors: map[string][]int{}}
		idx.groups[field] = g
	}
	g.patterns = append(g.patterns, word)
	return nativeWord{field, word}
}

func (idx *nativeIndex) gate(id int, gate nativeGate) {
	if len(gate.words)+len(gate.icons) == 0 {
		idx.always = append(idx.always, id)
		return
	}
	for _, word := range gate.words {
		idx.word(word.field, word.word)
		g := idx.groups[word.field]
		g.anchors[word.word] = append(g.anchors[word.word], id)
	}
	for _, icon := range gate.icons {
		idx.icons[icon] = append(idx.icons[icon], id)
	}
}

func (idx *nativeIndex) compile() {
	for _, g := range idx.groups {
		g.ac = newNativeAutomaton(g.patterns)
		g.patterns = nil
	}
}

// nativeText is local to one captured exchange. Normalization and serialization
// are lazy and shared between both native matchers, never cached in an Engine.
type nativeText struct {
	mc     *MatchContext
	fields map[nativeField]string
}

func newNativeText(mc *MatchContext) *nativeText {
	return &nativeText{mc: mc, fields: map[nativeField]string{}}
}
func (t *nativeText) get(field nativeField) string {
	if text, ok := t.fields[field]; ok {
		return text
	}
	var text string
	if field.mode != nativeExact {
		text = t.get(nativeField{part: field.part})
		switch field.mode {
		case nativeLower:
			text = strings.ToLower(text)
		case nativeFold:
			text = regexFoldText(text)
		case nativeLowerFold:
			text = regexFoldText(t.get(nativeField{part: field.part, mode: nativeLower}))
		}
	} else {
		switch field.part {
		case nativeBody:
			text = string(t.mc.BodyUTF8)
		case nativeHeader:
			text = string(t.mc.HeaderBlob)
		case nativeTitle:
			text = t.mc.Response.Title
		case nativeAll:
			text = t.get(nativeField{part: nativeHeader}) + "\n" + t.get(nativeField{part: nativeBody})
		case nativeEHoleHeader:
			data, _ := json.Marshal(t.mc.Response.Header)
			text = string(data)
		}
	}
	t.fields[field] = text
	return text
}

// Go regex case folding also equates long-s and Kelvin-sign with ASCII s/k.
// strings.ToLower alone is not a sound prefilter for those regex literals.
func regexFoldText(text string) string {
	return strings.Map(func(r rune) rune {
		if r < unicode.MaxASCII {
			if r >= 'A' && r <= 'Z' {
				return r + ('a' - 'A')
			}
			return r
		}
		minimum := r
		for other := unicode.SimpleFold(r); other != r; other = unicode.SimpleFold(other) {
			if other < minimum {
				minimum = other
			}
		}
		return unicode.ToLower(minimum)
	}, text)
}

type nativeScan struct {
	hits       map[nativeField]map[string]bool
	candidates []bool
}

func (idx *nativeIndex) scan(text *nativeText) nativeScan {
	s := nativeScan{hits: make(map[nativeField]map[string]bool, len(idx.groups)), candidates: make([]bool, idx.count)}
	for _, id := range idx.always {
		s.candidates[id] = true
	}
	for field, g := range idx.groups {
		hits := g.ac.matchString(text.get(field))
		s.hits[field] = hits
		for word := range hits {
			for _, id := range g.anchors[word] {
				s.candidates[id] = true
			}
		}
	}
	if text.mc.Response.FaviconHash != 0 {
		for _, id := range idx.icons[nativeIcon{value: formatIconHash(text.mc.Response.FaviconHash)}] {
			s.candidates[id] = true
		}
	}
	if value := text.mc.Response.FaviconMD5; value != "" {
		for _, id := range idx.icons[nativeIcon{md5: true, value: strings.ToLower(value)}] {
			s.candidates[id] = true
		}
	}
	return s
}

func (s nativeScan) contains(word nativeWord) bool { return s.hits[word.field][word.word] }

func (s nativeScan) all(words []nativeWord) bool {
	for _, word := range words {
		if !s.contains(word) {
			return false
		}
	}
	return true
}

func longestWord(words []nativeWord) nativeWord {
	best := words[0]
	for _, word := range words[1:] {
		if len(word.word) > len(best.word) {
			best = word
		}
	}
	return best
}

// requiredRegexLiterals is conservative: it only extracts literals from mandatory
// concatenations, captures and repetitions. Alternations/optional branches fall
// back to regex evaluation; they can never hide a genuine match.
func requiredRegexLiterals(pattern *regexp.Regexp, field nativeField) []nativeWord {
	parsed, err := syntax.Parse(pattern.String(), syntax.Perl)
	if err != nil {
		return nil
	}
	var words []nativeWord
	seen := map[nativeWord]bool{}
	var walk func(*syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		switch r.Op {
		case syntax.OpLiteral:
			if len(r.Rune) == 0 {
				return
			}
			// A regex replacement rune can also consume an invalid UTF-8 byte;
			// its encoded byte sequence is not a necessary substring in that case.
			for _, runeValue := range r.Rune {
				if runeValue == unicode.ReplacementChar {
					return
				}
			}
			word := nativeWord{field: field, word: string(r.Rune)}
			if r.Flags&syntax.FoldCase != 0 {
				word.word = regexFoldText(word.word)
				if field.mode == nativeLower {
					word.field.mode = nativeLowerFold
				} else {
					word.field.mode = nativeFold
				}
			}
			if !seen[word] {
				words = append(words, word)
				seen[word] = true
			}
		case syntax.OpCapture, syntax.OpPlus:
			walk(r.Sub[0])
		case syntax.OpRepeat:
			if r.Min > 0 {
				walk(r.Sub[0])
			}
		case syntax.OpConcat:
			for _, child := range r.Sub {
				walk(child)
			}
		}
	}
	walk(parsed)
	return words
}
