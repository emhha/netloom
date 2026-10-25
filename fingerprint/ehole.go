package fingerprint

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// EHoleRule is the native EHole fingerprint format. Keywords within a rule
// are ANDed; separate rules for a product are alternatives.
type EHoleRule struct {
	CMS      string   `json:"cms"`
	Method   string   `json:"method"`
	Location string   `json:"location"`
	Keyword  []string `json:"keyword"`
}

type eholeRule struct {
	EHoleRule
	patterns   []*regexp.Regexp
	hashes     []int32
	words      []nativeWord
	regexWords [][]nativeWord
}

// EHoleMatcher matches captured responses without issuing requests.
type EHoleMatcher struct {
	rules []eholeRule
	index *nativeIndex
}

func LoadEHoleJSON(data []byte) (*EHoleMatcher, error) {
	var file struct {
		Fingerprint []EHoleRule `json:"fingerprint"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("ehole: %w", err)
	}
	if len(file.Fingerprint) == 0 {
		return nil, fmt.Errorf("ehole: empty fingerprint collection")
	}
	m := &EHoleMatcher{index: newNativeIndex(len(file.Fingerprint))}
	for i, raw := range file.Fingerprint {
		if strings.TrimSpace(raw.CMS) == "" || len(raw.Keyword) == 0 {
			return nil, fmt.Errorf("ehole: rule %d has no name or patterns", i)
		}
		r := eholeRule{EHoleRule: raw}
		if raw.Location != "body" && raw.Location != "header" && raw.Location != "title" {
			return nil, fmt.Errorf("ehole: rule %d: unsupported location %q", i, raw.Location)
		}
		for _, word := range raw.Keyword {
			if word == "" {
				return nil, fmt.Errorf("ehole: rule %d: empty keyword", i)
			}
			switch raw.Method {
			case "keyword":
			case "regular":
				pattern, err := regexp.Compile(word)
				if err != nil {
					return nil, fmt.Errorf("ehole: rule %d: %w", i, err)
				}
				r.patterns = append(r.patterns, pattern)
			case "faviconhash":
				value, err := strconv.ParseInt(word, 10, 32)
				if err != nil {
					return nil, fmt.Errorf("ehole: rule %d: invalid favicon hash %q", i, word)
				}
				r.hashes = append(r.hashes, int32(value))
			default:
				return nil, fmt.Errorf("ehole: rule %d: unsupported method %q", i, raw.Method)
			}
		}
		field := nativeField{part: eholePart(raw.Location)}
		gate := nativeGate{}
		switch raw.Method {
		case "keyword":
			field.mode = nativeLower
			for _, word := range raw.Keyword {
				r.words = append(r.words, m.index.word(field, strings.ToLower(word)))
			}
			gate.words = []nativeWord{longestWord(r.words)}
		case "regular":
			for _, pattern := range r.patterns {
				words := requiredRegexLiterals(pattern, field)
				for _, word := range words {
					m.index.word(word.field, word.word)
				}
				r.regexWords = append(r.regexWords, words)
				if len(words) > 0 {
					gate.words = append(gate.words, longestWord(words))
				}
			}
			if len(gate.words) > 1 {
				gate.words = []nativeWord{longestWord(gate.words)}
			}
		case "faviconhash":
			for _, hash := range r.hashes {
				gate.icons = append(gate.icons, nativeIcon{value: formatIconHash(hash)})
			}
		}
		m.index.gate(i, gate)
		m.rules = append(m.rules, r)
	}
	m.index.compile()
	return m, nil
}

func (m *EHoleMatcher) Len() int { return len(m.rules) }

func (m *EHoleMatcher) match(ctx context.Context, mc *MatchContext) []Artifact {
	return m.matchPrepared(ctx, mc, newNativeText(mc))
}

func eholePart(location string) nativePart {
	switch location {
	case "header":
		return nativeEHoleHeader
	case "title":
		return nativeTitle
	default:
		return nativeBody
	}
}

func (m *EHoleMatcher) matchPrepared(ctx context.Context, mc *MatchContext, text *nativeText) []Artifact {
	if ctx.Err() != nil {
		return nil
	}
	scan := m.index.scan(text)
	var out []Artifact
	for id := range m.rules {
		if ctx.Err() != nil {
			break
		}
		if !scan.candidates[id] {
			continue
		}
		r := &m.rules[id]
		matched := true
		switch r.Method {
		case "keyword":
			for _, word := range r.words {
				if !scan.contains(word) {
					matched = false
					break
				}
			}
		case "regular":
			for i, pattern := range r.patterns {
				if !scan.all(r.regexWords[i]) || !pattern.MatchString(text.get(nativeField{part: eholePart(r.Location)})) {
					matched = false
					break
				}
			}
		case "faviconhash":
			matched = false
			if mc.Response.FaviconHash != 0 {
				for _, value := range r.hashes {
					if mc.Response.FaviconHash == value {
						matched = true
						break
					}
				}
			}
		}
		if matched {
			out = appendArtifact(out, Artifact{Name: r.CMS, Type: inferType(r.CMS), Confidence: 100, Source: "ehole"})
		}
	}
	return out
}
