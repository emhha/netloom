package fingerprint

import (
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
)

// Fingerprint is a compiled fingerprint rule with its name, type, source and
// the set of AST rule trees. Rules are in OR relationship: any single matching
// rule tree means the fingerprint is detected.
type Fingerprint struct {
	Name   string
	Type   string // "cms" | "framework" | "server" | ...
	Source string // "webfinger" | "wappalyzer" | "custom"

	// Rules are in OR relationship: matching any rule = fingerprint detected.
	Rules []Node
}

// ACIndex holds per-field Aho-Corasick automata built from all AST leaf nodes.
type ACIndex struct {
	BodyAC   *Automaton
	HeaderAC *Automaton
	TitleAC  *Automaton
	ServerAC *Automaton
}

// compilationResult is the output of compiling a set of webfinger YAML rules.
type compilationResult struct {
	Fingerprints []*Fingerprint
	HashMatcher  *HashMatcher
	ACIndex      *ACIndex
}

// HashMatcher maps int32 favicon hashes to the fingerprints that use them.
// It is separate from the AST path: icon_hash rules never enter the AST.
type HashMatcher struct {
	hashToFingerprints map[int32][]*Fingerprint
}

// NewHashMatcher creates an empty HashMatcher.
func NewHashMatcher() *HashMatcher {
	return &HashMatcher{hashToFingerprints: make(map[int32][]*Fingerprint)}
}

// Add registers hash → fp in the matcher.
func (hm *HashMatcher) Add(hash int32, fp *Fingerprint) {
	hm.hashToFingerprints[hash] = append(hm.hashToFingerprints[hash], fp)
}

// Match returns all fingerprints that match the given favicon hash.
func (hm *HashMatcher) Match(hash int32) []*Fingerprint {
	return hm.hashToFingerprints[hash]
}

// compileWebfingerYAML parses raw YAML bytes and compiles them into
// Fingerprints, a HashMatcher and an ACIndex. Malformed individual rules are
// logged and skipped rather than failing the whole load.
func compileWebfingerYAML(data []byte, source string) (*compilationResult, error) {
	raw, err := parseWebfingerYAML(data)
	if err != nil {
		return nil, fmt.Errorf("compiler.compileWebfingerYAML: %w", err)
	}

	hm := NewHashMatcher()
	var fps []*Fingerprint

	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, cmsName := range names {
		ruleExprs := raw[cmsName]
		fp := &Fingerprint{
			Name:   cmsName,
			Type:   inferType(cmsName),
			Source: source,
		}

		// Build a synthetic hash-matcher fingerprint entry for icon_hash rules.
		var hashFP *Fingerprint

		for _, expr := range ruleExprs {
			node, isHash, hashVal, parseErr := parseRule(expr)
			if parseErr != nil {
				slog.Debug("fingerprint: rule parse error",
					"cms", cmsName,
					"expr", truncate(expr, 80),
					"err", parseErr)
				continue
			}

			if isHash {
				h64, convErr := strconv.ParseInt(hashVal, 10, 64)
				if convErr != nil {
					slog.Debug("fingerprint: invalid icon_hash value",
						"cms", cmsName,
						"val", hashVal)
					continue
				}
				if hashFP == nil {
					hashFP = &Fingerprint{
						Name:   cmsName,
						Type:   fp.Type,
						Source: source,
					}
				}
				hm.Add(int32(h64), hashFP)
				continue
			}

			if node != nil {
				fp.Rules = append(fp.Rules, node)
			}
		}

		if len(fp.Rules) > 0 {
			fps = append(fps, fp)
		}
	}

	acIdx := buildACIndex(fps)

	return &compilationResult{
		Fingerprints: fps,
		HashMatcher:  hm,
		ACIndex:      acIdx,
	}, nil
}

// buildACIndex collects all leaf keywords from a set of fingerprints and builds
// per-field Aho-Corasick automata.
func buildACIndex(fps []*Fingerprint) *ACIndex {
	byField := make(map[Field][]string)

	for _, fp := range fps {
		for _, rule := range fp.Rules {
			var kws []fieldKeyword
			rule.collectKeywords(&kws)
			for _, kw := range kws {
				byField[kw.field] = append(byField[kw.field], kw.keyword)
			}
		}
	}

	return &ACIndex{
		BodyAC:   newAutomaton(byField[FieldBody]),
		HeaderAC: newAutomaton(byField[FieldHeader]),
		TitleAC:  newAutomaton(byField[FieldTitle]),
		ServerAC: newAutomaton(byField[FieldServer]),
	}
}

// inferType guesses the technology category from the CMS name. This is a
// best-effort heuristic; most webfinger rules don't carry explicit type tags.
func inferType(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "nginx") ||
		strings.Contains(lower, "apache") ||
		strings.Contains(lower, "iis") ||
		strings.Contains(lower, "webserver") ||
		strings.Contains(lower, "tomcat") ||
		strings.Contains(lower, "lighttpd"):
		return "server"
	case strings.Contains(lower, "php") ||
		strings.Contains(lower, "asp") ||
		strings.Contains(lower, "ruby") ||
		strings.Contains(lower, "python") ||
		strings.Contains(lower, "java") ||
		strings.Contains(lower, "node"):
		return "language"
	case strings.Contains(lower, "waf") ||
		strings.Contains(lower, "firewall") ||
		strings.Contains(lower, "shield") ||
		strings.Contains(lower, "defender"):
		return "waf"
	case strings.Contains(lower, "cdn") ||
		strings.Contains(lower, "cloudflare") ||
		strings.Contains(lower, "akamai") ||
		strings.Contains(lower, "fastly"):
		return "cdn"
	default:
		return "cms"
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
