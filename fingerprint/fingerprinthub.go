package fingerprint

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/emhha/netloom/httpdata"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type hubTemplate struct {
	ID   string `json:"id"`
	Info struct {
		Name string `json:"name"`
	} `json:"info"`
	HTTP []hubProbe `json:"http"`
}

type hubProbe struct {
	Method            string            `json:"method"`
	Path              []string          `json:"path"`
	Headers           map[string]string `json:"headers"`
	Body              string            `json:"body"`
	Raw               []string          `json:"raw"`
	MatchersCondition string            `json:"matchers-condition"`
	Matchers          []hubMatcher      `json:"matchers"`
	Extractors        []hubExtractor    `json:"extractors"`
}

type hubExtractor struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Part     string   `json:"part"`
	Regex    []string `json:"regex"`
	Group    *int     `json:"group"`
	patterns []*regexp.Regexp
}

type hubMatcher struct {
	Type            string   `json:"type"`
	Part            string   `json:"part"`
	Words           []string `json:"words"`
	Regex           []string `json:"regex"`
	Hash            []string `json:"hash"`
	Condition       string   `json:"condition"`
	CaseInsensitive bool     `json:"case-insensitive"`
	Negative        bool     `json:"negative"`
	patterns        []*regexp.Regexp
	words           []nativeWord
	icons           []nativeIcon
	regexWords      [][]nativeWord
}

// FingerprintHubMatcher implements passive matching of native v4 templates.
// Probe paths constrain the supplied response URL; templates never cause I/O.
type FingerprintHubMatcher struct {
	rules         []hubTemplate
	index         *nativeIndex
	constraintIDs [][]int
	probeIDs      [][]int
	constraints   int
}

func LoadFingerprintHubJSON(data []byte) (*FingerprintHubMatcher, error) {
	var rules []hubTemplate
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("fingerprinthub: %w", err)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("fingerprinthub: empty template collection")
	}
	for ti := range rules {
		t := &rules[ti]
		if t.ID == "" || len(t.HTTP) == 0 {
			return nil, fmt.Errorf("fingerprinthub: template %d requires id and http", ti)
		}
		for pi := range t.HTTP {
			probe := &t.HTTP[pi]
			if !validCondition(probe.MatchersCondition) || len(probe.Matchers) == 0 {
				return nil, fmt.Errorf("fingerprinthub: %s: invalid matcher group", t.ID)
			}
			for mi := range probe.Matchers {
				if err := compileHubMatcher(&probe.Matchers[mi]); err != nil {
					return nil, fmt.Errorf("fingerprinthub: %s probe %d matcher %d: %w", t.ID, pi, mi, err)
				}
			}
			for ei := range probe.Extractors {
				x := &probe.Extractors[ei]
				if x.Type != "regex" || (x.Part != "" && x.Part != "header" && x.Part != "body") {
					return nil, fmt.Errorf("fingerprinthub: %s: unsupported extractor", t.ID)
				}
				for _, s := range x.Regex {
					re, err := regexp.Compile(extendedPattern(s))
					if err != nil {
						return nil, fmt.Errorf("fingerprinthub: %s: extractor: %w", t.ID, err)
					}
					x.patterns = append(x.patterns, re)
				}
			}
		}
	}
	m := &FingerprintHubMatcher{rules: rules}
	m.compileIndex()
	return m, nil
}

func hubNativeField(part string, insensitive bool) nativeField {
	field := nativeField{}
	switch part {
	case "header", "all_headers":
		field.part = nativeHeader
	case "title":
		field.part = nativeTitle
	case "all":
		field.part = nativeAll
	}
	if insensitive {
		field.mode = nativeLower
	}
	return field
}

func (m *hubMatcher) compileGate(idx *nativeIndex) nativeGate {
	field := hubNativeField(m.Part, m.CaseInsensitive)
	gate := nativeGate{}
	switch m.Type {
	case "word":
		for _, word := range m.Words {
			if m.CaseInsensitive {
				word = strings.ToLower(word)
			}
			m.words = append(m.words, idx.word(field, word))
		}
		gate.words = m.words
		if m.Condition == "and" {
			gate.words = []nativeWord{longestWord(m.words)}
		}
	case "regex":
		unfiltered := false
		for _, pattern := range m.patterns {
			words := requiredRegexLiterals(pattern, field)
			for _, word := range words {
				idx.word(word.field, word.word)
			}
			m.regexWords = append(m.regexWords, words)
			if len(words) > 0 {
				gate.words = append(gate.words, longestWord(words))
			} else if m.Condition != "and" {
				unfiltered = true
			}
		}
		if m.Condition == "and" && len(gate.words) > 1 {
			gate.words = []nativeWord{longestWord(gate.words)}
		}
		if unfiltered {
			gate = nativeGate{}
		}
	case "favicon":
		for _, hash := range m.Hash {
			m.icons = append(m.icons, nativeIcon{md5: len(hash) == 32, value: strings.ToLower(hash)})
		}
		gate.icons = m.icons
	}
	if m.Negative {
		return nativeGate{}
	}
	return gate
}

func (m *FingerprintHubMatcher) compileIndex() {
	count := 0
	for _, t := range m.rules {
		count += len(t.HTTP)
	}
	m.index = newNativeIndex(count)
	m.constraintIDs = make([][]int, len(m.rules))
	m.probeIDs = make([][]int, len(m.rules))
	constraintMap := map[string]int{}
	id := 0
	for ti := range m.rules {
		t := &m.rules[ti]
		for pi := range t.HTTP {
			p := &t.HTTP[pi]
			// Requests sharing a constraint evaluate it only once per exchange.
			data, _ := json.Marshal(struct {
				Method  string
				Path    []string
				Headers map[string]string
				Body    string
				Raw     []string
			}{p.Method, p.Path, p.Headers, p.Body, p.Raw})
			key := string(data)
			constraint, ok := constraintMap[key]
			if !ok {
				constraint = len(constraintMap)
				constraintMap[key] = constraint
			}
			m.constraintIDs[ti] = append(m.constraintIDs[ti], constraint)
			m.probeIDs[ti] = append(m.probeIDs[ti], id)
			gate := nativeGate{}
			unfiltered := false
			for mi := range p.Matchers {
				candidate := p.Matchers[mi].compileGate(m.index)
				if p.MatchersCondition == "and" {
					if len(candidate.words)+len(candidate.icons) > 0 && (len(gate.words)+len(gate.icons) == 0 || len(candidate.words)+len(candidate.icons) < len(gate.words)+len(gate.icons)) {
						gate = candidate
					}
				} else {
					if len(candidate.words)+len(candidate.icons) == 0 {
						unfiltered = true
					}
					gate.words = append(gate.words, candidate.words...)
					gate.icons = append(gate.icons, candidate.icons...)
				}
			}
			if unfiltered {
				gate = nativeGate{}
			}
			m.index.gate(id, gate)
			id++
		}
	}
	m.constraints = len(constraintMap)
	m.index.compile()
}

func validCondition(s string) bool { return s == "" || s == "or" || s == "and" }

func compileHubMatcher(m *hubMatcher) error {
	if !validCondition(m.Condition) {
		return fmt.Errorf("unsupported condition %q", m.Condition)
	}
	switch m.Part {
	case "", "body", "header", "all_headers", "title", "all":
	default:
		return fmt.Errorf("unsupported part %q", m.Part)
	}
	n := 0
	switch m.Type {
	case "word":
		n = len(m.Words)
		for _, s := range m.Words {
			if s == "" {
				return fmt.Errorf("empty word")
			}
		}
	case "regex":
		n = len(m.Regex)
		for _, s := range m.Regex {
			if s == "" {
				return fmt.Errorf("empty regex")
			}
			if m.CaseInsensitive {
				s = "(?i)" + s
			}
			p, err := regexp.Compile(s)
			if err != nil {
				return err
			}
			m.patterns = append(m.patterns, p)
		}
	case "favicon":
		n = len(m.Hash)
		for i, s := range m.Hash {
			if len(s) == 32 {
				if _, err := hex.DecodeString(s); err != nil {
					return fmt.Errorf("invalid favicon MD5")
				}
			} else {
				value, err := strconv.ParseInt(s, 10, 32)
				if err != nil {
					return fmt.Errorf("invalid favicon mmh3 hash")
				}
				m.Hash[i] = strconv.FormatInt(value, 10)
			}
		}
	default:
		return fmt.Errorf("unsupported matcher type %q", m.Type)
	}
	if n == 0 {
		return fmt.Errorf("empty %s matcher", m.Type)
	}
	return nil
}

func (m *FingerprintHubMatcher) Len() int { return len(m.rules) }

func (m *FingerprintHubMatcher) match(ctx context.Context, mc *MatchContext) []Artifact {
	return m.matchPrepared(ctx, mc, newNativeText(mc))
}

func (m *FingerprintHubMatcher) matchPrepared(ctx context.Context, mc *MatchContext, text *nativeText) []Artifact {
	if ctx.Err() != nil {
		return nil
	}
	scan := m.index.scan(text)
	requests := make([]int8, m.constraints)
	var out []Artifact
	for ti := range m.rules {
		if ctx.Err() != nil {
			break
		}
		t := &m.rules[ti]
		for pi := range t.HTTP {
			if !scan.candidates[m.probeIDs[ti][pi]] {
				continue
			}
			p := &t.HTTP[pi]
			// A captured response is not evidence for a modified/active probe.
			constraint := m.constraintIDs[ti][pi]
			if requests[constraint] == 0 {
				requests[constraint] = -1
				if p.matchesRequest(mc.Request, mc.Response.URL) {
					requests[constraint] = 1
				}
			}
			if requests[constraint] < 0 {
				continue
			}
			matched := p.MatchersCondition == "and"
			for _, matcher := range p.Matchers {
				hit := matcher.matchPrepared(mc, text, scan)
				if p.MatchersCondition == "and" {
					matched = matched && hit
					if !matched {
						break
					}
				} else {
					matched = matched || hit
					if matched {
						break
					}
				}
			}
			if matched {
				name := t.Info.Name
				if name == "" {
					name = t.ID
				}
				version := ""
				for _, extractor := range p.Extractors {
					if extractor.Name == "version" {
						version = extractor.extract(mc)
						if version != "" {
							break
						}
					}
				}
				out = appendArtifact(out, Artifact{Name: name, Version: version, Type: inferType(name), Confidence: 100, Source: "fingerprinthub"})
				break
			}
		}
	}
	return out
}

// extendedPattern implements a leading (?x) without another regex dependency.
func extendedPattern(pattern string) string {
	if !strings.HasPrefix(pattern, "(?x)") {
		return pattern
	}
	var out strings.Builder
	escaped, inClass, comment := false, false, false
	for _, r := range strings.TrimPrefix(pattern, "(?x)") {
		if comment {
			if r == '\n' {
				comment = false
			}
			continue
		}
		if escaped {
			out.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			out.WriteRune(r)
			escaped = true
			continue
		}
		if r == '[' {
			inClass = true
		}
		if r == ']' {
			inClass = false
		}
		if !inClass {
			if r == '#' {
				comment = true
				continue
			}
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				continue
			}
		}
		out.WriteRune(r)
	}
	return out.String()
}

func (x hubExtractor) extract(mc *MatchContext) string {
	field := string(mc.BodyUTF8)
	if x.Part == "header" {
		field = string(mc.HeaderBlob)
	}
	for _, p := range x.patterns {
		groups := p.FindStringSubmatch(field)
		if len(groups) == 0 {
			continue
		}
		group := 1
		if x.Group != nil {
			group = *x.Group
		} else if len(groups) == 1 {
			group = 0
		}
		if group >= 0 && group < len(groups) {
			return groups[group]
		}
	}
	return ""
}

func (p hubProbe) matchesRequest(req *httpdata.Request, responseURL string) bool {
	if len(p.Raw) > 0 {
		return false
	}
	method := "GET"
	if req != nil {
		if req.Method != "" {
			method = req.Method
		}
		if req.URL != "" {
			responseURL = req.URL
		}
	} else if p.Body != "" || len(p.Headers) > 0 || p.Method != "" && p.Method != "GET" {
		return false
	}
	if p.Method != "" && p.Method != method {
		return false
	}
	if p.Body != "" && (req == nil || p.Body != string(req.Body)) {
		return false
	}
	for key, want := range p.Headers {
		found := false
		if req != nil {
			for actual, values := range req.Header {
				if strings.EqualFold(actual, key) {
					for _, value := range values {
						if value == want {
							found = true
						}
					}
				}
			}
		}
		if !found {
			return false
		}
	}
	return hubPathMatches(p.Path, responseURL)
}

func hubPathMatches(paths []string, rawURL string) bool {
	if len(paths) == 0 {
		return true
	}
	var target *url.URL
	if rawURL != "" {
		var err error
		target, err = url.Parse(rawURL)
		if err != nil || target.Host == "" {
			return false
		}
	}
	for _, path := range paths {
		// With no URL, only a generic homepage probe can match passively.
		if target == nil {
			if path == "{{BaseURL}}/" || path == "{{BaseURL}}" || path == "/" {
				return true
			}
			continue
		}
		base := target.Scheme + "://" + target.Host
		expanded := strings.ReplaceAll(strings.ReplaceAll(path, "{{BaseURL}}", base), "{{RootURL}}", base)
		if strings.Contains(expanded, "{{") {
			continue
		}
		u, err := url.Parse(expanded)
		if err != nil {
			continue
		}
		u = target.ResolveReference(u)
		a, b := u.EscapedPath(), target.EscapedPath()
		if a == "" {
			a = "/"
		}
		if b == "" {
			b = "/"
		}
		if strings.EqualFold(u.Scheme, target.Scheme) && strings.EqualFold(u.Host, target.Host) && a == b && u.RawQuery == target.RawQuery {
			return true
		}
	}
	return false
}

func (m hubMatcher) matchPrepared(mc *MatchContext, text *nativeText, scan nativeScan) bool {
	if m.Negative && mc.Response.BodyTruncated && (m.Part == "" || m.Part == "body" || m.Part == "all") {
		return false
	}
	and := m.Condition == "and"
	matched, known := and, false
	add := func(hit bool) bool {
		known = true
		if and {
			matched = matched && hit
			return !hit
		}
		matched = matched || hit
		return hit
	}
	switch m.Type {
	case "word":
		for _, word := range m.words {
			if add(scan.contains(word)) {
				break
			}
		}
	case "regex":
		field := text.get(hubNativeField(m.Part, m.CaseInsensitive))
		for i, pattern := range m.patterns {
			if add(scan.all(m.regexWords[i]) && pattern.MatchString(field)) {
				break
			}
		}
	case "favicon":
		for _, icon := range m.icons {
			if icon.md5 {
				if mc.Response.FaviconMD5 != "" && add(strings.EqualFold(icon.value, mc.Response.FaviconMD5)) {
					break
				}
			} else if mc.Response.FaviconHash != 0 && add(icon.value == formatIconHash(mc.Response.FaviconHash)) {
				break
			}
		}
	}
	if !known {
		return false
	}
	if m.Negative {
		return !matched
	}
	return matched
}
