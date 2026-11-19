package infoextract

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/emhha/netloom/ac"
)

const headOnlySize = 100 * 1024 // 100 KB

// Rule describes a single matching rule for sensitive information.
type Rule struct {
	Name        string   // unique identifier; same-name rule overwrites earlier one
	Pattern     string   // RE2 regular expression
	Color       string   // UI highlight: red/orange/yellow/green/blue/gray
	Scope       string   // "body" | "header" | "all"
	Sensitivity string   // "high" | "medium" | "low"
	Triggers    []string // AC keywords; nil/empty = fallback (always runs)
	Category    string   // "" = universal | "special" = JS/JSON only
}

// finding is a single extraction result.
type finding struct {
	RuleName    string
	Value       string // full regex match
	Capture     string // capture group 1, if present
	Sensitivity string
	Color       string
	Scope       string // "body" | "header"
}

// compiledRule is an internal, ready-to-run form of a Rule.
type compiledRule struct {
	Rule
	re         *regexp.Regexp
	triggerSet map[string]struct{}
}

// extractor is the two-phase sensitive-information extraction engine.
// It is safe for concurrent use and must not be copied after first use.
type extractor struct {
	mu       sync.RWMutex
	rules    []compiledRule // ordered, immutable snapshots; published together with the AC index
	ac       *ac.Matcher    // nil when no triggers exist (all fallback rules)
	identity uint64
}

var nextSnapshotIdentity atomic.Uint64

// snapshot is an immutable ruleset and its matching AC index. It is safe to
// copy and use concurrently; later addRule calls do not change its results.
// Its zero value is an empty ruleset with identity zero.
type snapshot struct {
	rules    []compiledRule
	ac       *ac.Matcher
	identity uint64
}

// snapshot captures the rules, AC index and identity under the same lock.
// Even a zero-value extractor receives its own nonzero initial identity.
func (e *extractor) snapshot() snapshot {
	e.mu.RLock()
	if e.identity != 0 {
		s := snapshot{rules: e.rules, ac: e.ac, identity: e.identity}
		e.mu.RUnlock()
		return s
	}
	e.mu.RUnlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.identity == 0 {
		e.identity = nextSnapshotIdentity.Add(1)
	}
	return snapshot{rules: e.rules, ac: e.ac, identity: e.identity}
}

func (e *extractor) loadDefaults() {
	for _, r := range defaultRules() {
		// Built-in rule patterns are verified by tests.
		_ = e.addRuleLocked(r)
	}
	e.rebuildAC()
}

// extract scans body and header, applying content-type routing.
// Binary content-types skip body matching; response headers are still analyzed.
func (e *extractor) extract(
	body []byte,
	header map[string][]string,
	contentType string,
) []finding {
	return e.snapshot().extract(body, header, contentType)
}

// extract scans both body and headers using this one immutable
// generation, with the same routing and result semantics as extractor.
func (s snapshot) extract(
	body []byte,
	header map[string][]string,
	contentType string,
) []finding {
	ct := strings.ToLower(contentType)
	// strip parameters (e.g. "text/html; charset=utf-8")
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}

	var findings []finding
	if !isBinary(ct) {
		findings = append(findings, s.extractBody(body, ct)...)
	}
	findings = append(findings, s.extractScope(serializeHeader(header), "header")...)
	return findings
}

// addRule compiles and appends a single rule, overwriting any existing rule
// with the same Name. Returns an error if the Pattern is not valid RE2.
// On error the internal state is not modified.
func (e *extractor) addRule(rule Rule) error {
	cr, err := compile(rule)
	if err != nil {
		return fmt.Errorf("infoextract.AddRule: %w", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.upsertLocked(cr)
	e.rebuildAC()
	return nil
}

// ─── internal ────────────────────────────────────────────────────────────────

// addRuleLocked compiles and upserts a rule. Must be called with mu held (write).
func (e *extractor) addRuleLocked(r Rule) error {
	cr, err := compile(r)
	if err != nil {
		return err
	}
	e.upsertLocked(cr)
	return nil
}

// upsertLocked inserts or replaces by Name. Must be called with mu held (write).
func (e *extractor) upsertLocked(cr compiledRule) {
	// Readers retain the slice after releasing mu. Never mutate its backing
	// array: publish a new rules snapshot under the same lock as its matcher.
	rules := make([]compiledRule, len(e.rules), len(e.rules)+1)
	copy(rules, e.rules)
	for i, existing := range rules {
		if existing.Name == cr.Name {
			rules[i] = cr
			e.rules = rules
			return
		}
	}
	e.rules = append(rules, cr)
}

// rebuildAC rebuilds the Aho-Corasick automaton from current rules.
// Must be called with mu held (write), or during single-threaded init.
func (e *extractor) rebuildAC() {
	e.identity = nextSnapshotIdentity.Add(1)
	var keywords []string
	seen := make(map[string]struct{})
	for _, cr := range e.rules {
		for _, t := range cr.Triggers {
			if _, dup := seen[t]; !dup {
				seen[t] = struct{}{}
				keywords = append(keywords, t)
			}
		}
	}
	if len(keywords) == 0 {
		e.ac = nil
		return
	}
	e.ac = ac.New(keywords)
}

// extractBody applies content-type routing and runs the two-phase extraction
// on the body bytes, returning findings with Scope="body".
func (s snapshot) extractBody(body []byte, ct string) []finding {
	isJS := ct == "application/javascript" || ct == "text/javascript"
	isJSON := ct == "application/json"
	isSpecial := isJS || isJSON

	scanBody := body
	if isJS && len(body) > headOnlySize {
		scanBody = body[:headOnlySize]
	}

	rules, ac := s.rules, s.ac

	var hitTriggers map[string]struct{}
	if ac != nil {
		hitTriggers = ac.Search(scanBody)
	}

	var findings []finding
	for _, cr := range rules {
		if cr.Scope == "header" {
			continue
		}
		if cr.Category == "special" && !isSpecial {
			continue
		}
		if len(cr.Triggers) > 0 {
			if !anyHit(cr.triggerSet, hitTriggers) {
				continue
			}
		}
		findings = append(findings, matchAll(cr, scanBody, "body")...)
	}
	return findings
}

// extractScope runs the two-phase extraction on content with the given scope
// ("body" or "header"). Used directly for header scanning.
func (e *extractor) extractScope(content []byte, scope string) []finding {
	return e.snapshot().extractScope(content, scope)
}

func (s snapshot) extractScope(content []byte, scope string) []finding {
	rules, ac := s.rules, s.ac

	var hitTriggers map[string]struct{}
	if ac != nil {
		hitTriggers = ac.Search(content)
	}

	var findings []finding
	for _, cr := range rules {
		switch cr.Scope {
		case "body":
			if scope != "body" {
				continue
			}
		case "header":
			if scope != "header" {
				continue
			}
			// "all" passes through for both scopes
		}
		if len(cr.Triggers) > 0 {
			if !anyHit(cr.triggerSet, hitTriggers) {
				continue
			}
		}
		findings = append(findings, matchAll(cr, content, scope)...)
	}
	return findings
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func compile(r Rule) (compiledRule, error) {
	if r.Pattern == "" {
		return compiledRule{}, fmt.Errorf("empty pattern")
	}
	re, err := regexp.Compile(r.Pattern)
	if err != nil {
		return compiledRule{}, err
	}
	if r.Color == "" {
		r.Color = "gray"
	}
	if r.Scope == "" {
		r.Scope = "all"
	}
	if r.Sensitivity == "" {
		r.Sensitivity = "low"
	}
	// Own the trigger slice, since future rebuilds must use the same keywords
	// as triggerSet even if the caller reuses its Rule after addRule returns.
	// Preserve empty elements: only an empty slice means fallback; a rule
	// containing solely empty keywords never triggered in the original AC.
	r.Triggers = append([]string(nil), r.Triggers...)
	ts := make(map[string]struct{}, len(r.Triggers))
	for _, t := range r.Triggers {
		ts[t] = struct{}{}
	}
	return compiledRule{Rule: r, re: re, triggerSet: ts}, nil
}

// matchAll runs the compiled regex against content and converts each match to
// a finding.
func matchAll(cr compiledRule, content []byte, scope string) []finding {
	matches := cr.re.FindAllSubmatch(content, 257)
	if len(matches) == 0 {
		return nil
	}
	out := make([]finding, 0, len(matches))
	for _, m := range matches {
		f := finding{
			RuleName:    cr.Name,
			Value:       string(m[0]),
			Sensitivity: cr.Sensitivity,
			Color:       cr.Color,
			Scope:       scope,
		}
		if len(m) > 1 {
			f.Capture = string(m[1])
		}
		out = append(out, f)
	}
	return out
}

// anyHit reports whether any key in set is present in hits.
// If hits is nil (no AC scan performed), returns false.
func anyHit(set, hits map[string]struct{}) bool {
	if hits == nil {
		return false
	}
	for k := range set {
		if _, ok := hits[k]; ok {
			return true
		}
	}
	return false
}

// isBinary returns true for content-types that should be skipped entirely.
func isBinary(ct string) bool {
	for _, prefix := range []string{
		"image/",
		"video/",
		"audio/",
		"application/wasm",
		"application/octet-stream",
	} {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return false
}

// serializeHeader converts a header map into a flat byte slice for AC / regex
// scanning. Format: "key: value\n" per header line (lowercase keys). Typed as
// the base map so both fhttp and net/http headers can be passed.
func serializeHeader(h map[string][]string) []byte {
	if len(h) == 0 {
		return nil
	}
	var sb strings.Builder
	for k, vv := range h {
		kl := strings.ToLower(k)
		for _, v := range vv {
			sb.WriteString(kl)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteByte('\n')
		}
	}
	return []byte(sb.String())
}
