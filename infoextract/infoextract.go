package infoextract

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/emhha/netloom/httpdata"
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

// Finding is a single extraction result.
type Finding struct {
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

// InfoExtractor is the two-phase sensitive-information extraction engine.
// It is safe for concurrent use.
type InfoExtractor struct {
	mu    sync.RWMutex
	rules []compiledRule // ordered; later entries shadow earlier ones with same Name
	ac    *automaton     // nil when no triggers exist (all fallback rules)
}

// New returns an InfoExtractor pre-loaded with the built-in ruleset.
func New() *InfoExtractor {
	e := &InfoExtractor{}
	for _, r := range defaultRules() {
		// ignore compile errors on built-in rules — they are tested
		_ = e.addRuleLocked(r)
	}
	e.rebuildAC()
	return e
}

// Name identifies the extractor.
func (e *InfoExtractor) Name() string { return "infoextract" }

// Extract reads resp.Body and
// resp.Header using resp.ContentType for routing.
func (e *InfoExtractor) Extract(resp *httpdata.Response) ([]httpdata.Artifact, error) {
	if resp == nil {
		return nil, nil
	}
	findings := e.ExtractWithContentType(resp.Body, resp.Header, resp.ContentType)
	arts := make([]httpdata.Artifact, 0, len(findings))
	for _, f := range findings {
		v := f.Capture
		if v == "" {
			v = f.Value
		}
		arts = append(arts, httpdata.Artifact{Type: f.RuleName, Value: v})
	}
	return arts, nil
}

// ExtractWithContentType scans body and header, applying content-type routing.
// Binary content-types skip body matching; response headers are still analyzed.
func (e *InfoExtractor) ExtractWithContentType(
	body []byte,
	header map[string][]string,
	contentType string,
) []Finding {
	ct := strings.ToLower(contentType)
	// strip parameters (e.g. "text/html; charset=utf-8")
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}

	var findings []Finding
	if !isBinary(ct) {
		findings = append(findings, e.extractBody(body, ct)...)
	}
	findings = append(findings, e.extractScope(serializeHeader(header), "header")...)
	return findings
}

// AddRule compiles and appends a single rule, overwriting any existing rule
// with the same Name. Returns an error if the Pattern is not valid RE2.
// On error the internal state is not modified.
func (e *InfoExtractor) AddRule(rule Rule) error {
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
func (e *InfoExtractor) addRuleLocked(r Rule) error {
	cr, err := compile(r)
	if err != nil {
		return err
	}
	e.upsertLocked(cr)
	return nil
}

// upsertLocked inserts or replaces by Name. Must be called with mu held (write).
func (e *InfoExtractor) upsertLocked(cr compiledRule) {
	for i, existing := range e.rules {
		if existing.Name == cr.Name {
			e.rules[i] = cr
			return
		}
	}
	e.rules = append(e.rules, cr)
}

// rebuildAC rebuilds the Aho-Corasick automaton from current rules.
// Must be called with mu held (write), or during single-threaded init.
func (e *InfoExtractor) rebuildAC() {
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
	e.ac = newAutomaton(keywords)
}

// extractBody applies content-type routing and runs the two-phase extraction
// on the body bytes, returning findings with Scope="body".
func (e *InfoExtractor) extractBody(body []byte, ct string) []Finding {
	isJS := ct == "application/javascript" || ct == "text/javascript"
	isJSON := ct == "application/json"
	isSpecial := isJS || isJSON

	scanBody := body
	if isJS && len(body) > headOnlySize {
		scanBody = body[:headOnlySize]
	}

	e.mu.RLock()
	rules := e.rules
	ac := e.ac
	e.mu.RUnlock()

	var hitTriggers map[string]struct{}
	if ac != nil {
		hitTriggers = ac.Search(scanBody)
	}

	var findings []Finding
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
func (e *InfoExtractor) extractScope(content []byte, scope string) []Finding {
	e.mu.RLock()
	rules := e.rules
	ac := e.ac
	e.mu.RUnlock()

	var hitTriggers map[string]struct{}
	if ac != nil {
		hitTriggers = ac.Search(content)
	}

	var findings []Finding
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
	ts := make(map[string]struct{}, len(r.Triggers))
	for _, t := range r.Triggers {
		ts[t] = struct{}{}
	}
	return compiledRule{Rule: r, re: re, triggerSet: ts}, nil
}

// matchAll runs the compiled regex against content and converts each match to
// a Finding.
func matchAll(cr compiledRule, content []byte, scope string) []Finding {
	matches := cr.re.FindAllSubmatch(content, 257)
	if len(matches) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(matches))
	for _, m := range matches {
		f := Finding{
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
