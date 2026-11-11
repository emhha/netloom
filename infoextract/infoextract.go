package infoextract

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/emhha/netloom/ac"
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
// It is safe for concurrent use and must not be copied after first use.
type InfoExtractor struct {
	mu       sync.RWMutex
	rules    []compiledRule // ordered, immutable snapshots; published together with ac
	ac       *ac.Matcher    // nil when no triggers exist (all fallback rules)
	identity uint64
}

var nextSnapshotIdentity atomic.Uint64

// Snapshot is an immutable ruleset and its matching AC index. It is safe to
// copy and use concurrently; later AddRule calls do not change its results.
// Its zero value is an empty ruleset with identity zero.
type Snapshot struct {
	rules    []compiledRule
	ac       *ac.Matcher
	identity uint64
}

// Identity returns a process-local cache identity, unique across published
// ruleset generations and extractor instances. It is not a persistent version
// or a content hash. Obtain a new Snapshot to observe successful AddRule calls.
func (s Snapshot) Identity() uint64 { return s.identity }

// Snapshot captures the rules, AC index and identity under the same lock.
// Even a zero-value InfoExtractor receives its own nonzero initial identity.
func (e *InfoExtractor) Snapshot() Snapshot {
	e.mu.RLock()
	if e.identity != 0 {
		s := Snapshot{rules: e.rules, ac: e.ac, identity: e.identity}
		e.mu.RUnlock()
		return s
	}
	e.mu.RUnlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.identity == 0 {
		e.identity = nextSnapshotIdentity.Add(1)
	}
	return Snapshot{rules: e.rules, ac: e.ac, identity: e.identity}
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
	return e.Snapshot().ExtractWithContentType(body, header, contentType)
}

// ExtractWithContentType scans both body and headers using this one immutable
// generation, with the same routing and result semantics as InfoExtractor.
func (s Snapshot) ExtractWithContentType(
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
		findings = append(findings, s.extractBody(body, ct)...)
	}
	findings = append(findings, s.extractScope(serializeHeader(header), "header")...)
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
func (e *InfoExtractor) rebuildAC() {
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
func (s Snapshot) extractBody(body []byte, ct string) []Finding {
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
	return e.Snapshot().extractScope(content, scope)
}

func (s Snapshot) extractScope(content []byte, scope string) []Finding {
	rules, ac := s.rules, s.ac

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
	// Own the trigger slice, since future rebuilds must use the same keywords
	// as triggerSet even if the caller reuses its Rule after AddRule returns.
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
