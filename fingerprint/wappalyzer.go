package fingerprint

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// WappalyzerRule holds the raw (pre-processed) definition of a single
// technology from the Wappalyzer JSON rule file.
type WappalyzerRule struct {
	Cats        []int               `json:"cats"`
	Headers     map[string]string   `json:"headers"`
	Cookies     map[string]string   `json:"cookies"`
	HTML        []string            `json:"html"`
	Scripts     []string            `json:"scripts"`
	ScriptSrc   []string            `json:"scriptSrc"`
	Meta        map[string][]string `json:"meta"`
	Implies     []string            `json:"implies"`
	Description string              `json:"description"`
	Website     string              `json:"website"`
	CPE         string              `json:"cpe"`
	Icon        string              `json:"icon"`
}

// WappalyzerPattern is a compiled pattern extracted from a Wappalyzer rule
// string. Patterns are pre-processed at load time.
type WappalyzerPattern struct {
	Regex      *regexp.Regexp
	VersionTpl string // e.g. "\1" or "\1?pro:free"
	Confidence int    // default 100
}

// wappalyzerTech is a fully compiled technology entry.
type wappalyzerTech struct {
	name    string
	cats    []int
	implies []string

	// compiled patterns per dimension
	headers   map[string][]*WappalyzerPattern // lowercase header name → patterns
	cookies   map[string][]*WappalyzerPattern // cookie name → patterns
	html      []*WappalyzerPattern
	scripts   []*WappalyzerPattern
	scriptSrc []*WappalyzerPattern
	meta      map[string][]*WappalyzerPattern // meta name → patterns
}

// WappalyzerMatcher is the Wappalyzer detection engine. It is initialised once
// from a JSON rule file and is safe for concurrent use after initialisation.
type WappalyzerMatcher struct {
	techs []*wappalyzerTech
}

// wappalyzerRuleFile covers both the legacy {"apps": {...}} and modern
// {"technologies": {...}} formats.
type wappalyzerRuleFile struct {
	Apps         map[string]WappalyzerRule `json:"apps"`
	Technologies map[string]WappalyzerRule `json:"technologies"`
}

// LoadWappalyzerJSON parses a Wappalyzer JSON rule file and returns a compiled
// WappalyzerMatcher. Missing or empty files return an empty matcher (no-op).
func LoadWappalyzerJSON(data []byte) (*WappalyzerMatcher, error) {
	if len(data) == 0 {
		return &WappalyzerMatcher{}, nil
	}

	var ruleFile wappalyzerRuleFile
	if err := json.Unmarshal(data, &ruleFile); err != nil {
		return nil, fmt.Errorf("wappalyzer.LoadJSON: %w", err)
	}

	// Merge both formats.
	rules := ruleFile.Apps
	if rules == nil {
		rules = make(map[string]WappalyzerRule)
	}
	for k, v := range ruleFile.Technologies {
		rules[k] = v
	}

	m := &WappalyzerMatcher{}
	for name, rule := range rules {
		tech := compileWappalyzerRule(name, rule)
		m.techs = append(m.techs, tech)
	}
	return m, nil
}

func compileWappalyzerRule(name string, rule WappalyzerRule) *wappalyzerTech {
	tech := &wappalyzerTech{
		name:    name,
		cats:    rule.Cats,
		implies: rule.Implies,
	}

	// Headers: lowercase the key names.
	if len(rule.Headers) > 0 {
		tech.headers = make(map[string][]*WappalyzerPattern, len(rule.Headers))
		for k, v := range rule.Headers {
			pat := compilePattern(v)
			if pat != nil {
				tech.headers[strings.ToLower(k)] = append(tech.headers[strings.ToLower(k)], pat)
			}
		}
	}

	// Cookies.
	if len(rule.Cookies) > 0 {
		tech.cookies = make(map[string][]*WappalyzerPattern, len(rule.Cookies))
		for k, v := range rule.Cookies {
			pat := compilePattern(v)
			if pat != nil {
				tech.cookies[strings.ToLower(k)] = append(tech.cookies[strings.ToLower(k)], pat)
			}
		}
	}

	for _, s := range rule.HTML {
		if p := compilePattern(s); p != nil {
			tech.html = append(tech.html, p)
		}
	}
	for _, s := range rule.Scripts {
		if p := compilePattern(s); p != nil {
			tech.scripts = append(tech.scripts, p)
		}
	}
	for _, s := range rule.ScriptSrc {
		if p := compilePattern(s); p != nil {
			tech.scriptSrc = append(tech.scriptSrc, p)
		}
	}

	if len(rule.Meta) > 0 {
		tech.meta = make(map[string][]*WappalyzerPattern, len(rule.Meta))
		for k, vs := range rule.Meta {
			for _, v := range vs {
				if p := compilePattern(v); p != nil {
					tech.meta[strings.ToLower(k)] = append(tech.meta[strings.ToLower(k)], p)
				}
			}
		}
	}

	return tech
}

// compilePattern splits a Wappalyzer pattern string on "\;" and compiles the
// regex and modifiers. Returns nil if the regex is invalid.
func compilePattern(raw string) *WappalyzerPattern {
	parts := strings.Split(raw, `\;`)
	regexStr := parts[0]

	// Apply Wappalyzer wildcard simplifications.
	regexStr = strings.ReplaceAll(regexStr, `\+`, `{1,250}`)
	// Only replace unescaped * — simple heuristic: replace * not preceded by .
	regexStr = replaceUnescapedStar(regexStr)

	re, err := regexp.Compile(`(?i)` + regexStr)
	if err != nil {
		return nil
	}

	pat := &WappalyzerPattern{
		Regex:      re,
		Confidence: 100,
	}

	for _, mod := range parts[1:] {
		switch {
		case strings.HasPrefix(mod, "version:"):
			pat.VersionTpl = strings.TrimPrefix(mod, "version:")
		case strings.HasPrefix(mod, "confidence:"):
			v := strings.TrimPrefix(mod, "confidence:")
			if n, err := strconv.Atoi(v); err == nil {
				pat.Confidence = n
			}
		}
	}

	return pat
}

// replaceUnescapedStar replaces bare '*' (not preceded by '.') with '{0,250}'.
// This approximates the Wappalyzer wildcard semantics.
func replaceUnescapedStar(s string) string {
	var sb strings.Builder
	prev := rune(0)
	for _, ch := range s {
		if ch == '*' && prev != '.' && prev != '\\' {
			sb.WriteString(`{0,250}`)
		} else {
			sb.WriteRune(ch)
		}
		prev = ch
	}
	return sb.String()
}

// match runs all Wappalyzer patterns against the MatchContext and returns
// detected artifacts.
func (wm *WappalyzerMatcher) name() string { return "wappalyzer" }

func (wm *WappalyzerMatcher) match(ctx *MatchContext) []Artifact {
	if wm == nil || ctx == nil || ctx.Response == nil {
		return nil
	}

	// confidence accumulator: techName → (confidence, version)
	type hit struct {
		confidence float64
		version    string
	}
	acc := make(map[string]*hit)

	addHit := func(name string, conf int, version string) {
		if h, ok := acc[name]; ok {
			h.confidence += float64(conf)
			if h.confidence > 100 {
				h.confidence = 100
			}
			if version != "" && h.version == "" {
				h.version = version
			}
		} else {
			acc[name] = &hit{confidence: float64(conf), version: version}
		}
	}

	resp := ctx.Response

	// Build lowercase header map once.
	lowerHeaders := make(map[string][]string, len(resp.Header))
	for k, vs := range resp.Header {
		lowerHeaders[strings.ToLower(k)] = vs
	}

	// Parse cookies from Set-Cookie header.
	cookieMap := parseCookies(resp.Header)

	// Reuse the HTML result prepared by Engine.Match.
	var htmlResult *HTMLParserResult
	if ctx.Response != nil {
		// HTMLParserResult is passed via ctx but we have no direct context access
		// here. Wappalyzer receives MatchContext which doesn't carry Meta.
		// The scripts/scriptSrc/meta data must be extracted from MatchContext
		// or from the body directly. We parse inline here if not pre-parsed.
		// In the pipeline, WappalyzerMatcher is called from within Extract()
		// which receives resp only. We store parsed HTML in a field on MatchContext.
		htmlResult = ctx.HTMLResult
	}

	bodyStr := string(ctx.BodyUTF8)

	for _, tech := range wm.techs {
		// Headers.
		for hk, pats := range tech.headers {
			vals := lowerHeaders[hk]
			for _, pat := range pats {
				for _, v := range vals {
					if m := pat.Regex.FindStringSubmatch(v); m != nil {
						ver := resolveVersion(pat.VersionTpl, m)
						addHit(tech.name, pat.Confidence, ver)
					}
				}
			}
		}

		// Cookies.
		for ck, pats := range tech.cookies {
			if cv, ok := cookieMap[ck]; ok {
				for _, pat := range pats {
					if m := pat.Regex.FindStringSubmatch(cv); m != nil {
						ver := resolveVersion(pat.VersionTpl, m)
						addHit(tech.name, pat.Confidence, ver)
					}
				}
			}
		}

		// HTML body.
		for _, pat := range tech.html {
			if m := pat.Regex.FindStringSubmatch(bodyStr); m != nil {
				ver := resolveVersion(pat.VersionTpl, m)
				addHit(tech.name, pat.Confidence, ver)
				break // one match per pattern group is enough
			}
		}

		// Scripts and ScriptSrc from HTML parser result.
		if htmlResult != nil {
			for _, pat := range tech.scripts {
				for _, sc := range htmlResult.Scripts {
					if m := pat.Regex.FindStringSubmatch(sc); m != nil {
						ver := resolveVersion(pat.VersionTpl, m)
						addHit(tech.name, pat.Confidence, ver)
					}
				}
			}
			for _, pat := range tech.scriptSrc {
				for _, src := range htmlResult.ScriptSrcs {
					if m := pat.Regex.FindStringSubmatch(src); m != nil {
						ver := resolveVersion(pat.VersionTpl, m)
						addHit(tech.name, pat.Confidence, ver)
					}
				}
			}
			// Meta tags.
			for mk, pats := range tech.meta {
				if contents, ok := htmlResult.MetaTags[mk]; ok {
					for _, content := range contents {
						for _, pat := range pats {
							if m := pat.Regex.FindStringSubmatch(content); m != nil {
								ver := resolveVersion(pat.VersionTpl, m)
								addHit(tech.name, pat.Confidence, ver)
							}
						}
					}
				}
			}
		}
	}

	var artifacts []Artifact
	for name, h := range acc {
		if h.confidence <= 0 {
			continue
		}
		art := Artifact{
			Type:       "framework",
			Name:       name,
			Version:    h.version,
			Confidence: h.confidence,
			Source:     "wappalyzer",
		}
		artifacts = append(artifacts, art)
	}

	// Add implied technologies.
	var implied []Artifact
	for _, art := range artifacts {
		for _, tech := range wm.techs {
			if tech.name != art.Name {
				continue
			}
			for _, imp := range tech.implies {
				impName := stripImplyVersion(imp)
				// Only add if not already detected.
				if !hasName(artifacts, impName) && !hasName(implied, impName) {
					implied = append(implied, Artifact{
						Type:       "framework",
						Name:       impName,
						Confidence: art.Confidence * 0.8,
						Source:     "wappalyzer",
						Implies:    nil,
					})
				}
			}
		}
	}
	artifacts = append(artifacts, implied...)
	return artifacts
}

// resolveVersion substitutes capture groups into a version template.
// Template syntax: "\1", "\2", ...; "\1?a:b" = group1 non-empty → "a" else "b".
func resolveVersion(tpl string, m []string) string {
	if tpl == "" {
		return ""
	}

	result := tpl
	for i := len(m) - 1; i >= 1; i-- {
		placeholder := fmt.Sprintf(`\%d`, i)
		result = strings.ReplaceAll(result, placeholder, m[i])
	}

	// Handle ternary: "\1?a:b"
	if idx := strings.Index(result, "?"); idx != -1 {
		cond := result[:idx]
		rest := result[idx+1:]
		colonIdx := strings.Index(rest, ":")
		if colonIdx != -1 {
			ifTrue := rest[:colonIdx]
			ifFalse := rest[colonIdx+1:]
			if cond != "" {
				return ifTrue
			}
			return ifFalse
		}
	}

	return strings.TrimSpace(result)
}

// parseCookies extracts cookie name → value from Set-Cookie headers.
func parseCookies(h interface{ Values(string) []string }) map[string]string {
	result := make(map[string]string)
	// Access Set-Cookie via type assertion to net/http.Header.
	type headerer interface {
		Values(string) []string
	}
	if hh, ok := h.(headerer); ok {
		for _, raw := range hh.Values("Set-Cookie") {
			// Parse "name=value; ..."
			parts := strings.SplitN(raw, ";", 2)
			kv := strings.SplitN(parts[0], "=", 2)
			if len(kv) == 2 {
				result[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
			}
		}
	}
	return result
}

func hasName(arts []Artifact, name string) bool {
	for _, a := range arts {
		if a.Name == name {
			return true
		}
	}
	return false
}

// stripImplyVersion removes version suffix from implies entries like "PHP\\5".
func stripImplyVersion(s string) string {
	if idx := strings.Index(s, `\`); idx != -1 {
		return s[:idx]
	}
	return s
}
