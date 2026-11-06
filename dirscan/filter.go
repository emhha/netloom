package dirscan

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/emhha/netloom"
)

// defaultExcludeStatus is the default set of status codes treated as "not found".
var defaultExcludeStatus = []int{400, 404, 500, 502, 503}

// filterChain encapsulates all compiled filter predicates for a scan run.
type filterChain struct {
	excludeStatus map[int]bool
	minSize       int
	maxSize       int
	excludeTexts  []string
	excludeRegex  []*regexp.Regexp

	// Advanced matchers (response must satisfy ALL/ANY in matcherMode).
	matchers    []predicate
	matcherMode string // "and" | "or"

	// Advanced filters (response must NOT satisfy ANY/ALL in filterMode).
	filters    []predicate
	filterMode string // "and" | "or"
}

// predicate is a compiled match function over a netloom.Response.
type predicate struct {
	name string
	fn   func(*netloom.Response) bool
}

// buildFilterChain compiles all filter predicates from cfg.
func buildFilterChain(cfg *Config) (*filterChain, error) {
	fc := &filterChain{
		excludeStatus: make(map[int]bool),
		matcherMode:   cfg.MatcherMode,
		filterMode:    cfg.FilterMode,
	}
	if fc.matcherMode == "" {
		fc.matcherMode = "or"
	}
	if fc.filterMode == "" {
		fc.filterMode = "or"
	}

	// Exclude status.
	excludes := cfg.ExcludeStatusCodes
	if len(excludes) == 0 {
		excludes = defaultExcludeStatus
	}
	for _, s := range excludes {
		fc.excludeStatus[s] = true
	}

	fc.minSize = cfg.MinSize
	fc.maxSize = cfg.MaxSize

	// Exclude texts.
	fc.excludeTexts = cfg.ExcludeTexts

	// Exclude regex.
	for _, rx := range cfg.ExcludeRegexes {
		compiled, err := regexp.Compile(rx)
		if err != nil {
			return nil, err
		}
		fc.excludeRegex = append(fc.excludeRegex, compiled)
	}

	// Advanced matchers.
	if cfg.MatchStatus != "" {
		fc.matchers = append(fc.matchers, makeStatusPredicate("match-status", cfg.MatchStatus))
	}
	if cfg.MatchSize != "" {
		p, err := makeSizePredicate("match-size", cfg.MatchSize)
		if err != nil {
			return nil, err
		}
		fc.matchers = append(fc.matchers, p)
	}
	if cfg.MatchWords != "" {
		p, err := makeIntPredicate("match-words", cfg.MatchWords, func(r *netloom.Response) int { return r.WordCount })
		if err != nil {
			return nil, err
		}
		fc.matchers = append(fc.matchers, p)
	}
	if cfg.MatchLines != "" {
		p, err := makeIntPredicate("match-lines", cfg.MatchLines, func(r *netloom.Response) int { return r.LineCount })
		if err != nil {
			return nil, err
		}
		fc.matchers = append(fc.matchers, p)
	}
	if cfg.MatchRegex != "" {
		p, err := makeRegexPredicate("match-regex", cfg.MatchRegex)
		if err != nil {
			return nil, err
		}
		fc.matchers = append(fc.matchers, p)
	}
	if cfg.MatchHeader != "" {
		fc.matchers = append(fc.matchers, makeHeaderPredicate("match-header", cfg.MatchHeader))
	}
	if cfg.MatchTime != "" {
		p, err := makeTimePredicate("match-time", cfg.MatchTime)
		if err != nil {
			return nil, err
		}
		fc.matchers = append(fc.matchers, p)
	}

	// Advanced filters (inverted matchers).
	if cfg.FilterStatus != "" {
		fc.filters = append(fc.filters, makeStatusPredicate("filter-status", cfg.FilterStatus))
	}
	if cfg.FilterSize != "" {
		p, err := makeSizePredicate("filter-size", cfg.FilterSize)
		if err != nil {
			return nil, err
		}
		fc.filters = append(fc.filters, p)
	}
	if cfg.FilterWords != "" {
		p, err := makeIntPredicate("filter-words", cfg.FilterWords, func(r *netloom.Response) int { return r.WordCount })
		if err != nil {
			return nil, err
		}
		fc.filters = append(fc.filters, p)
	}
	if cfg.FilterLines != "" {
		p, err := makeIntPredicate("filter-lines", cfg.FilterLines, func(r *netloom.Response) int { return r.LineCount })
		if err != nil {
			return nil, err
		}
		fc.filters = append(fc.filters, p)
	}
	if cfg.FilterRegex != "" {
		p, err := makeRegexPredicate("filter-regex", cfg.FilterRegex)
		if err != nil {
			return nil, err
		}
		fc.filters = append(fc.filters, p)
	}
	if cfg.FilterHeader != "" {
		fc.filters = append(fc.filters, makeHeaderPredicate("filter-header", cfg.FilterHeader))
	}
	if cfg.FilterTime != "" {
		p, err := makeTimePredicate("filter-time", cfg.FilterTime)
		if err != nil {
			return nil, err
		}
		fc.filters = append(fc.filters, p)
	}

	return fc, nil
}

// Keep returns true when the response should be reported as a result.
func (fc *filterChain) Keep(resp *netloom.Response) bool {
	if resp == nil {
		return false
	}

	// Basic: excluded status codes.
	if fc.excludeStatus[resp.StatusCode] {
		return false
	}

	// Basic: body size bounds.
	bodyLen := len(resp.Body)
	if fc.minSize > 0 && bodyLen < fc.minSize {
		return false
	}
	if fc.maxSize > 0 && bodyLen > fc.maxSize {
		return false
	}

	// Basic: excluded body texts.
	for _, t := range fc.excludeTexts {
		if strings.Contains(string(resp.Body), t) {
			return false
		}
	}

	// Basic: excluded body regexes.
	for _, rx := range fc.excludeRegex {
		if rx.Match(resp.Body) {
			return false
		}
	}

	// Advanced matchers: response must satisfy these.
	if len(fc.matchers) > 0 {
		if !evalPredicates(fc.matchers, fc.matcherMode, resp) {
			return false
		}
	}

	// Advanced filters: response must NOT satisfy these.
	if len(fc.filters) > 0 {
		if evalPredicates(fc.filters, fc.filterMode, resp) {
			return false
		}
	}

	return true
}

// evalPredicates evaluates a slice of predicates in the given mode ("and"|"or").
func evalPredicates(preds []predicate, mode string, resp *netloom.Response) bool {
	if len(preds) == 0 {
		return true
	}
	if strings.EqualFold(mode, "and") {
		for _, p := range preds {
			if !p.fn(resp) {
				return false
			}
		}
		return true
	}
	// Default "or": any match.
	for _, p := range preds {
		if p.fn(resp) {
			return true
		}
	}
	return false
}

// --- Predicate factories ---

// parseStatusSpec parses a comma-/range-separated status spec like "200,301,400-499".
func parseStatusSpec(spec string) []intRange {
	var out []intRange
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, errL := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, errH := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if errL == nil && errH == nil {
				out = append(out, intRange{lo, hi})
			}
		} else {
			v, err := strconv.Atoi(part)
			if err == nil {
				out = append(out, intRange{v, v})
			}
		}
	}
	return out
}

type intRange struct{ lo, hi int }

func (r intRange) contains(v int) bool { return v >= r.lo && v <= r.hi }

func makeStatusPredicate(name, spec string) predicate {
	ranges := parseStatusSpec(spec)
	return predicate{name: name, fn: func(r *netloom.Response) bool {
		for _, rng := range ranges {
			if rng.contains(r.StatusCode) {
				return true
			}
		}
		return false
	}}
}

func makeSizePredicate(name, spec string) (predicate, error) {
	// spec: "100" or "100-500"
	ranges := parseStatusSpec(spec) // reuse int range parser
	if len(ranges) == 0 {
		return predicate{}, nil
	}
	return predicate{name: name, fn: func(r *netloom.Response) bool {
		size := len(r.Body)
		for _, rng := range ranges {
			if rng.contains(size) {
				return true
			}
		}
		return false
	}}, nil
}

func makeIntPredicate(name, spec string, getter func(*netloom.Response) int) (predicate, error) {
	ranges := parseStatusSpec(spec)
	if len(ranges) == 0 {
		return predicate{}, nil
	}
	return predicate{name: name, fn: func(r *netloom.Response) bool {
		v := getter(r)
		for _, rng := range ranges {
			if rng.contains(v) {
				return true
			}
		}
		return false
	}}, nil
}

func makeRegexPredicate(name, pattern string) (predicate, error) {
	rx, err := regexp.Compile(pattern)
	if err != nil {
		return predicate{}, err
	}
	return predicate{name: name, fn: func(r *netloom.Response) bool {
		return rx.Match(r.Body)
	}}, nil
}

// makeHeaderPredicate parses "Header-Name: value" or "Header-Name" specs.
func makeHeaderPredicate(name, spec string) predicate {
	if idx := strings.Index(spec, ":"); idx >= 0 {
		hdr := strings.TrimSpace(spec[:idx])
		val := strings.TrimSpace(spec[idx+1:])
		return predicate{name: name, fn: func(r *netloom.Response) bool {
			return strings.Contains(r.Header.Get(hdr), val)
		}}
	}
	hdr := strings.TrimSpace(spec)
	return predicate{name: name, fn: func(r *netloom.Response) bool {
		return r.Header.Get(hdr) != ""
	}}
}

// makeTimePredicate parses a duration string like "500ms" or "2s".
func makeTimePredicate(name, spec string) (predicate, error) {
	d, err := time.ParseDuration(spec)
	if err != nil {
		// Try plain milliseconds.
		ms, merr := strconv.ParseFloat(strings.TrimSuffix(spec, "ms"), 64)
		if merr != nil {
			return predicate{}, err
		}
		d = time.Duration(ms * float64(time.Millisecond))
	}
	return predicate{name: name, fn: func(r *netloom.Response) bool {
		return r.ResponseTime <= d
	}}, nil
}

// categorizeResult assigns a ResultCategory based on the URL path.
func categorizeResult(path string) ResultCategory {
	p := strings.ToLower(path)
	// VCS.
	if strings.HasPrefix(p, ".git") || strings.HasPrefix(p, ".svn") ||
		strings.HasPrefix(p, ".hg") || strings.HasPrefix(p, ".bzr") ||
		strings.HasPrefix(p, "cvs/") || strings.Contains(p, ".ds_store") ||
		strings.Contains(p, "thumbs.db") {
		return CategoryVCS
	}
	// Config.
	configPatterns := []string{
		".env", "web.config", ".htaccess", ".htpasswd", "nginx.conf",
		"config.php", "config.py", "config.json", "settings.py",
		"application.properties", "application.yml",
		"swagger.json", "openapi.json", "api-docs",
		"db.sql", "database.sql", "dump.sql", "backup.sql",
	}
	for _, pat := range configPatterns {
		if strings.Contains(p, pat) {
			return CategoryConfig
		}
	}
	// Backup.
	backupExts := []string{".bak", ".backup", ".old", ".orig", ".copy", ".zip", ".tar", ".gz", ".7z", ".rar", ".sql"}
	for _, ext := range backupExts {
		if strings.HasSuffix(p, ext) {
			return CategoryBackup
		}
	}
	// Developer leftovers.
	leakDirs := []string{
		"old/", "test/", "tests/", "sandbox/", "demo/", "dev/", "develop/",
		"debug/", "local/", "staging/", "stage/", "pre/", "preview/",
		"beta/", "canary/", "tmp/", "temp/", "bak/", "history/",
		"archive/", "legacy/", "previous/",
	}
	for _, d := range leakDirs {
		if strings.HasPrefix(p, d) || strings.Contains(p, "/"+d) {
			return CategoryLeak
		}
	}
	return CategoryCommon
}
