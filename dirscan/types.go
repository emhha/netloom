// Package dirscan provides a high-performance directory scanner built on top of
// the netloom engine. It replicates dirsearch's core logic — wildcard/soft-404
// auto-calibration, dual-queue (_items/_extra), crawl, and recursive directory
// scanning — while running entirely on the netloom Scheduler for concurrency,
// rate-limiting, and SSRF protection.
//
// Zero business dependencies: no scope validation, no DB access, no audit log.
// All of those concerns live in the service layer above.
package dirscan

import (
	"context"
	"time"
)

// ScanMode selects how the scanner chooses wordlists and tuning.
type ScanMode string

const (
	// ModeAPI keeps caller-provided preset/wordlist semantics.
	ModeAPI ScanMode = "api"
	// ModeAuto enables fingerprint- and WAF-aware preset selection.
	ModeAuto ScanMode = "auto"
)

// ScanPreset selects the built-in wordlist configuration.
type ScanPreset string

const (
	// PresetFull scans with the main dictionary plus all category files.
	PresetFull ScanPreset = "full"
	// PresetQuick scans only the common category.
	PresetQuick ScanPreset = "quick"
	// PresetLeak scans vcs+conf+keys+leak categories (no main dict).
	PresetLeak ScanPreset = "leak"
	// PresetBackup scans only the backups category.
	PresetBackup ScanPreset = "backup"
	// PresetFramework scans framework-specific paths selected by Fingerprint.
	PresetFramework ScanPreset = "framework"
	// PresetCustom uses wordlists specified in Config.CustomWordlists.
	PresetCustom ScanPreset = "custom"
)

// ResultCategory classifies a scan hit by the type of finding.
type ResultCategory string

const (
	CategoryVCS       ResultCategory = "vcs"
	CategoryConfig    ResultCategory = "config"
	CategoryBackup    ResultCategory = "backup"
	CategoryLeak      ResultCategory = "leak"
	CategoryFramework ResultCategory = "framework"
	CategoryCommon    ResultCategory = "common"
)

// Config is the complete configuration for a directory scan run.
type Config struct {
	// WordlistDir is an explicit directory of caller-supplied dictionaries.
	WordlistDir string
	// BaseURL is the scan root; all dictionary paths are appended to this.
	// Example: "https://example.com/app/"
	BaseURL string
	// TargetID is the project target row the scan result should be written to.
	TargetID int64
	// Wordlist overrides Preset when non-empty; the slice is used as-is.
	Wordlist []string
	// Extensions appended during extension-fuzz (default ["php","html","asp","jsp"]).
	Extensions []string
	// Threads controls netloom concurrency (default 30; SmartSkip lowers to 20).
	Threads int
	// Timeout is the per-request deadline (default 10s).
	Timeout time.Duration
	// UserAgent overrides the default HTTP User-Agent header.
	UserAgent string
	// Headers are extra headers sent on every request.
	Headers map[string]string
	// TLSProfile selects the browser TLS fingerprint (e.g. "chrome_131"); empty
	// uses the netloom default profile. Passed to netloom.ProfileByName.
	TLSProfile string

	// --- Preset & wordlist selection ---

	// Mode controls whether the scan runs in API mode or auto mode.
	Mode ScanMode
	// Preset selects a built-in wordlist bundle. In auto mode it may be used as a hint.
	Preset ScanPreset
	// Framework is required when Preset == PresetFramework.
	Framework string
	// CustomWordlists holds logical filenames (e.g. "corp-leak.txt") relative to
	// the custom/ wordlist directory. Absolute paths and ".." are rejected.
	CustomWordlists []string
	// Fingerprint contains technology stack labels (from the fingerprint module)
	// used to auto-load matching framework dictionaries.
	Fingerprint []string
	// WordlistMaxSize caps the total number of entries after expansion (default 100,000).
	WordlistMaxSize int

	// --- Extension handling (dirsearch semantics) ---

	// ForceExtensions appends every extension to every path (including those
	// that already have one), plus a trailing-slash variant.
	ForceExtensions bool
	// OverwriteExtensions replaces the extension of paths that already have one,
	// except for excluded media/config extensions.
	OverwriteExtensions bool
	// Prefixes are prepended to each dictionary entry (e.g. "test_", "staging_").
	Prefixes []string
	// Suffixes are appended to each dictionary entry (e.g. "_old", ".bak").
	Suffixes []string

	// --- Recursion (all off by default) ---

	// Recursive enables recursion into discovered directory paths (ending in /).
	Recursive bool
	// DeepRecursive adds every ancestor directory of a discovered path.
	DeepRecursive bool
	// ForceRecursive appends "/" to any discovered path to force directory recursion.
	ForceRecursive bool
	// RecursionDepth caps the recursion depth (0 = unlimited).
	RecursionDepth int
	// RecursionStatus lists status codes that trigger recursion (e.g. [200,301]).
	// Empty means any 2xx triggers recursion.
	RecursionStatus []int
	// ExcludeSubdirs is a blacklist of subpath fragments; matched directories
	// are not recursed into.
	ExcludeSubdirs []string

	// --- crawl (off by default) ---

	// Crawl enables link extraction from discovered responses.
	Crawl bool

	// --- Wildcard / soft-404 detection ---

	// EnableWildcardDetect enables per-directory soft-404 auto-calibration (default true).
	EnableWildcardDetect bool
	// WildcardThreshold is the number of identical response fingerprints before
	// a path is classified as wildcard (default 8; 3 when auto-calibrate fires).
	WildcardThreshold int
	// AutoWAFDetected is set by the auto mode preflight to record whether the
	// target looked WAF- or challenge-protected.
	AutoWAFDetected bool

	// --- Basic filters ---

	// ExcludeStatusCodes omits responses with these status codes
	// (default [400,404,500,502,503]).
	ExcludeStatusCodes []int
	// MinSize / MaxSize filter by response body byte count.
	MinSize, MaxSize int
	// ExcludeTexts rejects any response whose body contains one of these strings.
	ExcludeTexts []string
	// ExcludeRegexes rejects any response whose body matches one of these regexes.
	ExcludeRegexes []string

	// --- Advanced Matcher / Filter ---

	// Matcher fields: responses must satisfy these to be reported.
	MatchStatus, MatchSize, MatchWords, MatchLines, MatchRegex, MatchHeader, MatchTime string
	// Filter fields: responses must NOT satisfy these to be reported.
	FilterStatus, FilterSize, FilterWords, FilterLines, FilterRegex, FilterHeader, FilterTime string
	// MatcherMode / FilterMode combine conditions: "and" | "or" (default "or").
	MatcherMode, FilterMode string

	// --- Error recovery ---

	// MaxConsecutiveErrors is the number of consecutive request errors per
	// directory before scanning that directory is abandoned (default 8).
	MaxConsecutiveErrors int
	// MaxTime is an overall scan deadline applied to the context.
	MaxTime time.Duration
	// TargetMaxTime is a per-directory deadline (unused placeholder for now).
	TargetMaxTime time.Duration
}

// Result represents a single discovered path.
type Result struct {
	// URL is the full discovered URL.
	URL string
	// Path is the path relative to BaseURL.
	Path string
	// StatusCode is the HTTP response status.
	StatusCode int
	// ContentLength is the response body size in bytes.
	ContentLength int
	// ContentType is the response Content-Type header value.
	ContentType string
	// ResponseTime is the round-trip duration.
	ResponseTime time.Duration
	// RedirectURL is the Location header value for 3xx responses.
	RedirectURL string
	// Category classifies the finding (vcs/config/backup/leak/framework/common).
	Category ResultCategory
	// BodyHash is the xxhash-derived fingerprint of the response body.
	BodyHash string
	// Words is the word count in the response body.
	Words int
	// Lines is the line count in the response body.
	Lines int
}

// Run executes the directory scan described by cfg and returns all discovered
// results. The caller is responsible for scope validation before calling Run.
// ctx cancellation propagates to all in-flight requests.
func Run(ctx context.Context, cfg *Config) ([]Result, error) {
	s, err := newScanner(cfg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.engine.Close() }()
	return s.run(ctx)
}
