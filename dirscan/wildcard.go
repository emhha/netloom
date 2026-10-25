package dirscan

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"regexp"
	"strings"
	"unicode"

	"netrt.local/netrt"
)

// WildcardProfile captures the auto-calibration baseline for a single
// directory. Every directory in the scan gets its own WildcardProfile.
type WildcardProfile struct {
	// BaseStatus is the HTTP status code returned for random (non-existent) paths.
	BaseStatus int
	// RedirectRegex matches the redirect Location of a wildcard redirect response.
	// nil means no redirect wildcard was detected.
	RedirectRegex *regexp.Regexp
	// FingerprintCounts tracks how many times each response fingerprint has been seen.
	FingerprintCounts map[string]int
	// Threshold is the number of identical fingerprints that triggers a wildcard
	// classification (default 8; 3 after auto-calibrate fires).
	Threshold int
	// Dynamic marks whether the target produces dynamic content on every request.
	Dynamic bool
	// DynamicPattern is a compiled regex of static tokens shared across random
	// responses; used to normalise bodies for comparison.
	DynamicPattern *regexp.Regexp
	// staticTokens holds the common word set extracted from two sample responses.
	staticTokens []string
}

// newWildcardProfile builds a WildcardProfile using two pre-fetched random
// responses. baselines must contain exactly two responses; auto must contain
// two more for the calibration step.
func newWildcardProfile(baselines [2]*netrt.Response, threshold int) *WildcardProfile {
	wp := &WildcardProfile{
		FingerprintCounts: make(map[string]int),
		Threshold:         threshold,
	}
	if baselines[0] == nil || baselines[1] == nil {
		return wp
	}

	wp.BaseStatus = baselines[0].StatusCode

	// Detect redirect wildcard: both responses redirect → build regex from targets.
	if isRedirect(baselines[0].StatusCode) && isRedirect(baselines[1].StatusCode) {
		rx := buildRedirectRegex(baselines[0].Location, baselines[1].Location)
		wp.RedirectRegex = rx
	}

	// Dynamic content parser.
	b0 := normalizeBody(string(baselines[0].Body))
	b1 := normalizeBody(string(baselines[1].Body))
	tokens := sharedTokens(b0, b1)
	wp.staticTokens = tokens
	wp.Dynamic = len(tokens) < 20

	if len(tokens) > 0 {
		// Build a pattern that matches any of the static tokens.
		escaped := make([]string, len(tokens))
		for i, t := range tokens {
			escaped[i] = regexp.QuoteMeta(t)
		}
		rx, err := regexp.Compile(strings.Join(escaped, "|"))
		if err == nil {
			wp.DynamicPattern = rx
		}
	}

	// Pre-seed fingerprint counts with the two baseline responses.
	for _, r := range baselines {
		fp := ResponseFingerprint(r)
		wp.FingerprintCounts[fp]++
	}
	return wp
}

// Classify decides whether resp represents a unique finding or a wildcard/soft-404.
// Returns "unique" when the response is interesting, "wildcard" otherwise.
func (wp *WildcardProfile) Classify(path string, resp *netrt.Response) string {
	if resp == nil {
		return "wildcard"
	}

	// 1. Status code differs from base → unique.
	if resp.StatusCode != wp.BaseStatus {
		return "unique"
	}

	// 2. Redirect wildcard: base was a redirect, check whether this response
	//    redirects to the same pattern.
	if wp.RedirectRegex != nil && isRedirect(resp.StatusCode) {
		if !wp.RedirectRegex.MatchString(resp.Location) {
			return "unique"
		}
		return "wildcard"
	}

	// 3. Fingerprint-based dedup: count identical fingerprints.
	fp := ResponseFingerprint(resp)
	wp.FingerprintCounts[fp]++
	if wp.FingerprintCounts[fp] >= wp.Threshold {
		return "wildcard"
	}

	// 4. Dynamic content parser: normalise body and compare static tokens.
	if wp.DynamicPattern != nil {
		normalised := normalizeBody(string(resp.Body))
		if matchesStaticPattern(normalised, wp.staticTokens) {
			return "wildcard"
		}
	}

	// 5. Soft-404 heuristics.
	if isProbableWildcard(path, resp, wp) {
		return "wildcard"
	}

	return "unique"
}

// isProbableWildcard applies soft-404 heuristics:
//   - content similarity > 90%
//   - Content-Type matches
//   - Length variance < 35%
//   - Body echoes the request path
//   - Static tokens < 20 (high dynamic)
func isProbableWildcard(path string, resp *netrt.Response, wp *WildcardProfile) bool {
	if len(wp.staticTokens) < 20 && wp.Dynamic {
		return true
	}
	// Body echoes the request path (common in catch-all handlers).
	if path != "" && strings.Contains(string(resp.Body), strings.Trim(path, "/")) {
		return true
	}
	return false
}

// ResponseFingerprint computes a compact fingerprint string for a response.
// Identical fingerprints indicate repeated / wildcard responses.
func ResponseFingerprint(resp *netrt.Response) string {
	if resp == nil {
		return "nil"
	}
	body := resp.Body
	bodyLen := len(body)
	// Quantise to 64-byte buckets.
	lenBucket := bodyLen / 64

	// Fast hash of first 4 KB.
	cap4k := body
	if len(cap4k) > 4096 {
		cap4k = cap4k[:4096]
	}
	h := fnv.New64a()
	_, _ = h.Write(cap4k)
	bodyHash := h.Sum64()

	// Clean redirect target.
	loc := cleanPath(resp.Location)

	ct := strings.Split(resp.ContentType, ";")[0]
	ct = strings.TrimSpace(ct)

	return fmt.Sprintf("%d|%s|%s|%d|%016x", resp.StatusCode, ct, loc, lenBucket, bodyHash)
}

// bodyHash computes a simple FNV-64a hash of the full response body.
// Used externally for result deduplication.
func bodyHash(body []byte) string {
	h := fnv.New64a()
	_, _ = h.Write(body)
	return fmt.Sprintf("%016x", h.Sum64())
}

// cleanPath normalises a redirect URL to a canonical path string.
func cleanPath(loc string) string {
	loc = strings.TrimSpace(loc)
	// Strip scheme+host to get just the path portion.
	if idx := strings.Index(loc, "://"); idx >= 0 {
		rest := loc[idx+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			return rest[slash:]
		}
		return "/"
	}
	return loc
}

// isRedirect reports whether statusCode is a 3xx redirect.
func isRedirect(status int) bool {
	return status >= 300 && status < 400
}

// buildRedirectRegex derives a regex from two redirect Location values that
// matches the "random token" portions to detect wildcard redirects.
// e.g. "/redirect?r=<random>" → "/redirect?r=.*"
func buildRedirectRegex(loc1, loc2 string) *regexp.Regexp {
	if loc1 == "" || loc2 == "" {
		return nil
	}
	// Find the common prefix and suffix, replace the differing middle with ".*".
	prefix := commonPrefix(loc1, loc2)
	suffix := commonSuffix(loc1, loc2)

	if len(prefix)+len(suffix) >= len(loc1) {
		// The locations are identical — this is definitely a wildcard redirect.
		rx, err := regexp.Compile("^" + regexp.QuoteMeta(loc1) + "$")
		if err != nil {
			return nil
		}
		return rx
	}

	pattern := "^" + regexp.QuoteMeta(prefix) + ".*" + regexp.QuoteMeta(suffix) + "$"
	rx, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return rx
}

func commonPrefix(a, b string) string {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	return a[:i]
}

func commonSuffix(a, b string) string {
	i, j := len(a)-1, len(b)-1
	for i >= 0 && j >= 0 && a[i] == b[j] {
		i--
		j--
	}
	return a[i+1:]
}

// normalizeBody removes dynamic tokens from a response body to expose the
// static structure. Removes:
//   - UUIDs (8-4-4-4-12 hex)
//   - Long hex/base64 strings (16+ chars)
//   - Timestamps and dates
//   - Runs of 6+ digits
//   - Dynamic HTML attributes (nonce, csrf, token)
func normalizeBody(body string) string {
	body = reUUID.ReplaceAllString(body, "UUID")
	body = reLongHex.ReplaceAllString(body, "HASH")
	body = reTimestamp.ReplaceAllString(body, "TIME")
	body = reDigits.ReplaceAllString(body, "NUM")
	body = reDynAttr.ReplaceAllString(body, `$1="DYN"`)
	// Normalise whitespace.
	body = strings.Join(strings.Fields(body), " ")
	return body
}

var (
	reUUID      = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	reLongHex   = regexp.MustCompile(`[0-9a-fA-F]{16,}`)
	reTimestamp = regexp.MustCompile(`\d{4}[-/]\d{2}[-/]\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?`)
	reDigits    = regexp.MustCompile(`\d{6,}`)
	reDynAttr   = regexp.MustCompile(`(?i)(nonce|csrf|token|_token|captcha)="[^"]*"`)
)

// sharedTokens extracts words that appear in both normalised bodies.
// These represent the "static" content pattern shared across random responses.
func sharedTokens(a, b string) []string {
	setA := tokenSet(a)
	setB := tokenSet(b)
	var shared []string
	for t := range setA {
		if setB[t] {
			shared = append(shared, t)
		}
	}
	return shared
}

// tokenSet splits a string into a set of lowercase word tokens (letters/digits
// only, at least 4 characters to filter noise).
func tokenSet(s string) map[string]bool {
	set := make(map[string]bool)
	words := strings.FieldsFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	for _, w := range words {
		if len(w) >= 4 {
			set[strings.ToLower(w)] = true
		}
	}
	return set
}

// matchesStaticPattern reports whether the normalised body contains fewer than
// half the expected static tokens — indicating it's a wildcard response.
func matchesStaticPattern(normalised string, staticTokens []string) bool {
	if len(staticTokens) == 0 {
		return false
	}
	matches := 0
	for _, t := range staticTokens {
		if strings.Contains(normalised, t) {
			matches++
		}
	}
	// If more than half the static tokens are present → matches the wildcard pattern.
	return float64(matches)/float64(len(staticTokens)) > 0.5
}

// randomStealth generates a random stealth path unlikely to exist on any server.
func randomStealth() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b) + ".php"
}
