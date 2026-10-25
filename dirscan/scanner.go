package dirscan

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"netrt.local/netrt"

	http "github.com/bogdanfinn/fhttp"
)

// scanner is the orchestrator that owns the directories queue and drives the
// netrt engine through the scan lifecycle. It maps to dirsearch's Controller.
type scanner struct {
	cfg     *Config
	engine  *netrt.Engine
	filter  *filterChain
	baseURL *url.URL

	mu         sync.Mutex
	passedURLs map[string]bool // visited directory URLs (dedup for recursion)
	bodyHashes map[string]bool // seen body hashes (response dedup)
	results    []Result
	consecErrs int // consecutive error counter for current directory
}

// newScanner validates cfg and constructs a scanner.
func newScanner(cfg *Config) (*scanner, error) {
	if cfg == nil {
		return nil, fmt.Errorf("dirscan.newScanner: nil config")
	}
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("dirscan.newScanner: BaseURL is required")
	}

	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("dirscan.newScanner: invalid BaseURL: %w", err)
	}

	fc, err := buildFilterChain(cfg)
	if err != nil {
		return nil, fmt.Errorf("dirscan.newScanner: build filter chain: %w", err)
	}

	threads := cfg.Threads
	if threads <= 0 {
		threads = 30
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	eng, err := netrt.New(netrt.Config{
		Threads:       threads,
		Timeout:       timeout,
		Retries:       1,
		MaxHostErrors: cfg.MaxConsecutiveErrors,
	})
	if err != nil {
		return nil, fmt.Errorf("dirscan.newScanner: create engine: %w", err)
	}

	return &scanner{
		cfg:        cfg,
		engine:     eng,
		filter:     fc,
		baseURL:    base,
		passedURLs: make(map[string]bool),
		bodyHashes: make(map[string]bool),
	}, nil
}

// run executes the full scan and returns all results.
func (s *scanner) run(ctx context.Context) ([]Result, error) {
	if s.cfg.MaxTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.MaxTime)
		defer cancel()
	}

	if err := s.prepareScan(ctx); err != nil {
		return nil, fmt.Errorf("dirscan.scanner.run: prepare scan: %w", err)
	}

	// Build the wordlist.
	wordlist, err := BuildWordlist(s.cfg)
	if err != nil {
		return nil, fmt.Errorf("dirscan.scanner.run: %w", err)
	}
	if len(wordlist) == 0 {
		return nil, nil
	}

	// Initial directory queue: start with the BaseURL path.
	startPath := s.baseURL.Path
	if !strings.HasSuffix(startPath, "/") {
		startPath += "/"
	}
	directories := []string{startPath}

	s.mu.Lock()
	s.passedURLs[startPath] = true
	s.mu.Unlock()

	threshold := s.cfg.WildcardThreshold
	if threshold <= 0 {
		threshold = 8
	}
	enableWC := s.cfg.EnableWildcardDetect
	// Default to enabled.
	if !enableWC && s.cfg.WildcardThreshold == 0 && !s.cfg.EnableWildcardDetect {
		enableWC = true
	}

	// Process directories one at a time (recursive main loop).
	for len(directories) > 0 {
		if ctx.Err() != nil {
			break
		}
		dir := directories[0]
		directories = directories[1:]

		s.consecErrs = 0

		// Build WildcardProfile for this directory.
		var wp *WildcardProfile
		if enableWC {
			wp = s.buildWildcardProfile(ctx, dir, threshold)
		}

		// Collect _items for this directory.
		items := make([]string, len(wordlist))
		copy(items, wordlist)

		// _extra queue: paths discovered by crawl (consumed first).
		extra := make([]string, 0)
		extraSet := make(map[string]bool)

		// Process _extra then _items.
		for {
			var path string
			if len(extra) > 0 {
				path = extra[0]
				extra = extra[1:]
			} else if len(items) > 0 {
				path = items[0]
				items = items[1:]
			} else {
				break
			}

			if ctx.Err() != nil {
				break
			}

			maxErr := s.cfg.MaxConsecutiveErrors
			if maxErr <= 0 {
				maxErr = 8
			}
			if s.consecErrs >= maxErr {
				break
			}

			fullURL := joinURL(s.cfg.BaseURL, dir, path)

			resp, err := s.engine.Send(ctx, s.buildRequest(fullURL))
			if err != nil {
				s.consecErrs++
				continue
			}
			s.consecErrs = 0

			if resp.Error != nil {
				s.consecErrs++
				continue
			}

			// Classify against wildcard profile.
			classification := "unique"
			if wp != nil {
				classification = wp.Classify(path, resp)
			}
			if classification == "wildcard" {
				continue
			}

			// Apply filter chain.
			if !s.filter.Keep(resp) {
				continue
			}

			// Response body dedup.
			bh := bodyHash(resp.Body)
			s.mu.Lock()
			if s.bodyHashes[bh] {
				s.mu.Unlock()
				continue
			}
			s.bodyHashes[bh] = true
			s.mu.Unlock()

			// Count words and lines for Matcher/Filter.
			words, lines := countWordsLines(resp.Body)
			resp.WordCount = words
			resp.LineCount = lines

			// Categorise and report the result.
			relPath := relativePath(dir, path)
			cat := categorizeResult(relPath)
			result := Result{
				URL:           fullURL,
				Path:          relPath,
				StatusCode:    resp.StatusCode,
				ContentLength: len(resp.Body),
				ContentType:   resp.ContentType,
				ResponseTime:  resp.ResponseTime,
				RedirectURL:   resp.Location,
				Category:      cat,
				BodyHash:      bh,
				Words:         words,
				Lines:         lines,
			}
			s.mu.Lock()
			s.results = append(s.results, result)
			s.mu.Unlock()

			// Crawl: extract links from response.
			if s.cfg.Crawl {
				links := ExtractLinks(resp, fullURL)
				for _, link := range links {
					if !extraSet[link] {
						extraSet[link] = true
						extra = append(extra, link)
					}
					// Also recurse if it looks like a directory.
					if strings.HasSuffix(link, "/") {
						newDir := joinDirPath(dir, link)
						directories = s.addDirectory(directories, newDir, dir)
					}
				}
			}

			// Recursion decision.
			if s.cfg.Recursive || s.cfg.DeepRecursive || s.cfg.ForceRecursive {
				newDirs := s.recursionDirs(dir, path, resp)
				for _, nd := range newDirs {
					directories = s.addDirectory(directories, nd, dir)
				}
			}
		}
	}

	s.mu.Lock()
	out := make([]Result, len(s.results))
	copy(out, s.results)
	s.mu.Unlock()
	return out, nil
}

// buildWildcardProfile sends two random stealth requests to establish the
// baseline and constructs a WildcardProfile.
func (s *scanner) buildWildcardProfile(ctx context.Context, dir string, threshold int) *WildcardProfile {
	var baselines [2]*netrt.Response
	for i := 0; i < 2; i++ {
		probe := randomStealth()
		fullURL := joinURL(s.cfg.BaseURL, dir, probe)
		resp, err := s.engine.Send(ctx, s.buildRequest(fullURL))
		if err != nil || resp.Error != nil {
			return &WildcardProfile{
				FingerprintCounts: make(map[string]int),
				Threshold:         threshold,
			}
		}
		baselines[i] = resp
	}
	return newWildcardProfile(baselines, threshold)
}

// buildRequest creates a netrt.Request for the given URL with configured headers.
func (s *scanner) buildRequest(fullURL string) *netrt.Request {
	req := &netrt.Request{
		Method:  http.MethodGet,
		URL:     fullURL,
		Header:  http.Header{},
		Profile: netrt.ProfileByName(s.cfg.TLSProfile),
		Timeout: s.cfg.Timeout,
	}
	if s.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", s.cfg.UserAgent)
	}
	for k, v := range s.cfg.Headers {
		req.Header.Set(k, v)
	}
	return req
}

// recursionDirs returns new directory paths to recurse into based on the
// discovered path and response, according to the configured recursion mode.
func (s *scanner) recursionDirs(baseDir, path string, resp *netrt.Response) []string {
	var dirs []string

	// Check recursion-status: only recurse when status is in RecursionStatus.
	if len(s.cfg.RecursionStatus) > 0 {
		statusOK := false
		for _, st := range s.cfg.RecursionStatus {
			if resp.StatusCode == st {
				statusOK = true
				break
			}
		}
		if !statusOK {
			// Redirect-only check: if redirect target is path+"/" we recurse.
			if isRedirect(resp.StatusCode) {
				canonical := joinDirPath(baseDir, path)
				if !strings.HasSuffix(canonical, "/") {
					canonical += "/"
				}
				if cleanPath(resp.Location) == canonical {
					dirs = append(dirs, canonical)
				}
			}
			return dirs
		}
	}

	switch {
	case s.cfg.ForceRecursive:
		// Force-append "/" to any discovered path.
		forcePath := joinDirPath(baseDir, path)
		if !strings.HasSuffix(forcePath, "/") {
			forcePath += "/"
		}
		dirs = append(dirs, forcePath)

	case s.cfg.DeepRecursive:
		// Add every ancestor directory.
		full := joinDirPath(baseDir, path)
		segments := strings.Split(strings.Trim(full, "/"), "/")
		for i := range segments {
			ancestor := "/" + strings.Join(segments[:i+1], "/") + "/"
			dirs = append(dirs, ancestor)
		}

	case s.cfg.Recursive:
		// Only recurse directory paths (ending in /).
		full := joinDirPath(baseDir, path)
		if strings.HasSuffix(path, "/") || fileExt(path) == "" {
			if !strings.HasSuffix(full, "/") {
				full += "/"
			}
			dirs = append(dirs, full)
		}
	}

	// Redirect "path/" canonicalization.
	if isRedirect(resp.StatusCode) && resp.Location != "" {
		loc := cleanPath(resp.Location)
		canon := joinDirPath(baseDir, path)
		if !strings.HasSuffix(canon, "/") {
			canon += "/"
		}
		if loc == canon {
			dirs = append(dirs, canon)
		}
	}

	return dirs
}

// addDirectory adds newDir to the queue if it passes the three-check gate:
// 1. Not in exclude-subdirs blacklist.
// 2. Within recursion depth.
// 3. Not already visited.
func (s *scanner) addDirectory(queue []string, newDir, baseDir string) []string {
	// 1. Exclude-subdirs blacklist.
	for _, excl := range s.cfg.ExcludeSubdirs {
		if strings.Contains(newDir, excl) {
			return queue
		}
	}

	// 2. Recursion depth.
	if s.cfg.RecursionDepth > 0 {
		depth := depthOf(newDir, baseDir)
		if depth > s.cfg.RecursionDepth {
			return queue
		}
	}

	// 3. Dedup.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.passedURLs[newDir] {
		return queue
	}
	s.passedURLs[newDir] = true
	return append(queue, newDir)
}

// depthOf returns the number of path segments that newDir adds relative to baseDir.
func depthOf(newDir, baseDir string) int {
	rel := strings.TrimPrefix(newDir, baseDir)
	rel = strings.Trim(rel, "/")
	if rel == "" {
		return 0
	}
	return len(strings.Split(rel, "/"))
}

// joinURL assembles a full URL by joining the base URL, directory path, and
// dictionary entry path. It preserves the base scheme/host and ensures the
// path stays within the base URL's subtree.
func joinURL(baseURL, dir, path string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return baseURL + dir + path
	}
	// dir is an absolute path like "/app/api/"; path is a relative segment.
	joined := strings.TrimRight(dir, "/") + "/" + strings.TrimLeft(path, "/")
	base.Path = joined
	base.RawQuery = ""
	return base.String()
}

// joinDirPath combines a directory base path with a sub-path.
func joinDirPath(dir, sub string) string {
	d := strings.TrimRight(dir, "/")
	s := strings.TrimLeft(sub, "/")
	if s == "" {
		return d + "/"
	}
	return d + "/" + s
}

// relativePath strips the directory prefix from a path to get the portion
// relative to the scan base.
func relativePath(dir, path string) string {
	full := joinDirPath(dir, path)
	return full
}

// countWordsLines returns the word and line counts for body text.
func countWordsLines(body []byte) (words, lines int) {
	text := string(body)
	for _, line := range strings.Split(text, "\n") {
		if line != "" {
			lines++
		}
		for _, f := range strings.Fields(line) {
			if f != "" {
				words++
			}
		}
	}
	return words, lines
}

// prepareScan initializes shared resources, performs auto-mode preflight, and
// rebuilds the runtime engine with the final tuning decisions.
func (s *scanner) prepareScan(ctx context.Context) error {

	if s.cfg.Mode == ModeAuto && s.cfg.Preset == "" {
		if err := TuneAutoConfig(ctx, s.cfg); err != nil {
			return err
		}
	}

	if s.cfg.Preset == "" {
		s.cfg.Preset = PresetQuick
	}
	if s.cfg.Threads <= 0 {
		s.cfg.Threads = 30
	}
	if s.cfg.WildcardThreshold <= 0 {
		s.cfg.WildcardThreshold = 8
	}

	eng, err := netrt.New(netrt.Config{
		Threads:       s.cfg.Threads,
		Timeout:       effectiveTimeout(s.cfg.Timeout),
		Retries:       1,
		MaxHostErrors: s.cfg.MaxConsecutiveErrors,
	})
	if err != nil {
		return fmt.Errorf("dirscan.prepareScan: create engine: %w", err)
	}
	_ = s.engine.Close()
	s.engine = eng
	return nil
}

type autoProfile struct {
	preset      ScanPreset
	threads     int
	wafDetected bool
}

// detectAutoProfile performs a small preflight against random paths and returns
// a recommended preset / thread count for auto mode.
func (s *scanner) detectAutoProfile(ctx context.Context) (*autoProfile, error) {
	profile := &autoProfile{
		preset:  PresetQuick,
		threads: s.cfg.Threads,
	}
	if profile.threads <= 0 {
		profile.threads = 20
	}
	if profile.threads > 20 {
		profile.threads = 20
	}

	probeEng, err := netrt.New(netrt.Config{
		Threads:       2,
		Timeout:       minDuration(effectiveTimeout(s.cfg.Timeout), 5*time.Second),
		Retries:       0,
		MaxHostErrors: 2,
	})
	if err != nil {
		return nil, fmt.Errorf("dirscan.detectAutoProfile: create probe engine: %w", err)
	}

	defer probeEng.Close()
	startPath := s.baseURL.Path
	if !strings.HasSuffix(startPath, "/") {
		startPath += "/"
	}
	statuses := make([]int, 0, 2)
	var bodies [][]byte
	for i := 0; i < 2; i++ {
		probe := randomStealth()
		fullURL := joinURL(s.cfg.BaseURL, startPath, probe)
		resp, sendErr := probeEng.Send(ctx, s.buildRequest(fullURL))
		if sendErr != nil || resp == nil || resp.Error != nil {
			continue
		}
		statuses = append(statuses, resp.StatusCode)
		bodies = append(bodies, resp.Body)
		if isWAFResponse(resp) {
			profile.wafDetected = true
		}
	}

	if len(statuses) >= 2 {
		if statuses[0] == statuses[1] && bytes.Equal(bodies[0], bodies[1]) {
			// Highly stable responses usually mean a catch-all page; keep the scan
			// conservative by lowering concurrency a bit even if it isn't a WAF.
			profile.threads = minInt(profile.threads, 15)
		}
	}

	if profile.wafDetected {
		profile.threads = minInt(profile.threads, 10)
		if s.cfg.Preset == "" || s.cfg.Preset == PresetFull {
			profile.preset = PresetLeak
		}
	}

	// Fingerprint-aware default: keep the smaller quick/leak bundles and let the
	// loaded framework dictionaries expand the coverage.
	if s.cfg.Preset != "" {
		profile.preset = s.cfg.Preset
	}
	return profile, nil
}

func isWAFResponse(resp *netrt.Response) bool {
	if resp == nil {
		return false
	}
	switch resp.StatusCode {
	case 403, 406, 429, 503:
		return true
	}
	body := strings.ToLower(string(resp.Body))
	for _, needle := range []string{"captcha", "access denied", "forbidden", "security check", "request blocked", "unusual traffic"} {
		if strings.Contains(body, needle) {
			return true
		}
	}
	return false
}

func effectiveTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return 10 * time.Second
	}
	return timeout
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}
