package dirscan

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

// WordlistMaxSizeDefault is the default cap on total wordlist entries.
const WordlistMaxSizeDefault = 100_000

// BuildWordlist assembles and deduplicates the wordlist according to cfg.Preset
// (or cfg.Wordlist when non-empty), expands templates and extensions, and
// enforces WordlistMaxSize.
func BuildWordlist(cfg *Config) ([]string, error) {
	maxSize := cfg.WordlistMaxSize
	if maxSize <= 0 {
		maxSize = WordlistMaxSizeDefault
	}

	var raw []string
	var err error

	if len(cfg.Wordlist) > 0 {
		// Caller-supplied wordlist takes precedence over preset.
		raw = make([]string, len(cfg.Wordlist))
		copy(raw, cfg.Wordlist)
	} else {
		raw, err = loadPreset(cfg)
		if err != nil {
			return nil, fmt.Errorf("dirscan.BuildWordlist: %w", err)
		}
	}

	// Expand %EXT% and other placeholders.
	exts := cfg.Extensions
	if len(exts) == 0 {
		exts = []string{"php", "html", "asp", "jsp"}
	}
	vars := templateVars(exts)
	var expanded []string
	for _, entry := range raw {
		if strings.Contains(entry, "%") {
			expanded = append(expanded, ExpandTemplate(entry, vars)...)
		} else {
			expanded = append(expanded, entry)
		}
	}

	// Apply extension fuzz / overwrite.
	expanded = applyExtensions(expanded, cfg, exts)

	// Apply prefixes and suffixes.
	expanded = applyPrefixSuffix(expanded, cfg.Prefixes, cfg.Suffixes)

	// Deduplicate (preserve first-occurrence order).
	seen := make(map[string]struct{}, len(expanded))
	deduped := make([]string, 0, len(expanded))
	for _, p := range expanded {
		key := normalizePath(p)
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			deduped = append(deduped, p)
		}
	}

	if len(deduped) > maxSize {
		return nil, fmt.Errorf("dirscan.BuildWordlist: wordlist exceeds max size %d (got %d)", maxSize, len(deduped))
	}
	return deduped, nil
}

// normalizePath lowercases and strips leading/trailing slashes for dedup keys.
func normalizePath(p string) string {
	p = strings.ToLower(p)
	p = strings.Trim(p, "/")
	return p
}

// loadPreset loads the raw paths for the given preset.
func loadPreset(cfg *Config) ([]string, error) {
	base, err := explicitWordlistDir(cfg.WordlistDir)
	if err != nil {
		return nil, err
	}

	var paths []string
	preset := cfg.Preset
	if preset == "" {
		preset = PresetQuick
	}

	switch preset {
	case PresetQuick:
		paths, err = loadCategory(base, "common.txt")
		if err != nil {
			return nil, err
		}
		if len(cfg.Fingerprint) > 0 {
			fw, _ := LoadFrameworkByFingerprint(base, cfg.Fingerprint)
			paths = append(paths, fw...)
		}
		return paths, nil
	case PresetFull:
		paths, err = loadCategories(base, "common.txt", "conf.txt", "db.txt", "backups.txt",
			"keys.txt", "logs.txt", "vcs.txt", "leak.txt")
		if err != nil {
			return nil, err
		}
		main, merr := loadFile(filepath.Join(base, "dicc.txt"))
		if merr == nil {
			paths = append(paths, main...)
		}
		// Framework fingerprint dict.
		if len(cfg.Fingerprint) > 0 {
			fw, ferr := LoadFrameworkByFingerprint(base, cfg.Fingerprint)
			if ferr == nil {
				paths = append(paths, fw...)
			}
		}
		return paths, nil
	case PresetLeak:
		paths, err = loadCategories(base, "vcs.txt", "conf.txt", "keys.txt", "leak.txt")
		if err != nil {
			return nil, err
		}
		if len(cfg.Fingerprint) > 0 {
			fw, _ := LoadFrameworkByFingerprint(base, cfg.Fingerprint)
			paths = append(paths, fw...)
		}
		return paths, nil
	case PresetBackup:
		paths, err = loadCategory(base, "backups.txt")
		if err != nil {
			return nil, err
		}
		if len(cfg.Fingerprint) > 0 {
			fw, _ := LoadFrameworkByFingerprint(base, cfg.Fingerprint)
			paths = append(paths, fw...)
		}
		return paths, nil
	case PresetFramework:
		if len(cfg.Fingerprint) > 0 {
			return LoadFrameworkByFingerprint(base, cfg.Fingerprint)
		}
		if cfg.Framework != "" {
			return loadFrameworkByName(base, cfg.Framework)
		}
		return nil, fmt.Errorf("dirscan.loadPreset: preset=framework requires Fingerprint or Framework")
	case PresetCustom:
		if len(cfg.CustomWordlists) == 0 {
			return nil, fmt.Errorf("dirscan.loadPreset: preset=custom requires CustomWordlists")
		}
		for _, name := range cfg.CustomWordlists {
			if err := validateCustomName(name); err != nil {
				return nil, err
			}
			safe := filepath.Join(base, "custom", filepath.Clean(name))
			if !strings.HasPrefix(safe, filepath.Join(base, "custom")+string(filepath.Separator)) {
				return nil, fmt.Errorf("dirscan.loadPreset: load custom wordlist %q: path escapes custom directory", name)
			}
			entries, cerr := loadFile(safe)
			if cerr != nil {
				return nil, fmt.Errorf("dirscan.loadPreset: load custom wordlist %q: %w", name, cerr)
			}
			paths = append(paths, entries...)
		}
		return paths, nil
	default:
		return nil, fmt.Errorf("dirscan.loadPreset: unknown preset %q", preset)
	}
}

// validateCustomName rejects custom wordlist names that could cause path
// traversal: absolute paths and any component containing "..".
func validateCustomName(name string) error {
	if filepath.IsAbs(name) {
		return fmt.Errorf("dirscan.validateCustomName: absolute path not allowed: %q", name)
	}
	for _, part := range strings.Split(name, string(filepath.Separator)) {
		if part == ".." {
			return fmt.Errorf("dirscan.validateCustomName: path traversal not allowed: %q", name)
		}
	}
	return nil
}

// loadCategory loads a single category file.
func loadCategory(base, filename string) ([]string, error) {
	p := filepath.Join(base, "categories", filename)
	entries, err := loadFile(p)
	if err != nil {
		// Gracefully degrade if the file doesn't exist yet.
		return nil, nil
	}
	return entries, nil
}

// loadCategories loads multiple category files, merging their entries.
func loadCategories(base string, filenames ...string) ([]string, error) {
	var all []string
	for _, f := range filenames {
		entries, err := loadCategory(base, f)
		if err != nil {
			continue
		}
		all = append(all, entries...)
	}
	return all, nil
}

// LoadWordlist loads a wordlist from path. path may carry a "CATEGORY:" prefix
// to resolve relative to the categories directory. Lines starting with "#" and
// blank lines are ignored.
func LoadWordlist(base, path string) ([]string, error) {
	if strings.HasPrefix(path, "CATEGORY:") {
		var err error
		base, err = explicitWordlistDir(base)
		if err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(path, "CATEGORY:")
		if err := validateCustomName(name); err != nil {
			return nil, err
		}
		if strings.HasSuffix(name, "/*") {
			return loadDir(filepath.Join(base, "categories", strings.TrimSuffix(name, "/*")))
		}
		path = filepath.Join(base, "categories", name)
	}
	return loadFile(path)
}

// loadDir loads all .txt files from a directory (non-recursive).
func loadDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("dirscan.loadDir: %w", err)
	}
	var all []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		lines, err := loadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		all = append(all, lines...)
	}
	return all, nil
}

// loadFile reads a wordlist file, stripping comments and blank lines.
func loadFile(path string) ([]string, error) {
	f, err := os.Open(path) //nolint:gosec // path validated by caller
	if err != nil {
		return nil, fmt.Errorf("dirscan.loadFile: %w", err)
	}
	defer func() { _ = f.Close() }()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}

// LoadFrameworkByFingerprint maps fingerprint labels to framework wordlist paths
// and merges their entries. Unrecognised labels are silently skipped.
func LoadFrameworkByFingerprint(base string, fingerprints []string) ([]string, error) {
	base, err := explicitWordlistDir(base)
	if err != nil {
		return nil, fmt.Errorf("dirscan.LoadFrameworkByFingerprint: %w", err)
	}
	var all []string
	for _, fp := range fingerprints {
		p := frameworkPath(base, fp)
		if p == "" {
			continue
		}
		entries, err := loadFile(p)
		if err != nil {
			continue // degrade gracefully
		}
		all = append(all, entries...)
	}
	return all, nil
}

// loadFrameworkByName loads a single named framework dictionary.
func loadFrameworkByName(base, name string) ([]string, error) {
	p := frameworkPath(base, name)
	if p == "" {
		return nil, fmt.Errorf("dirscan.loadFrameworkByName: unknown framework %q", name)
	}
	return loadFile(p)
}

// frameworkPath returns the file path for a known framework label.
// Returns empty string when the label is unknown.
func frameworkPath(base, label string) string {
	label = strings.ToLower(label)
	known := map[string]string{
		"wordpress": filepath.Join(base, "categories", "php", "wordpress.txt"),
		"laravel":   filepath.Join(base, "categories", "php", "laravel.txt"),
		"symfony":   filepath.Join(base, "categories", "php", "symfony.txt"),
		"joomla":    filepath.Join(base, "categories", "php", "joomla.txt"),
		"drupal":    filepath.Join(base, "categories", "php", "drupal.txt"),
		"magento":   filepath.Join(base, "categories", "php", "magento.txt"),
		"django":    filepath.Join(base, "categories", "python", "django.txt"),
		"flask":     filepath.Join(base, "categories", "python", "flask.txt"),
		"fastapi":   filepath.Join(base, "categories", "python", "fastapi.txt"),
		"spring":    filepath.Join(base, "categories", "java", "spring.txt"),
		"struts":    filepath.Join(base, "categories", "java", "struts.txt"),
		"express":   filepath.Join(base, "categories", "node", "express.txt"),
		"aspx":      filepath.Join(base, "categories", "dotnet", "aspx.txt"),
		"docker":    filepath.Join(base, "categories", "infra", "docker.txt"),
		"k8s":       filepath.Join(base, "categories", "infra", "k8s.txt"),
		"aws":       filepath.Join(base, "categories", "infra", "aws.txt"),
	}
	if p, ok := known[label]; ok {
		return p
	}
	return ""
}

// ExpandTemplate expands a template string that may contain %PLACEHOLDER%
// tokens by computing the Cartesian product of all variable values.
// Unknown placeholders are left unchanged.
func ExpandTemplate(tmpl string, vars map[string][]string) []string {
	results := []string{tmpl}
	for key, vals := range vars {
		token := "%" + key + "%"
		if !strings.Contains(tmpl, token) {
			continue
		}
		var next []string
		for _, cur := range results {
			for _, v := range vals {
				next = append(next, strings.ReplaceAll(cur, token, v))
			}
		}
		results = next
	}
	return results
}

// templateVars builds the default variable map for template expansion.
func templateVars(exts []string) map[string][]string {
	now := time.Now()
	return map[string][]string{
		"EXT":     exts,
		"SUBJECT": {"user", "article", "product", "order", "admin"},
		"ENV":     {"dev", "test", "staging", "prod"},
		"DB":      {"mysql", "postgres", "redis"},
		"ARCHIVE": {"zip", "tar", "gz", "7z"},
		"YYYY":    {now.Format("2006")},
		"YY":      {now.Format("06")},
		"MM":      {now.Format("01")},
		"DD":      {now.Format("02")},
	}
}

// excludedOverwriteExts are extensions that should not be replaced by
// OverwriteExtensions mode (media/config/data formats).
var excludedOverwriteExts = map[string]bool{
	"js": true, "json": true, "css": true, "xml": true,
	"yml": true, "yaml": true, "ini": true, "conf": true,
	"png": true, "jpg": true, "jpeg": true, "gif": true,
	"svg": true, "ico": true, "pdf": true, "mp4": true,
	"woff": true, "woff2": true, "ttf": true,
}

// applyExtensions handles ForceExtensions and OverwriteExtensions modes.
// When neither flag is set it applies the default fuzz: paths with no
// extension and not ending in "/" get each extension appended (original
// preserved); paths with %EXT% already replaced by ExpandTemplate are left
// alone.
func applyExtensions(paths []string, cfg *Config, exts []string) []string {
	if len(exts) == 0 {
		return paths
	}
	var out []string
	for _, p := range paths {
		ext := fileExt(p)
		isDir := strings.HasSuffix(p, "/")

		switch {
		case cfg.ForceExtensions:
			// Append each extension; also keep original and dir variant.
			out = append(out, p)
			if !isDir {
				out = append(out, p+"/")
			}
			for _, e := range exts {
				if excludedOverwriteExts[ext] {
					out = append(out, p)
				} else {
					out = append(out, p+"."+e)
				}
			}
		case cfg.OverwriteExtensions && ext != "" && !excludedOverwriteExts[ext]:
			// Replace extension.
			stem := strings.TrimSuffix(p, "."+ext)
			for _, e := range exts {
				out = append(out, stem+"."+e)
			}
		default:
			// Default fuzz: no extension + not a dir → append extensions.
			out = append(out, p)
			if ext == "" && !isDir {
				for _, e := range exts {
					out = append(out, p+"."+e)
				}
			}
		}
	}
	return out
}

// fileExt returns the file extension without the dot, or empty string.
// A dotfile like ".hidden" (base name starts with ".") has no extension.
func fileExt(path string) string {
	base := filepath.Base(path)
	// Dotfiles (base starts with ".") are not considered to have an extension.
	if strings.HasPrefix(base, ".") {
		// Only treat the part after the first dot as an extension if there are
		// additional dots (e.g. ".env.local" → "local").
		rest := base[1:]
		if idx := strings.LastIndex(rest, "."); idx >= 0 {
			candidate := rest[idx+1:]
			if isExtCandidate(candidate) {
				return strings.ToLower(candidate)
			}
		}
		return ""
	}
	if idx := strings.LastIndex(base, "."); idx >= 0 {
		candidate := base[idx+1:]
		if isExtCandidate(candidate) {
			return strings.ToLower(candidate)
		}
	}
	return ""
}

// isExtCandidate reports whether s looks like a valid file extension:
// non-empty, ≤10 chars, all ASCII letters or digits.
func isExtCandidate(s string) bool {
	if len(s) == 0 || len(s) > 10 {
		return false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// applyPrefixSuffix generates additional wordlist entries by prepending
// prefixes and appending suffixes to each existing entry.
func applyPrefixSuffix(paths, prefixes, suffixes []string) []string {
	if len(prefixes) == 0 && len(suffixes) == 0 {
		return paths
	}
	out := make([]string, 0, len(paths)*(1+len(prefixes)+len(suffixes)))
	out = append(out, paths...)
	for _, p := range paths {
		for _, pre := range prefixes {
			out = append(out, pre+p)
		}
		for _, suf := range suffixes {
			out = append(out, p+suf)
		}
	}
	return out
}

// GenerateBackupNames generates backup filename variations for a given filename.
// It combines date-based and suffix-based patterns.
func GenerateBackupNames(filename string, cfg *Config) []string {
	now := time.Now()
	suffixes := []string{
		".bak", ".backup", ".old", ".orig", ".copy", ".tmp",
		".zip", ".tar.gz", ".tar", ".gz", ".7z", ".rar",
		"~", ".swp",
	}
	dates := []string{
		now.Format("20060102"),
		now.Format("2006-01-02"),
		now.Format("200601"),
		now.Format("2006"),
	}

	ext := fileExt(filename)
	stem := filename
	if ext != "" {
		stem = strings.TrimSuffix(filename, "."+ext)
	}

	seen := make(map[string]struct{})
	add := func(s string) string {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			return s
		}
		return ""
	}

	var out []string
	for _, suf := range suffixes {
		if v := add(filename + suf); v != "" {
			out = append(out, v)
		}
		if ext != "" {
			if v := add(stem + suf + "." + ext); v != "" {
				out = append(out, v)
			}
		}
	}
	for _, d := range dates {
		for _, suf := range suffixes {
			if v := add(stem + "_" + d + suf); v != "" {
				out = append(out, v)
			}
		}
	}
	_ = cfg // reserved for future use (custom suffix lists)
	return out
}

// explicitWordlistDir requires caller-owned resources; it never creates files.
func explicitWordlistDir(base string) (string, error) {
	if base == "" {
		return "", fmt.Errorf("dirscan: WordlistDir is required when Wordlist is empty")
	}
	return filepath.Clean(base), nil
}
