package fingerprint

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// WebfingerMatcher owns compiled webfinger/custom YAML rules, AST keyword
// indexes and captured icon hashes, just as the JSON sources own their indexes.
type WebfingerMatcher struct {
	fps         []*Fingerprint
	hashMatcher *HashMatcher
	acIndex     *ACIndex
}

// LoadWebfingerYAML compiles native webfinger YAML without accessing files or
// creating a network Engine. Invalid individual expressions retain the existing
// compiler's skip behavior; empty input returns an empty matcher.
func LoadWebfingerYAML(data []byte) (*WebfingerMatcher, error) {
	res, err := compileWebfingerYAML(data, "webfinger")
	if err != nil {
		return nil, err
	}
	return &WebfingerMatcher{fps: res.Fingerprints, hashMatcher: res.HashMatcher, acIndex: res.ACIndex}, nil
}

// Len reports distinct technology names, including icon-only fingerprints.
func (m *WebfingerMatcher) Len() int {
	if m == nil {
		return 0
	}
	names := map[string]struct{}{}
	for _, fp := range m.fps {
		names[fp.Name] = struct{}{}
	}
	if m.hashMatcher != nil {
		for _, fps := range m.hashMatcher.hashToFingerprints {
			for _, fp := range fps {
				names[fp.Name] = struct{}{}
			}
		}
	}
	return len(names)
}

func loadWebfingerMatcher(ctx context.Context, cfg Config, strict bool, logger *slog.Logger) (*WebfingerMatcher, error) {
	m := &WebfingerMatcher{hashMatcher: NewHashMatcher(), acIndex: &ACIndex{}}
	if len(cfg.WebfingerYAML) > 0 {
		loaded, err := LoadWebfingerYAML(cfg.WebfingerYAML)
		if err != nil {
			if strict {
				return nil, err
			}
			logger.Warn("fingerprint: failed to compile caller-supplied webfinger rules", "err", err)
		} else {
			m = loaded
		}
		if strict && m.Len() == 0 {
			return nil, fmt.Errorf("fingerprint: enabled webfinger has no valid rules")
		}
	}
	if cfg.CustomRulesDir != "" {
		fps, hashes, err := m.loadCustomRules(ctx, cfg.CustomRulesDir, logger)
		if err != nil {
			logger.Warn("fingerprint: failed to load custom rules", "dir", cfg.CustomRulesDir, "err", err)
		} else {
			m.fps = append(m.fps, fps...)
			m.mergeHashMatcher(hashes)
		}
		m.acIndex = buildACIndex(m.fps)
	}
	return m, nil
}

func (m *WebfingerMatcher) match(ctx context.Context, mc *MatchContext) []Artifact {
	if m == nil || mc == nil || mc.Response == nil || ctx.Err() != nil {
		return nil
	}
	// Reuse decoded body/header data; the index-specific hit set stays local.
	local := *mc
	local.Hits = map[Field]map[string]bool{}
	populateACHits(&local, m.acIndex)
	var out []Artifact
	if hash := local.Response.FaviconHash; hash != 0 && m.hashMatcher != nil {
		for _, fp := range m.hashMatcher.Match(hash) {
			out = appendArtifact(out, Artifact{Type: fp.Type, Name: fp.Name, Confidence: 100, Source: fp.Source})
		}
	}
	for _, fp := range m.fps {
		if ctx.Err() != nil {
			break
		}
		if matchFingerprint(fp, &local) {
			out = appendArtifact(out, Artifact{Type: fp.Type, Name: fp.Name, Confidence: 100, Source: fp.Source})
		}
	}
	return out
}

// matchFingerprint returns true if any of fp.Rules match ctx (OR semantics).
func matchFingerprint(fp *Fingerprint, ctx *MatchContext) bool {
	for _, rule := range fp.Rules {
		if rule.Match(ctx) {
			return true
		}
	}
	return false
}

// mergeHashMatcher merges src into the webfinger icon index.
func (m *WebfingerMatcher) mergeHashMatcher(src *HashMatcher) {
	if src == nil {
		return
	}
	for h, fps := range src.hashToFingerprints {
		for _, fp := range fps {
			m.hashMatcher.Add(h, fp)
		}
	}
}

// loadCustomRules reads all *.yaml files from dir and compiles them.
func (m *WebfingerMatcher) loadCustomRules(_ context.Context, dir string, logger *slog.Logger) ([]*Fingerprint, *HashMatcher, error) {
	clean := filepath.Clean(dir)
	entries, err := os.ReadDir(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, NewHashMatcher(), nil
		}
		return nil, nil, fmt.Errorf("fingerprint.loadCustomRules: %w", err)
	}

	var allFPS []*Fingerprint
	allHM := NewHashMatcher()

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(clean, entry.Name())
		data, readErr := os.ReadFile(path) //nolint:gosec // path is cleaned and restricted to dir
		if readErr != nil {
			logger.Warn("fingerprint: skip custom rule file", "path", path, "err", readErr)
			continue
		}
		res, compErr := compileWebfingerYAML(data, "custom")
		if compErr != nil {
			logger.Warn("fingerprint: skip malformed custom rule file", "path", path, "err", compErr)
			continue
		}
		allFPS = append(allFPS, res.Fingerprints...)
		for h, fps := range res.HashMatcher.hashToFingerprints {
			for _, fp := range fps {
				allHM.Add(h, fp)
			}
		}
	}
	return allFPS, allHM, nil
}
