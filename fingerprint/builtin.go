package fingerprint

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
)

// Source identifies a built-in fingerprint rule source.
type Source string

const (
	SourceWebfinger      Source = "webfinger"
	SourceEHole          Source = "ehole"
	SourceWappalyzer     Source = "wappalyzer"
	SourceFingerprintHub Source = "fingerprinthub"
)

//go:embed rules/sources.json rules/finger.yaml rules/ehole.json rules/wappalyzer.json rules/fingerprinthub_v4.json
var builtinRules embed.FS

// NewBuiltin compiles the SDK's bundled rules, without file paths or disk I/O.
// With no sources, it follows the bundled sources.json enabled flags. Explicit
// sources select only those matchers, including sources disabled in that profile.
// Use New with Config for caller-provided rules instead.
func NewBuiltin(ctx context.Context, sources ...Source) (*Engine, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	profile, err := builtinRules.ReadFile("rules/sources.json")
	if err != nil {
		return nil, fmt.Errorf("fingerprint: built-in profile: %w", err)
	}
	var settings map[string]SourceSetting
	if err := json.Unmarshal(profile, &settings); err != nil {
		return nil, fmt.Errorf("fingerprint: built-in profile: %w", err)
	}
	if len(sources) > 0 {
		for name, setting := range settings {
			setting.Enabled = false
			settings[name] = setting
		}
		for _, source := range sources {
			setting, ok := settings[string(source)]
			if !ok {
				return nil, fmt.Errorf("fingerprint: unknown built-in source %q", source)
			}
			setting.Enabled = true
			settings[string(source)] = setting
		}
	}
	e := &Engine{logger: slog.Default()}
	// Stable order also makes validation/compilation errors deterministic.
	for _, source := range []Source{SourceWebfinger, SourceEHole, SourceFingerprintHub, SourceWappalyzer} {
		setting := settings[string(source)]
		if !setting.Enabled {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := builtinRules.ReadFile("rules/" + setting.File)
		if err != nil {
			return nil, fmt.Errorf("fingerprint: built-in %s: %w", source, err)
		}
		switch source {
		case SourceWebfinger:
			e.webfinger, err = loadWebfingerMatcher(ctx, Config{WebfingerYAML: data}, true, e.logger)
		case SourceEHole:
			e.ehole, err = LoadEHoleJSON(data)
		case SourceFingerprintHub:
			e.fingerprinthub, err = LoadFingerprintHubJSON(data)
		case SourceWappalyzer:
			e.wappalyzer, err = LoadWappalyzerJSON(data)
		}
		if err != nil {
			return nil, fmt.Errorf("fingerprint: built-in %s: %w", source, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return e, nil
}
