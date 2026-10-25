package fingerprint

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SourceSetting selects one native rule file. Paths are relative to RulesDir.
type SourceSetting struct {
	Enabled bool   `json:"enabled"`
	File    string `json:"file"`
}

func loadSourceProfile(dir string) (Config, error) {
	data, err := os.ReadFile(filepath.Join(dir, "sources.json"))
	if err != nil {
		return Config{}, fmt.Errorf("fingerprint: source profile: %w", err)
	}
	var sources map[string]SourceSetting
	if err = json.Unmarshal(data, &sources); err != nil {
		return Config{}, fmt.Errorf("fingerprint: source profile: %w", err)
	}
	var cfg Config
	for name, source := range sources {
		if name != "webfinger" && name != "wappalyzer" && name != "ehole" && name != "fingerprinthub" {
			return Config{}, fmt.Errorf("fingerprint: unknown source %q", name)
		}
		if !source.Enabled {
			continue
		}
		if source.File == "" || filepath.Base(source.File) != source.File || strings.ContainsAny(source.File, "/\\") || source.File == "." || source.File == ".." {
			return Config{}, fmt.Errorf("fingerprint: invalid source filename %q", source.File)
		}
		path := filepath.Join(dir, source.File)
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("fingerprint: enabled source %s is unavailable: %w", name, err)
		}
		if len(data) == 0 {
			return Config{}, fmt.Errorf("fingerprint: enabled source %s is empty", name)
		}
		switch name {
		case "webfinger":
			cfg.WebfingerYAML = data
		case "wappalyzer":
			// Profile loading is strict, unlike the legacy optional path API.
			var file wappalyzerRuleFile
			if err := json.Unmarshal(data, &file); err != nil {
				return Config{}, fmt.Errorf("fingerprint: wappalyzer: %w", err)
			}
			if len(file.Apps)+len(file.Technologies) == 0 {
				return Config{}, fmt.Errorf("fingerprint: enabled wappalyzer has no rules")
			}
			cfg.WappalyzerJSONPath = path
		case "ehole":
			cfg.EHoleJSONPath = path
		case "fingerprinthub":
			cfg.FingerprintHubJSONPath = path
		}
	}
	return cfg, nil
}
