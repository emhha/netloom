package dirscan

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/emhha/netloom"

	http "github.com/bogdanfinn/fhttp"
)

// TuneAutoConfig performs the dirsearch-style auto-mode preflight in place.
// It is best-effort: preflight failures keep the caller on the original config.
func TuneAutoConfig(ctx context.Context, cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("dirscan.TuneAutoConfig: nil config")
	}
	if cfg.Mode != ModeAuto {
		return nil
	}

	profile := autoProfile{
		preset:  PresetQuick,
		threads: cfg.Threads,
	}
	if profile.threads <= 0 {
		profile.threads = 20
	}
	if profile.threads > 20 {
		profile.threads = 20
	}

	probeEng, err := netloom.New(netloom.Config{
		Threads:       2,
		Timeout:       minDuration(effectiveTimeout(cfg.Timeout), 5*time.Second),
		Retries:       0,
		MaxHostErrors: 2,
	})
	if err != nil {
		return nil
	}

	defer probeEng.Close()

	startPath := "/"
	if cfg.BaseURL != "" {
		if base, perr := url.Parse(cfg.BaseURL); perr == nil && base.Path != "" {
			startPath = base.Path
			if !strings.HasSuffix(startPath, "/") {
				startPath += "/"
			}
		}
	}

	statuses := make([]int, 0, 2)
	var bodies [][]byte
	for i := 0; i < 2; i++ {
		probe := randomStealth()
		fullURL := joinURL(cfg.BaseURL, startPath, probe)
		resp, sendErr := probeEng.Send(ctx, buildAutoProbeRequest(cfg, fullURL))
		if sendErr != nil || resp == nil || resp.Error != nil {
			continue
		}
		statuses = append(statuses, resp.StatusCode)
		bodies = append(bodies, resp.Body)
		if isWAFResponse(resp) {
			profile.wafDetected = true
		}
	}

	if len(statuses) >= 2 && bytes.Equal(bodies[0], bodies[1]) {
		profile.threads = minInt(profile.threads, 15)
	}
	if profile.wafDetected {
		profile.threads = minInt(profile.threads, 10)
		if cfg.WildcardThreshold <= 0 || cfg.WildcardThreshold > 3 {
			cfg.WildcardThreshold = 3
		}
	}
	if profile.threads > 0 && (cfg.Threads <= 0 || profile.threads < cfg.Threads) {
		cfg.Threads = profile.threads
	}
	cfg.AutoWAFDetected = profile.wafDetected
	if cfg.Preset == "" {
		cfg.Preset = profile.preset
	}
	if cfg.Preset == "" {
		cfg.Preset = PresetQuick
	}
	return nil
}

func buildAutoProbeRequest(cfg *Config, fullURL string) *netloom.Request {
	req := &netloom.Request{
		Method:  http.MethodGet,
		URL:     fullURL,
		Header:  http.Header{},
		Profile: netloom.ProfileByName(cfg.TLSProfile),
		Timeout: effectiveTimeout(cfg.Timeout),
	}
	if cfg.UserAgent != "" {
		req.Header.Set("User-Agent", cfg.UserAgent)
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}
	return req
}
