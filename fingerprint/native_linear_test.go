package fingerprint

// Frozen pre-index implementation: independent semantic oracle and benchmark baseline.
import (
	"context"
	"encoding/json"
	"net/url"
	"netrt.local/netrt/httpdata"
	"strconv"
	"strings"
)

func linearEHoleMatch(m *EHoleMatcher, ctx context.Context, mc *MatchContext) []Artifact {
	// EHole compares headers serialized as JSON, not an HTTP wire header block.
	header, _ := json.Marshal(mc.Response.Header)
	fields := map[string]string{"body": string(mc.BodyUTF8), "header": string(header), "title": mc.Response.Title}
	lower := map[string]string{}
	for key, value := range fields {
		lower[key] = strings.ToLower(value)
	}
	var out []Artifact
	for _, r := range m.rules {
		if ctx.Err() != nil {
			break
		}
		matched := true
		switch r.Method {
		case "keyword":
			for _, word := range r.Keyword {
				if !strings.Contains(lower[r.Location], strings.ToLower(word)) {
					matched = false
					break
				}
			}
		case "regular":
			for _, pattern := range r.patterns {
				if !pattern.MatchString(fields[r.Location]) {
					matched = false
					break
				}
			}
		case "faviconhash":
			matched = false
			if mc.Response.FaviconHash != 0 {
				for _, value := range r.hashes {
					if mc.Response.FaviconHash == value {
						matched = true
						break
					}
				}
			}
		}
		if matched {
			out = appendArtifact(out, Artifact{Name: r.CMS, Type: inferType(r.CMS), Confidence: 100, Source: "ehole"})
		}
	}
	return out
}

func linearHubMatch(m *FingerprintHubMatcher, ctx context.Context, mc *MatchContext) []Artifact {
	var out []Artifact
	for _, t := range m.rules {
		if ctx.Err() != nil {
			break
		}
		for _, p := range t.HTTP {
			// A captured response is not evidence for a modified/active probe.
			if !linearProbeMatchesRequest(p, mc.Request, mc.Response.URL) {
				continue
			}
			matched := p.MatchersCondition == "and"
			for _, matcher := range p.Matchers {
				hit := linearHubMatcherMatch(matcher, mc)
				if p.MatchersCondition == "and" {
					matched = matched && hit
					if !matched {
						break
					}
				} else {
					matched = matched || hit
					if matched {
						break
					}
				}
			}
			if matched {
				name := t.Info.Name
				if name == "" {
					name = t.ID
				}
				version := ""
				for _, extractor := range p.Extractors {
					if extractor.Name == "version" {
						version = extractor.extract(mc)
						if version != "" {
							break
						}
					}
				}
				out = appendArtifact(out, Artifact{Name: name, Version: version, Type: inferType(name), Confidence: 100, Source: "fingerprinthub"})
				break
			}
		}
	}
	return out
}

func linearProbeMatchesRequest(p hubProbe, req *httpdata.Request, responseURL string) bool {
	if len(p.Raw) > 0 {
		return false
	}
	method := "GET"
	if req != nil {
		if req.Method != "" {
			method = req.Method
		}
		if req.URL != "" {
			responseURL = req.URL
		}
	} else if p.Body != "" || len(p.Headers) > 0 || p.Method != "" && p.Method != "GET" {
		return false
	}
	if p.Method != "" && p.Method != method {
		return false
	}
	if p.Body != "" && (req == nil || p.Body != string(req.Body)) {
		return false
	}
	for key, want := range p.Headers {
		found := false
		if req != nil {
			for actual, values := range req.Header {
				if strings.EqualFold(actual, key) {
					for _, value := range values {
						if value == want {
							found = true
						}
					}
				}
			}
		}
		if !found {
			return false
		}
	}
	return linearHubPathMatches(p.Path, responseURL)
}

func linearHubPathMatches(paths []string, rawURL string) bool {
	if len(paths) == 0 {
		return true
	}
	var target *url.URL
	if rawURL != "" {
		var err error
		target, err = url.Parse(rawURL)
		if err != nil || target.Host == "" {
			return false
		}
	}
	for _, path := range paths {
		// With no URL, only a generic homepage probe can match passively.
		if target == nil {
			if path == "{{BaseURL}}/" || path == "{{BaseURL}}" || path == "/" {
				return true
			}
			continue
		}
		base := target.Scheme + "://" + target.Host
		expanded := strings.ReplaceAll(strings.ReplaceAll(path, "{{BaseURL}}", base), "{{RootURL}}", base)
		if strings.Contains(expanded, "{{") {
			continue
		}
		u, err := url.Parse(expanded)
		if err != nil {
			continue
		}
		u = target.ResolveReference(u)
		a, b := u.EscapedPath(), target.EscapedPath()
		if a == "" {
			a = "/"
		}
		if b == "" {
			b = "/"
		}
		if strings.EqualFold(u.Scheme, target.Scheme) && strings.EqualFold(u.Host, target.Host) && a == b && u.RawQuery == target.RawQuery {
			return true
		}
	}
	return false
}

func linearHubMatcherMatch(m hubMatcher, mc *MatchContext) bool {
	if m.Negative && mc.Response.BodyTruncated && (m.Part == "" || m.Part == "body" || m.Part == "all") {
		return false
	}
	field := string(mc.BodyUTF8)
	switch m.Part {
	case "header", "all_headers":
		field = string(mc.HeaderBlob)
	case "title":
		field = mc.Response.Title
	case "all":
		field = string(mc.HeaderBlob) + "\n" + field
	}
	if m.CaseInsensitive {
		field = strings.ToLower(field)
	}
	var hits []bool
	switch m.Type {
	case "word":
		for _, word := range m.Words {
			if m.CaseInsensitive {
				word = strings.ToLower(word)
			}
			hits = append(hits, strings.Contains(field, word))
		}
	case "regex":
		for _, p := range m.patterns {
			hits = append(hits, p.MatchString(field))
		}
	case "favicon":
		if mc.Response.FaviconHash == 0 && mc.Response.FaviconMD5 == "" {
			return false
		}
		for _, s := range m.Hash {
			if len(s) == 32 {
				if mc.Response.FaviconMD5 != "" {
					hits = append(hits, strings.EqualFold(s, mc.Response.FaviconMD5))
				}
			} else {
				if mc.Response.FaviconHash != 0 {
					hits = append(hits, s == strconv.FormatInt(int64(mc.Response.FaviconHash), 10))
				}
			}
		}
	}
	if len(hits) == 0 {
		return false
	}
	matched := m.Condition == "and"
	for _, hit := range hits {
		if m.Condition == "and" {
			matched = matched && hit
		} else {
			matched = matched || hit
		}
	}
	if m.Negative {
		return !matched
	}
	return matched
}
