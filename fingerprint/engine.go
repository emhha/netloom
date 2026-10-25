package fingerprint

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"netrt.local/netrt/httpdata"

	"golang.org/x/net/html"
)

// HTMLParserResult holds structured data extracted from a single HTML parse
// pass, shared by the offline matchers.
type HTMLParserResult struct {
	Title      string
	Scripts    []string            // inline <script> content
	ScriptSrcs []string            // <script src="..."> URLs
	MetaTags   map[string][]string // <meta name="X" content="Y"> → name → []content
	Links      []string            // <link href="..."> values
	FaviconURL string              // best favicon URL or ""
}

// Config controls rule loading for Engine.
type Config struct {
	// RulesDir selects sources.json in an explicit resource directory.
	// Enabled sources are required; missing/invalid files return an error.
	RulesDir               string
	EHoleJSONPath          string
	FingerprintHubJSONPath string
	// WebfingerYAML contains caller-supplied rules in memory. Repository rule
	// files are loaded only when CustomRulesDir explicitly selects their directory.
	WebfingerYAML []byte
	// WappalyzerJSONPath is the path to the Wappalyzer rules JSON file.
	// Empty or missing → the engine embeds no Wappalyzer rules (no detections).
	WappalyzerJSONPath string

	// CustomRulesDir is the directory scanned for *.yaml custom rule files
	// (same format as finger.yaml). Empty → no custom rules loaded.
	CustomRulesDir string
}

// Engine is the top-level fingerprint engine. It compiles all rules once at
// construction and is safe for concurrent use afterward.
type Engine struct {
	webfinger      *WebfingerMatcher
	wappalyzer     *WappalyzerMatcher
	logger         *slog.Logger
	ehole          *EHoleMatcher
	fingerprinthub *FingerprintHubMatcher
}

// New builds a fingerprint Engine from the given Config.
// Legacy optional YAML/Wappalyzer inputs degrade gracefully; source profiles
// and explicit native JSON inputs report missing or invalid enabled rules.
func New(ctx context.Context, cfg Config) (*Engine, error) {
	profileMode := cfg.RulesDir != ""
	if cfg.RulesDir != "" {
		if len(cfg.WebfingerYAML) > 0 || cfg.CustomRulesDir != "" || cfg.WappalyzerJSONPath != "" || cfg.EHoleJSONPath != "" || cfg.FingerprintHubJSONPath != "" {
			return nil, fmt.Errorf("fingerprint: RulesDir cannot be combined with individual rule inputs")
		}
		var err error
		cfg, err = loadSourceProfile(cfg.RulesDir)
		if err != nil {
			return nil, err
		}
	}
	e := &Engine{logger: slog.Default()}
	if len(cfg.WebfingerYAML) > 0 || cfg.CustomRulesDir != "" {
		var err error
		e.webfinger, err = loadWebfingerMatcher(ctx, cfg, profileMode, e.logger)
		if err != nil {
			return nil, err
		}
	}

	// Load Wappalyzer rules.
	wapData, err := loadFileOptional(cfg.WappalyzerJSONPath)
	if err != nil {
		e.logger.Warn("fingerprint: failed to read Wappalyzer file", "path", cfg.WappalyzerJSONPath, "err", err)
	}
	wm, err := LoadWappalyzerJSON(wapData)
	if err != nil {
		e.logger.Warn("fingerprint: failed to compile Wappalyzer rules", "err", err)
		wm = &WappalyzerMatcher{}
	}
	e.wappalyzer = wm
	if cfg.EHoleJSONPath != "" {
		data, err := os.ReadFile(cfg.EHoleJSONPath)
		if err != nil {
			return nil, fmt.Errorf("fingerprint: read ehole: %w", err)
		}
		e.ehole, err = LoadEHoleJSON(data)
		if err != nil {
			return nil, err
		}
	}
	if cfg.FingerprintHubJSONPath != "" {
		data, err := os.ReadFile(cfg.FingerprintHubJSONPath)
		if err != nil {
			return nil, fmt.Errorf("fingerprint: read fingerprinthub: %w", err)
		}
		e.fingerprinthub, err = LoadFingerprintHubJSON(data)
		if err != nil {
			return nil, err
		}
	}

	return e, nil
}

// Match runs all fingerprint engines against the response and returns the
// detected artifacts. It is safe for concurrent use.
func (e *Engine) Match(ctx context.Context, resp *httpdata.Response) []Artifact {
	return e.MatchExchange(ctx, nil, resp)
}

// MatchExchange also checks native probe method/path/header constraints against
// the captured request. It never sends probes or modifies either input.
func (e *Engine) MatchExchange(ctx context.Context, req *httpdata.Request, resp *httpdata.Response) []Artifact {
	if resp == nil {
		return nil
	}

	if ctx.Err() != nil {
		return nil
	}
	mc := NewMatchContext(resp, nil)
	mc.Request = req
	mc.HTMLResult = parseHTML(mc.BodyUTF8, resp.Header)
	if resp.Title == "" && mc.HTMLResult.Title != "" {
		local := *resp
		local.Title = mc.HTMLResult.Title
		mc.Response = &local
	}

	var results []Artifact

	if e.webfinger != nil {
		for _, art := range e.webfinger.match(ctx, mc) {
			results = appendArtifact(results, art)
		}
		if ctx.Err() != nil {
			return results
		}
	}

	// Each source owns its compiled rules and matching implementation.
	if e.wappalyzer != nil {
		for _, art := range e.wappalyzer.match(mc) {
			results = appendArtifact(results, art)
		}
	}
	var text *nativeText
	if e.ehole != nil || e.fingerprinthub != nil {
		text = newNativeText(mc)
	}
	if e.ehole != nil {
		for _, art := range e.ehole.matchPrepared(ctx, mc, text) {
			results = appendArtifact(results, art)
		}
	}
	if e.fingerprinthub != nil {
		for _, art := range e.fingerprinthub.matchPrepared(ctx, mc, text) {
			results = appendArtifact(results, art)
		}
	}

	return dedup(results)
}

// MatchResponse satisfies the probe.FingerprintMatcher interface, returning
// only technology names (no version or confidence) for backward compatibility.
func (e *Engine) MatchResponse(resp *httpdata.Response) []string {
	arts := e.Match(context.Background(), resp)
	names := make([]string, 0, len(arts))
	for _, a := range arts {
		names = append(names, a.Name)
	}
	return names
}

// appendArtifact adds art to dst using SetIfNotExists confidence accumulation.
func appendArtifact(dst []Artifact, art Artifact) []Artifact {
	for i := range dst {
		if dst[i].Name == art.Name {
			dst[i].Confidence += art.Confidence
			if dst[i].Confidence > 100 {
				dst[i].Confidence = 100
			}
			if art.Version != "" && dst[i].Version == "" {
				dst[i].Version = art.Version
			}
			return dst
		}
	}
	return append(dst, art)
}

// dedup removes zero-confidence artifacts.
func dedup(arts []Artifact) []Artifact {
	out := arts[:0]
	for _, a := range arts {
		if a.Confidence > 0 {
			out = append(out, a)
		}
	}
	return out
}

// loadFileOptional reads path and returns data. Returns (nil, nil) when path is
// empty or the file does not exist; returns (nil, err) on other errors.
func loadFileOptional(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	clean := filepath.Clean(path)
	data, err := os.ReadFile(clean) //nolint:gosec // caller-supplied path, no traversal concern at this layer
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fingerprint.loadFileOptional: %w", err)
	}
	return data, nil
}

// parseHTML parses raw HTML bytes and extracts structured data. The header is
// typed as the base map so both fhttp and net/http headers can be passed.
func parseHTML(body []byte, h map[string][]string) *HTMLParserResult {
	result := &HTMLParserResult{
		MetaTags: make(map[string][]string),
	}

	if len(body) == 0 {
		return result
	}

	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		// Partial parse is acceptable; return whatever we got.
		return result
	}

	_ = h // reserved — Content-Type charset may be used in future
	walkHTML(doc, result)

	// Resolve best favicon URL.
	result.FaviconURL = pickFaviconURL(result.Links)
	return result
}

// walkHTML traverses the HTML node tree and fills result.
func walkHTML(n *html.Node, result *HTMLParserResult) {
	if n == nil {
		return
	}

	if n.Type == html.ElementNode {
		tag := strings.ToLower(n.Data)
		switch tag {
		case "title":
			if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
				result.Title = strings.TrimSpace(n.FirstChild.Data)
			}

		case "script":
			src := attrVal(n, "src")
			if src != "" {
				result.ScriptSrcs = append(result.ScriptSrcs, src)
			} else if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
				content := strings.TrimSpace(n.FirstChild.Data)
				if content != "" {
					result.Scripts = append(result.Scripts, content)
				}
			}

		case "meta":
			name := strings.ToLower(attrVal(n, "name"))
			if name == "" {
				name = strings.ToLower(attrVal(n, "property"))
			}
			content := attrVal(n, "content")
			if name != "" && content != "" {
				result.MetaTags[name] = append(result.MetaTags[name], content)
			}

		case "link":
			href := attrVal(n, "href")
			if href != "" {
				result.Links = append(result.Links, href)
			}
		}
	}

	for child := n.FirstChild; child != nil; child = child.NextSibling {
		walkHTML(child, result)
	}
}

// attrVal returns the value of the named attribute, or "".
func attrVal(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if strings.ToLower(a.Key) == name {
			return a.Val
		}
	}
	return ""
}

// pickFaviconURL selects the best favicon URL from a list of link href values.
// It prefers rel="icon" and rel="shortcut icon" links, and falls back to "".
// The caller (FaviconExtractor) resolves relative URLs against the target.
func pickFaviconURL(links []string) string {
	// links are href values; we need the corresponding rel attributes.
	// Since we store hrefs without rel here, this is a simplified version.
	// In practice, FaviconExtractor re-scans resp.Body for rel="icon" links.
	// This field is populated when walkHTML is extended to also pass rel.
	return ""
}
