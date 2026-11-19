package infoextract

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime"
	"sync"

	"github.com/emhha/netloom/passive"
)

// Plugin checks response bodies and headers for sensitive information candidates.
// Its zero value has no rules. Use New to load the built-in rules. Set
// configuration fields before starting analysis and do not copy after use.
type Plugin struct {
	// CacheLimit bounds the combined body and header deduplication entries.
	// Zero selects 256 entries; a negative value disables deduplication.
	CacheLimit int
	// HashBodyForCache uses content hashes instead of URL, media type and length.
	HashBodyForCache bool
	mu               sync.Mutex
	cache            *passive.Registry
	cacheIdentity    uint64
	cacheUsesHash    bool
	extractor        extractor
}

var _ passive.Plugin = (*Plugin)(nil)

// New returns a passive plugin with the built-in rules installed.
func New() *Plugin {
	p := &Plugin{}
	p.extractor.loadDefaults()
	return p
}

// AddRule adds or replaces a rule by name. An invalid pattern leaves the
// rules unchanged. AddRule can run concurrently with analysis.
func (p *Plugin) AddRule(rule Rule) error { return p.extractor.addRule(rule) }

func (p *Plugin) Metadata() passive.Metadata {
	return passive.Metadata{ID: "infoextract", Version: "5", Description: "正文默认按项目/会话/URL/内容类型/长度去重，响应头独立分析"}
}
func (p *Plugin) CacheKey(passive.Input) string { return "" }
func (p *Plugin) Analyze(ctx context.Context, in passive.Input) (passive.Result, error) {
	cache, err := p.registry()
	if err != nil {
		return passive.Result{}, err
	}
	parts, err := cache.Analyze(ctx, in, []string{"infoextract_body", "infoextract_headers"})
	if err != nil {
		return passive.Result{}, err
	}
	result := passive.Result{CacheHit: true}
	for _, part := range parts {
		result.Artifacts = append(result.Artifacts, part.Artifacts...)
		result.CacheHit = result.CacheHit && part.CacheHit
		result.Truncated = result.Truncated || part.Truncated
		if part.Status != "completed" {
			result.Status, result.Error = part.Status, part.Error
		}
	}
	result.Data, err = json.Marshal(struct {
		BodyCacheHit   bool `json:"body_cache_hit"`
		HeaderCacheHit bool `json:"header_cache_hit"`
	}{parts[0].CacheHit, parts[1].CacheHit})
	return result, err
}

// registry pins both cache-key computation and body/header execution to one
// immutable ruleset. Reading a live generation only in CacheKey would allow an
// AddRule between CacheKey and Analyze to cache new results under an old key.
func (p *Plugin) registry() (*passive.Registry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	snapshot := p.extractor.snapshot()
	if p.cache == nil || p.cacheIdentity != snapshot.identity || p.cacheUsesHash != p.HashBodyForCache {
		cache, err := passive.NewDeduplicating([]passive.Plugin{
			informationPart{Snapshot: snapshot, HashBody: p.HashBodyForCache}, informationPart{Snapshot: snapshot, Headers: true},
		}, informationCacheLimit(p.CacheLimit))
		if err != nil {
			return nil, err
		}
		p.cache, p.cacheIdentity, p.cacheUsesHash = cache, snapshot.identity, p.HashBodyForCache
	}
	// Older in-flight calls retain their own registry. A generation change
	// drops our reference rather than mutating plugins used by those calls.
	return p.cache, nil
}

type informationPart struct {
	Snapshot snapshot
	Headers  bool
	HashBody bool
}

func (p informationPart) Metadata() passive.Metadata {
	id := "infoextract_body"
	if p.Headers {
		id = "infoextract_headers"
	}
	return passive.Metadata{ID: id, Version: "1"}
}

func (p informationPart) CacheKey(in passive.Input) string {
	if !p.Headers {
		if p.HashBody {
			return passive.ContentKey(in.Site, in.SessionID, in.Request.URL, in.Response.ContentType, in.Response.Body)
		}
		return passive.ContentLengthKey(in)
	}
	data, _ := json.Marshal(struct {
		Site, Session, URL, ContentType string
		Headers                         map[string][]string
	}{in.Site, in.SessionID, in.Request.URL, in.Response.ContentType, in.Response.Header})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (p informationPart) Analyze(ctx context.Context, in passive.Input) (passive.Result, error) {
	if err := ctx.Err(); err != nil {
		return passive.Result{}, err
	}
	body, headers := in.Response.Body, map[string][]string(nil)
	if p.Headers {
		body, headers = nil, in.Response.Header
	}
	findings := p.Snapshot.extract(body, headers, in.Response.ContentType)
	result := passive.Result{}
	ct, _, _ := mime.ParseMediaType(in.Response.ContentType)
	if !p.Headers && (ct == "application/javascript" || ct == "text/javascript") && len(body) > headOnlySize {
		result.Truncated = true
	}
	for _, f := range findings {
		value := f.Value
		result.Artifacts = append(result.Artifacts, passive.Artifact{Type: "sensitive_candidate", Value: value, Rule: f.RuleName, Scope: f.Scope})
		if len(result.Artifacts) == 256 {
			result.Truncated = true
			break
		}
	}
	return result, ctx.Err()
}

func informationCacheLimit(n int) int {
	if n == 0 {
		return 256
	}
	return n
}
