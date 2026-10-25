package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime"
	"sync"

	"netrt.local/netrt/fingerprint"
	"netrt.local/netrt/infoextract"
	"netrt.local/netrt/passive"
)

type Information struct {
	Extractor  *infoextract.InfoExtractor
	CacheLimit int
	once       sync.Once
	cache      *passive.Registry
	cacheErr   error
}

func (p *Information) Metadata() passive.Metadata {
	return passive.Metadata{ID: "infoextract", Version: "3", Description: "正文按项目/会话/URL/内容去重，响应头独立提取敏感信息候选"}
}
func (p *Information) CacheKey(passive.Input) string { return "" }
func (p *Information) Analyze(ctx context.Context, in passive.Input) (passive.Result, error) {
	p.once.Do(func() {
		p.cache, p.cacheErr = passive.New([]passive.Plugin{
			informationPart{Extractor: p.Extractor}, informationPart{Extractor: p.Extractor, Headers: true},
		}, informationCacheLimit(p.CacheLimit))
	})
	if p.cacheErr != nil {
		return passive.Result{}, p.cacheErr
	}
	parts, err := p.cache.Analyze(ctx, in, []string{"infoextract_body", "infoextract_headers"})
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

type informationPart struct {
	Extractor *infoextract.InfoExtractor
	Headers   bool
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
		return passive.ContentKey(in.Site, in.SessionID, in.Request.URL, in.Response.ContentType, in.Response.Body)
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
	findings := p.Extractor.ExtractWithContentType(body, headers, in.Response.ContentType)
	result := passive.Result{}
	ct, _, _ := mime.ParseMediaType(in.Response.ContentType)
	if !p.Headers && (ct == "application/javascript" || ct == "text/javascript") && len(body) > 100*1024 {
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

type Fingerprint struct{ Engine *fingerprint.Engine }

func (p Fingerprint) Metadata() passive.Metadata {
	return passive.Metadata{ID: "fingerprint", Version: "3", Description: "基于已取得请求与响应的技术指纹分析"}
}
func (p Fingerprint) CacheKey(in passive.Input) string { return passive.ResponseKey(in) }
func (p Fingerprint) Analyze(ctx context.Context, in passive.Input) (passive.Result, error) {
	if err := ctx.Err(); err != nil {
		return passive.Result{}, err
	}
	result := passive.Result{}
	for _, technology := range p.Engine.MatchExchange(ctx, in.Request, in.Response) {
		result.Artifacts = append(result.Artifacts, passive.Artifact{Type: "technology", Value: technology.Name, Rule: technology.Source})
	}
	return result, ctx.Err()
}

func informationCacheLimit(n int) int {
	if n == 0 {
		return 256
	}
	return n
}
