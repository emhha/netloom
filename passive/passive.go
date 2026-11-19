// Package passive defines response-analysis plugins independent of project storage.
package passive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/emhha/netloom/httpdata"
)

type Input struct {
	Site      string
	SessionID string
	Request   *httpdata.Request
	Response  *httpdata.Response
}

type Artifact struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Rule  string `json:"rule,omitempty"`
	Scope string `json:"scope,omitempty"`
}

type Metadata struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

type Result struct {
	PluginID  string          `json:"plugin_id"`
	Version   string          `json:"version"`
	Status    string          `json:"status"`
	CacheHit  bool            `json:"cache_hit"`
	Artifacts []Artifact      `json:"artifacts"`
	Data      json.RawMessage `json:"data,omitempty"`
	Error     string          `json:"error,omitempty"`
	Truncated bool            `json:"truncated,omitempty"`
}

// Plugins receive read-only input. CacheKey declares their own reuse scope;
// an empty key disables reuse. Computation stays inside the plugin.
type Plugin interface {
	Metadata() Metadata
	CacheKey(Input) string
	Analyze(context.Context, Input) (Result, error)
}

type entry struct {
	done   chan struct{}
	result Result
}

type Registry struct {
	plugins      map[string]Plugin
	mu           sync.Mutex
	cache        map[string]*entry
	order        []string
	limit        int
	skipFindings bool
}

func New(plugins []Plugin, cacheLimit int) (*Registry, error) {
	return newRegistry(plugins, cacheLimit, false)
}

// NewDeduplicating remembers successful cache keys without retaining their
// findings. A cache hit skips the plugin and reports CacheHit with no Artifacts
// or Data. Plugins with empty keys and failed analyses continue to run.
func NewDeduplicating(plugins []Plugin, cacheLimit int) (*Registry, error) {
	return newRegistry(plugins, cacheLimit, true)
}

func newRegistry(plugins []Plugin, cacheLimit int, skipFindings bool) (*Registry, error) {
	if cacheLimit == 0 {
		cacheLimit = 128
	}
	r := &Registry{plugins: make(map[string]Plugin), cache: make(map[string]*entry), limit: cacheLimit, skipFindings: skipFindings}
	for _, p := range plugins {
		meta := p.Metadata()
		if meta.ID == "" || meta.Version == "" {
			return nil, fmt.Errorf("passive.New: plugin ID and version are required")
		}
		if _, exists := r.plugins[meta.ID]; exists {
			return nil, fmt.Errorf("passive.New: duplicate plugin %s", meta.ID)
		}
		r.plugins[meta.ID] = p
	}
	return r, nil
}

func (r *Registry) Plugins() []Metadata {
	out := make([]Metadata, 0, len(r.plugins))
	for _, p := range r.plugins {
		out = append(out, p.Metadata())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (r *Registry) Validate(ids []string) error {
	seen := make(map[string]bool)
	for _, id := range ids {
		if _, ok := r.plugins[id]; !ok {
			return fmt.Errorf("passive: unknown plugin %s", id)
		}
		if seen[id] {
			return fmt.Errorf("passive: duplicate plugin %s", id)
		}
		seen[id] = true
	}
	return nil
}

func (r *Registry) Analyze(ctx context.Context, in Input, ids []string) ([]Result, error) {
	if in.Request == nil || in.Response == nil {
		return nil, fmt.Errorf("passive.Analyze: request and response are required")
	}
	if ids == nil {
		for _, p := range r.Plugins() {
			ids = append(ids, p.ID)
		}
	}
	if err := r.Validate(ids); err != nil {
		return nil, err
	}
	results := make([]Result, 0, len(ids))
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		results = append(results, r.analyze(ctx, r.plugins[id], in))
	}
	return results, nil
}

func (r *Registry) analyze(ctx context.Context, p Plugin, in Input) Result {
	meta := p.Metadata()
	key := p.CacheKey(in)
	var pending *entry
	if key != "" && r.limit > 0 {
		key = meta.ID + ":" + meta.Version + ":" + key
		r.mu.Lock()
		if cached, ok := r.cache[key]; ok {
			r.mu.Unlock()
			select {
			case <-ctx.Done():
				return Result{PluginID: meta.ID, Version: meta.Version, Status: "failed", Error: ctx.Err().Error(), Artifacts: []Artifact{}}
			case <-cached.done:
				result := clone(cached.result)
				result.CacheHit = result.Status == "completed"
				return result
			}
		}
		for len(r.cache) >= r.limit && len(r.order) > 0 {
			delete(r.cache, r.order[0])
			r.order = r.order[1:]
		}
		if len(r.cache) < r.limit {
			pending = &entry{done: make(chan struct{})}
			r.cache[key] = pending
		}
		r.mu.Unlock()
	}
	result, err := execute(ctx, p, in)
	result.PluginID, result.Version = meta.ID, meta.Version
	if result.Status == "" {
		result.Status = "completed"
	}
	if err != nil {
		result.Status, result.Error = "failed", err.Error()
	}
	if result.Artifacts == nil {
		result.Artifacts = []Artifact{}
	}
	if len(result.Artifacts) > 256 {
		result.Artifacts, result.Truncated = result.Artifacts[:256], true
	}
	bytesUsed := 0
	for index := range result.Artifacts {
		artifact := &result.Artifacts[index]
		bytesUsed += len(artifact.Value) + len(artifact.Rule) + len(artifact.Type) + len(artifact.Scope)
		if bytesUsed > 64<<10 {
			result.Artifacts, result.Truncated = result.Artifacts[:index], true
			break
		}
		artifact.Value = strings.Clone(artifact.Value)
	}
	if len(result.Data) > 64<<10 {
		result.Data, result.Truncated = nil, true
	}
	if pending != nil {
		r.mu.Lock()
		if r.skipFindings && result.Status == "completed" {
			pending.result = Result{PluginID: result.PluginID, Version: result.Version, Status: result.Status, Truncated: result.Truncated}
		} else {
			pending.result = clone(result)
		}
		if result.Status == "completed" {
			r.order = append(r.order, key)
		} else {
			delete(r.cache, key)
		}
		close(pending.done)
		r.mu.Unlock()
	}
	return result
}

func execute(ctx context.Context, p Plugin, in Input) (result Result, err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("passive: plugin execution failed")
		}
	}()
	return p.Analyze(ctx, in)
}

func clone(result Result) Result {
	result.Artifacts = append([]Artifact{}, result.Artifacts...)
	result.Data = append(json.RawMessage(nil), result.Data...)
	return result
}

// ResponseKey includes response and request context, excluding elapsed time.
func ResponseKey(in Input) string {
	data, err := json.Marshal(struct {
		Site, SessionID, URL, Method, Title, ContentType, Server string
		RequestHeaders, Headers                                  map[string][]string
		RequestBody, Body                                        []byte
		Status                                                   int
		TLS                                                      *httpdata.TLSInfo
		Favicon                                                  int32
		FaviconMD5, ResponseURL                                  string
		BodyTruncated                                            bool
	}{in.Site, in.SessionID, in.Request.URL, in.Request.Method, in.Response.Title, in.Response.ContentType,
		in.Response.WebServer, in.Request.Header, in.Response.Header, in.Request.Body,
		in.Response.Body, in.Response.StatusCode, in.Response.TLS, in.Response.FaviconHash,
		in.Response.FaviconMD5, in.Response.URL, in.Response.BodyTruncated})
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
