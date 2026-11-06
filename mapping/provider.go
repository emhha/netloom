package mapping

import (
	"context"
	"errors"
	"strings"
)

// ErrEngineNotConfigured 表示引擎缺少 API Key，无法发起认证请求。
var ErrEngineNotConfigured = errors.New("mapping: engine not configured")

// Result 是单条测绘结果的统一表示。
type Result struct {
	Host       string         `json:"host"`
	Domain     string         `json:"domain"`
	IP         string         `json:"ip"`
	Port       int            `json:"port"`
	Title      string         `json:"title"`
	StatusCode int            `json:"status_code"`
	Scheme     string         `json:"scheme"`
	Country    string         `json:"country"`
	ASN        string         `json:"asn"`
	Org        string         `json:"org"`
	Components []string       `json:"components"`
	Source     string         `json:"source"`
	Sources    []string       `json:"sources,omitempty"`
	Raw        map[string]any `json:"raw,omitempty"`
}

// Engine 是测绘引擎的统一接口。
type Engine interface {
	Name() string
	Search(ctx context.Context, query string, limit int) ([]Result, error)
	ConvertQuery(query string) string
}

// SecretReader 由调用方提供，按键返回明文凭据；存储与解密由调用方负责。
type SecretReader interface {
	Get(ctx context.Context, key string) ([]byte, error)
}

// readKey 读取指定 secret key 的明文；未配置时返回空串。
func readKey(ctx context.Context, secrets SecretReader, key string) string {
	if secrets == nil {
		return ""
	}
	raw, err := secrets.Get(ctx, key)
	if err != nil || len(raw) == 0 {
		return ""
	}
	return strings.TrimSpace(string(raw))
}
