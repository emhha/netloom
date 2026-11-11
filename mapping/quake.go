package mapping

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/emhha/netloom/httpclient"
)

// quakeAPIURL 是 360Quake service 搜索接口。
const quakeAPIURL = "https://quake.360.net/api/v3/search/quake_service"

// quakeShortcuts 过滤无效/蜜罐数据（reference 提供的固定 shortcut ID）。
var quakeShortcuts = []string{"63734bfa9c27d4249ca7261c", "635fcb52cc57190bd8826d09"}

// QuakeEngine 实现基于 360Quake API 的测绘引擎，满足 Engine。
// API Key（quake_key）在每次查询时通过调用方提供的 secrets 读取；本包不解密或保存凭据。
// 并发安全：字段构造后只读。
type QuakeEngine struct {
	session quakeHTTPClient
	secrets SecretReader
	baseURL string // 默认 quakeAPIURL；测试时覆盖为 httptest.Server.URL
	source  string // httpclient 限速桶名称，默认 "quake"；测试时覆盖以跳过限流
}

// NewQuakeEngine 构造 QuakeEngine。secrets 用于运行时读取 "quake_key"。
type quakeHTTPClient interface {
	Post(context.Context, string, string, []byte, map[string]string) (*http.Response, error)
}

func NewQuakeEngine(session quakeHTTPClient, secrets SecretReader) *QuakeEngine {
	return &QuakeEngine{session: session, secrets: secrets, baseURL: quakeAPIURL, source: "quake"}
}

func (e *QuakeEngine) Name() string { return "quake" }

// ConvertQuery 将通用输入（example.com 或 1.2.3.4）转换为 Quake 查询语法。
func (e *QuakeEngine) ConvertQuery(query string) string {
	query = strings.TrimSpace(query)
	if net.ParseIP(query) != nil {
		return fmt.Sprintf(`ip:"%s"`, query)
	}
	return fmt.Sprintf(`domain:"%s"`, query)
}

// Search 调用 Quake API 执行查询，分页拉取至 limit，按源限流（1 req/s）。
func (e *QuakeEngine) Search(ctx context.Context, query string, limit int) ([]Result, error) {
	apiKey, err := readKey(ctx, e.secrets, "quake_key")
	if err != nil {
		return nil, err
	}
	if apiKey == "" {
		return nil, ErrEngineNotConfigured
	}
	if limit <= 0 {
		limit = 100
	}
	pageSize := limit
	if pageSize > 100 {
		pageSize = 100
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"X-QuakeToken": apiKey,
	}

	var results []Result
	for start := 0; len(results) < limit; start += pageSize {
		reqBody, err := json.Marshal(map[string]any{
			"query":        query,
			"start":        start,
			"size":         pageSize,
			"latest":       true,
			"ignore_cache": false,
			"shortcuts":    quakeShortcuts,
			"include": []string{
				"ip", "port", "hostname", "domain", "asn", "org",
				"location.country_cn",
				"service.name", "service.response",
				"service.http.title", "service.http.status_code",
				"components.product_name_cn", "components.version",
			},
		})
		if err != nil {
			return nil, fmt.Errorf("mapping.QuakeEngine.Search: marshal request: %w", err)
		}

		resp, err := e.session.Post(ctx, e.baseURL, e.source, reqBody, headers)
		if err != nil {
			return nil, fmt.Errorf("mapping.QuakeEngine.Search: http: %w", err)
		}
		respBody, err := httpclient.ReadBody(resp)
		if err != nil {
			return nil, fmt.Errorf("mapping.QuakeEngine.Search: read body: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("quake: HTTP %d", resp.StatusCode)
		}
		page, total, err := parseQuakePage(respBody)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		results = append(results, page...)

		if total > 0 && len(results) >= total {
			break
		}
	}

	if len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

// parseQuakePage 解析单页 Quake 响应为 []Result 及分页 total。
func parseQuakePage(data []byte) ([]Result, int, error) {
	var raw struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    []struct {
			IP       string `json:"ip"`
			Port     int    `json:"port"`
			Hostname string `json:"hostname"`
			Domain   string `json:"domain"`
			ASN      int    `json:"asn"`
			Org      string `json:"org"`
			Location struct {
				CountryCN string `json:"country_cn"`
			} `json:"location"`
			Service struct {
				Name string `json:"name"`
				HTTP struct {
					Title      string `json:"title"`
					StatusCode int    `json:"status_code"`
				} `json:"http"`
			} `json:"service"`
			Components []struct {
				ProductName string `json:"product_name_cn"`
				Version     string `json:"version"`
			} `json:"components"`
		} `json:"data"`
		Meta struct {
			Pagination struct {
				Total int `json:"total"`
			} `json:"pagination"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, 0, fmt.Errorf("mapping.QuakeEngine.Search: decode: %w", err)
	}
	if raw.Code != 0 {
		return nil, 0, fmt.Errorf("mapping.QuakeEngine.Search: api error %d: %s", raw.Code, raw.Message)
	}

	results := make([]Result, 0, len(raw.Data))
	for _, d := range raw.Data {
		scheme := d.Service.Name
		if scheme == "" {
			scheme = "unknown"
		}
		if d.Service.Name == "http/ssl" || d.Service.Name == "https" {
			scheme = "https"
		}

		host := d.Hostname
		if host == "" {
			host = d.IP
		}
		domain := d.Domain
		if domain == "" {
			domain = d.Hostname
		}

		asn := ""
		if d.ASN > 0 {
			asn = fmt.Sprintf("AS%d", d.ASN)
		}

		components := make([]string, 0, len(d.Components))
		for _, c := range d.Components {
			if c.ProductName == "" {
				continue
			}
			if c.Version != "" {
				components = append(components, c.ProductName+"/"+c.Version)
			} else {
				components = append(components, c.ProductName)
			}
		}

		results = append(results, Result{
			Host:       host,
			Domain:     domain,
			IP:         d.IP,
			Port:       d.Port,
			Title:      d.Service.HTTP.Title,
			StatusCode: d.Service.HTTP.StatusCode,
			Scheme:     scheme,
			Country:    d.Location.CountryCN,
			ASN:        asn,
			Org:        d.Org,
			Components: components,
			Source:     "quake",
			Raw: map[string]any{
				"ip":     d.IP,
				"port":   d.Port,
				"domain": domain,
			},
		})
	}
	return results, raw.Meta.Pagination.Total, nil
}

func NewQuakeEngineAt(session quakeHTTPClient, secrets SecretReader, endpoint string) *QuakeEngine {
	e := NewQuakeEngine(session, secrets)
	if endpoint != "" {
		e.baseURL = endpoint
	}
	return e
}
