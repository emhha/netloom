package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime"
	"net/url"
	"strings"

	"net/http"
	"netrt.local/netrt/passive"
)

// HTTPPolicy reports configuration observations from the captured response only.
// Cookie values are never included in its artifacts.
type HTTPPolicy struct{}

func (HTTPPolicy) Metadata() passive.Metadata {
	return passive.Metadata{ID: "http_policy", Version: "1", Description: "仅分析已捕获的安全响应头与 Cookie 属性，输出待确认的配置观察项，不发送额外请求"}
}

func policyHeaders(header http.Header) http.Header {
	selected := make(http.Header)
	for _, key := range []string{"Content-Type", "Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Set-Cookie"} {
		for name, values := range header {
			if strings.EqualFold(key, name) {
				selected[key] = append(selected[key], values...)
			}
		}
	}
	return selected
}

func (HTTPPolicy) CacheKey(in passive.Input) string {
	if in.Request == nil || in.Response == nil {
		return ""
	}
	data, err := json.Marshal(struct {
		Site, Session, URL, ContentType string
		Status                          int
		Headers                         http.Header
	}{in.Site, in.SessionID, in.Request.URL, in.Response.ContentType, in.Response.StatusCode, policyHeaders(in.Response.Header)})
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (HTTPPolicy) Analyze(ctx context.Context, in passive.Input) (passive.Result, error) {
	if err := ctx.Err(); err != nil {
		return passive.Result{}, err
	}
	result := passive.Result{Artifacts: []passive.Artifact{}}
	u, err := url.Parse(in.Request.URL)
	if err != nil {
		return result, err
	}
	headers := policyHeaders(in.Response.Header)
	add := func(rule, value string) {
		result.Artifacts = append(result.Artifacts, passive.Artifact{Type: "http_policy_observation", Rule: rule, Value: value, Scope: "response_headers"})
	}
	contentType, _, _ := mime.ParseMediaType(in.Response.ContentType)
	if contentType == "" {
		contentType, _, _ = mime.ParseMediaType(headers.Get("Content-Type"))
	}
	html := contentType == "text/html" || contentType == "application/xhtml+xml"
	if html && in.Response.StatusCode >= 200 && in.Response.StatusCode < 400 && in.Response.StatusCode != 204 && in.Response.StatusCode != 304 {
		csp := headers.Get("Content-Security-Policy")
		if strings.TrimSpace(csp) == "" {
			add("html_missing_csp", "HTML 响应未声明 Content-Security-Policy；需结合页面内容确认适用策略")
		}
		if !strings.EqualFold(strings.TrimSpace(headers.Get("X-Content-Type-Options")), "nosniff") {
			add("html_missing_nosniff", "HTML 响应未设置 X-Content-Type-Options: nosniff")
		}
		hasFramePolicy := false
		for _, directive := range strings.Split(csp, ";") {
			fields := strings.Fields(directive)
			if len(fields) > 1 && strings.EqualFold(fields[0], "frame-ancestors") {
				hasFramePolicy = true
			}
		}
		xfo := strings.ToUpper(strings.TrimSpace(headers.Get("X-Frame-Options")))
		if !hasFramePolicy && xfo != "DENY" && xfo != "SAMEORIGIN" {
			add("html_missing_frame_policy", "HTML 响应未声明有效的 frame-ancestors、DENY 或 SAMEORIGIN；是否允许嵌入需人工确认")
		}
	}
	if u.Scheme == "https" && strings.TrimSpace(headers.Get("Strict-Transport-Security")) == "" {
		add("https_missing_hsts", "HTTPS 响应未声明 Strict-Transport-Security；是否启用需结合域名部署确认")
	}
	response := &http.Response{Header: headers}
	for index, cookie := range response.Cookies() {
		if index >= 256 {
			result.Truncated = true
			break
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if cookie.MaxAge < 0 {
			continue
		}
		name := cookie.Name
		if len(name) > 128 {
			name = name[:128] + "…"
		}
		lower := strings.ToLower(cookie.Name)
		sessionLike := strings.Contains(lower, "session") || strings.Contains(lower, "auth") || strings.Contains(lower, "token") || lower == "sid" || lower == "jsessionid" || lower == "phpsessid"
		if sessionLike && !cookie.HttpOnly {
			add("session_cookie_missing_httponly", name+": 会话候选 Cookie 未设置 HttpOnly，需确认是否必须供脚本访问")
		}
		if u.Scheme == "https" && !cookie.Secure {
			add("https_cookie_missing_secure", name+": HTTPS 响应设置的 Cookie 未声明 Secure")
		}
		if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
			add("samesite_none_without_secure", name+": SameSite=None 未同时设置 Secure")
		}
		if strings.HasPrefix(cookie.Name, "__Secure-") && !cookie.Secure {
			add("secure_cookie_prefix_invalid", name+": __Secure- 前缀要求 Secure")
		}
		if strings.HasPrefix(cookie.Name, "__Host-") && (!cookie.Secure || cookie.Domain != "" || cookie.Path != "/") {
			add("host_cookie_prefix_invalid", name+": __Host- 前缀要求 Secure、Path=/ 且不设置 Domain")
		}
	}
	result.Data, err = json.Marshal(struct {
		Kind  string `json:"kind"`
		Count int    `json:"observation_count"`
		HTML  bool   `json:"html_response"`
	}{"configuration_observations", len(result.Artifacts), html})
	return result, err
}
