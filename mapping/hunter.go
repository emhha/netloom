package mapping

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/emhha/netloom/httpclient"
)

type HunterEngine struct {
	session  queryHTTPClient
	secrets  SecretReader
	endpoint string
}

func NewHunterEngine(session queryHTTPClient, secrets SecretReader, endpoint string) *HunterEngine {
	if endpoint == "" {
		endpoint = "https://hunter.qianxin.com/openApi/search"
	}
	return &HunterEngine{session, secrets, endpoint}
}
func (e *HunterEngine) Name() string { return "hunter" }
func (e *HunterEngine) ConvertQuery(query string) string {
	if net.ParseIP(query) != nil {
		return "ip=" + strconv.Quote(query)
	}
	return "domain=" + strconv.Quote(query)
}
func (e *HunterEngine) Search(ctx context.Context, query string, limit int) ([]Result, error) {
	key := readKey(ctx, e.secrets, "hunter_key")
	if key == "" {
		return nil, ErrEngineNotConfigured
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	size := min(limit, 10)
	results := []Result{}
	for page := 1; len(results) < limit; page++ {
		u, err := url.Parse(e.endpoint)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("api-key", key)
		q.Set("search", base64.URLEncoding.EncodeToString([]byte(query)))
		q.Set("page", strconv.Itoa(page))
		q.Set("page_size", strconv.Itoa(size))
		u.RawQuery = q.Encode()
		response, err := e.session.Get(ctx, u.String(), "hunter", nil)
		if err != nil {
			return nil, err
		}
		body, err := httpclient.ReadBody(response)
		if err != nil {
			return nil, err
		}
		if response.StatusCode != 200 {
			return nil, fmt.Errorf("hunter: HTTP %d", response.StatusCode)
		}
		var raw struct {
			Code int `json:"code"`
			Data struct {
				Total int `json:"total"`
				Arr   []struct {
					URL        string `json:"url"`
					IP         string `json:"ip"`
					Port       int    `json:"port"`
					Domain     string `json:"domain"`
					WebTitle   string `json:"web_title"`
					Protocol   string `json:"protocol"`
					Country    string `json:"country"`
					StatusCode int    `json:"status_code"`
					Company    string `json:"company"`
					Components []struct {
						Name    string `json:"name"`
						Version string `json:"version"`
					} `json:"component"`
				} `json:"arr"`
			} `json:"data"`
		}
		if err = json.Unmarshal(body, &raw); err != nil {
			return nil, fmt.Errorf("hunter: invalid response")
		}
		if raw.Code != 200 {
			return nil, fmt.Errorf("hunter: query rejected (%d)", raw.Code)
		}
		for _, r := range raw.Data.Arr {
			host := r.Domain
			scheme := r.Protocol
			if u, err := url.Parse(r.URL); err == nil && u.Hostname() != "" {
				host = u.Hostname()
				scheme = u.Scheme
			}
			if host == "" {
				host = r.IP
			}
			components := []string{}
			for _, c := range r.Components {
				if c.Name != "" {
					components = append(components, strings.TrimSuffix(c.Name+"/"+c.Version, "/"))
				}
			}
			results = append(results, Result{Host: host, Domain: r.Domain, IP: r.IP, Port: r.Port, Scheme: scheme, Title: r.WebTitle, Country: r.Country, StatusCode: r.StatusCode, Org: r.Company, Components: components, Source: "hunter"})
		}
		if len(raw.Data.Arr) < size || raw.Data.Total > 0 && len(results) >= raw.Data.Total {
			break
		}
	}
	return results[:min(len(results), limit)], nil
}
