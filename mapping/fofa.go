package mapping

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/emhha/netloom/httpclient"
)

type queryHTTPClient interface {
	Get(context.Context, string, string, map[string]string) (*http.Response, error)
}
type FofaEngine struct {
	session  queryHTTPClient
	secrets  SecretReader
	endpoint string
}

func NewFofaEngine(session queryHTTPClient, secrets SecretReader, endpoint string) *FofaEngine {
	if endpoint == "" {
		endpoint = "https://fofa.info/api/v1/search/all"
	}
	return &FofaEngine{session, secrets, endpoint}
}
func (e *FofaEngine) Name() string { return "fofa" }
func (e *FofaEngine) ConvertQuery(query string) string {
	if net.ParseIP(query) != nil {
		return "ip=" + strconv.Quote(query)
	}
	return "domain=" + strconv.Quote(query)
}
func (e *FofaEngine) Search(ctx context.Context, query string, limit int) ([]Result, error) {
	key := readKey(ctx, e.secrets, "fofa_key")
	if key == "" {
		return nil, ErrEngineNotConfigured
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	fields := []string{"host", "ip", "port", "protocol", "domain", "title", "country_name", "as_number", "as_organization"}
	results := []Result{}
	size := min(limit, 100)
	for page := 1; len(results) < limit; page++ {
		u, err := url.Parse(e.endpoint)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("key", key)
		if email := readKey(ctx, e.secrets, "fofa_email"); email != "" {
			q.Set("email", email)
		}
		q.Set("qbase64", base64.StdEncoding.EncodeToString([]byte(query)))
		q.Set("page", strconv.Itoa(page))
		q.Set("size", strconv.Itoa(size))
		q.Set("fields", strings.Join(fields, ","))
		u.RawQuery = q.Encode()
		response, err := e.session.Get(ctx, u.String(), "fofa", nil)
		if err != nil {
			return nil, err
		}
		body, err := httpclient.ReadBody(response)
		if err != nil {
			return nil, err
		}
		if response.StatusCode != 200 {
			return nil, fmt.Errorf("fofa: HTTP %d", response.StatusCode)
		}
		var raw struct {
			Error   bool                `json:"error"`
			Size    int                 `json:"size"`
			Results [][]json.RawMessage `json:"results"`
		}
		if err = json.Unmarshal(body, &raw); err != nil {
			return nil, fmt.Errorf("fofa: invalid response")
		}
		if raw.Error {
			return nil, fmt.Errorf("fofa: query rejected")
		}
		for _, row := range raw.Results {
			if len(row) < 4 {
				return nil, fmt.Errorf("fofa: incomplete result")
			}
			get := func(i int) string {
				if i >= len(row) {
					return ""
				}
				var s string
				if json.Unmarshal(row[i], &s) == nil {
					return s
				}
				var n json.Number
				if json.Unmarshal(row[i], &n) == nil {
					return n.String()
				}
				return ""
			}
			port, _ := strconv.Atoi(get(2))
			host := get(0)
			scheme := get(3)
			if parsed, err := url.Parse(host); err == nil && parsed.Hostname() != "" {
				host = parsed.Hostname()
				scheme = parsed.Scheme
			}
			if host == "" {
				host = get(1)
			}
			results = append(results, Result{Host: host, IP: get(1), Port: port, Scheme: scheme, Domain: get(4), Title: get(5), Country: get(6), ASN: get(7), Org: get(8), Source: "fofa"})
		}
		if len(raw.Results) < size || len(results) >= raw.Size && raw.Size > 0 {
			break
		}
	}
	return results[:min(len(results), limit)], nil
}
