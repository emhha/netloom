package netloom

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var ErrRedirectLimit = errors.New("netloom: redirect limit exceeded")

type Sender interface {
	Send(context.Context, *Request) (*Response, error)
}

type RedirectPolicy struct {
	Follow      bool
	MaxHops     int
	ValidateURL func(context.Context, string) error
}

type RedirectHop struct {
	URL        string `json:"url"`
	Method     string `json:"method"`
	StatusCode int    `json:"status_code"`
	Location   string `json:"location,omitempty"`
}

type Exchange struct {
	Request  *Request
	Response *Response
	Hops     []RedirectHop
}

// Do performs a bounded redirect chain, validating every destination before sending.
// Send remains a single-hop operation; pipeline analysis belongs to its caller.
func Do(ctx context.Context, sender Sender, request *Request, policy RedirectPolicy) (*Exchange, error) {
	if request == nil {
		return nil, ErrNilRequest
	}
	if len(request.Raw) > 0 && policy.Follow {
		return nil, fmt.Errorf("netloom: raw requests do not support automatic redirects")
	}
	if policy.MaxHops < 0 || policy.MaxHops > 20 {
		return nil, fmt.Errorf("netloom: max redirects must be between 0 and 20")
	}
	if policy.MaxHops == 0 {
		policy.MaxHops = 10
	}
	current := cloneRequest(request)
	if current.Method == "" {
		current.Method = "GET"
	}
	exchange := &Exchange{Hops: []RedirectHop{}}
	start := time.Now()
	defer func() {
		if exchange.Response != nil {
			exchange.Response.InitialURL = request.URL
			exchange.Response.Redirects = append([]RedirectHop(nil), exchange.Hops...)
			exchange.Response.TotalTime = time.Since(start)
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return exchange, err
		}
		if _, err := HTTPURL(current.URL); err != nil {
			return exchange, err
		}
		if policy.ValidateURL != nil {
			if err := policy.ValidateURL(ctx, current.URL); err != nil {
				return exchange, err
			}
		}
		response, err := sender.Send(ctx, current)
		// Keep the last captured response when a later hop fails before headers.
		if response != nil {
			exchange.Request, exchange.Response = current, response
		}
		if err != nil {
			return exchange, err
		}
		if response == nil {
			return exchange, fmt.Errorf("netloom: sender returned no response")
		}
		location := response.Header.Get("Location")
		if location == "" {
			location = response.Location
		}
		if !policy.Follow || !redirectStatus(response.StatusCode) || location == "" {
			return exchange, nil
		}
		if len(exchange.Hops) >= policy.MaxHops {
			return exchange, ErrRedirectLimit
		}
		nextURL, err := ResolveRedirect(current.URL, location)
		if err != nil {
			return exchange, err
		}
		exchange.Hops = append(exchange.Hops, RedirectHop{URL: current.URL, Method: current.Method, StatusCode: response.StatusCode, Location: nextURL})
		next := cloneRequest(current)
		next.URL = nextURL
		if response.StatusCode == 303 && current.Method != "HEAD" || (response.StatusCode == 301 || response.StatusCode == 302) && current.Method == "POST" {
			next.Method, next.Body = "GET", nil
			deleteHeaders(next, "Content-Type", "Content-Length", "Content-Encoding", "Transfer-Encoding")
		}
		if !SameOrigin(current.URL, nextURL) {
			next.TLSConfig = nil // client identity and custom trust are origin-scoped
			deleteHeaders(next, "Authorization", "Proxy-Authorization", "Cookie", "Host", "Origin", "Referer", "X-Api-Key", "X-Auth-Token")
		}
		current = next
	}
}

func HTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("netloom: URL must be HTTP/HTTPS without embedded credentials")
	}
	return u, nil
}

func ResolveRedirect(current, location string) (string, error) {
	base, err := HTTPURL(current)
	if err != nil {
		return "", err
	}
	reference, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("netloom: invalid redirect Location: %w", err)
	}
	next := base.ResolveReference(reference)
	next.Fragment, next.RawFragment = "", ""
	if _, err := HTTPURL(next.String()); err != nil {
		return "", err
	}
	return next.String(), nil
}

func SameOrigin(left, right string) bool {
	a, err := HTTPURL(left)
	if err != nil {
		return false
	}
	b, err := HTTPURL(right)
	if err != nil {
		return false
	}
	port := func(u *url.URL) string {
		if u.Port() != "" {
			return u.Port()
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

func redirectStatus(status int) bool {
	return status == 301 || status == 302 || status == 303 || status == 307 || status == 308
}

func cloneRequest(request *Request) *Request {
	copy := *request
	copy.Header = request.Header.Clone()
	copy.HeaderOrder = append([]string(nil), request.HeaderOrder...)
	copy.Body = append([]byte(nil), request.Body...)
	copy.Raw = append([]byte(nil), request.Raw...)
	return &copy
}

func deleteHeaders(request *Request, names ...string) {
	for key := range request.Header {
		for _, name := range names {
			if strings.EqualFold(key, name) {
				delete(request.Header, key)
				break
			}
		}
	}
}
