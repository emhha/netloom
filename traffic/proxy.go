package traffic

import (
	"fmt"
	"net/url"

	"github.com/emhha/netloom/internal/proxyconfig"
)

// ProxyConfig sets outbound proxies. A nil value inherits; a pointer to an
// empty string explicitly selects a direct connection. New copies the values.
type ProxyConfig struct {
	Default *string
	Request *string
	MITM    *string
}

// RequestOptions overrides settings for one active request or scheduled task.
type RequestOptions struct {
	Proxy *string // nil honors Request.Proxy, then the Request/Default configuration
}

func resolveProxies(cfg ProxyConfig) (string, *string, error) {
	var request string
	if value := proxyValue(cfg.Request, cfg.Default); value != nil {
		request = *value
		if err := validateRequestProxy(request); err != nil {
			return "", nil, fmt.Errorf("traffic: request proxy: %w", err)
		}
	}
	if value := proxyValue(cfg.MITM, cfg.Default); value != nil {
		mitm := *value
		if _, err := parseMITMProxy(mitm); err != nil {
			return "", nil, fmt.Errorf("traffic: MITM proxy: %w", err)
		}
		return request, &mitm, nil
	}
	return request, nil, nil
}

func proxyValue(override, fallback *string) *string {
	if override != nil {
		return override
	}
	return fallback
}

func validateRequestProxy(value string) error {
	_, err := proxyconfig.Parse(value, "http", "https", "socks4", "socks4a", "socks5", "socks5h")
	return err
}

func parseMITMProxy(value string) (*url.URL, error) {
	return proxyconfig.Parse(value, "http", "https", "socks5", "socks5h")
}
