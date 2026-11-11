package netloom

import (
	"github.com/emhha/netloom/internal/proxyconfig"
	"net/url"
)

// ErrInvalidProxy identifies a local proxy configuration error. Such errors
// never cause direct fallback, retries or target-host failure accounting.
var ErrInvalidProxy = proxyconfig.ErrInvalid

func validateProxy(req *Request) error {
	_, err := parseProxy(req.Proxy)
	return err
}

func parseProxy(raw string) (*url.URL, error) {
	return proxyconfig.Parse(raw, "http", "https", "socks4", "socks4a", "socks5", "socks5h")
}
