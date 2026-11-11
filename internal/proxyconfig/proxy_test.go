package proxyconfig

import (
	"errors"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	schemes := []string{"http", "https", "socks4", "socks4a", "socks5", "socks5h"}
	for _, raw := range []string{"", "http://proxy.test", "https://proxy.test/", "HTTP://proxy.test", "http://[fe80::1%25eth0]/", "HTTPS://user:secret@[::1]/", "http://user:secret@[::1]:8080/", "socks4://proxy.test:1080", "socks4a://proxy.test:1080", "socks5://proxy.test:1080", "socks5h://user:secret@[::1]:1080/"} {
		t.Run(raw, func(t *testing.T) {
			u, err := Parse(raw, schemes...)
			if err != nil {
				t.Fatal(err)
			}
			if raw == "" && u != nil {
				t.Fatal("direct mode must return nil")
			}
			if u != nil && u.Scheme != strings.ToLower(u.Scheme) {
				t.Fatal("scheme not normalized")
			}
		})
	}
	for _, raw := range []string{" ", "\t", "proxy.test:8080", "//proxy.test:8080", "http://", "http:///host", "http://:80", "http://proxy.test:", "http://proxy.test:0", "http://proxy.test:65536", "http://proxy.test:abc", "http://proxy.test:-1", "http://proxy.test/path", "http://proxy.test/?", "http://proxy.test/?q=secret", "http://proxy.test/#", "http://proxy.test/#secret", "http://bad host:80", "http://bad\\host:80", "http://[not-ip]:80", "http://::1:80", "socks5://proxy.test", "http://user:secret%0a@proxy.test", "http://user:secret%zz@proxy.test"} {
		t.Run(raw, func(t *testing.T) {
			_, err := Parse(raw, schemes...)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("expected invalid, got %v", err)
			}
			if strings.Contains(err.Error(), "secret") || (len(raw) > 10 && strings.Contains(err.Error(), raw)) {
				t.Fatalf("unsafe error %v", err)
			}
		})
	}
	_, err := Parse("ftp://user:secret@proxy.test:21", schemes...)
	if !errors.Is(err, ErrInvalid) || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("sentinels: %v", err)
	}
}
