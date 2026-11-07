package netloom

import (
	"fmt"
	"strconv"
	"strings"

	http "github.com/bogdanfinn/fhttp"
)

func headerToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return true
}

func normalizeWireHeaders(h *http.Request, req *Request) error {
	seen := map[string]bool{}
	for key, values := range h.Header {
		lower := strings.ToLower(key)
		if !headerToken(key) || seen[lower] {
			return fmt.Errorf("netloom: invalid or case-duplicate request header")
		}
		seen[lower] = true
		for _, v := range values {
			for i := 0; i < len(v); i++ {
				if v[i] == 127 || v[i] < 32 && v[i] != '\t' {
					return fmt.Errorf("netloom: invalid control byte in request header")
				}
			}
		}
		switch lower {
		case "host":
			if len(values) != 1 || values[0] == "" || strings.ContainsAny(values[0], " /\\\t@?#") {
				return fmt.Errorf("netloom: invalid Host header")
			}
			h.Host = values[0]
			delete(h.Header, key)
		case "content-length":
			if len(values) != 1 {
				return fmt.Errorf("netloom: ambiguous Content-Length")
			}
			n, err := strconv.ParseInt(values[0], 10, 64)
			expected := int64(len(req.Body))
			if req.Upload != nil {
				expected = req.Upload.length
			}
			if err != nil || n < 0 || expected < 0 || n != expected {
				return fmt.Errorf("netloom: Content-Length must match body source length")
			}
			delete(h.Header, key)
		case "transfer-encoding":
			return fmt.Errorf("netloom: Transfer-Encoding is transport-owned; use Raw for literal framing")
		}
	}
	for _, name := range req.HeaderOrder {
		if !headerToken(name) {
			return fmt.Errorf("netloom: invalid header order entry")
		}
	}
	return nil
}

// safeRequestHeaders is a copy suitable for diagnostics. Credentials and cookie
// values are not returned as ordinary response evidence.
func safeRequestHeaders(h http.Header) http.Header {
	out := h.Clone()
	for k := range out {
		switch strings.ToLower(k) {
		case "authorization", "proxy-authorization", "cookie":
			out[k] = []string{"[REDACTED]"}
		case strings.ToLower(http.HeaderOrderKey):
			delete(out, k)
		}
	}
	return out
}
