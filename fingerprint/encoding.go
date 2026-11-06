package fingerprint

import (
	"bytes"
	"io"
	"mime"
	"strings"

	"github.com/emhha/netloom/httpdata"
	"golang.org/x/net/html/charset"
)

// decodeBodyToUTF8 returns the response body decoded to UTF-8. If the body is
// already UTF-8 (or charset detection fails) the raw body is returned as-is.
// The original resp.Body is never modified.
func decodeBodyToUTF8(resp *httpdata.Response) []byte {
	if len(resp.Body) == 0 {
		return resp.Body
	}

	enc := detectCharset(resp)
	if enc == "" || isUTF8(enc) {
		return resp.Body
	}

	// Find the encoding via golang.org/x/net/html/charset.
	e, _ := charset.Lookup(enc)
	if e == nil {
		return resp.Body
	}

	reader := e.NewDecoder().Reader(bytes.NewReader(resp.Body))
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return resp.Body
	}
	return decoded
}

// detectCharset extracts the charset name from Content-Type header or HTML
// meta tag. Returns empty string if unknown.
func detectCharset(resp *httpdata.Response) string {
	ct := resp.Header.Get("Content-Type")
	if ct != "" {
		_, params, err := mime.ParseMediaType(ct)
		if err == nil {
			if cs := params["charset"]; cs != "" {
				return strings.TrimSpace(cs)
			}
		}
	}

	// Fallback: scan meta charset in the first 4 KB of body.
	return sniffMetaCharset(resp.Body)
}

// sniffMetaCharset scans the first 4096 bytes of body for:
//   - <meta charset="...">
//   - <meta http-equiv="Content-Type" content="text/html; charset=...">
func sniffMetaCharset(body []byte) string {
	if len(body) > 4096 {
		body = body[:4096]
	}
	s := strings.ToLower(string(body))

	// Look for charset= pattern.
	idx := strings.Index(s, "charset=")
	if idx == -1 {
		return ""
	}
	s = s[idx+len("charset="):]

	// Strip quotes.
	if len(s) > 0 && (s[0] == '"' || s[0] == '\'') {
		s = s[1:]
	}

	// Read until delimiter.
	end := strings.IndexAny(s, "\"' ;>")
	if end == -1 {
		end = len(s)
	}
	cs := strings.TrimSpace(s[:end])
	return cs
}

func isUTF8(enc string) bool {
	enc = strings.ToLower(strings.TrimSpace(enc))
	return enc == "utf-8" || enc == "utf8"
}
