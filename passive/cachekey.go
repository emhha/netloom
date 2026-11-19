package passive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func normalizedURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	u.Host = host
	if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	}
	u.Fragment, u.RawFragment = "", ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

// SiteKey binds per-site plugins to a project and a canonical origin.
func SiteKey(projectID, rawURL string) string {
	u, err := url.Parse(normalizedURL(rawURL))
	if err != nil || u.Host == "" {
		return ""
	}
	return projectID + ":" + u.Scheme + "://" + u.Host
}

// ContentKey identifies body analysis independently of volatile response headers.
func ContentKey(site, session, rawURL, contentType string, body []byte) string {
	canonicalURL := normalizedURL(rawURL)
	if canonicalURL == "" {
		return ""
	}
	bodyHash := sha256.Sum256(body)
	data, _ := json.Marshal([]string{site, session, canonicalURL, normalizedContentType(contentType), hex.EncodeToString(bodyHash[:])})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func normalizedContentType(value string) string {
	if mediaType, _, err := mime.ParseMediaType(value); err == nil {
		return strings.ToLower(mediaType)
	}
	return value
}

// ContentLengthKey identifies body analysis by metadata without reading body
// bytes. It may match different content of the same length. A truncated body
// requires a positive Content-Length and uses a separate key from complete
// evidence. An empty key disables reuse when the full length is unknown.
func ContentLengthKey(in Input) string {
	if in.Request == nil || in.Response == nil {
		return ""
	}
	canonicalURL := normalizedURL(in.Request.URL)
	if canonicalURL == "" {
		return ""
	}
	resp := in.Response
	length, captured := uint64(len(resp.Body)), -1
	var encoding string
	if resp.BodyTruncated {
		lengths := resp.Header.Values("Content-Length")
		if len(lengths) != 1 || len(resp.Body) == 0 {
			return ""
		}
		var err error
		length, err = strconv.ParseUint(strings.TrimSpace(lengths[0]), 10, 63)
		if err != nil || length == 0 {
			return ""
		}
		captured = len(resp.Body)
		encoding = strings.Join(resp.Header.Values("Content-Encoding"), ",")
	}
	data, _ := json.Marshal(struct {
		Site, Session, URL, Type, Encoding string
		Length                             uint64
		Captured                           int
	}{in.Site, in.SessionID, canonicalURL, normalizedContentType(resp.ContentType), encoding, length, captured})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
