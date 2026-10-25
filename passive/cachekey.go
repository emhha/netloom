package passive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime"
	"net"
	"net/url"
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
	if mediaType, _, parseErr := mime.ParseMediaType(contentType); parseErr == nil {
		contentType = strings.ToLower(mediaType)
	}
	bodyHash := sha256.Sum256(body)
	data, _ := json.Marshal([]string{site, session, canonicalURL, contentType, hex.EncodeToString(bodyHash[:])})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
