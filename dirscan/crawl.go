package dirscan

import (
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
	"netrt.local/netrt"
)

// mediaExtBlacklist lists file extensions that are not worth adding to the
// crawl queue because they are clearly not directory-scan targets.
var mediaExtBlacklist = map[string]bool{
	"png": true, "jpg": true, "jpeg": true, "gif": true, "ico": true,
	"svg": true, "webp": true, "mp4": true, "mp3": true, "avi": true,
	"css": true, "woff": true, "woff2": true, "ttf": true, "eot": true,
	"pdf": true, "zip": true, "tar": true, "gz": true,
}

// reURLInText matches absolute URLs embedded in JavaScript / JSON / plain text.
var reURLInText = regexp.MustCompile(`https?://[^\s"'<>]+`)

// reRobotsPath matches Allow/Disallow lines in robots.txt.
var reRobotsPath = regexp.MustCompile(`(?i)(?:Allow|Disallow):\s*(/[^\s]*)`)

// ExtractLinks parses a response and returns a deduplicated list of relative
// paths scoped to the same host as baseURL. Only paths that pass
// isValidLink are included.
func ExtractLinks(resp *netrt.Response, baseURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	ct := strings.ToLower(resp.ContentType)
	// Strip parameters from content-type.
	if idx := strings.Index(ct, ";"); idx >= 0 {
		ct = ct[:idx]
	}
	ct = strings.TrimSpace(ct)

	var raw []string
	switch {
	case strings.Contains(ct, "text/html"):
		raw = extractHTML(resp.Body)
	case strings.Contains(ct, "text/plain") && looksLikeRobots(resp):
		raw = extractRobots(resp.Body)
	default:
		// JavaScript, JSON, plain text — regex sweep for embedded URLs.
		raw = extractByRegex(resp.Body, base)
	}
	// Also always run regex on HTML to catch JS-embedded URLs.
	if strings.Contains(ct, "text/html") {
		raw = append(raw, extractByRegex(resp.Body, base)...)
	}

	return dedupeLinks(filterLinks(raw, base))
}

// looksLikeRobots checks if the response path is robots.txt.
func looksLikeRobots(resp *netrt.Response) bool {
	return resp != nil && strings.Contains(strings.ToLower(resp.Location), "robots")
}

// extractHTML parses HTML and collects href/src/action/data attribute values.
func extractHTML(body []byte) []string {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}
	var links []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			attrs := urlAttrs(n.Data)
			for _, a := range n.Attr {
				if attrs[a.Key] && a.Val != "" {
					links = append(links, a.Val)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return links
}

// urlAttrs returns the set of attribute names that carry URL values for a
// given HTML tag name.
func urlAttrs(tag string) map[string]bool {
	switch tag {
	case "a", "area", "base", "link":
		return map[string]bool{"href": true}
	case "script", "iframe", "embed", "source", "audio", "video":
		return map[string]bool{"src": true}
	case "form":
		return map[string]bool{"action": true}
	case "img":
		return map[string]bool{"src": true, "data-src": true}
	case "meta":
		return map[string]bool{"content": true}
	default:
		return map[string]bool{"href": true, "src": true, "action": true, "data": true}
	}
}

// extractRobots pulls Allow/Disallow paths from robots.txt body.
func extractRobots(body []byte) []string {
	var links []string
	for _, m := range reRobotsPath.FindAllSubmatch(body, -1) {
		if len(m) >= 2 {
			links = append(links, string(m[1]))
		}
	}
	return links
}

// extractByRegex sweeps body for embedded absolute URLs that match the base
// host, converting them to relative paths.
func extractByRegex(body []byte, base *url.URL) []string {
	var links []string
	for _, raw := range reURLInText.FindAll(body, -1) {
		u, err := url.Parse(string(raw))
		if err != nil {
			continue
		}
		if !sameHost(u, base) {
			continue
		}
		links = append(links, u.RequestURI())
	}
	return links
}

// filterLinks resolves each raw link relative to base, keeps only same-host
// paths, and rejects media files.
func filterLinks(raw []string, base *url.URL) []string {
	var out []string
	for _, link := range raw {
		link = strings.TrimSpace(link)
		if link == "" || strings.HasPrefix(link, "#") || strings.HasPrefix(link, "javascript:") || strings.HasPrefix(link, "mailto:") {
			continue
		}
		u, err := base.Parse(link)
		if err != nil {
			continue
		}
		if !sameHost(u, base) {
			continue
		}
		if !isValidLink(u) {
			continue
		}
		// Convert to relative path.
		rel := u.Path
		if u.RawQuery != "" {
			rel += "?" + u.RawQuery
		}
		if rel == "" || rel == "/" {
			continue
		}
		out = append(out, rel)
	}
	return out
}

// sameHost reports whether u shares the same host as base.
func sameHost(u, base *url.URL) bool {
	return strings.EqualFold(u.Hostname(), base.Hostname())
}

// isValidLink reports whether the URL is worth adding to the scan queue.
func isValidLink(u *url.URL) bool {
	ext := fileExt(u.Path)
	if ext != "" && mediaExtBlacklist[ext] {
		return false
	}
	return true
}

// dedupeLinks removes duplicate paths while preserving order.
func dedupeLinks(links []string) []string {
	seen := make(map[string]struct{}, len(links))
	out := make([]string, 0, len(links))
	for _, l := range links {
		if _, ok := seen[l]; !ok {
			seen[l] = struct{}{}
			out = append(out, l)
		}
	}
	return out
}
