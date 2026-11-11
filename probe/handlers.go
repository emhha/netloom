package probe

import (
	"crypto/md5" //nolint:gosec // md5 used for body dedup hash, not security
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/emhha/netloom"
)

// certExtractor implements netloom.Extractor. It surfaces TLS certificate
// information already captured by the Transport as a structured Artifact so
// it travels through the Pipeline alongside other extraction outputs.
// The TLSInfo itself is preserved on the Response; this extractor adds a
// human-readable Artifact for visibility in pipeline logs.
type certExtractor struct{}

func (certExtractor) Name() string { return "cert" }

func (certExtractor) Extract(resp *netloom.Response) ([]netloom.Artifact, error) {
	if resp.TLS == nil {
		return nil, nil
	}
	arts := []netloom.Artifact{
		{Type: "cert.subject", Value: resp.TLS.Subject},
		{Type: "cert.issuer", Value: resp.TLS.Issuer},
		{Type: "cert.sha256", Value: resp.TLS.FingerprintSHA256},
		{Type: "cert.not_after", Value: resp.TLS.NotAfter.String()},
	}
	for _, san := range resp.TLS.SANs {
		arts = append(arts, netloom.Artifact{Type: "cert.san", Value: san})
	}
	return arts, nil
}

// htmlExtractor implements netloom.Extractor. It extracts the <title> element
// from the response body and writes it back to resp.Title.
type htmlExtractor struct{}

func (htmlExtractor) Name() string { return "html" }

func (htmlExtractor) Extract(resp *netloom.Response) ([]netloom.Artifact, error) {
	if len(resp.Body) == 0 {
		return nil, nil
	}
	title := extractTitle(resp.Body)
	if title != "" {
		resp.Title = title
	}
	// Compute and store body hash for soft-404 detection.
	if resp.BodyHash == "" {
		h := md5.Sum(resp.Body) //nolint:gosec // md5 used only for dedup, not cryptographic purpose
		resp.BodyHash = hex.EncodeToString(h[:])
	}
	return nil, nil
}

// extractTitle scans body bytes for the first <title>…</title> content.
// It does not use an HTML parser to avoid the golang.org/x/net/html import
// (which is already a dependency, but a simple scan is sufficient here).
func extractTitle(body []byte) string {
	lower := strings.ToLower(string(body))
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += len("<title>")
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}
	title := string(body[start : start+end])
	title = strings.TrimSpace(title)
	// Collapse whitespace.
	fields := strings.Fields(title)
	return strings.Join(fields, " ")
}

// buildPipeline constructs response-only analysis. Request options are applied
// by buildRequest before Do sends the first request or follows redirects.
func buildPipeline(_ *Config) []netloom.Handler {
	cert := netloom.AsExtractor(certExtractor{})
	html := netloom.AsExtractor(htmlExtractor{})
	return []netloom.Handler{cert, html}
}

// defaultUserAgent returns the default User-Agent header value for probe requests.
func defaultUserAgent() string {
	return fmt.Sprintf("Mozilla/5.0 (compatible; netloom-probe/%s)", "1.0")
}
