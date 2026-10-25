package probe

import (
	"crypto/md5" //nolint:gosec // md5 used for body dedup hash, not security
	"encoding/hex"
	"fmt"
	"netrt.local/netrt"
	"strings"

	http "github.com/bogdanfinn/fhttp"
)

// headerMutator adds the configured User-Agent and any custom headers to
// every request before it is dispatched by the Transport.
type headerMutator struct {
	userAgent     string
	customHeaders map[string]string
}

func (m *headerMutator) Mutate(req *netrt.Request) error {
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	if m.userAgent != "" {
		req.Header.Set("User-Agent", m.userAgent)
	}
	for k, v := range m.customHeaders {
		req.Header.Set(k, v)
	}
	return nil
}

// proxyMutator sets the proxy on the request when a ProxyURL is configured.
type proxyMutator struct {
	proxyURL string
}

func (m *proxyMutator) Mutate(req *netrt.Request) error {
	if m.proxyURL != "" {
		req.Proxy = m.proxyURL
	}
	return nil
}

// tlsProfileMutator applies the browser TLS fingerprint profile to the request.
// Certificate verification is handled unconditionally by the netrt transport
// (scanning always skips verify), so only the profile name is carried here.
type tlsProfileMutator struct {
	profileName string
}

func (m *tlsProfileMutator) Mutate(req *netrt.Request) error {
	req.Profile = netrt.ProfileByName(m.profileName)
	return nil
}

// certExtractor implements netrt.Extractor. It surfaces TLS certificate
// information already captured by the Transport as a structured Artifact so
// it travels through the Pipeline alongside other extraction outputs.
// The TLSInfo itself is preserved on the Response; this extractor adds a
// human-readable Artifact for visibility in pipeline logs.
type certExtractor struct{}

func (certExtractor) Name() string { return "cert" }

func (certExtractor) Extract(resp *netrt.Response) ([]netrt.Artifact, error) {
	if resp.TLS == nil {
		return nil, nil
	}
	arts := []netrt.Artifact{
		{Type: "cert.subject", Value: resp.TLS.Subject},
		{Type: "cert.issuer", Value: resp.TLS.Issuer},
		{Type: "cert.sha256", Value: resp.TLS.FingerprintSHA256},
		{Type: "cert.not_after", Value: resp.TLS.NotAfter.String()},
	}
	for _, san := range resp.TLS.SANs {
		arts = append(arts, netrt.Artifact{Type: "cert.san", Value: san})
	}
	return arts, nil
}

// htmlExtractor implements netrt.Extractor. It extracts the <title> element
// from the response body and writes it back to resp.Title.
type htmlExtractor struct{}

func (htmlExtractor) Name() string { return "html" }

func (htmlExtractor) Extract(resp *netrt.Response) ([]netrt.Artifact, error) {
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

// buildPipeline constructs the ordered handler slice for a probe request.
// Request-side mutators run first (priority 10→30), then response-side
// extractors run after the Transport returns (via AsExtractor wrapping).
func buildPipeline(cfg *Config) []netrt.Handler {
	// Request-side: ProxyMutator → HeaderMutator → TLSProfileMutator
	proxy := netrt.AsMutator(&proxyMutator{proxyURL: cfg.ProxyURL})
	header := netrt.AsMutator(&headerMutator{
		userAgent:     defaultUserAgent(),
		customHeaders: cfg.CustomHeaders,
	})
	tls := netrt.AsMutator(&tlsProfileMutator{
		profileName: cfg.TLSProfile,
	})

	// Response-side: CertExtractor → HTMLExtractor (soft404 is applied outside pipeline)
	cert := netrt.AsExtractor(certExtractor{})
	html := netrt.AsExtractor(htmlExtractor{})

	return []netrt.Handler{proxy, header, tls, cert, html}
}

// defaultUserAgent returns the default User-Agent header value for probe requests.
func defaultUserAgent() string {
	return fmt.Sprintf("Mozilla/5.0 (compatible; netrt-probe/%s)", "1.0")
}
