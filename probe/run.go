package probe

import (
	"context"
	"crypto/md5" //nolint:gosec // md5 used for body dedup hash only
	"encoding/hex"
	"fmt"
	"net/url"
	"netrt.local/netrt"
	"strings"
	"sync"

	http "github.com/bogdanfinn/fhttp"
)

// Run executes a batch liveness probe against targets and streams results.
//
// Each element of targets is a raw URL (e.g. "https://example.com",
// "http://1.2.3.4:8080"). Scope authorization must be performed by the caller
// before Run is invoked. netrt Transport permanently rejects loopback and
// link-local addresses at the dial layer.
//
// The returned channel is closed when all targets have been processed or ctx
// is cancelled.
func Run(ctx context.Context, targets []string, cfg *Config) <-chan *Result {
	out := make(chan *Result, len(targets))
	if cfg == nil {
		cfg = &Config{}
	}

	ratePerSecond, threads := cfg.rateParams()
	engCfg := netrt.Config{
		Threads:       threads,
		RatePerSecond: ratePerSecond,
		Timeout:       cfg.timeout(),
		Retries:       retries(cfg.MaxRetries),
		MaxBodySize:   cfg.maxBodySize(),
		CookieJar:     cfg.EnableCookies,
	}

	eng, err := netrt.New(engCfg)
	if err != nil {
		// Engine construction should never fail with standard config; surface as
		// an error result per target and close immediately.
		go func() {
			defer close(out)
			for _, t := range targets {
				out <- &Result{
					Target:    t,
					TargetKey: buildTargetKey(t),
					Error:     fmt.Sprintf("probe: engine init: %v", err),
				}
			}
		}()
		return out
	}

	go func() {
		defer close(out)
		defer eng.Close()
		runProbe(ctx, targets, cfg, eng, out)
	}()

	return out
}

// runProbe drives the fan-out across targets using a bounded worker pool.
// Each target runs the HTTPS→HTTP fallback sequence independently.
func runProbe(ctx context.Context, targets []string, cfg *Config, eng *netrt.Engine, out chan<- *Result) {
	_, threads := cfg.rateParams()
	if threads <= 0 {
		threads = 50
	}

	detector := newSoft404Detector(0) // threshold=3 default

	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	pipeline := buildPipeline(cfg)

targetLoop:
	for _, raw := range targets {
		select {
		case <-ctx.Done():
			break targetLoop
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			r := probeTarget(ctx, target, cfg, eng, pipeline, detector)
			select {
			case <-ctx.Done():
			case out <- r:
			}
		}(raw)
	}

	wg.Wait()
}

// probeTarget probes a single target applying HTTPS→HTTP fallback logic.
// It returns a single Result (alive or failed).
func probeTarget(
	ctx context.Context,
	target string,
	cfg *Config,
	eng *netrt.Engine,
	pipeline []netrt.Handler,
	detector *Soft404Detector,
) *Result {
	// Normalise: if no scheme, prepend https.
	probeURL := normaliseURL(target)

	// Determine whether to try HTTPS first or use the explicit scheme.
	u, err := url.Parse(probeURL)
	if err != nil {
		return &Result{
			Target:    target,
			TargetKey: buildTargetKey(target),
			Error:     fmt.Sprintf("probe: parse url: %v", err),
		}
	}

	scheme := strings.ToLower(u.Scheme)

	// If caller explicitly gave http:// and NoFallback is irrelevant (only HTTPS→HTTP,
	// not HTTP→HTTPS), probe HTTP directly.
	if scheme == "http" {
		return probeHTTP(ctx, target, probeURL, cfg, eng, pipeline, detector)
	}

	// Probe HTTPS first.
	httpsURL := toScheme(u, "https")
	r := probeHTTPS(ctx, target, httpsURL, cfg, eng, pipeline, detector)
	if r.Error == "" || r.StatusCode > 0 || len(r.Redirects) > 0 {
		// Any HTTP response (including 4xx/5xx) means the host is alive; do not fall back.
		return r
	}

	// HTTPS connection failed; fall back to HTTP unless disabled.
	if cfg.NoFallback {
		return r
	}

	httpURL := toScheme(u, "http")
	return probeHTTP(ctx, target, httpURL, cfg, eng, pipeline, detector)
}

// probeHTTPS sends an HTTPS request and handles redirects.
func probeHTTPS(
	ctx context.Context,
	target, rawURL string,
	cfg *Config,
	eng *netrt.Engine,
	pipeline []netrt.Handler,
	detector *Soft404Detector,
) *Result {
	return sendWithRedirects(ctx, target, rawURL, cfg, eng, pipeline, detector)
}

// probeHTTP sends an HTTP request and handles redirects.
func probeHTTP(
	ctx context.Context,
	target, rawURL string,
	cfg *Config,
	eng *netrt.Engine,
	pipeline []netrt.Handler,
	detector *Soft404Detector,
) *Result {
	return sendWithRedirects(ctx, target, rawURL, cfg, eng, pipeline, detector)
}

// sendWithRedirects performs the initial request and, when FollowRedirect is
// true, traces the redirect chain up to MaxRedirects hops.
func sendWithRedirects(
	ctx context.Context,
	target, rawURL string,
	cfg *Config,
	eng *netrt.Engine,
	pipeline []netrt.Handler,
	detector *Soft404Detector,
) *Result {
	req := buildRequest(rawURL, cfg)
	exchange, err := netrt.Do(ctx, eng, req, netrt.RedirectPolicy{Follow: cfg.FollowRedirect, MaxHops: cfg.MaxRedirects, ValidateURL: cfg.ValidateURL})
	if err != nil {
		failed := &Result{Target: target, URL: rawURL, TargetKey: buildTargetKey(rawURL), Error: fmt.Sprintf("probe: %v", err)}
		if exchange != nil {
			failed.Redirects = exchange.Hops
			if exchange.Request != nil {
				failed.URL = exchange.Request.URL
				failed.TargetKey = buildTargetKey(failed.URL)
			}
			if exchange.Response != nil {
				failed.StatusCode = exchange.Response.StatusCode
				failed.ResponseTime = exchange.Response.TotalTime
			}
		}
		return failed
	}
	req, resp := exchange.Request, exchange.Response
	pipelineCtx := netrt.NewContext(ctx, req, pipeline, nil)
	pipelineCtx.Resp = resp
	if err := pipelineCtx.Next(); err != nil {
		return &Result{Target: target, URL: req.URL, TargetKey: buildTargetKey(req.URL), Error: fmt.Sprintf("probe: analyze response: %v", err)}
	}
	resp = pipelineCtx.Resp
	if resp.BodyHash == "" && len(resp.Body) > 0 {
		hash := md5.Sum(resp.Body)
		resp.BodyHash = hex.EncodeToString(hash[:])
	}
	var fingerprints []string
	if cfg.EnableFingerprint {
		fingerprints = matchFingerprints(resp)
	}
	return &Result{Target: target, URL: req.URL, TargetKey: buildTargetKey(req.URL), StatusCode: resp.StatusCode, Title: resp.Title,
		WebServer: resp.WebServer, IP: resp.IP, CNAME: resp.CNAME, ResponseTime: resp.TotalTime, ContentLength: resp.ContentLength, BodyHash: resp.BodyHash,
		TLS: resp.TLS, Fingerprints: fingerprints, IsSoft404: detector.Check(resp.StatusCode, resp.BodyHash), Redirects: exchange.Hops}
}

// buildRequest constructs a netrt.Request from the probe URL and config.
func buildRequest(rawURL string, cfg *Config) *netrt.Request {
	req := &netrt.Request{
		Method:    "GET",
		URL:       rawURL,
		Timeout:   cfg.timeout(),
		Profile:   netrt.ProfileByName(cfg.TLSProfile),
		Proxy:     cfg.ProxyURL,
		VerifyTLS: !cfg.SkipVerify,
	}
	if len(cfg.CustomHeaders) > 0 {
		req.Header = make(http.Header, len(cfg.CustomHeaders))
		for k, v := range cfg.CustomHeaders {
			req.Header[k] = []string{v}
		}
	}
	return req
}

// isRedirect reports whether the status code is a 3xx redirect.
func isRedirect(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

// resolveRedirect resolves the Location header value against the current URL.
func resolveRedirect(current, location string) (string, error) {
	return netrt.ResolveRedirect(current, location)
}

// normaliseURL ensures rawURL has a scheme. Bare hostnames / IPs get "https://".
func normaliseURL(raw string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	return "https://" + raw
}

// toScheme replaces the scheme in u and returns the new URL string.
func toScheme(u *url.URL, scheme string) string {
	cp := *u
	cp.Scheme = scheme
	return cp.String()
}

// retries maps the MaxRetries field, applying the default (2) when zero.
func retries(n int) int {
	if n < 0 {
		return -1
	}
	if n == 0 {
		return 2
	}
	return n
}
