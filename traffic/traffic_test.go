package traffic_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emhha/netloom"
	"github.com/emhha/netloom/infoextract"
	"github.com/emhha/netloom/mitm"
	"github.com/emhha/netloom/passive"
	"github.com/emhha/netloom/passive/plugins"
	"github.com/emhha/netloom/traffic"
)

type countPlugin struct {
	id         string
	cache      bool
	executions atomic.Int64
}

func (p *countPlugin) Metadata() passive.Metadata { return passive.Metadata{ID: p.id, Version: "1"} }
func (p *countPlugin) CacheKey(in passive.Input) string {
	if p.cache {
		return passive.ContentKey(in.Site, in.SessionID, in.Request.URL, in.Response.ContentType, in.Response.Body)
	}
	return ""
}
func (p *countPlugin) Analyze(context.Context, passive.Input) (passive.Result, error) {
	p.executions.Add(1)
	return passive.Result{}, nil
}

func tunnel(t *testing.T, origin string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var connections atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "app.test:443" {
			http.Error(w, "unexpected target", http.StatusForbidden)
			return
		}
		remote, err := net.DialTimeout("tcp", origin, time.Second)
		if err != nil {
			http.Error(w, "no upstream", http.StatusBadGateway)
			return
		}
		defer remote.Close()
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		connections.Add(1)
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if buffered.Flush() != nil {
			return
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = io.Copy(remote, buffered)
			_ = remote.Close()
		}()
		_, _ = io.Copy(client, remote)
		_ = client.Close()
		<-done
	}))
	t.Cleanup(server.Close)
	return server, &connections
}

func reportWithin(t *testing.T, reports <-chan traffic.Report) traffic.Report {
	t.Helper()
	select {
	case report := <-reports:
		return report
	case <-time.After(4 * time.Second):
		t.Fatal("no analysis report")
		return traffic.Report{}
	}
}

func TestSharedAnalysisProxyAndTLS(t *testing.T) {
	const target = "https://app.test/static/main.js"
	const fixture1 = "LTAIFixtureOnly0001"
	const fixture2 = "LTAIFixtureOnly0002"
	type hello struct {
		ciphers, versions []uint16
		protocols         []string
	}
	hellos := make(chan hello, 12)
	var revision atomic.Int64
	var requests atomic.Int64
	withoutGrease := func(values []uint16) []uint16 {
		return slices.DeleteFunc(slices.Clone(values), func(value uint16) bool {
			return value&0x0f0f == 0x0a0a && byte(value>>8) == byte(value)
		})
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fixture := fixture1
		if revision.Load() != 0 {
			fixture = fixture2
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("X-Visit", fmt.Sprint(requests.Add(1)))
		encoded := gzip.NewWriter(w)
		_, _ = fmt.Fprintf(encoded, "const syntheticTestValue = %q;", fixture)
		_ = encoded.Close()
	}))
	origin.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		hellos <- hello{withoutGrease(h.CipherSuites), withoutGrease(h.SupportedVersions), slices.Clone(h.SupportedProtos)}
		return nil, nil
	}}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	proxyA, countA := tunnel(t, origin.Listener.Addr().String())
	proxyB, countB := tunnel(t, origin.Listener.Addr().String())

	engine, err := netloom.New(netloom.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	req := &netloom.Request{URL: target, Profile: netloom.ProfileByName("chrome_120"), Proxy: proxyA.URL}
	plain, err := engine.Send(t.Context(), req)
	if err != nil || plain.StatusCode != http.StatusOK {
		t.Fatalf("plain send: %v", err)
	}
	baseline := <-hellos

	cached := &countPlugin{id: "cached", cache: true}
	uncached := &countPlugin{id: "uncached"}
	registry, err := passive.New([]passive.Plugin{&plugins.Information{Extractor: infoextract.New()}, cached, uncached}, 16)
	if err != nil {
		t.Fatal(err)
	}
	reports := make(chan traffic.Report, 8)
	flow, err := traffic.New(traffic.Config{Engine: engine, Registry: registry, Proxies: traffic.ProxyConfig{Default: &proxyA.URL},
		OnReport: func(report traffic.Report) { reports <- report }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(flow.Close)

	check := func(report traffic.Report, source traffic.Source, fixture string, hit bool) {
		t.Helper()
		expectedURL := target
		if source == traffic.SourceMITM {
			expectedURL = "https://app.test:443/static/main.js"
		}
		if report.Source != source || report.URL != expectedURL || report.StatusCode != 200 || report.ResponseIncomplete || report.DecodeError != nil || report.AnalysisError != nil {
			t.Fatalf("bad report: %+v", report)
		}
		var inspected bool
		for _, result := range report.Results {
			if result.PluginID != "infoextract" {
				continue
			}
			var state struct {
				BodyCacheHit   bool `json:"body_cache_hit"`
				HeaderCacheHit bool `json:"header_cache_hit"`
			}
			if err := json.Unmarshal(result.Data, &state); err != nil || state.BodyCacheHit != hit || state.HeaderCacheHit {
				t.Fatalf("unexpected cache status %s: %v", result.Data, err)
			}
			inspected = slices.ContainsFunc(result.Artifacts, func(a passive.Artifact) bool { return a.Rule == "aliyun_access_key" && a.Value == fixture })
		}
		if !inspected {
			t.Fatalf("synthetic finding missing: %+v", report.Results)
		}
	}

	req.Proxy = ""
	resp, report, err := flow.Send(t.Context(), req, traffic.RequestOptions{})
	if err != nil || !bytes.Equal(plain.Body, resp.Body) || req.Proxy != "" {
		t.Fatalf("active response or request changed: %v", err)
	}
	if active := <-hellos; !reflect.DeepEqual(active, baseline) {
		t.Fatalf("active TLS changed: before=%+v after=%+v", baseline, active)
	}
	check(report, traffic.SourceRequest, fixture1, false)

	ca, err := mitm.NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	originTrust := x509.NewCertPool()
	originTrust.AddCert(origin.Certificate())
	backend, err := flow.NewMITMBackend(func(_ context.Context, target *url.URL) error {
		if target.Hostname() != "app.test" {
			return errors.New("unexpected target")
		}
		return nil
	}, &http.Transport{DisableCompression: true, TLSClientConfig: &tls.Config{
		RootCAs: originTrust, ServerName: origin.Certificate().DNSNames[0],
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(backend.CloseIdleConnections)
	proxy := mitm.New(ca, backend, mitm.Options{})
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)
	t.Cleanup(proxy.Close)
	proxyURL, _ := url.Parse(server.URL)
	browserTrust := x509.NewCertPool()
	if !browserTrust.AppendCertsFromPEM(ca.CertificatePEM()) {
		t.Fatal("could not load MITM CA")
	}
	browserTransport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableCompression: true, TLSClientConfig: &tls.Config{RootCAs: browserTrust}}
	t.Cleanup(browserTransport.CloseIdleConnections)
	browser := &http.Client{Transport: browserTransport, Timeout: 4 * time.Second}
	viaMITM, err := browser.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := io.ReadAll(viaMITM.Body)
	_ = viaMITM.Body.Close()
	if err != nil || !bytes.Equal(resp.Body, encoded) || viaMITM.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("MITM changed compressed response: %v", err)
	}
	check(reportWithin(t, reports), traffic.SourceMITM, fixture1, true)
	if countA.Load() != 3 || countB.Load() != 0 {
		t.Fatalf("shared proxy did not serve both paths: A=%d B=%d", countA.Load(), countB.Load())
	}

	revision.Store(1)
	stream, err := flow.SendStream(t.Context(), req, traffic.RequestOptions{Proxy: &proxyB.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, stream.Body); err != nil {
		t.Fatal(err)
	}
	if err := stream.Body.Close(); err != nil {
		t.Fatal(err)
	}
	check(reportWithin(t, reports), traffic.SourceRequest, fixture2, false)
	var handlerCalls atomic.Int64
	task, err := flow.PrepareTask(netloom.Task{Req: req, Pipeline: []netloom.Handler{func(*netloom.Context) error {
		handlerCalls.Add(1)
		return nil
	}}}, traffic.RequestOptions{Proxy: &proxyB.URL})
	if err != nil {
		t.Fatal(err)
	}
	run, err := engine.Run(t.Context(), []netloom.Task{task})
	if err != nil {
		t.Fatal(err)
	}
	for result := range run {
		if result.Ctx.Resp.Error != nil {
			t.Fatal(result.Ctx.Resp.Error)
		}
	}
	check(reportWithin(t, reports), traffic.SourceRequest, fixture2, true)
	flow.Close()
	if countB.Load() != 2 || cached.executions.Load() != 2 || uncached.executions.Load() != 4 || handlerCalls.Load() != 1 || len(reports) != 0 {
		t.Fatalf("B=%d cache=%d uncached=%d handler=%d pending=%d", countB.Load(), cached.executions.Load(), uncached.executions.Load(), handlerCalls.Load(), len(reports))
	}
}

func TestProxyValidation(t *testing.T) {
	registry, _ := passive.New(nil, 0)
	secret := "http://user:secret@host.invalid/bad"
	_, err := traffic.New(traffic.Config{Registry: registry, Proxies: traffic.ProxyConfig{MITM: &secret}})
	if !errors.Is(err, netloom.ErrInvalidProxy) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unexpected proxy error: %v", err)
	}
}
