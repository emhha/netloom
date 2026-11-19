package traffic_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emhha/netloom/mitm"
	"github.com/emhha/netloom/passive"
	"github.com/emhha/netloom/passive/plugins/infoextract"
	"github.com/emhha/netloom/passive/plugins/serialization"
	"github.com/emhha/netloom/traffic"
)

const loadWorkers = 8

func BenchmarkMITMLoad(b *testing.B) {
	for _, mode := range []string{"forward-only", "metadata-cache", "body-hash-cache", "both-plugins", "slow-plugin"} {
		b.Run(mode, func(b *testing.B) { benchmarkMITMLoad(b, mode) })
	}
}

func benchmarkMITMLoad(b *testing.B, mode string) {
	const status = `{"ok":true}`
	script := compressedFixture(b)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", strconv.Itoa(len(status)))
			_, _ = io.WriteString(w, status)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(script)))
		_, _ = w.Write(script)
	}))
	b.Cleanup(origin.Close)
	target, err := url.Parse(origin.URL)
	if err != nil {
		b.Fatal(err)
	}
	upstream := origin.Client().Transport.(*http.Transport).Clone()
	upstream.DisableCompression = true
	upstream.MaxIdleConnsPerHost = loadWorkers
	b.Cleanup(upstream.CloseIdleConnections)
	fixture := &loadBackend{origin: target, transport: upstream}
	var backend mitm.Backend = fixture

	var flow *traffic.Traffic
	var reports, reportErrors, bodyHits int
	if mode != "forward-only" {
		info := infoextract.New()
		info.HashBodyForCache = mode == "body-hash-cache"
		selected := []passive.Plugin{info}
		if mode == "both-plugins" {
			selected = append(selected, serialization.New())
		}
		if mode == "slow-plugin" {
			selected = append(selected, delayedPlugin{})
		}
		registry, err := passive.New(selected, 128)
		if err != nil {
			b.Fatal(err)
		}
		flow, err = traffic.New(traffic.Config{Registry: registry, OnReport: func(report traffic.Report) {
			reports++
			failed := report.AnalysisError != nil || report.DecodeError != nil || report.TransportError != nil || report.ResponseIncomplete || report.ResponseTruncated || len(report.Results) != len(selected)
			for _, result := range report.Results {
				failed = failed || result.Status != "completed"
				if result.PluginID == "infoextract" && bytes.Contains(result.Data, []byte(`"body_cache_hit":true`)) {
					bodyHits++
				}
			}
			if failed {
				reportErrors++
			}
		}})
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(flow.Close)
		backend, err = flow.WrapMITM(backend)
		if err != nil {
			b.Fatal(err)
		}
	}

	var forwarded sync.WaitGroup
	forwarded.Add(b.N)
	client := loadProxyClient(b, loadCompletionBackend{backend, &forwarded})
	latencies := make([]time.Duration, b.N)
	var next atomic.Int64
	var workers sync.WaitGroup
	var firstErr error
	var failOnce sync.Once
	b.ReportAllocs()
	b.ResetTimer()
	for range loadWorkers {
		workers.Go(func() {
			for {
				i := int(next.Add(1) - 1)
				if i >= b.N {
					return
				}
				path, size := "/main.js", len(script)
				switch i % 10 {
				case 8:
					path = "/main.js?revision=" + strconv.Itoa(i)
				case 9:
					path, size = "/status", len(status)
				}
				start := time.Now()
				err := readLoadResponse(client, origin.URL+path, size)
				latencies[i] = time.Since(start)
				if err != nil {
					failOnce.Do(func() { firstErr = err })
				}
			}
		})
	}
	workers.Wait()
	b.StopTimer()
	if firstErr != nil {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		b.Fatalf("forwarding: %v; upstream: %v", firstErr, fixture.err)
	}

	// EOF on the client can precede the server's deferred body close. Wait
	// for submission before draining the analysis queue and counting drops.
	closed := make(chan struct{})
	go func() { forwarded.Wait(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		b.Fatal("response bodies did not close")
	}
	slices.Sort(latencies)
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "forward_req/s")
	b.ReportMetric(float64(latencies[(95*b.N-1)/100].Nanoseconds())/1e3, "p95_us")
	b.ReportMetric(float64(latencies[(99*b.N-1)/100].Nanoseconds())/1e3, "p99_us")
	if flow != nil {
		flow.Close()
		dropped := flow.Dropped()
		if reports+int(dropped) != b.N || reportErrors != 0 {
			b.Fatalf("requests=%d reports=%d dropped=%d report errors=%d", b.N, reports, dropped, reportErrors)
		}
		b.ReportMetric(float64(reports)*100/float64(b.N), "reports_%")
		b.ReportMetric(float64(dropped)*100/float64(b.N), "dropped_%")
		if reports > 0 {
			b.ReportMetric(float64(bodyHits)*100/float64(reports), "body_hits_%")
		}
	}
}

func compressedFixture(b *testing.B) []byte {
	b.Helper()
	data := make([]byte, 64<<10)
	seed := rand.New(rand.NewPCG(17, 29))
	for i := range data {
		data[i] = byte('a' + seed.IntN(26))
	}
	copy(data, `const workload = "`)
	copy(data[len(data)-2:], `";`)
	var compressed bytes.Buffer
	encoder := gzip.NewWriter(&compressed)
	if _, err := encoder.Write(data); err != nil {
		b.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		b.Fatal(err)
	}
	return compressed.Bytes()
}

func loadProxyClient(b *testing.B, backend mitm.Backend) *http.Client {
	b.Helper()
	ca, err := mitm.NewAuthority()
	if err != nil {
		b.Fatal(err)
	}
	proxy := mitm.New(ca, backend, mitm.Options{})
	server := httptest.NewServer(proxy)
	b.Cleanup(server.Close)
	b.Cleanup(proxy.Close)
	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		b.Fatal(err)
	}
	trust := x509.NewCertPool()
	if !trust.AppendCertsFromPEM(ca.CertificatePEM()) {
		b.Fatal("cannot trust fixture CA")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trust},
		DisableCompression: true, MaxIdleConnsPerHost: loadWorkers, MaxConnsPerHost: loadWorkers,
	}}
	b.Cleanup(client.CloseIdleConnections)
	return client
}

func readLoadResponse(client *http.Client, target string, expected int) error {
	response, err := client.Get(target)
	if err != nil {
		return err
	}
	size, readErr := io.Copy(io.Discard, response.Body)
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || size != int64(expected) {
		return fmt.Errorf("response HTTP %d, size %d, expected %d", response.StatusCode, size, expected)
	}
	return nil
}

type loadBackend struct {
	origin    *url.URL
	transport *http.Transport
	mu        sync.Mutex
	err       error
}

func (f *loadBackend) CheckTarget(_ context.Context, target *url.URL) error {
	if target.Scheme != f.origin.Scheme || target.Host != f.origin.Host {
		return errors.New("target is outside the load fixture")
	}
	return nil
}

func (f *loadBackend) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := f.transport.RoundTrip(req)
	if err != nil {
		f.mu.Lock()
		if f.err == nil {
			f.err = err
		}
		f.mu.Unlock()
	}
	return resp, err
}

type loadCompletionBackend struct {
	mitm.Backend
	forwarded *sync.WaitGroup
}

func (f loadCompletionBackend) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := f.Backend.RoundTrip(req)
	if err == nil && response != nil && response.Body != nil {
		response.Body = &loadCompletionBody{response.Body, f.forwarded}
	}
	return response, err
}

type loadCompletionBody struct {
	io.ReadCloser
	forwarded *sync.WaitGroup
}

func (b *loadCompletionBody) Close() error {
	err := b.ReadCloser.Close()
	b.forwarded.Done()
	return err
}

type delayedPlugin struct{}

func (delayedPlugin) Metadata() passive.Metadata    { return passive.Metadata{ID: "delay", Version: "1"} }
func (delayedPlugin) CacheKey(passive.Input) string { return "" }
func (delayedPlugin) Analyze(ctx context.Context, _ passive.Input) (passive.Result, error) {
	timer := time.NewTimer(2 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
		return passive.Result{}, nil
	case <-ctx.Done():
		return passive.Result{}, ctx.Err()
	}
}
