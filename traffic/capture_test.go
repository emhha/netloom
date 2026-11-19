package traffic

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/emhha/netloom"
	"github.com/emhha/netloom/httpdata"
	"github.com/emhha/netloom/passive"
)

func TestCaptureDoesNotWaitForAnalysis(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	reports := make(chan Report, 2)
	registry, _ := passive.New(nil, 0)
	tt, err := New(Config{Registry: registry, QueueSize: 1, BodyLimit: 4, OnReport: func(report Report) {
		if report.ID == 1 {
			close(entered)
			<-release
		}
		reports <- report
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer tt.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	wrap := func() io.ReadCloser {
		return tt.captureResponse(io.NopCloser(strings.NewReader("abcdefgh")), tt.observe(SourceMITM,
			&httpdata.Request{URL: "https://app.test/"}, &httpdata.Response{StatusCode: 200}, nil))
	}
	first := wrap()
	// Reading beyond the capture limit emits the report before EOF/Close, and
	// does not change the bytes available to the forwarding reader.
	prefix := make([]byte, 5)
	if _, err := io.ReadFull(first, prefix); err != nil {
		t.Fatal(err)
	}
	<-entered
	if body, err := io.ReadAll(first); string(prefix)+string(body) != "abcdefgh" || err != nil {
		t.Fatalf("forwarding changed: %q %q %v", prefix, body, err)
	}
	_ = first.Close()
	_ = first.Close()
	second, third := wrap(), wrap()
	_ = second.Close()
	_ = third.Close()
	if tt.Dropped() != 1 {
		t.Fatalf("dropped=%d", tt.Dropped())
	}
	close(release)
	tt.Close()
	a, b := <-reports, <-reports
	if a.ID != 1 || !a.ResponseTruncated || a.ResponseIncomplete || b.ID != 2 || b.ResponseTruncated || !b.ResponseIncomplete {
		t.Fatalf("unexpected capture state: %+v %+v", a, b)
	}
}

func TestRequestProxyPrecedence(t *testing.T) {
	registry, _ := passive.New(nil, 0)
	shared, request, mitm, direct := "http://shared.test", "http://request.test", "http://mitm.test", ""
	tt, err := New(Config{Registry: registry, Proxies: ProxyConfig{Default: &shared, Request: &request, MITM: &mitm}, OnReport: func(Report) {}})
	if err != nil {
		t.Fatal(err)
	}
	defer tt.Close()
	request, mitm = "mutated", "mutated"
	r := &netloom.Request{}
	tt.applyRequestProxy(r, RequestOptions{})
	if r.Proxy != "http://request.test" {
		t.Fatalf("request proxy=%q", r.Proxy)
	}
	tt.applyRequestProxy(r, RequestOptions{Proxy: &direct})
	if r.Proxy != "" {
		t.Fatalf("explicit direct proxy=%q", r.Proxy)
	}
	r.Proxy = "http://existing.test"
	tt.applyRequestProxy(r, RequestOptions{})
	if r.Proxy != "http://existing.test" {
		t.Fatalf("explicit request proxy=%q", r.Proxy)
	}
	tr := &http.Transport{}
	backend, err := tt.NewMITMBackend(func(context.Context, *url.URL) error { return nil }, tr)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.CloseIdleConnections()
	parsed, err := backend.transport.Proxy(nil)
	if err != nil || parsed.String() != "http://mitm.test" || tr.Proxy != nil {
		t.Fatalf("MITM proxy=%v %v", parsed, err)
	}
	if _, err := tt.WrapMITM(backend); err == nil {
		t.Fatal("wrapped an already observed backend")
	}
	invalid := "invalid"
	if _, err := New(Config{Registry: registry, Proxies: ProxyConfig{Default: &invalid}}); !errors.Is(err, netloom.ErrInvalidProxy) {
		t.Fatalf("invalid proxy: %v", err)
	}
}
