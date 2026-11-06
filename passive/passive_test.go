package passive

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/emhha/netloom/httpdata"
)

type countingPlugin struct {
	count atomic.Int32
	fail  bool
}

func (p *countingPlugin) Metadata() Metadata       { return Metadata{ID: "test", Version: "1"} }
func (p *countingPlugin) CacheKey(in Input) string { return ResponseKey(in) }
func (p *countingPlugin) Analyze(_ context.Context, in Input) (Result, error) {
	p.count.Add(1)
	if p.fail {
		return Result{}, fmt.Errorf("failed")
	}
	return Result{Artifacts: []Artifact{{Type: "body", Value: string(in.Response.Body)}}}, nil
}

func TestAnalysisReuseIncludesHeadersAndSite(t *testing.T) {
	p := &countingPlugin{}
	r, err := New([]Plugin{p}, 2)
	if err != nil {
		t.Fatal(err)
	}
	in := Input{Site: "project:https://example.com", Request: &httpdata.Request{URL: "https://example.com/app.js"},
		Response: &httpdata.Response{Body: []byte("key"), Header: map[string][]string{"Set-Cookie": {"a=1"}}}}
	first, err := r.Analyze(context.Background(), in, nil)
	if err != nil || first[0].CacheHit {
		t.Fatalf("first result: %+v %v", first, err)
	}
	second, err := r.Analyze(context.Background(), in, nil)
	if err != nil || !second[0].CacheHit || p.count.Load() != 1 {
		t.Fatalf("reuse result: %+v %v", second, err)
	}
	second[0].Artifacts[0].Value = "changed"
	third, _ := r.Analyze(context.Background(), in, nil)
	if third[0].Artifacts[0].Value != "key" {
		t.Fatal("caller changed cached result")
	}
	in.Response.Header["Set-Cookie"] = []string{"a=2"}
	if _, err := r.Analyze(context.Background(), in, nil); err != nil {
		t.Fatal(err)
	}
	in.Site = "other:https://example.com"
	if _, err := r.Analyze(context.Background(), in, nil); err != nil {
		t.Fatal(err)
	}
	if p.count.Load() != 3 {
		t.Fatalf("analysis count = %d", p.count.Load())
	}
}

func TestFailureIsNotCachedAndUnknownPluginRejected(t *testing.T) {
	p := &countingPlugin{fail: true}
	r, err := New([]Plugin{p}, 1)
	if err != nil {
		t.Fatal(err)
	}
	in := Input{Request: &httpdata.Request{}, Response: &httpdata.Response{}}
	for i := 0; i < 2; i++ {
		result, err := r.Analyze(context.Background(), in, nil)
		if err != nil || result[0].Status != "failed" {
			t.Fatalf("failure result: %+v %v", result, err)
		}
	}
	if p.count.Load() != 2 {
		t.Fatal("failed analysis was cached")
	}
	if _, err := r.Analyze(context.Background(), in, []string{"aspnet_viewstate"}); err == nil {
		t.Fatal("reserved plugin should not execute")
	}
}
