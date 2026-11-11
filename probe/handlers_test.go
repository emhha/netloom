package probe

import (
	"context"
	"testing"

	"github.com/emhha/netloom"
)

func TestBuildRequestAppliesOptionsBeforeSending(t *testing.T) {
	cfg := &Config{ProbeConfig: ProbeConfig{ProxyURL: "http://proxy.example:8080", TLSProfile: "chrome_131", CustomHeaders: map[string]string{"X-Custom": "before-send"}}}
	req := buildRequest("https://scan.example/", cfg)
	if req.Proxy != cfg.ProxyURL || req.Header.Get("X-Custom") != "before-send" || req.Header.Get("User-Agent") != defaultUserAgent() {
		t.Fatalf("request options missing: %+v", req)
	}
	cfg.CustomHeaders["user-agent"] = "custom-agent"
	req = buildRequest("https://scan.example/", cfg)
	if req.Header.Get("User-Agent") != "custom-agent" {
		t.Fatalf("custom user agent lost: %v", req.Header)
	}
	// Response analysis must not run request mutators or rewrite wire evidence.
	resp := &netloom.Response{Body: []byte("<title>example</title>")}
	c := netloom.NewContext(context.Background(), req, buildPipeline(cfg), nil)
	c.Resp = resp
	if err := c.Next(); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("User-Agent") != "custom-agent" || resp.Title != "example" {
		t.Fatalf("response analysis changed request or lost extraction: req=%+v resp=%+v", req, resp)
	}
}
