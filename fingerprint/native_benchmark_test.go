package fingerprint

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/emhha/netloom/httpdata"
)

func BenchmarkNativeMatchers(b *testing.B) {
	ehData, err := os.ReadFile("rules/ehole.json")
	if err != nil {
		b.Fatal(err)
	}
	hubData, err := os.ReadFile("rules/fingerprinthub_v4.json")
	if err != nil {
		b.Fatal(err)
	}
	eh, err := LoadEHoleJSON(ehData)
	if err != nil {
		b.Fatal(err)
	}
	hub, err := LoadFingerprintHubJSON(hubData)
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	for _, size := range []struct {
		name  string
		bytes int
		hit   bool
	}{{"4KiB", 4 << 10, false}, {"64KiB", 64 << 10, false}, {"256KiB", 256 << 10, false}, {"64KiB-mixed-hit", 64 << 10, true}} {
		pattern := []byte("<p>ordinary response text 12345</p>")
		body := bytes.Repeat(pattern, (size.bytes+len(pattern)-1)/len(pattern))[:size.bytes]
		response := &httpdata.Response{Body: body, Header: http.Header{"Content-Type": {"text/html"}}, Title: "Example"}
		if size.hit {
			prefix := "<title>d-link router</title>/seeyon/USER-DATA/IMAGES/LOGIN/login.gif"
			for _, rule := range hub.rules {
				found := false
				for _, probe := range rule.HTTP {
					for _, matcher := range probe.Matchers {
						if matcher.Type == "word" && (matcher.Part == "" || matcher.Part == "body") && !matcher.Negative {
							prefix += " " + strings.Join(matcher.Words, " ")
							found = true
							break
						}
					}
					if found {
						break
					}
				}
				if found {
					break
				}
			}
			copy(body, prefix)
			response.Title = "d-link router"
			response.Header.Set("Server", "nginx/1.26.0")
			response.FaviconHash = 617142232
		}
		req := &httpdata.Request{URL: "https://example.test/", Method: "GET"}
		for _, source := range []string{"EHole", "FingerprintHub"} {
			mc := NewMatchContext(response, nil)
			mc.Request = req
			expected := 0
			if source == "EHole" {
				expected = len(linearEHoleMatch(eh, ctx, mc))
			} else {
				expected = len(linearHubMatch(hub, ctx, mc))
			}
			if size.hit && expected == 0 {
				b.Fatal("mixed fixture did not match", source)
			}
			b.Run(source+"/"+size.name, func(b *testing.B) {
				for _, variant := range []string{"linear", "indexed"} {
					b.Run(variant, func(b *testing.B) {
						b.ReportAllocs()
						b.SetBytes(int64(len(response.Body)))
						for b.Loop() {
							mc := NewMatchContext(response, nil)
							mc.Request = req
							var result []Artifact
							if source == "EHole" {
								if variant == "linear" {
									result = linearEHoleMatch(eh, ctx, mc)
								} else {
									result = eh.match(ctx, mc)
								}
							} else {
								if variant == "linear" {
									result = linearHubMatch(hub, ctx, mc)
								} else {
									result = hub.match(ctx, mc)
								}
							}
							if len(result) != expected {
								b.Fatal("benchmark result count changed", result)
							}
						}
					})
				}
			})
		}
	}
}

var benchmarkNativeMatcher any

func BenchmarkNativeMatcherBuild(b *testing.B) {
	for _, source := range []struct{ name, path string }{{"EHole", "rules/ehole.json"}, {"FingerprintHub", "rules/fingerprinthub_v4.json"}} {
		data, err := os.ReadFile(source.path)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(source.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if source.name == "EHole" {
					m, err := LoadEHoleJSON(data)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkNativeMatcher = m
				} else {
					m, err := LoadFingerprintHubJSON(data)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkNativeMatcher = m
				}
			}
			b.Cleanup(func() { benchmarkNativeMatcher = nil })
		})
	}
}
