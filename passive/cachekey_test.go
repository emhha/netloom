package passive

import (
	"net/http"
	"testing"

	"github.com/emhha/netloom/httpdata"
)

func TestResponseKeySeparatesNativeFingerprintEvidence(t *testing.T) {
	input := Input{Request: &httpdata.Request{URL: "https://example.test/", Method: "GET"}, Response: &httpdata.Response{Body: []byte("same page")}}
	key := ResponseKey(input)
	for _, change := range []func(*httpdata.Response){
		func(r *httpdata.Response) { r.FaviconMD5 = "0123456789abcdef0123456789abcdef" },
		func(r *httpdata.Response) { r.BodyTruncated = true },
		func(r *httpdata.Response) { r.URL = "https://example.test/admin" },
	} {
		r := *input.Response
		change(&r)
		copy := input
		copy.Response = &r
		if ResponseKey(copy) == key {
			t.Fatal("different fingerprint evidence reused cached result")
		}
	}
}

func TestContentLengthKeyUsesOnlyMetadata(t *testing.T) {
	in := Input{Site: "project", SessionID: "session",
		Request:  &httpdata.Request{URL: "https://example.test:443/app.js"},
		Response: &httpdata.Response{ContentType: "application/javascript; charset=utf-8", Body: []byte("one")},
	}
	key := ContentLengthKey(in)
	in.Request.URL = "https://example.test/app.js"
	in.Response.ContentType = "application/javascript"
	in.Response.Body = []byte("two")
	if key == "" || ContentLengthKey(in) != key {
		t.Fatal("equal length and canonical metadata did not reuse the key")
	}
	in.Response.Body = []byte("four")
	if ContentLengthKey(in) == key {
		t.Fatal("changed length reused the key")
	}
	in.Response.BodyTruncated = true
	for _, lengths := range [][]string{nil, {"0"}, {"-4"}, {"bad"}, {"100", "200"}} {
		in.Response.Header = http.Header{"Content-Length": lengths}
		if ContentLengthKey(in) != "" {
			t.Fatalf("unknown declared length was cached: %q", lengths)
		}
	}
	in.Response.Header.Set("Content-Length", "100")
	prefixKey := ContentLengthKey(in)
	if prefixKey == "" || prefixKey == key {
		t.Fatal("truncated response did not get a separate key")
	}
	in.Response.Header.Set("Content-Length", "101")
	if ContentLengthKey(in) == prefixKey {
		t.Fatal("different declared length reused the key")
	}
	in.Response.Header.Set("Content-Length", "100")
	in.Response.Body = []byte("five!")
	if ContentLengthKey(in) == prefixKey {
		t.Fatal("different captured length reused the key")
	}
}

func TestContentKeyNormalizesURLAndSeparatesEvidence(t *testing.T) {
	if SiteKey("p", "HTTPS://Example.com:443/app.js") != SiteKey("p", "https://example.com/") {
		t.Fatal("equivalent site origins produced different keys")
	}
	key := ContentKey("p", "s", "HTTPS://Example.com:443/app.js#one", "application/javascript; charset=utf-8", []byte("key"))
	if key != ContentKey("p", "s", "https://example.com/app.js#two", "application/javascript", []byte("key")) {
		t.Fatal("equivalent URLs or content types produced different keys")
	}
	for _, changed := range []string{
		ContentKey("p2", "s", "https://example.com/app.js", "application/javascript", []byte("key")),
		ContentKey("p", "s2", "https://example.com/app.js", "application/javascript", []byte("key")),
		ContentKey("p", "s", "https://example.com/app.js?version=2", "application/javascript", []byte("key")),
		ContentKey("p", "s", "https://example.com/app.js", "application/javascript", []byte("new key")),
		ContentKey("p", "s", "https://example.com/app.js", "application/octet-stream", []byte("key")),
	} {
		if changed == key {
			t.Fatal("different evidence reused the same key")
		}
	}
}
