package passive

import (
	"netrt.local/netrt/httpdata"
	"testing"
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
