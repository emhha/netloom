package nethttp

import "testing"

func TestCurlImportAndRejectedShellOrFiles(t *testing.T) {
	in, err := ParseCurl("curl 'https://example.test/api' -X PATCH -H 'X-Test: a' -H 'X-Test: b' --data-raw '@literal' -u 'user:pass' -L --max-time 2.5")
	if err != nil || in.Method != "PATCH" || in.Body != "@literal" || len(in.HeaderValues["X-Test"]) != 2 || in.TimeoutSeconds != 3 || in.BasicAuth.Password != "pass" {
		t.Fatalf("parse=%+v err=%v", in, err)
	}
	jsonRequest, err := ParseCurl(`curl https://example.test --json '{"a":' --json '1}'`)
	if err != nil || jsonRequest.Body != `{"a":1}` {
		t.Fatalf("json concatenation=%s %v", jsonRequest.Body, err)
	}
	get, err := ParseCurl(`curl -G https://example.test -d 'a=1' -d 'b=2'`)
	if err != nil || get.URL != "https://example.test?a=1&b=2" || get.Body != "" {
		t.Fatalf("get=%+v %v", get, err)
	}
	for _, raw := range []string{`curl https://example.test; id`, `curl https://example.test -H "X: $(id)"`, `curl https://example.test -d @/etc/passwd`, `curl https://example.test -F f=@private`, `curl https://a.test https://b.test`, `curl https://a.test --proxy http://127.0.0.1:1`, `curl https://a.test --unknown`, `curl 'unterminated`, `curl https://a.test --max-time NaN`} {
		if _, err := ParseCurl(raw); err == nil {
			t.Errorf("unsupported curl accepted: %s", raw)
		}
	}
}
