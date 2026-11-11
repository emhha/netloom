package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestValidHTTPProxyIsUsed(t *testing.T) {
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.String() != "http://example.invalid/path" {
			t.Errorf("unexpected proxy target %s", r.URL)
		}
		if r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpzZWNyZXQ=" {
			t.Errorf("proxy authorization not preserved")
		}
		_, _ = w.Write([]byte("via proxy"))
	}))
	defer proxy.Close()
	raw := "HTTP://user:secret@" + strings.TrimPrefix(proxy.URL, "http://") + "/"
	s := NewSession(Options{Proxy: raw, DisableRetries: true})
	defer s.Close()
	if s.Err() != nil {
		t.Fatal(s.Err())
	}
	resp, err := s.Get(context.Background(), "http://example.invalid/path", t.Name(), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := ReadBody(resp)
	if err != nil || string(body) != "via proxy" || hits.Load() != 1 {
		t.Fatalf("body=%q error=%v hits=%d", body, err, hits.Load())
	}
}
