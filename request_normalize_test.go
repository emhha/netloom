package netloom

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
)

func TestNormalRequestPreflightAndHost(t *testing.T) {
	for _, headers := range []fhttp.Header{
		{"X-Bad\r\n": []string{"x"}}, {"X-A": []string{"bad\r\nvalue"}}, {"X-A": []string{"x"}, "x-a": []string{"y"}},
		{"Content-Length": []string{"2"}}, {"content-length": []string{"3", "3"}}, {"Transfer-Encoding": []string{"chunked"}},
		{"Host": []string{"a", "b"}}, {"Host": []string{"bad host"}}, {fhttp.HeaderOrderKey: []string{"x-a"}},
	} {
		var opens atomic.Int32
		source, _ := NewReplayableUpload(3, func(context.Context) (io.ReadCloser, error) {
			opens.Add(1)
			return io.NopCloser(strings.NewReader("abc")), nil
		})
		req := &Request{URL: "http://example.test", Method: "POST", Header: headers, Upload: source}
		if _, err := buildWireRequest(context.Background(), req); err == nil {
			t.Fatalf("accepted invalid headers: %q", headers)
		}
		if opens.Load() != 0 {
			t.Fatal("invalid headers opened source")
		}
	}
	req := &Request{URL: "http://example.test/a", Method: "POST", Body: []byte("abc"), Header: fhttp.Header{"host": []string{"virtual.test"}, "content-length": []string{"3"}, "X-Values": []string{"a", "b"}}}
	wire, err := buildWireRequest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if wire.Host != "virtual.test" || wire.URL.Host != "example.test" || wire.ContentLength != 3 {
		t.Fatalf("normalized request: %+v", wire)
	}
	if len(req.Header) != 3 || len(wire.Header) != 1 {
		t.Fatal("headers mutated or framing retained")
	}
	if wire.GetBody == nil {
		t.Fatal("bytes body lost replay")
	}
	_ = wire.Body.Close()
	for _, bad := range []*Request{{URL: "http://u:p@example.test"}, {URL: "ftp://example.test"}, {URL: "http://example.test", HeaderOrder: []string{"Bad:Header"}}} {
		if _, err := buildWireRequest(context.Background(), bad); err == nil {
			t.Fatal("invalid normal request accepted")
		}
	}
}

func TestNormalRequestHeaderEvidenceRedaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("Cookie") != "private=x" {
			t.Error("wire credentials missing")
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	e := pooledEngine(t, 1)
	req := &Request{URL: server.URL, Header: fhttp.Header{"Authorization": []string{"Bearer secret"}, "Cookie": []string{"private=x"}, "Proxy-Authorization": []string{"Basic private"}}}
	for _, stream := range []bool{false, true} {
		var response *Response
		if stream {
			s, err := e.SendStream(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, s.Body)
			_ = s.Body.Close()
			response = s.Response
		} else {
			r, err := e.Send(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			response = r
		}
		for _, h := range []string{"Authorization", "Proxy-Authorization", "Cookie"} {
			if response.RequestHeaders.Get(h) != "[REDACTED]" {
				t.Fatalf("unredacted %s=%q", h, response.RequestHeaders.Get(h))
			}
		}
	}
	if req.Header.Get("Authorization") != "Bearer secret" {
		t.Fatal("caller credentials mutated")
	}
}

func TestRawRequestBypassesNormalizationAndRetry(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	literal := []byte("POST /literal HTTP/1.1\r\nHost: not-url.test\r\nx-Dup: a\r\nX-DUP: b\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, len(literal))
		_, _ = io.ReadFull(conn, b)
		received <- b
		_, _ = io.WriteString(conn, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}()
	e := pooledEngine(t, 1)
	e.rawT.(*rawTransport).noGuard = true
	var events []AttemptInfo
	response, err := e.Send(context.Background(), &Request{URL: "http://" + listener.Addr().String(), Raw: literal, Header: fhttp.Header{"Invalid:Name": []string{"\r\n"}}, RetryPolicy: &RetryPolicy{MaxRetries: 2, StatusCodes: []int{503}, Observer: func(a AttemptInfo) { events = append(events, a) }}})
	if err != nil || response.StatusCode != 503 {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	select {
	case b := <-received:
		if string(b) != string(literal) {
			t.Fatalf("Raw changed: %q", b)
		}
	case <-time.After(time.Second):
		t.Fatal("no Raw bytes")
	}
	if len(events) != 1 || events[0].WillRetry {
		t.Fatalf("Raw retried: %+v", events)
	}
}
