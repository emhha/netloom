package netrt

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	http "github.com/bogdanfinn/fhttp"
)

type redirectSender func(context.Context, *Request) (*Response, error)

func (f redirectSender) Send(ctx context.Context, r *Request) (*Response, error) { return f(ctx, r) }

func TestRedirectMethodAndCredentialBoundaries(t *testing.T) {
	for _, tc := range []struct {
		status       int
		method, body string
	}{{301, "GET", ""}, {302, "GET", ""}, {303, "GET", ""}, {307, "POST", "payload"}, {308, "POST", "payload"}} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			calls := 0
			input := &Request{TLSConfig: &TLSOptions{}, URL: "https://first.test/start", Method: "POST", Body: []byte("payload"), Header: http.Header{"Authorization": {"secret"}, "Cookie": {"sid=secret"}, "X-Api-Key": {"secret"}, "Content-Type": {"text/plain"}, "Accept": {"text/plain"}}}
			sender := redirectSender(func(ctx context.Context, req *Request) (*Response, error) {
				calls++
				if calls == 1 {
					return &Response{StatusCode: tc.status, Header: http.Header{"Location": {"https://second.test/end"}}}, nil
				}
				if req.TLSConfig != nil {
					t.Fatal("client TLS identity crossed origin")
				}
				if req.Method != tc.method || string(req.Body) != tc.body {
					t.Fatalf("redirect changed method/body incorrectly: %s %q", req.Method, req.Body)
				}
				if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" || req.Header.Get("X-Api-Key") != "" {
					t.Fatal("credentials crossed origin")
				}
				if tc.body == "" && req.Header.Get("Content-Type") != "" {
					t.Fatal("body header kept after GET conversion")
				}
				return &Response{StatusCode: 200}, nil
			})
			exchange, err := Do(context.Background(), sender, input, RedirectPolicy{Follow: true})
			if err != nil || calls != 2 || len(exchange.Hops) != 1 || exchange.Request.URL != "https://second.test/end" {
				t.Fatalf("redirect failed: %v", err)
			}
			if input.Header.Get("Authorization") != "secret" || string(input.Body) != "payload" {
				t.Fatal("caller request was mutated")
			}
		})
	}
}

func TestRedirectValidationStopsBeforeSending(t *testing.T) {
	calls := 0
	denied := errors.New("scope denied")
	sender := redirectSender(func(context.Context, *Request) (*Response, error) {
		calls++
		return &Response{StatusCode: 302, Location: "http://outside.test/"}, nil
	})
	exchange, err := Do(context.Background(), sender, &Request{URL: "https://allowed.test"}, RedirectPolicy{Follow: true, ValidateURL: func(ctx context.Context, raw string) error {
		if strings.Contains(raw, "outside.test") {
			return denied
		}
		return nil
	}})
	if !errors.Is(err, denied) || calls != 1 || exchange.Response.StatusCode != 302 {
		t.Fatalf("out-of-scope hop sent: calls=%d err=%v", calls, err)
	}
	for _, location := range []string{"file:///tmp/x", "http://user:password@allowed.test/", "mailto:test@example.com"} {
		if _, err := ResolveRedirect("https://allowed.test/", location); err == nil {
			t.Fatalf("unsafe redirect accepted: %s", location)
		}
	}
	calls = 0
	_, err = Do(context.Background(), sender, &Request{URL: "https://allowed.test"}, RedirectPolicy{Follow: true, MaxHops: 2})
	if !errors.Is(err, ErrRedirectLimit) || calls != 3 {
		t.Fatalf("redirect cap failed: calls=%d err=%v", calls, err)
	}
}

type brokenBody struct{ read bool }

func (b *brokenBody) Read(p []byte) (int, error) {
	if b.read {
		return 0, io.ErrUnexpectedEOF
	}
	b.read = true
	return copy(p, "partial"), nil
}
func TestBodyReadErrorsAreNotSuccess(t *testing.T) {
	body, truncated, err := readCappedResult(&brokenBody{}, 1024)
	if !errors.Is(err, io.ErrUnexpectedEOF) || string(body) != "partial" || truncated {
		t.Fatalf("read error hidden: %q %v %v", body, truncated, err)
	}
	body, truncated, err = readCappedResult(strings.NewReader("12345"), 3)
	if err != nil || !truncated || string(body) != "123" {
		t.Fatal("intentional evidence cap must be distinguished from read failure")
	}
}
