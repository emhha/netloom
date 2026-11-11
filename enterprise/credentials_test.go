package enterprise

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type cookieReaderFunc func(context.Context, string) ([]byte, error)

func (f cookieReaderFunc) Get(ctx context.Context, key string) ([]byte, error) {
	return f(ctx, key)
}

type cookieHTTPFunc func(context.Context, string, string, map[string]string) (*http.Response, error)

func (f cookieHTTPFunc) Get(ctx context.Context, endpoint, source string, headers map[string]string) (*http.Response, error) {
	return f(ctx, endpoint, source, headers)
}

func cookieOperations() []struct {
	name string
	run  func(*AiqichaProvider) error
} {
	return []struct {
		name string
		run  func(*AiqichaProvider) error
	}{
		{"SearchByName", func(p *AiqichaProvider) error { _, err := p.SearchByName(context.Background(), "query"); return err }},
		{"GetCompanyDetail", func(p *AiqichaProvider) error { _, err := p.GetCompanyDetail(context.Background(), "pid"); return err }},
		{"GetSubsidiaries", func(p *AiqichaProvider) error { _, err := p.GetSubsidiaries(context.Background(), "pid"); return err }},
		{"GetBranches", func(p *AiqichaProvider) error { _, err := p.GetBranches(context.Background(), "pid"); return err }},
		{"FetchTable", func(p *AiqichaProvider) error { _, err := p.FetchTable(context.Background(), "pid", "icp"); return err }},
	}
}

func TestCookieFailuresPreventRequests(t *testing.T) {
	storageErr := errors.New("credential store unavailable")
	for _, op := range cookieOperations() {
		t.Run(op.name, func(t *testing.T) {
			for _, tc := range []struct {
				name      string
				nilReader bool
				raw       string
				cause     error
			}{
				{name: "nil reader", nilReader: true},
				{name: "empty"},
				{name: "whitespace", raw: " \t\r\n"},
				{name: "storage", raw: "must-not-be-sent", cause: storageErr},
				{name: "canceled", cause: context.Canceled},
				{name: "deadline", cause: context.DeadlineExceeded},
			} {
				t.Run(tc.name, func(t *testing.T) {
					reads, calls := 0, 0
					var reader cookieReader
					if !tc.nilReader {
						reader = cookieReaderFunc(func(_ context.Context, key string) ([]byte, error) {
							reads++
							if key != "aiqicha_cookie" {
								t.Fatalf("credential key=%q", key)
							}
							if tc.cause != nil {
								return []byte(tc.raw), fmt.Errorf("reader: %w", tc.cause)
							}
							return []byte(tc.raw), nil
						})
					}
					client := cookieHTTPFunc(func(context.Context, string, string, map[string]string) (*http.Response, error) {
						calls++
						return nil, errors.New("unexpected HTTP request")
					})
					err := op.run(NewAiqichaProvider(client, reader))
					want := tc.cause
					if want == nil {
						want = ErrNotConfigured
					}
					if !errors.Is(err, want) {
						t.Fatalf("error=%v; want %v", err, want)
					}
					if tc.cause != nil && (errors.Is(err, ErrNotConfigured) || !strings.Contains(err.Error(), "aiqicha_cookie")) {
						t.Fatalf("read failure lacks context or is misclassified as missing: %v", err)
					}
					wantReads := 1
					if tc.nilReader {
						wantReads = 0
					}
					if calls != 0 || reads != wantReads {
						t.Fatalf("HTTP calls=%d credential reads=%d; want 0/%d", calls, reads, wantReads)
					}
				})
			}
		})
	}
}

func TestCookieTrimAndRotationPerQuery(t *testing.T) {
	reads, calls := 0, 0
	reader := cookieReaderFunc(func(context.Context, string) ([]byte, error) {
		reads++
		return []byte(fmt.Sprintf(" \t cookie-%d \r\n", reads)), nil
	})
	client := cookieHTTPFunc(func(_ context.Context, _, _ string, headers map[string]string) (*http.Response, error) {
		calls++
		if headers["Cookie"] != fmt.Sprintf("cookie-%d", calls) {
			t.Fatal("cookie was not trimmed or reread for each query")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"status":0,"data":{"resultList":[]}}`))}, nil
	})
	provider := NewAiqichaProvider(client, reader)
	for range 2 {
		if _, err := provider.SearchByName(context.Background(), "query"); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 || reads != 2 {
		t.Fatalf("HTTP calls=%d reads=%d; want 2/2", calls, reads)
	}
}

func TestUnsupportedTableStillChecksCredentials(t *testing.T) {
	cause := errors.New("credential read failed")
	provider := NewAiqichaProvider(nil, cookieReaderFunc(func(context.Context, string) ([]byte, error) {
		return nil, cause
	}))
	if _, err := provider.FetchTable(context.Background(), "pid", "unsupported"); !errors.Is(err, cause) {
		t.Fatalf("error=%v; want credentials checked before field dispatch", err)
	}
	provider = NewAiqichaProvider(nil, cookieReaderFunc(func(context.Context, string) ([]byte, error) {
		return []byte("cookie"), nil
	}))
	if table, err := provider.FetchTable(context.Background(), "pid", "unsupported"); table != nil || err != nil {
		t.Fatalf("table=%v error=%v; want nil/nil for unsupported field", table, err)
	}
}
