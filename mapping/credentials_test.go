package mapping

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type credentialReaderFunc func(context.Context, string) ([]byte, error)

func (f credentialReaderFunc) Get(ctx context.Context, key string) ([]byte, error) {
	return f(ctx, key)
}

type credentialHTTPClient struct {
	get  func(context.Context, string, string, map[string]string) (*http.Response, error)
	post func(context.Context, string, string, []byte, map[string]string) (*http.Response, error)
}

func (c credentialHTTPClient) Get(ctx context.Context, endpoint, source string, headers map[string]string) (*http.Response, error) {
	return c.get(ctx, endpoint, source, headers)
}
func (c credentialHTTPClient) Post(ctx context.Context, endpoint, source string, body []byte, headers map[string]string) (*http.Response, error) {
	return c.post(ctx, endpoint, source, body, headers)
}

func credentialEngines(client credentialHTTPClient, reader SecretReader) []Engine {
	return []Engine{
		NewFofaEngine(client, reader, "https://example.invalid/fofa"),
		NewHunterEngine(client, reader, "https://example.invalid/hunter"),
		NewQuakeEngineAt(client, reader, "https://example.invalid/quake"),
	}
}

func TestCredentialReadErrorsPreventRequests(t *testing.T) {
	storageErr := errors.New("credential store unavailable")
	for _, cause := range []error{storageErr, context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			calls := 0
			unexpected := func() (*http.Response, error) {
				calls++
				return nil, errors.New("unexpected HTTP request")
			}
			client := credentialHTTPClient{
				get: func(context.Context, string, string, map[string]string) (*http.Response, error) { return unexpected() },
				post: func(context.Context, string, string, []byte, map[string]string) (*http.Response, error) {
					return unexpected()
				},
			}
			reader := credentialReaderFunc(func(context.Context, string) ([]byte, error) {
				// An error must take precedence even when a reader returns bytes too.
				return []byte("must-not-be-sent"), fmt.Errorf("reader: %w", cause)
			})
			for _, engine := range credentialEngines(client, reader) {
				t.Run(engine.Name(), func(t *testing.T) {
					results, err := engine.Search(context.Background(), "query", 1)
					if !errors.Is(err, cause) || errors.Is(err, ErrEngineNotConfigured) || results != nil {
						t.Fatalf("results=%v error=%v; want wrapped read failure", results, err)
					}
					if !strings.Contains(err.Error(), engine.Name()+"_key") {
						t.Fatalf("missing credential key context: %v", err)
					}
				})
			}
			if calls != 0 {
				t.Fatalf("HTTP calls=%d; want 0", calls)
			}
		})
	}
}

func TestMissingCredentialsPreventRequests(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reader SecretReader
	}{
		{name: "nil reader"},
		{name: "empty", reader: credentialReaderFunc(func(context.Context, string) ([]byte, error) { return nil, nil })},
		{name: "whitespace", reader: credentialReaderFunc(func(context.Context, string) ([]byte, error) { return []byte(" \t\r\n"), nil })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Nil callbacks deliberately fail if a provider reaches HTTP.
			for _, engine := range credentialEngines(credentialHTTPClient{}, tc.reader) {
				if _, err := engine.Search(context.Background(), "query", 1); !errors.Is(err, ErrEngineNotConfigured) {
					t.Fatalf("%s: error=%v; want missing credential", engine.Name(), err)
				}
			}
		})
	}
}

func TestFofaOptionalEmailReadErrorPreventsRequests(t *testing.T) {
	for _, cause := range []error{errors.New("email store failure"), context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			var keys []string
			reader := credentialReaderFunc(func(_ context.Context, key string) ([]byte, error) {
				keys = append(keys, key)
				if key == "fofa_key" {
					return []byte("configured"), nil
				}
				return []byte("must-not-be-sent"), cause
			})
			engine := NewFofaEngine(credentialHTTPClient{}, reader, "https://example.invalid")
			if _, err := engine.Search(context.Background(), "query", 101); !errors.Is(err, cause) || errors.Is(err, ErrEngineNotConfigured) {
				t.Fatalf("error=%v; want optional credential read failure", err)
			}
			if strings.Join(keys, ",") != "fofa_key,fofa_email" {
				t.Fatalf("credential reads=%v", keys)
			}
		})
	}
}

func mappingJSONResponse(t *testing.T, value any) *http.Response {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(data)))}
}

func TestFofaCredentialsSnapshotPerSearch(t *testing.T) {
	reads := map[string]int{}
	reader := credentialReaderFunc(func(_ context.Context, key string) ([]byte, error) {
		reads[key]++
		return []byte(fmt.Sprintf("  %s-%d \t", key, reads[key])), nil
	})
	calls := 0
	client := credentialHTTPClient{get: func(_ context.Context, endpoint, source string, _ map[string]string) (*http.Response, error) {
		calls++
		u, err := url.Parse(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		search := (calls + 1) / 2
		q := u.Query()
		if source != "fofa" || q.Get("key") != fmt.Sprintf("fofa_key-%d", search) || q.Get("email") != fmt.Sprintf("fofa_email-%d", search) {
			t.Fatalf("wrong source or credential snapshot on call %d", calls)
		}
		wantPage, count := "1", 100
		if calls%2 == 0 {
			wantPage, count = "2", 1
		}
		if q.Get("page") != wantPage {
			t.Fatalf("page=%q; want %q", q.Get("page"), wantPage)
		}
		rows := make([][]any, count)
		for i := range rows {
			rows[i] = []any{"example.invalid", "192.0.2.1", 443, "https"}
		}
		return mappingJSONResponse(t, map[string]any{"size": 101, "results": rows}), nil
	}}
	engine := NewFofaEngine(client, reader, "https://example.invalid/fofa")
	for search := 1; search <= 2; search++ {
		results, err := engine.Search(context.Background(), "query", 101)
		if err != nil || len(results) != 101 {
			t.Fatalf("search %d: results=%d error=%v", search, len(results), err)
		}
		if reads["fofa_key"] != search || reads["fofa_email"] != search {
			t.Fatalf("search %d: credential reads=%v; want once per search", search, reads)
		}
	}
	if calls != 4 {
		t.Fatalf("HTTP calls=%d; want 4", calls)
	}
}

func TestFofaMissingOptionalEmail(t *testing.T) {
	for _, email := range []string{"", " \t\n"} {
		t.Run(fmt.Sprintf("length=%d", len(email)), func(t *testing.T) {
			reader := credentialReaderFunc(func(_ context.Context, key string) ([]byte, error) {
				if key == "fofa_key" {
					return []byte("  key \t"), nil
				}
				return []byte(email), nil
			})
			calls := 0
			client := credentialHTTPClient{get: func(_ context.Context, endpoint, _ string, _ map[string]string) (*http.Response, error) {
				calls++
				u, err := url.Parse(endpoint)
				if err != nil {
					t.Fatal(err)
				}
				if u.Query().Get("key") != "key" || u.Query().Has("email") {
					t.Fatal("required key not trimmed or missing optional email sent")
				}
				return mappingJSONResponse(t, map[string]any{"results": []any{}}), nil
			}}
			engine := NewFofaEngine(client, reader, "https://example.invalid/fofa")
			if _, err := engine.Search(context.Background(), "query", 1); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("HTTP calls=%d; want 1", calls)
			}
		})
	}
}
