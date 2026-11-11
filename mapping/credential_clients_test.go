package mapping

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

// These intentionally implement only the one operation each provider requires.
// Adding a second method to a provider's injected interface must break this test.
type credentialGetOnly func(context.Context, string, string, map[string]string) (*http.Response, error)

func (f credentialGetOnly) Get(ctx context.Context, endpoint, source string, headers map[string]string) (*http.Response, error) {
	return f(ctx, endpoint, source, headers)
}

type credentialPostOnly func(context.Context, string, string, []byte, map[string]string) (*http.Response, error)

func (f credentialPostOnly) Post(ctx context.Context, endpoint, source string, body []byte, headers map[string]string) (*http.Response, error) {
	return f(ctx, endpoint, source, body, headers)
}

func TestCredentialRotationPreservesNarrowClients(t *testing.T) {
	for _, name := range []string{"fofa", "hunter", "quake"} {
		t.Run(name, func(t *testing.T) {
			reads, calls := 0, 0
			reader := credentialReaderFunc(func(_ context.Context, key string) ([]byte, error) {
				if key == "fofa_email" {
					return nil, nil
				}
				if key != name+"_key" {
					t.Fatalf("unexpected credential key %q", key)
				}
				reads++
				return []byte(fmt.Sprintf(" \t key-%d \r\n", reads)), nil
			})
			check := func(source, key string) {
				calls++
				if source != name || key != fmt.Sprintf("key-%d", calls) || reads != calls {
					t.Fatalf("source=%q reads=%d calls=%d: credential not trimmed or refreshed", source, reads, calls)
				}
			}
			get := credentialGetOnly(func(_ context.Context, endpoint, source string, _ map[string]string) (*http.Response, error) {
				u, err := url.Parse(endpoint)
				if err != nil {
					t.Fatal(err)
				}
				if name == "fofa" {
					check(source, u.Query().Get("key"))
					return mappingJSONResponse(t, map[string]any{"results": []any{}}), nil
				}
				check(source, u.Query().Get("api-key"))
				return mappingJSONResponse(t, map[string]any{"code": 200, "data": map[string]any{"arr": []any{}}}), nil
			})
			post := credentialPostOnly(func(_ context.Context, _, source string, _ []byte, headers map[string]string) (*http.Response, error) {
				check(source, headers["X-QuakeToken"])
				return mappingJSONResponse(t, map[string]any{"code": 0, "data": []any{}}), nil
			})
			var engine Engine
			switch name {
			case "fofa":
				engine = NewFofaEngine(get, reader, "https://example.invalid/fofa")
			case "hunter":
				engine = NewHunterEngine(get, reader, "https://example.invalid/hunter")
			case "quake":
				engine = NewQuakeEngineAt(post, reader, "https://example.invalid/quake")
			}
			for range 2 {
				results, err := engine.Search(context.Background(), "query", 1)
				if err != nil || len(results) != 0 {
					t.Fatalf("results=%v error=%v", results, err)
				}
			}
			if calls != 2 || reads != 2 {
				t.Fatalf("HTTP calls=%d credential reads=%d; want 2/2", calls, reads)
			}
		})
	}
}
