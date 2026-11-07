package nethttp

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emhha/netloom"
)

func phase4TestUpload(t *testing.T, opened *atomic.Int32) *netloom.Upload {
	t.Helper()
	upload, err := netloom.NewReplayableUpload(7, func(context.Context) (io.ReadCloser, error) {
		opened.Add(1)
		return io.NopCloser(strings.NewReader("payload")), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return upload
}

func TestBuildRequestPhase4JSONAndDefaults(t *testing.T) {
	for _, tc := range []struct {
		name, body   string
		retry        bool
		methodsEmpty bool
		auth         bool
	}{
		{"omitted", `{"url":"https://example.test"}`, false, false, false},
		{"null", `{"url":"https://example.test","retry":null,"auth":null}`, false, false, false},
		{"empty-retry", `{"url":"https://example.test","retry":{}}`, true, false, false},
		{"empty-methods", `{"url":"https://example.test","retry":{"methods":[]}}`, true, true, false},
		{"basic", `{"url":"https://example.test","auth":{"scheme":"basic","username":"user","password":"pass"}}`, false, false, true},
		{"digest", `{"url":"https://example.test","auth":{"scheme":"digest","username":"user","password":"pass","max_challenges":1},"retry":{"max_retries":2,"methods":["POST"],"status_codes":[429,503],"base_delay_ms":25,"max_delay_ms":100,"respect_retry_after":true},"capture_request_body":512}`, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var input RequestInput
			if err := json.Unmarshal([]byte(tc.body), &input); err != nil {
				t.Fatal(err)
			}
			req, err := BuildRequest(input)
			if err != nil {
				t.Fatal(err)
			}
			if (req.RetryPolicy != nil) != tc.retry || (req.Auth != nil) != tc.auth {
				t.Fatalf("retry=%+v auth=%+v", req.RetryPolicy, req.Auth)
			}
			if tc.methodsEmpty && req.RetryPolicy.Methods == nil {
				t.Fatal("explicit empty methods became nil/default methods")
			}
			if tc.name == "digest" {
				p := req.RetryPolicy
				if p.MaxRetries != 2 || len(p.Methods) != 1 || p.Methods[0] != "POST" || len(p.StatusCodes) != 2 || p.BaseDelay != 25*time.Millisecond || p.MaxDelay != 100*time.Millisecond || !p.RespectRetryAfter || req.CaptureRequestBody != 512 || req.Auth.MaxChallenges != 1 {
					t.Fatalf("incorrect structured conversion: %+v %+v", p, req.Auth)
				}
			}
			if req.Auth != nil && req.Header.Get("Authorization") != "" {
				t.Fatal("adapter generated authentication instead of delegating request-local policy")
			}
		})
	}
}

func TestBuildRequestPhase4NativeUploadNoOpen(t *testing.T) {
	var opens atomic.Int32
	source := phase4TestUpload(t, &opens)
	for _, tc := range []struct {
		name  string
		input RequestInput
	}{
		{"upload", RequestInput{Upload: source}},
		{"multipart", RequestInput{StreamingMultipart: []netloom.UploadPart{{Name: "field", FileName: "metadata.txt", Body: source}}}},
		{"empty-multipart", RequestInput{StreamingMultipart: []netloom.UploadPart{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.input
			in.URL = "https://example.test"
			in.Method = "POST"
			req, err := BuildRequest(in)
			if err != nil {
				t.Fatal(err)
			}
			if req.Upload == nil || len(req.Body) != 0 || opens.Load() != 0 {
				t.Fatalf("native body conversion consumed source: req=%+v opens=%d", req, opens.Load())
			}
			if tc.name == "upload" && req.Upload != source {
				t.Fatal("native Upload identity was not retained")
			}
			if tc.name != "upload" && !strings.HasPrefix(req.Header.Get("Content-Type"), "multipart/form-data; boundary=") {
				t.Fatalf("multipart type=%q", req.Header.Get("Content-Type"))
			}
			encoded, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "Upload") || strings.Contains(string(encoded), "StreamingMultipart") || strings.Contains(string(encoded), "metadata.txt") || strings.Contains(string(encoded), "payload") {
				t.Fatalf("serialized native reader metadata: %s", encoded)
			}
		})
	}
	// Unknown JSON objects cannot construct native readers or request file access.
	var injected RequestInput
	if err := json.Unmarshal([]byte(`{"url":"https://example.test","upload":{"path":"/not/a/real/file"},"streaming_multipart":[{"body":{"path":"/also/not/opened"}}]}`), &injected); err != nil {
		t.Fatal(err)
	}
	req, err := BuildRequest(injected)
	if err != nil {
		t.Fatal(err)
	}
	if req.Upload != nil || injected.Upload != nil || injected.StreamingMultipart != nil || opens.Load() != 0 {
		t.Fatal("JSON injected/opened native upload")
	}
}

func TestBuildRequestPhase4Snapshots(t *testing.T) {
	input := RequestInput{URL: "https://example.test", Retry: &RetryInput{MaxRetries: 2, Methods: []string{"GET"}, StatusCodes: []int{503}, BaseDelayMS: 5, MaxDelayMS: 20}, Auth: &AuthInput{Scheme: netloom.AuthDigest, Username: "before", Password: "secret", MaxChallenges: 1}}
	req, err := BuildRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Retry.Methods[0] = "POST"
	input.Retry.StatusCodes[0] = 429
	input.Retry.MaxRetries = 8
	input.Auth.Username = "after"
	input.Auth.Password = "after"
	if req.RetryPolicy.Methods[0] != "GET" || req.RetryPolicy.StatusCodes[0] != 503 || req.RetryPolicy.MaxRetries != 2 || req.Auth.Username != "before" || req.Auth.Password != "secret" {
		t.Fatal("request policy aliases input")
	}
	req.RetryPolicy.Methods[0] = "HEAD"
	req.RetryPolicy.StatusCodes[0] = 500
	req.Auth.Username = "request"
	if input.Retry.Methods[0] != "POST" || input.Retry.StatusCodes[0] != 429 || input.Auth.Username != "after" {
		t.Fatal("input aliases request policy")
	}
}

func TestBuildRequestPhase4ConflictsAndLimits(t *testing.T) {
	var opens atomic.Int32
	source := phase4TestUpload(t, &opens)
	for _, tc := range []struct {
		name  string
		input RequestInput
	}{
		{"upload-body", RequestInput{Upload: source, Body: "x"}},
		{"upload-encoding", RequestInput{Upload: source, BodyEncoding: "utf8"}},
		{"upload-form-empty", RequestInput{Upload: source, Form: []NameValue{}}},
		{"upload-buffered-multipart-empty", RequestInput{Upload: source, Multipart: []MultipartPart{}}},
		{"upload-streaming-empty", RequestInput{Upload: source, StreamingMultipart: []netloom.UploadPart{}}},
		{"streaming-form-empty", RequestInput{StreamingMultipart: []netloom.UploadPart{}, Form: []NameValue{}}},
		{"upload-content-length", RequestInput{Upload: source, Headers: map[string]string{"Content-Length": "7"}}},
		{"streaming-content-length", RequestInput{StreamingMultipart: []netloom.UploadPart{}, Headers: map[string]string{"Content-Length": "0"}}},
		{"streaming-content-type", RequestInput{StreamingMultipart: []netloom.UploadPart{}, Headers: map[string]string{"Content-Type": "multipart/form-data"}}},
		{"streaming-empty-content-type", RequestInput{StreamingMultipart: []netloom.UploadPart{}, Headers: map[string]string{"Content-Type": ""}}},
		{"invalid-streaming-part", RequestInput{StreamingMultipart: []netloom.UploadPart{{Name: "x"}}}},
		{"both-auth", RequestInput{BasicAuth: &BasicCredentials{}, Auth: &AuthInput{Scheme: netloom.AuthBasic}}},
		{"auth-header", RequestInput{Auth: &AuthInput{Scheme: netloom.AuthBasic}, Headers: map[string]string{"Authorization": "Basic x"}}},
		{"auth-empty-header", RequestInput{Auth: &AuthInput{Scheme: netloom.AuthBasic}, Headers: map[string]string{"Authorization": ""}}},
		{"auth-empty", RequestInput{Auth: &AuthInput{}}},
		{"auth-unknown", RequestInput{Auth: &AuthInput{Scheme: "ntlm"}}},
		{"auth-user-colon", RequestInput{Auth: &AuthInput{Scheme: netloom.AuthBasic, Username: "a:b"}}},
		{"auth-control", RequestInput{Auth: &AuthInput{Scheme: netloom.AuthDigest, Password: "x\n"}}},
		{"auth-max", RequestInput{Auth: &AuthInput{Scheme: netloom.AuthDigest, MaxChallenges: 3}}},
		{"auth-max-negative", RequestInput{Auth: &AuthInput{Scheme: netloom.AuthDigest, MaxChallenges: -1}}},
		{"retry-negative", RequestInput{Retry: &RetryInput{MaxRetries: -1}}},
		{"retry-too-many", RequestInput{Retry: &RetryInput{MaxRetries: 101}}},
		{"retry-method", RequestInput{Retry: &RetryInput{Methods: []string{"get"}}}},
		{"retry-status", RequestInput{Retry: &RetryInput{StatusCodes: []int{200}}}},
		{"retry-negative-delay", RequestInput{Retry: &RetryInput{BaseDelayMS: -1}}},
		{"retry-overflow-delay", RequestInput{Retry: &RetryInput{BaseDelayMS: math.MaxInt64}}},
		{"retry-overflow-max-delay", RequestInput{Retry: &RetryInput{MaxDelayMS: math.MaxInt64}}},
		{"retry-max-delay", RequestInput{Retry: &RetryInput{MaxDelayMS: 60001}}},
		{"retry-inverted", RequestInput{Retry: &RetryInput{BaseDelayMS: 20, MaxDelayMS: 10}}},
		{"capture-negative", RequestInput{CaptureRequestBody: -1}},
		{"capture-too-large", RequestInput{CaptureRequestBody: 1<<20 + 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.input
			in.URL = "https://example.test"
			if _, err := BuildRequest(in); err == nil {
				t.Fatal("invalid phase4 input accepted")
			}
			if opens.Load() != 0 {
				t.Fatal("validation consumed native reader")
			}
		})
	}
}

func TestBuildRequestPhase4BasicCompatibilityAndBoundaries(t *testing.T) {
	req, err := BuildRequest(RequestInput{URL: "https://example.test", BasicAuth: &BasicCredentials{Username: "old", Password: "pass"}})
	if err != nil || req.Auth != nil || req.Header.Get("Authorization") != "Basic b2xkOnBhc3M=" {
		t.Fatalf("legacy Basic Auth changed: req=%+v err=%v", req, err)
	}
	req, err = BuildRequest(RequestInput{URL: "https://example.test", CaptureRequestBody: 1 << 20, Retry: &RetryInput{BaseDelayMS: 60000, MaxDelayMS: 60000}})
	if err != nil || req.CaptureRequestBody != 1<<20 || req.RetryPolicy.BaseDelay != time.Minute {
		t.Fatalf("valid boundaries rejected: %+v %v", req, err)
	}
	var in RequestInput
	if err := json.Unmarshal([]byte(`{"url":"https://example.test","auth":{"scheme":"basic","username":"u","password":"p","authenticator":{"path":"not-loadable"}}}`), &in); err != nil {
		t.Fatal(err)
	}
	req, err = BuildRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	if req.Auth.Authenticator != nil {
		t.Fatal("JSON supplied native authentication extension")
	}
}
