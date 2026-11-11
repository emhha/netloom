package dirscan

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/emhha/netloom"
)

type scanEngineFunc func(context.Context, *netloom.Request) (*netloom.Response, error)

func (f scanEngineFunc) Send(ctx context.Context, req *netloom.Request) (*netloom.Response, error) {
	return f(ctx, req)
}
func (scanEngineFunc) Close() error { return nil }

func preparedScanner(t *testing.T, cfg *Config, send scanEngineFunc) *scanner {
	t.Helper()
	s, err := newScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.engine.Close(); err != nil {
		t.Fatal(err)
	}
	s.engine = send
	return s
}

// Exercise actual scan orchestration, not merely depthOf arithmetic: every
// accepted directory causes the wordlist to run again and discovers another.
func TestScanRecursionDepthFixedRoot(t *testing.T) {
	for _, mode := range []string{"recursive", "deep", "force"} {
		for _, limit := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s/depth%d", mode, limit), func(t *testing.T) {
				cfg := &Config{BaseURL: "https://scan.example/app/", Threads: 1, Wordlist: []string{"next/"},
					RecursionDepth: limit, WildcardThreshold: 8}
				cfg.Recursive = mode == "recursive"
				cfg.DeepRecursive = mode == "deep"
				cfg.ForceRecursive = mode == "force"
				var requested []string
				s := preparedScanner(t, cfg, func(_ context.Context, req *netloom.Request) (*netloom.Response, error) {
					u, err := url.Parse(req.URL)
					if err != nil {
						t.Error(err)
						return nil, err
					}
					requested = append(requested, u.Path)
					if strings.Count(u.Path, "next/") > 4 {
						return nil, errors.New("test safety stop: unbounded recursion")
					}
					return mockResp(200, "text/plain", req.URL), nil
				})
				_, err := s.scan(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if len(requested) != limit+1 {
					t.Fatalf("requests = %v, want %d directory wordlist passes", requested, limit+1)
				}
				for dir := range s.passedURLs {
					if depthOf(dir, "/app/") > limit {
						t.Errorf("out-of-budget directory queued: %s", dir)
					}
				}
			})
		}
	}
}

func TestScanCrawlDepthAndRootBoundary(t *testing.T) {
	cfg := &Config{BaseURL: "https://scan.example/app/", Threads: 1, Wordlist: []string{"index.html"},
		Crawl: true, RecursionDepth: 2, WildcardThreshold: 8}
	var requested []string
	s := preparedScanner(t, cfg, func(_ context.Context, req *netloom.Request) (*netloom.Response, error) {
		u, err := url.Parse(req.URL)
		if err != nil {
			t.Error(err)
			return nil, err
		}
		requested = append(requested, u.Path)
		body := req.URL
		switch u.Path {
		case "/app/index.html":
			body += `<a href="a/">relative</a><a href="/app/absolute/">absolute</a><a href="/outside/">outside</a><a href="/application/">prefix neighbor</a><a href="../escape/">parent</a>`
		case "/app/a/index.html":
			body += `<a href="b/">second level</a>`
		case "/app/a/b/index.html":
			body += `<a href="c/">over depth</a>`
		}
		return mockResp(200, "text/html", body), nil
	})
	if _, err := s.scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/app/a/", "/app/absolute/", "/app/a/b/"} {
		if !s.passedURLs[want] {
			t.Errorf("directory %s was not queued: %v", want, s.passedURLs)
		}
		found := false
		for _, got := range requested {
			found = found || got == want+"index.html"
		}
		if !found {
			t.Errorf("directory %s wordlist not executed: %v", want, requested)
		}
	}
	for _, got := range requested {
		if !strings.HasPrefix(got, "/app/") || strings.HasPrefix(got, "/app/app/") || strings.HasPrefix(got, "/app/a/b/c/") {
			t.Errorf("unexpected crawl request: %s", got)
		}
	}
}

func TestScanCancellationPreservesPartialResults(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		for _, completed := range []int{0, 1} {
			t.Run(fmt.Sprintf("deadline=%v/completed=%d", deadline, completed), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				wantErr := error(context.Canceled)
				if deadline {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), time.Second)
					wantErr = context.DeadlineExceeded
				}
				defer cancel()
				calls := 0
				cfg := &Config{BaseURL: "https://scan.example/app/", Threads: 1, Wordlist: []string{"one/", "two/", "three/"}, WildcardThreshold: 8}
				s := preparedScanner(t, cfg, func(ctx context.Context, req *netloom.Request) (*netloom.Response, error) {
					calls++
					if calls <= completed {
						return mockResp(200, "text/plain", "completed evidence"), nil
					}
					if !deadline {
						cancel()
					}
					<-ctx.Done()
					return nil, ctx.Err()
				})
				results, err := s.scan(ctx)
				if !errors.Is(err, wantErr) || len(results) != completed || calls != completed+1 {
					t.Fatalf("results=%v err=%v calls=%d; want %d results, %v, %d calls", results, err, calls, completed, wantErr, completed+1)
				}
				if completed > 0 && results[0].URL != "https://scan.example/app/one/" {
					t.Fatalf("partial evidence changed: %+v", results[0])
				}
			})
		}
	}
}

func TestRunAlreadyCanceledAndMaxTime(t *testing.T) {
	for _, maxTime := range []time.Duration{0, time.Nanosecond} {
		ctx, cancel := context.WithCancel(context.Background())
		wantErr := error(context.DeadlineExceeded)
		if maxTime == 0 {
			cancel()
			wantErr = context.Canceled
		}
		results, err := Run(ctx, &Config{BaseURL: "https://scan.example/app/", MaxTime: maxTime, Wordlist: []string{"one/"}})
		cancel()
		if !errors.Is(err, wantErr) || len(results) != 0 {
			t.Fatalf("MaxTime=%s results=%v err=%v, want %v", maxTime, results, err, wantErr)
		}
	}
}
