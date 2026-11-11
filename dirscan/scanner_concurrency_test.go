package dirscan

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emhha/netloom"
)

// Timers are deadlock guards only. Dispatch, completion and cancellation are
// ordered by channels, never by sleeping or relying on elapsed network time.
func concurrencyContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func concurrencyAwait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case value := <-ch:
		return value
	case <-timer.C:
		t.Fatal("timed out waiting for concurrency test barrier")
		var zero T
		return zero
	}
}

func concurrencyGate(t *testing.T) (<-chan struct{}, func()) {
	t.Helper()
	gate := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	return gate, release
}

type concurrentScanOutcome struct {
	results []Result
	err     error
}

func concurrencyRun(s *scanner, ctx context.Context) <-chan concurrentScanOutcome {
	done := make(chan concurrentScanOutcome, 1)
	go func() {
		results, err := s.scan(ctx)
		done <- concurrentScanOutcome{results, err}
	}()
	return done
}

func concurrencyConfig(threads int, words ...string) *Config {
	// Use explicit file extensions so BuildWordlist's default extension fuzz
	// cannot insert extra tasks between the barrier-controlled dictionary jobs.
	paths := make([]string, len(words))
	for i, word := range words {
		paths[i] = word
		if fileExt(word) == "" && !strings.HasSuffix(word, "/") {
			paths[i] += ".txt"
		}
	}
	return &Config{BaseURL: "https://scan.example/app/", Wordlist: paths,
		Threads: threads, WildcardThreshold: 8}
}

func concurrencyPath(req *netloom.Request) string {
	return strings.TrimSuffix(strings.TrimPrefix(req.URL, "https://scan.example/app/"), ".txt")
}

func concurrencyRecordPeak(peak *atomic.Int32, current int32) {
	for previous := peak.Load(); current > previous; previous = peak.Load() {
		if peak.CompareAndSwap(previous, current) {
			return
		}
	}
}

func TestScanConcurrencyThreadsOverlapAndCap(t *testing.T) {
	for _, threads := range []int{1, 3, 7} {
		t.Run(fmt.Sprintf("threads%d", threads), func(t *testing.T) {
			ctx := concurrencyContext(t)
			gate, release := concurrencyGate(t)
			words := make([]string, threads*3+1)
			for i := range words {
				words[i] = fmt.Sprintf("item-%02d", i)
			}
			started := make(chan string, len(words))
			var active, peak, calls atomic.Int32
			s := preparedScanner(t, concurrencyConfig(threads, words...), func(ctx context.Context, req *netloom.Request) (*netloom.Response, error) {
				calls.Add(1)
				concurrencyRecordPeak(&peak, active.Add(1))
				defer active.Add(-1)
				started <- concurrencyPath(req)
				select {
				case <-gate:
					return mockResp(200, "text/plain", req.URL), nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			})
			done := concurrencyRun(s, ctx)
			for range threads {
				concurrencyAwait(t, started)
			}
			if got := active.Load(); got != int32(threads) {
				t.Fatalf("only %d requests overlap, want %d", got, threads)
			}
			if got := calls.Load(); got != int32(threads) {
				t.Fatalf("dispatched %d requests while all %d slots were blocked", got, threads)
			}
			release()
			out := concurrencyAwait(t, done)
			if out.err != nil || len(out.results) != len(words) || calls.Load() != int32(len(words)) || active.Load() != 0 || peak.Load() != int32(threads) {
				t.Fatalf("results=%d err=%v calls=%d active=%d peak=%d", len(out.results), out.err, calls.Load(), active.Load(), peak.Load())
			}
			for i, result := range out.results {
				if result.URL != "https://scan.example/app/"+words[i]+".txt" {
					t.Fatalf("result %d is not in dispatch order: %+v", i, result)
				}
			}
		})
	}
}

func TestScanConcurrencyDefaultLimit(t *testing.T) {
	for _, threads := range []int{0, -1, -30} {
		if got := scanConcurrency(threads); got != 30 {
			t.Errorf("scanConcurrency(%d)=%d, want 30", threads, got)
		}
	}
	if got := scanConcurrency(4); got != 4 {
		t.Fatalf("explicit concurrency = %d, want 4", got)
	}
}

func TestScanConcurrencySlowFirstBoundsReorderWindow(t *testing.T) {
	ctx := &concurrencyObservedContext{Context: concurrencyContext(t), polled: make(chan int32, 32)}
	first, releaseFirst := concurrencyGate(t)
	others, releaseOthers := concurrencyGate(t)
	started := make(chan string, 8)
	finished := make(chan string, 8)
	var admitted, aggregated, tooMany atomic.Int32
	s := preparedScanner(t, concurrencyConfig(3), func(ctx context.Context, req *netloom.Request) (*netloom.Response, error) {
		if admitted.Add(1)-aggregated.Load() > 3 {
			tooMany.Store(1)
		}
		path := concurrencyPath(req)
		started <- path
		gate := others
		if path == "first" {
			gate = first
		}
		select {
		case <-gate:
			finished <- path
			return mockResp(200, "text/plain", req.URL), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	words := []string{"first", "second", "third", "fourth", "fifth", "sixth"}
	var order []string // coordinator-owned; read only after done.
	done := make(chan struct{}, 1)
	go func() {
		s.scanDirectory(ctx, "/app/", words, func(reply scanReply) ([]string, bool) {
			order = append(order, reply.job.path)
			aggregated.Add(1)
			return nil, true
		})
		done <- struct{}{}
	}()
	for range 3 {
		concurrencyAwait(t, started)
	}
	// One entry check, one initial loop check, and three admissions reach
	// coordinator poll five with a full window.
	for concurrencyAwait(t, ctx.polled) < 5 {
	}
	releaseOthers()
	for range 2 {
		if path := concurrencyAwait(t, finished); path == "first" {
			t.Fatal("slow first request completed before its gate opened")
		}
	}
	// Poll seven acknowledges both out-of-order replies at the coordinator,
	// not just their Send returns. They still occupy their original slots.
	for concurrencyAwait(t, ctx.polled) < 7 {
	}
	if admitted.Load() != 3 || aggregated.Load() != 0 {
		t.Fatalf("slow first did not retain the window: admitted=%d aggregated=%d", admitted.Load(), aggregated.Load())
	}
	releaseFirst()
	concurrencyAwait(t, done)
	if tooMany.Load() != 0 || !reflect.DeepEqual(order, words) || aggregated.Load() != int32(len(words)) {
		t.Fatalf("unaggregated window exceeded or replies reordered: tooMany=%d order=%v", tooMany.Load(), order)
	}
}

func TestScanConcurrencyOutOfOrderDedupUsesDispatchPriority(t *testing.T) {
	ctx := concurrencyContext(t)
	first, releaseFirst := concurrencyGate(t)
	started := make(chan string, 3)
	laterFinished := make(chan struct{}, 2)
	s := preparedScanner(t, concurrencyConfig(3, "first", "second", "third"), func(ctx context.Context, req *netloom.Request) (*netloom.Response, error) {
		path := concurrencyPath(req)
		started <- path
		if path == "first" {
			select {
			case <-first:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		} else {
			laterFinished <- struct{}{}
		}
		return mockResp(200, "text/plain", "same body from all paths"), nil
	})
	done := concurrencyRun(s, ctx)
	for range 3 {
		concurrencyAwait(t, started)
	}
	for range 2 {
		concurrencyAwait(t, laterFinished)
	}
	releaseFirst()
	out := concurrencyAwait(t, done)
	if out.err != nil || len(out.results) != 1 || out.results[0].URL != "https://scan.example/app/first.txt" {
		t.Fatalf("completion order changed duplicate winner: %+v err=%v", out.results, out.err)
	}
}

// A manually fired deadline lets the test expire only after all workers have
// entered Send, without making a real-time delay part of the assertion.
type concurrencyDeadline struct {
	context.Context
	done chan struct{}
}

func (c *concurrencyDeadline) Done() <-chan struct{} { return c.done }
func (c *concurrencyDeadline) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return c.Context.Err()
	}
}

func TestScanConcurrencyCancellationJoinsWorkersAndKeepsSuccess(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%v", deadline), func(t *testing.T) {
			safety := concurrencyContext(t)
			ctx, cancel := context.WithCancel(safety)
			defer cancel()
			stop := cancel
			wantErr := error(context.Canceled)
			if deadline {
				manual := &concurrencyDeadline{Context: safety, done: make(chan struct{})}
				var once sync.Once
				stop = func() { once.Do(func() { close(manual.done) }) }
				t.Cleanup(stop)
				ctx = manual
				wantErr = context.DeadlineExceeded
			}
			exitGate, allowExit := concurrencyGate(t)
			successGate, allowSuccess := concurrencyGate(t)
			started := make(chan string, 6)
			canceled := make(chan struct{}, 3)
			succeeded := make(chan struct{}, 1)
			var active, calls atomic.Int32
			s := preparedScanner(t, concurrencyConfig(3, "blocked-first", "successful-second", "blocked-third", "not-admitted"), func(ctx context.Context, req *netloom.Request) (*netloom.Response, error) {
				calls.Add(1)
				active.Add(1)
				defer active.Add(-1)
				path := concurrencyPath(req)
				started <- path
				if path == "successful-second" {
					select {
					case <-successGate:
						succeeded <- struct{}{}
						return mockResp(200, "text/plain", "completed evidence"), nil
					case <-safety.Done():
						return nil, safety.Err()
					}
				}
				<-ctx.Done()
				canceled <- struct{}{}
				select {
				case <-exitGate:
				case <-safety.Done():
				}
				return nil, ctx.Err()
			})
			done := concurrencyRun(s, ctx)
			for range 3 {
				concurrencyAwait(t, started)
			}
			allowSuccess()
			concurrencyAwait(t, succeeded)
			stop()
			for range 2 {
				concurrencyAwait(t, canceled)
			}
			select {
			case out := <-done:
				t.Fatalf("scan returned before workers exited: %+v active=%d", out, active.Load())
			default:
			}
			allowExit()
			out := concurrencyAwait(t, done)
			if !errors.Is(out.err, wantErr) || active.Load() != 0 || calls.Load() != 3 || len(out.results) != 1 || out.results[0].URL != "https://scan.example/app/successful-second.txt" {
				t.Fatalf("results=%+v err=%v active=%d calls=%d", out.results, out.err, active.Load(), calls.Load())
			}
		})
	}
}

// Err is observed only on the scan coordinator: the derived worker context
// owns its own Err method. This lets a test acknowledge a buffered out-of-order
// reply without sleeping or assuming that a Send return means it was received.
type concurrencyObservedContext struct {
	context.Context
	polls  atomic.Int32
	polled chan int32
}

func (c *concurrencyObservedContext) Err() error {
	err := c.Context.Err()
	if err == nil {
		poll := c.polls.Add(1)
		select {
		case c.polled <- poll:
		default:
		}
	}
	return err
}

func TestScanConcurrencyFailureThresholdDoesNotResumeAfterSuccess(t *testing.T) {
	ctx := &concurrencyObservedContext{Context: concurrencyContext(t), polled: make(chan int32, 32)}
	nilGate, releaseNil := concurrencyGate(t)
	responseGate, releaseResponse := concurrencyGate(t)
	started := make(chan string, 6)
	var calls, active atomic.Int32
	cfg := concurrencyConfig(3, "nil", "response-error", "successful-inflight", "not-admitted", "also-not-admitted")
	cfg.MaxConsecutiveErrors = 2
	s := preparedScanner(t, cfg, func(ctx context.Context, req *netloom.Request) (*netloom.Response, error) {
		calls.Add(1)
		active.Add(1)
		defer active.Add(-1)
		path := concurrencyPath(req)
		started <- path
		if path == "successful-inflight" {
			<-ctx.Done()
			return mockResp(200, "text/plain", "success despite directory stop"), nil
		}
		gate := responseGate
		if path == "nil" {
			gate = nilGate
		}
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if path == "nil" {
			return nil, nil
		}
		resp := mockResp(200, "text/plain", "failed response")
		resp.Error = errors.New("response failure")
		return resp, nil
	})
	done := concurrencyRun(s, ctx)
	for range 3 {
		concurrencyAwait(t, started)
	}
	// Two scan-level Err checks, one scanDirectory entry check, its initial
	// loop check, and three admissions reach poll seven. Only the buffered
	// response-error reply can advance the coordinator to poll eight: neither
	// earlier reply nor the third in-flight success may complete yet.
	for concurrencyAwait(t, ctx.polled) < 7 {
	}
	releaseResponse()
	for concurrencyAwait(t, ctx.polled) < 8 {
	}
	releaseNil()
	out := concurrencyAwait(t, done)
	// Canceled jobs admitted after this success would skip Engine.Send, so
	// calls alone cannot detect them. They would nevertheless be aggregated
	// as failures and make consecErrs nonzero again.
	if out.err != nil || calls.Load() != 3 || active.Load() != 0 || s.consecErrs != 0 || len(out.results) != 1 || out.results[0].URL != "https://scan.example/app/successful-inflight.txt" {
		t.Fatalf("directory stop resumed admission or lost success: results=%+v err=%v calls=%d active=%d consecErrs=%d", out.results, out.err, calls.Load(), active.Load(), s.consecErrs)
	}
}

func TestScanConcurrencyFailureThresholdBoundaryAndReset(t *testing.T) {
	for _, failure := range []string{"error", "nil", "response-error"} {
		t.Run(failure, func(t *testing.T) {
			ctx := concurrencyContext(t)
			var calls atomic.Int32
			cfg := concurrencyConfig(1, "failure-before", "success", "failure-one", "failure-two", "not-admitted")
			cfg.MaxConsecutiveErrors = 2
			s := preparedScanner(t, cfg, func(_ context.Context, req *netloom.Request) (*netloom.Response, error) {
				calls.Add(1)
				if concurrencyPath(req) == "success" {
					return mockResp(200, "text/plain", "success resets consecutive count"), nil
				}
				switch failure {
				case "error":
					return nil, errors.New("send failure")
				case "nil":
					return nil, nil
				default:
					return &netloom.Response{Error: errors.New("response failure")}, nil
				}
			})
			out := concurrencyAwait(t, concurrencyRun(s, ctx))
			if out.err != nil || calls.Load() != 4 || len(out.results) != 1 {
				t.Fatalf("threshold must stop at two consecutive failures, not earlier/later: results=%+v err=%v calls=%d", out.results, out.err, calls.Load())
			}
		})
	}
}

func TestScanConcurrencySerialCrawlPrecedesUnsentDictionary(t *testing.T) {
	ctx := concurrencyContext(t)
	cfg := concurrencyConfig(1, "index.html", "dictionary")
	cfg.Crawl = true
	var mu sync.Mutex
	var requested []string
	s := preparedScanner(t, cfg, func(_ context.Context, req *netloom.Request) (*netloom.Response, error) {
		path := concurrencyPath(req)
		mu.Lock()
		requested = append(requested, path)
		mu.Unlock()
		body := "response for " + path
		if path == "index.html" {
			body += `<a href="found">found</a><a href="/outside/">outside</a>`
		}
		return mockResp(200, "text/html", body), nil
	})
	out := concurrencyAwait(t, concurrencyRun(s, ctx))
	mu.Lock()
	defer mu.Unlock()
	if out.err != nil || !reflect.DeepEqual(requested, []string{"index.html", "found", "dictionary"}) {
		t.Fatalf("crawl did not precede unsent dictionary: %v err=%v", requested, out.err)
	}
}

func TestScanConcurrencyCrawlDepthAndSerialDirectories(t *testing.T) {
	ctx := concurrencyContext(t)
	indexGate, releaseIndex := concurrencyGate(t)
	tailGate, releaseTail := concurrencyGate(t)
	started := make(chan string, 12)
	crawlStarted := make(chan struct{}, 1)
	var rootTail, directoryOverlap atomic.Int32
	var mu sync.Mutex
	var requested []string
	cfg := concurrencyConfig(2, "index.html", "tail")
	cfg.Crawl, cfg.RecursionDepth = true, 1
	s := preparedScanner(t, cfg, func(ctx context.Context, req *netloom.Request) (*netloom.Response, error) {
		path := concurrencyPath(req)
		mu.Lock()
		requested = append(requested, path)
		mu.Unlock()
		if path == "tail" {
			rootTail.Add(1)
			defer rootTail.Add(-1)
		}
		if strings.HasPrefix(path, "a/") && path != "a/" && rootTail.Load() != 0 {
			directoryOverlap.Store(1)
		}
		started <- path
		body := "response for " + path
		var gate <-chan struct{}
		switch path {
		case "index.html":
			gate = indexGate
			body += `<a href="a/">allowed</a><a href="/app/a/b/">too deep</a><a href="/outside/">outside</a><a href="/application/">neighbor</a>`
		case "tail":
			gate = tailGate
		case "a/":
			crawlStarted <- struct{}{}
		case "a/index.html":
			body += `<a href="b/">too deep</a>`
		}
		if gate != nil {
			select {
			case <-gate:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return mockResp(200, "text/html", body), nil
	})
	done := concurrencyRun(s, ctx)
	for range 2 {
		concurrencyAwait(t, started)
	}
	releaseIndex()
	concurrencyAwait(t, crawlStarted)
	if rootTail.Load() != 1 || directoryOverlap.Load() != 0 {
		t.Fatalf("root tail was not still in flight, or child directory overlapped it: tail=%d overlap=%d", rootTail.Load(), directoryOverlap.Load())
	}
	releaseTail()
	out := concurrencyAwait(t, done)
	mu.Lock()
	defer mu.Unlock()
	if out.err != nil || directoryOverlap.Load() != 0 || !s.passedURLs["/app/a/"] || len(s.passedURLs) != 2 {
		t.Fatalf("directories=%v overlap=%d err=%v", s.passedURLs, directoryOverlap.Load(), out.err)
	}
	foundChild := false
	for _, path := range requested {
		foundChild = foundChild || path == "a/index.html"
		if strings.HasPrefix(path, "a/b/") || strings.Contains(path, "outside") || strings.Contains(path, "application") || strings.HasPrefix(path, "app/") {
			t.Errorf("out-of-root/depth or duplicated crawl path: %s", path)
		}
	}
	if !foundChild {
		t.Fatalf("queued child directory did not execute its dictionary: %v", requested)
	}
}

func TestScanConcurrencyWildcardClassificationMatchesSerialOrder(t *testing.T) {
	ctx := concurrencyContext(t)
	words := []string{"alpha", "bravo", "charlie", "delta"}
	bodies := make(map[string]string, len(words))
	for i, word := range words {
		// Same fingerprint prefix/length, but distinct complete-body hashes:
		// wildcard frequency, not body dedup, decides which paths survive.
		bodies[word] = strings.Repeat("z", 4096) + fmt.Sprintf("%04d", i)
	}
	if ResponseFingerprint(mockResp(200, "text/plain", bodies["alpha"])) != ResponseFingerprint(mockResp(200, "text/plain", bodies["bravo"])) || bodyHash([]byte(bodies["alpha"])) == bodyHash([]byte(bodies["bravo"])) {
		t.Fatal("wildcard test fixture must share fingerprint but not complete body hash")
	}
	var baselineTokens []string
	for i := range 24 {
		baselineTokens = append(baselineTokens, fmt.Sprintf("baselineword%02d", i))
	}
	baseline := strings.Join(baselineTokens, " ")
	response := func(req *netloom.Request) *netloom.Response {
		if body, ok := bodies[concurrencyPath(req)]; ok {
			return mockResp(200, "text/plain", body)
		}
		return mockResp(200, "text/plain", baseline)
	}
	serialCfg := concurrencyConfig(1, words...)
	serialCfg.EnableWildcardDetect, serialCfg.WildcardThreshold = true, 3
	serial := preparedScanner(t, serialCfg, func(_ context.Context, req *netloom.Request) (*netloom.Response, error) {
		return response(req), nil
	})
	want := concurrencyAwait(t, concurrencyRun(serial, ctx))
	if want.err != nil || len(want.results) != 2 {
		t.Fatalf("serial wildcard fixture results=%+v err=%v", want.results, want.err)
	}
	first, releaseFirst := concurrencyGate(t)
	started := make(chan string, len(words))
	laterFinished := make(chan struct{}, len(words))
	parallelCfg := concurrencyConfig(3, words...)
	parallelCfg.EnableWildcardDetect, parallelCfg.WildcardThreshold = true, 3
	parallel := preparedScanner(t, parallelCfg, func(ctx context.Context, req *netloom.Request) (*netloom.Response, error) {
		path := concurrencyPath(req)
		if _, ok := bodies[path]; ok {
			started <- path
			if path == "alpha" {
				select {
				case <-first:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			} else {
				laterFinished <- struct{}{}
			}
		}
		return response(req), nil
	})
	done := concurrencyRun(parallel, ctx)
	for range 3 {
		concurrencyAwait(t, started)
	}
	for range 2 {
		concurrencyAwait(t, laterFinished)
	}
	releaseFirst()
	got := concurrencyAwait(t, done)
	if got.err != nil || !reflect.DeepEqual(got.results, want.results) {
		t.Fatalf("out-of-order wildcard classification differs from serial: got=%+v want=%+v err=%v", got.results, want.results, got.err)
	}
}

func TestScanConcurrencyWildcardCancellationDoesNotDispatchDictionary(t *testing.T) {
	ctx, cancel := context.WithCancel(concurrencyContext(t))
	defer cancel()
	started := make(chan struct{}, 2)
	var calls atomic.Int32
	cfg := concurrencyConfig(3, "dictionary")
	cfg.EnableWildcardDetect = true
	s := preparedScanner(t, cfg, func(ctx context.Context, _ *netloom.Request) (*netloom.Response, error) {
		calls.Add(1)
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	done := concurrencyRun(s, ctx)
	concurrencyAwait(t, started)
	cancel()
	out := concurrencyAwait(t, done)
	if !errors.Is(out.err, context.Canceled) || len(out.results) != 0 || calls.Load() != 1 {
		t.Fatalf("dictionary dispatched after wildcard cancellation: results=%+v err=%v calls=%d", out.results, out.err, calls.Load())
	}
}

func TestScanConcurrencyAggregatesWordAndLineFilters(t *testing.T) {
	for _, option := range []string{"match-words", "match-lines", "filter-words", "filter-lines"} {
		t.Run(option, func(t *testing.T) {
			ctx := concurrencyContext(t)
			cfg := concurrencyConfig(3, "two-words", "two-lines", "one-word")
			var want []string
			switch option {
			case "match-words":
				cfg.MatchWords = "2"
				want = []string{"two-words", "two-lines"}
			case "match-lines":
				cfg.MatchLines = "2"
				want = []string{"two-lines"}
			case "filter-words":
				cfg.FilterWords = "2"
				want = []string{"one-word"}
			case "filter-lines":
				cfg.FilterLines = "2"
				want = []string{"two-words", "one-word"}
			}
			bodies := map[string]string{"two-words": "alpha beta", "two-lines": "gamma\ndelta", "one-word": "epsilon"}
			s := preparedScanner(t, cfg, func(_ context.Context, req *netloom.Request) (*netloom.Response, error) {
				return mockResp(200, "text/plain", bodies[concurrencyPath(req)]), nil
			})
			out := concurrencyAwait(t, concurrencyRun(s, ctx))
			got := make([]string, 0, len(out.results))
			for _, result := range out.results {
				got = append(got, strings.TrimSuffix(strings.TrimPrefix(result.URL, cfg.BaseURL), ".txt"))
			}
			if out.err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("%s results=%v want=%v err=%v", option, got, want, out.err)
			}
		})
	}
}
