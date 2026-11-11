package netloom

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// All requests in these tests terminate in an injected transport, never a dial.
type lifecycleRegressionTransport func(context.Context, *Request) (*Response, error)

func (f lifecycleRegressionTransport) RoundTrip(ctx context.Context, req *Request) (*Response, error) {
	return f(ctx, req)
}

const lifecycleRegressionTimeout = 5 * time.Second

func lifecycleRegressionReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	timer := time.NewTimer(lifecycleRegressionTimeout)
	defer timer.Stop()
	select {
	case value := <-ch:
		return value
	case <-timer.C:
		t.Fatal("lifecycle barrier timed out (possible goroutine leak/deadlock)")
		var zero T
		return zero
	}
}

func lifecycleRegressionDrain(t *testing.T, results <-chan *Result) []*Result {
	t.Helper()
	timer := time.NewTimer(lifecycleRegressionTimeout)
	defer timer.Stop()
	var got []*Result
	for {
		select {
		case result, ok := <-results:
			if !ok {
				return got
			}
			got = append(got, result)
		case <-timer.C:
			t.Fatal("results did not close")
			return got
		}
	}
}

func lifecycleRegressionEngine(t *testing.T, threads int, tr Transport) *Engine {
	t.Helper()
	e, err := New(Config{Threads: threads, Retries: -1, RatePerSecond: 1000000})
	if err != nil {
		t.Fatal(err)
	}
	e.tlsT, e.rawT = tr, tr
	return e
}

func TestEngineLifecycleRegressionSubmitSingleFlightAndReuse(t *testing.T) {
	entered, gate := make(chan struct{}), make(chan struct{})
	var release sync.Once
	e := lifecycleRegressionEngine(t, 1, lifecycleRegressionTransport(func(context.Context, *Request) (*Response, error) {
		return &Response{StatusCode: 200}, nil
	}))
	t.Cleanup(func() { release.Do(func() { close(gate) }); _ = e.Close() })
	task := Task{Req: &Request{URL: "https://lifecycle.test/seed"}, Pipeline: []Handler{func(*Context) error {
		close(entered)
		<-gate
		return nil
	}}}
	if e.Submit(Task{Req: task.Req}) {
		t.Fatal("Submit accepted work without a Run")
	}
	results, err := e.Run(context.Background(), []Task{task})
	if err != nil {
		t.Fatal(err)
	}
	lifecycleRegressionReceive(t, entered)
	if other, err := e.Run(context.Background(), nil); !errors.Is(err, ErrEngineBusy) || other != nil {
		t.Fatalf("concurrent Run: results=%v error=%v; want nil, ErrEngineBusy", other, err)
	}
	if e.Submit(Task{}) {
		t.Fatal("Submit accepted a nil request")
	}
	if !e.Submit(Task{Req: &Request{URL: "https://lifecycle.test/submitted"}}) {
		t.Fatal("Submit rejected work while the seed pipeline was held")
	}
	release.Do(func() { close(gate) })
	got := lifecycleRegressionDrain(t, results)
	if len(got) != 2 {
		t.Fatalf("got %d results, want seed and submitted task", len(got))
	}
	seen := make(map[string]bool)
	for _, result := range got {
		if result.Ctx.Resp.Error != nil {
			t.Errorf("task failed: %v", result.Ctx.Resp.Error)
		}
		seen[result.Ctx.Req.URL] = true
	}
	if !seen[task.Req.URL] || !seen["https://lifecycle.test/submitted"] {
		t.Fatalf("wrong completed tasks: %v", seen)
	}
	if e.Submit(Task{Req: task.Req}) {
		t.Fatal("Submit accepted work after results closed")
	}
	// Results closure is the public barrier for onDone clearing the active Run.
	for range 4 {
		next, err := e.Run(context.Background(), nil)
		if err != nil {
			t.Fatalf("completed Run remained busy: %v", err)
		}
		if got := lifecycleRegressionDrain(t, next); len(got) != 0 {
			t.Fatalf("empty Run produced %d results", len(got))
		}
	}
}

func TestEngineLifecycleRegressionConcurrentCloseWaitsForWorkAndResults(t *testing.T) {
	for _, callerCancel := range []bool{false, true} {
		t.Run(fmt.Sprintf("caller_cancel=%t", callerCancel), func(t *testing.T) {
			const workers, closers = 2, 6
			entered := make(chan struct{}, workers+1)
			cancelled := make(chan error, workers+1)
			exited := make(chan struct{}, workers+1)
			gate := make(chan struct{})
			var release sync.Once
			tr := lifecycleRegressionTransport(func(ctx context.Context, _ *Request) (*Response, error) {
				entered <- struct{}{}
				<-ctx.Done()
				cancelled <- ctx.Err()
				<-gate // Cancellation alone must not let Close return before work exits.
				exited <- struct{}{}
				return nil, ctx.Err()
			})
			e := lifecycleRegressionEngine(t, workers, tr)
			ctx, cancel := context.WithCancel(context.Background())
			var goroutines sync.WaitGroup
			t.Cleanup(func() {
				cancel()
				release.Do(func() { close(gate) })
				_ = e.Close()
				goroutines.Wait()
			})
			seeds := make([]Task, 100) // Keep the bounded feeder backpressured too.
			for i := range seeds {
				seeds[i] = Task{Req: &Request{URL: "https://lifecycle.test/run"}}
			}
			results, err := e.Run(ctx, seeds)
			if err != nil {
				t.Fatal(err)
			}
			sendDone := make(chan error, 1)
			goroutines.Add(1)
			go func() {
				defer goroutines.Done()
				_, err := e.Send(ctx, &Request{URL: "https://lifecycle.test/send"})
				sendDone <- err
			}()
			for range workers + 1 {
				lifecycleRegressionReceive(t, entered)
			}
			if callerCancel {
				cancel()
				for range workers + 1 {
					if err := lifecycleRegressionReceive(t, cancelled); !errors.Is(err, context.Canceled) {
						t.Errorf("caller cancellation: %v", err)
					}
				}
			}
			start := make(chan struct{})
			ready := make(chan struct{}, closers)
			closeDone := make(chan error, closers)
			for range closers {
				goroutines.Add(1)
				go func() {
					defer goroutines.Done()
					ready <- struct{}{}
					<-start
					err := e.Close()
					// Check closure in the Close caller, not after a later drain
					// that could hide an early-return/late-results-close race.
					for {
						select {
						case _, ok := <-results:
							if !ok {
								closeDone <- err
								return
							}
						default:
							closeDone <- errors.New("Close returned before results closed")
							return
						}
					}
				}()
			}
			for range closers {
				lifecycleRegressionReceive(t, ready)
			}
			close(start)
			if !callerCancel {
				for range workers + 1 {
					if err := lifecycleRegressionReceive(t, cancelled); !errors.Is(err, context.Canceled) {
						t.Errorf("Engine cancellation: %v", err)
					}
				}
			}
			select {
			case err := <-closeDone:
				t.Fatalf("Close returned with transports still held: %v", err)
			default:
			}
			if e.Submit(seeds[0]) {
				t.Error("cancelled/closing Run accepted Submit")
			}
			release.Do(func() { close(gate) })
			for range closers {
				if err := lifecycleRegressionReceive(t, closeDone); err != nil {
					t.Error(err)
				}
			}
			for range workers + 1 {
				lifecycleRegressionReceive(t, exited)
			}
			if err := lifecycleRegressionReceive(t, sendDone); !errors.Is(err, context.Canceled) {
				t.Errorf("Send cancellation: %v", err)
			}
			goroutines.Wait()
			if results, err := e.Run(context.Background(), nil); results != nil || !errors.Is(err, ErrEngineClosed) {
				t.Fatalf("Run after Close: results=%v error=%v", results, err)
			}
			if e.Submit(seeds[0]) {
				t.Error("closed Engine accepted Submit")
			}
		})
	}
}

func TestEngineLifecycleRegressionRunSubmitPublicationStress(t *testing.T) {
	// The public Submit path reads the published scheduler's run context.
	// Racing it with startup catches unsafe context publication under -race;
	// keeping a transport held lets us check cancellation without private hooks.
	for iteration := range 64 {
		t.Run(fmt.Sprint(iteration), func(t *testing.T) {
			entered, gate := make(chan struct{}, 1), make(chan struct{})
			var release sync.Once
			e := lifecycleRegressionEngine(t, 8, lifecycleRegressionTransport(func(ctx context.Context, _ *Request) (*Response, error) {
				select {
				case entered <- struct{}{}:
				default:
				}
				<-gate
				return nil, ctx.Err()
			}))
			ctx, cancel := context.WithCancel(context.Background())
			var wg sync.WaitGroup
			t.Cleanup(func() {
				cancel()
				release.Do(func() { close(gate) })
				_ = e.Close()
				wg.Wait()
			})
			task := Task{Req: &Request{URL: "https://lifecycle.test/stress"}}
			start := make(chan struct{})
			type runOutcome struct {
				results <-chan *Result
				err     error
			}
			runDone := make(chan runOutcome, 1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				results, err := e.Run(ctx, []Task{task})
				runDone <- runOutcome{results, err}
			}()
			for range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					// At most 25 total tasks fit in the 32-slot queue,
					// so cancellation rejection cannot be masked by fullness.
					for range 3 {
						e.Submit(task)
					}
				}()
			}
			close(start)
			outcome := lifecycleRegressionReceive(t, runDone)
			if outcome.err != nil {
				t.Fatal(outcome.err)
			}
			lifecycleRegressionReceive(t, entered)
			wg.Wait()
			cancel()
			for range 8 {
				if e.Submit(task) {
					t.Error("published Run context did not inherit caller cancellation")
				}
			}
			release.Do(func() { close(gate) })
			lifecycleRegressionDrain(t, outcome.results)
		})
	}
}

func TestEngineLifecycleRegressionRunSubmitCloseStartupStress(t *testing.T) {
	for iteration := range 64 {
		t.Run(fmt.Sprint(iteration), func(t *testing.T) {
			e := lifecycleRegressionEngine(t, 1, lifecycleRegressionTransport(func(ctx context.Context, _ *Request) (*Response, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}))
			var wg sync.WaitGroup
			t.Cleanup(func() { _ = e.Close(); wg.Wait() })
			start := make(chan struct{})
			task := Task{Req: &Request{URL: "https://lifecycle.test/startup"}}
			type runOutcome struct {
				results <-chan *Result
				err     error
			}
			runDone := make(chan runOutcome, 1)
			closeDone := make(chan error, 1)
			wg.Add(3)
			go func() {
				defer wg.Done()
				<-start
				results, err := e.Run(context.Background(), []Task{task})
				runDone <- runOutcome{results, err}
			}()
			go func() { defer wg.Done(); <-start; closeDone <- e.Close() }()
			go func() {
				defer wg.Done()
				<-start
				for range 32 {
					e.Submit(task)
				}
			}()
			close(start)
			if err := lifecycleRegressionReceive(t, closeDone); err != nil {
				t.Error(err)
			}
			outcome := lifecycleRegressionReceive(t, runDone)
			if outcome.err == nil {
				// No asynchronous wait: Close already promised channel closure.
				for {
					select {
					case _, ok := <-outcome.results:
						if !ok {
							wg.Wait()
							return
						}
					default:
						t.Fatal("startup-racing Close returned before Run results closed")
					}
				}
			}
			if !errors.Is(outcome.err, ErrEngineClosed) || outcome.results != nil {
				t.Errorf("startup Run: results=%v error=%v", outcome.results, outcome.err)
			}
			wg.Wait()
		})
	}
}
