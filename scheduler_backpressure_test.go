package netloom

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunReturnsBeforeLargeSeedBatchDrains(t *testing.T) {
	engine, err := New(Config{Threads: 1, RatePerSecond: 100000, Retries: -1})
	if err != nil {
		t.Fatal(err)
	}
	stub := &recordTransport{kind: "tls"}
	engine.tlsT, engine.rawT = stub, stub
	seeds := make([]Task, 1000)
	for i := range seeds {
		seeds[i] = Task{Req: &Request{URL: "http://example.com"}}
	}
	seeds = append([]Task{{}}, seeds...)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	results, err := engine.Run(ctx, seeds)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for range results {
		count++
	}
	if count != 1000 || ctx.Err() != nil {
		t.Fatalf("seed producer blocked consumers: count=%d err=%v", count, ctx.Err())
	}
	results, err = engine.Run(ctx, []Task{{Req: &Request{URL: "http://example.com"}}})
	if err != nil {
		t.Fatalf("completed Run still busy: %v", err)
	}
	for range results {
	}
}

func TestFullDerivedQueueReturnsErrorInsteadOfDeadlock(t *testing.T) {
	engine, err := New(Config{Threads: 1, RatePerSecond: 100000, Retries: -1})
	if err != nil {
		t.Fatal(err)
	}
	stub := &recordTransport{kind: "tls"}
	engine.tlsT, engine.rawT = stub, stub
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	results, err := engine.Run(ctx, []Task{{Req: &Request{URL: "http://example.com"}, Pipeline: []Handler{func(c *Context) error {
		for range 20 {
			c.Emit(Task{Req: &Request{URL: "http://example.com/derived"}})
		}
		return nil
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	rejected := false
	for result := range results {
		count++
		if errors.Is(result.Ctx.Resp.Error, ErrQueueFull) {
			rejected = true
		}
	}
	if !rejected || count != 5 || ctx.Err() != nil {
		t.Fatalf("queue backpressure hidden or deadlocked: count=%d rejected=%v err=%v", count, rejected, ctx.Err())
	}
}

func TestCancellationStopsBlockedSeedProducer(t *testing.T) {
	engine, err := New(Config{Threads: 1, RatePerSecond: 1})
	if err != nil {
		t.Fatal(err)
	}
	stub := &recordTransport{kind: "tls"}
	engine.tlsT, engine.rawT = stub, stub
	seeds := make([]Task, 1000)
	for i := range seeds {
		seeds[i] = Task{Req: &Request{URL: "http://example.com"}}
	}
	ctx, cancel := context.WithCancel(context.Background())
	results, err := engine.Run(ctx, seeds)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	done := make(chan struct{})
	go func() {
		for range results {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled feeder or workers leaked")
	}
}

func TestCancellationUnblocksAbandonedResults(t *testing.T) {
	engine, err := New(Config{Threads: 1, RatePerSecond: 100000, Retries: -1})
	if err != nil {
		t.Fatal(err)
	}
	stub := &recordTransport{kind: "tls"}
	engine.tlsT, engine.rawT = stub, stub
	processed := make(chan struct{}, 3)
	seeds := make([]Task, 100)
	for i := range seeds {
		seeds[i] = Task{Req: &Request{URL: "http://example.com"}, Pipeline: []Handler{func(c *Context) error {
			select {
			case processed <- struct{}{}:
			default:
			}
			return nil
		}}}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results, err := engine.Run(ctx, seeds)
	if err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	sch := engine.sch
	engine.mu.Unlock()
	// A one-worker results buffer fills before the second result is delivered.
	for range 2 {
		select {
		case <-processed:
		case <-time.After(time.Second):
			t.Fatal("worker did not reach delivery")
		}
	}
	cancel()
	done := make(chan struct{})
	go func() { sch.workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("abandoned results prevented shutdown")
	}
	for range results {
	}
}
