package netloom

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Done is evaluated after acquire has registered its waiter reference. The
// notification makes retention tests independent of sleeps or scheduler speed.
type hostWaitContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *hostWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func hostStateAwait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("host state barrier timed out")
		var zero T
		return zero
	}
}

func TestHostSemaphoreRetainsWaitersAndReclaimsIdle(t *testing.T) {
	h := newHostSemaphore(1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.acquire(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	original := h.used["a"]
	h.mu.Unlock()
	waiter := &hostWaitContext{Context: ctx, entered: make(chan struct{})}
	acquired := make(chan error, 1)
	go func() { acquired <- h.acquire(waiter, "a") }()
	hostStateAwait(t, waiter.entered)
	h.mu.Lock()
	refs := original.refs
	h.mu.Unlock()
	if refs != 2 {
		t.Fatalf("holder+waiter refs=%d", refs)
	}
	h.release("a")
	if err := hostStateAwait(t, acquired); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	retained := h.used["a"]
	h.mu.Unlock()
	if retained != original {
		t.Fatal("waiter was detached from its original admission state")
	}

	canceledCtx, stop := context.WithCancel(ctx)
	waiting := &hostWaitContext{Context: canceledCtx, entered: make(chan struct{})}
	failed := make(chan error, 1)
	go func() { failed <- h.acquire(waiting, "a") }()
	hostStateAwait(t, waiting.entered)
	stop()
	if err := hostStateAwait(t, failed); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter: %v", err)
	}
	h.mu.Lock()
	refs = retained.refs
	h.mu.Unlock()
	if refs != 1 {
		t.Fatalf("canceled waiter retained reference: %d", refs)
	}
	h.release("a")
	h.release("missing") // unmatched release must not allocate state.
	if len(h.used) != 0 {
		t.Fatalf("retained idle hosts: %v", h.used)
	}
	if err := h.acquire(canceledCtx, "canceled"); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled: %v", err)
	}
	if len(h.used) != 0 {
		t.Fatal("pre-canceled admission created state")
	}
}

func TestHostSemaphoreConcurrentReclamationPreservesLimit(t *testing.T) {
	h := newHostSemaphore(3)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var active [2]atomic.Int32
	var violations atomic.Int32
	var wg sync.WaitGroup
	failures := make(chan error, 16)
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				index := (i + worker) % 2
				host := fmt.Sprint(index)
				if err := h.acquire(ctx, host); err != nil {
					failures <- err
					return
				}
				if active[index].Add(1) > 3 {
					violations.Add(1)
				}
				active[index].Add(-1)
				h.release(host)
			}
		}(worker)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	hostStateAwait(t, done)
	close(failures)
	for err := range failures {
		t.Errorf("acquire: %v", err)
	}
	if violations.Load() != 0 || len(h.used) != 0 {
		t.Fatalf("limit violations=%d retained=%d", violations.Load(), len(h.used))
	}
}

func TestEngineSendReleasesDistinctHostState(t *testing.T) {
	e, err := New(Config{Threads: 4, RatePerSecond: 1000000, Retries: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	stub := &recordTransport{kind: "tls"}
	e.tlsT, e.rawT = stub, stub
	for i := 0; i < 300; i++ {
		if _, err := e.Send(context.Background(), &Request{URL: fmt.Sprintf("http://host-%d.invalid/", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.sendHosts.used) != 0 {
		t.Fatalf("idle host state after Send: %d", len(e.sendHosts.used))
	}
}

func TestSchedulerHostErrorHistoryIsRunScoped(t *testing.T) {
	cfg := Config{MaxHostErrors: 1}.withDefaults()
	stub := &recordTransport{kind: "tls"}
	s := newScheduler(cfg, stub, stub, nil)
	for i := 0; i < 300; i++ {
		host := fmt.Sprint(i)
		s.recordHostError(host)
		s.resetHostError(host)
	}
	if len(s.hostErrorCount) != 0 {
		t.Fatalf("successful hosts retained: %d", len(s.hostErrorCount))
	}
	s.recordHostError("bad")
	s.recordHostError("bad")
	s.resetHostError("bad") // late in-flight success cannot reopen a skipped host.
	if !s.skipped["bad"] {
		t.Fatal("skip decision did not remain sticky")
	}
	s.recordHostError("pending-failure")
	if s.hostErrorCount["pending-failure"] != 1 {
		t.Fatal("failure history was evicted during Run")
	}
	s.shutdown()
	if s.skipped != nil || s.hostErrorCount != nil {
		t.Fatal("completed Run retained error history map storage")
	}
	next := newScheduler(cfg, stub, stub, nil)
	if len(next.skipped) != 0 || len(next.hostErrorCount) != 0 {
		t.Fatal("new Run inherited host history")
	}
	next.shutdown()
}
