package netloom

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type waitingTransport struct {
	started chan struct{}
	once    sync.Once
}

func (w *waitingTransport) RoundTrip(ctx context.Context, _ *Request) (*Response, error) {
	w.once.Do(func() { close(w.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestCloseCancelsSendAndRejectsNewWork(t *testing.T) {
	e, _ := New(Config{Retries: -1})
	tr := &waitingTransport{started: make(chan struct{})}
	e.tlsT = tr
	done := make(chan error, 1)
	go func() { _, err := e.Send(context.Background(), &Request{URL: "https://example.test"}); done <- err }()
	select {
	case <-tr.started:
	case <-time.After(time.Second):
		t.Fatal("Send did not start")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Send: %v", err)
	}
	if _, err := e.Send(context.Background(), &Request{}); !errors.Is(err, ErrEngineClosed) {
		t.Fatal(err)
	}
	if _, err := e.Run(context.Background(), nil); !errors.Is(err, ErrEngineClosed) {
		t.Fatal(err)
	}
	if _, err := e.SendStream(context.Background(), &Request{}); !errors.Is(err, ErrEngineClosed) {
		t.Fatal(err)
	}
	if e.Submit(Task{Req: &Request{}}) {
		t.Fatal("closed engine accepted task")
	}
	_ = e.Close()
}

func TestCloseStopsRunWithAbandonedResults(t *testing.T) {
	e, _ := New(Config{Threads: 1, Retries: -1, RatePerSecond: 100000})
	tr := &waitingTransport{started: make(chan struct{})}
	e.tlsT = tr
	tasks := make([]Task, 100)
	for i := range tasks {
		tasks[i] = Task{Req: &Request{URL: "https://example.test"}}
	}
	results, err := e.Run(context.Background(), tasks)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-tr.started:
	case <-time.After(time.Second):
		t.Fatal("Run did not start")
	}
	done := make(chan struct{})
	go func() { _ = e.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close blocked")
	}
	for range results {
	}
}

func TestRedirectFailurePreservesLastResponse(t *testing.T) {
	failure := errors.New("next hop failed")
	calls := 0
	sender := redirectSender(func(context.Context, *Request) (*Response, error) {
		calls++
		if calls == 1 {
			return &Response{StatusCode: 302, Location: "https://other.test"}, nil
		}
		return nil, failure
	})
	exchange, err := Do(context.Background(), sender, &Request{URL: "https://first.test"}, RedirectPolicy{Follow: true})
	if !errors.Is(err, failure) || exchange.Response == nil || exchange.Response.StatusCode != 302 || exchange.Request.URL != "https://first.test" {
		t.Fatalf("exchange=%+v err=%v", exchange, err)
	}
}

func TestRawProxyIsRejectedBeforeDial(t *testing.T) {
	_, err := newRawTransport(1024).RoundTrip(context.Background(), &Request{URL: "http://127.0.0.1", Proxy: "http://proxy.test", Raw: []byte("GET / HTTP/1.1\r\n\r\n")})
	if err == nil || errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("Raw proxy should fail before direct dial: %v", err)
	}
}
