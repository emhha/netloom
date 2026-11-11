package netloom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
)

type taskMutatorFunc func(*Request) error

func (f taskMutatorFunc) Mutate(req *Request) error { return f(req) }

func TestTaskMutatorsBeforeSendAndRetry(t *testing.T) {
	var hits, mutations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/changed" || r.Method != "PUT" || r.Header.Get("X-Mutated") != "yes" || string(body) != "new" {
			t.Errorf("wire request: %s %s headers=%v body=%q", r.Method, r.URL, r.Header, body)
		}
		if hits.Add(1) == 1 {
			w.WriteHeader(503)
		}
	}))
	defer server.Close()
	e := pooledEngine(t, 1)
	original := &Request{URL: "http://original.invalid/", Method: "GET", Header: fhttp.Header{"X-Original": {"yes"}}, Body: []byte("old"), PhaseTimeouts: &PhaseTimeouts{Total: time.Second}}
	var order []int
	mutators := []Mutator{
		taskMutatorFunc(func(r *Request) error {
			order = append(order, 1)
			mutations.Add(1)
			r.URL = server.URL + "/changed"
			r.Method = "PUT"
			r.Header.Set("X-Mutated", "yes")
			copy(r.Body, "new")
			r.PhaseTimeouts.Total = 2 * time.Second
			r.RetryPolicy = &RetryPolicy{MaxRetries: 1, Methods: []string{"PUT"}, StatusCodes: []int{503}}
			return nil
		}),
		taskMutatorFunc(func(r *Request) error {
			order = append(order, 2)
			if r.Method != "PUT" {
				t.Error("mutators not ordered")
			}
			return nil
		}),
	}
	analyzed := false
	ch, err := e.Run(context.Background(), []Task{{Req: original, Mutators: mutators, Pipeline: []Handler{func(c *Context) error {
		analyzed = true
		if c.Resp == nil || c.Resp.StatusCode != 200 || c.Req.URL != server.URL+"/changed" {
			t.Errorf("response-only pipeline: %+v", c)
		}
		return c.Next()
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	results := 0
	for r := range ch {
		results++
		if r.Ctx.Resp.Error != nil {
			t.Fatal(r.Ctx.Resp.Error)
		}
	}
	if results != 1 || !analyzed || hits.Load() != 2 || mutations.Load() != 1 || len(order) != 2 || order[0] != 1 || order[1] != 2 {
		t.Fatalf("results=%d analyzed=%v hits=%d mutations=%d order=%v", results, analyzed, hits.Load(), mutations.Load(), order)
	}
	if original.URL != "http://original.invalid/" || original.Method != "GET" || original.Header.Get("X-Mutated") != "" || string(original.Body) != "old" || original.PhaseTimeouts.Total != time.Second || original.RetryPolicy != nil {
		t.Fatalf("caller request was changed: %+v", original)
	}
}

func TestTaskMutatorErrorDoesNotSendOrAnalyze(t *testing.T) {
	failure := errors.New("mutation rejected")
	for _, m := range []Mutator{nil, taskMutatorFunc(func(*Request) error { return failure })} {
		var hits atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
		e := pooledEngine(t, 1)
		analyzed := false
		ch, err := e.Run(context.Background(), []Task{{Req: &Request{URL: server.URL}, Mutators: []Mutator{m}, Pipeline: []Handler{func(*Context) error { analyzed = true; return nil }}}})
		if err != nil {
			t.Fatal(err)
		}
		results := 0
		for r := range ch {
			results++
			if r.Ctx.Resp == nil || r.Ctx.Resp.Error == nil {
				t.Fatal("missing mutator error result")
			}
			if m != nil && !errors.Is(r.Ctx.Resp.Error, failure) {
				t.Fatalf("error chain lost: %v", r.Ctx.Resp.Error)
			}
		}
		server.Close()
		if results != 1 || hits.Load() != 0 || analyzed {
			t.Fatalf("results=%d hits=%d analyzed=%v", results, hits.Load(), analyzed)
		}
	}
}

func TestTaskMutatorsChooseRewrittenHostAdmission(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer server.Close()
	e := pooledEngine(t, 1)
	s := newScheduler(e.cfg, e.tlsT, e.rawT, e.logger)
	s.results = make(chan *Result, 1)
	original := &Request{URL: "http://skipped.invalid/"}
	s.skipped[hostKey(original.URL)] = true
	s.process(context.Background(), Task{Req: original, Mutators: []Mutator{taskMutatorFunc(func(r *Request) error {
		r.URL = server.URL
		return nil
	})}})
	if hits.Load() != 1 || len(s.results) != 1 {
		t.Fatalf("rewritten host was skipped: hits=%d results=%d", hits.Load(), len(s.results))
	}
	r := <-s.results
	// The original host is skipped, so a successful request also demonstrates
	// that admission used the rewritten host. Idle slots must not be retained.
	if r.Ctx.Resp.Error != nil || len(s.hostSem.used) != 0 {
		t.Fatalf("wrong host admission or retained idle state: resp=%+v hosts=%v", r.Ctx.Resp, s.hostSem.used)
	}
}

func TestAsMutatorRejectsResponseContext(t *testing.T) {
	called := false
	m := taskMutatorFunc(func(r *Request) error { called = true; r.URL = "changed"; return nil })
	c := NewContext(context.Background(), &Request{URL: "original"}, []Handler{AsMutator(m)}, nil)
	c.Resp = &Response{StatusCode: 200}
	if err := c.run(); !errors.Is(err, ErrMutatorAfterSend) || called || c.Req.URL != "original" {
		t.Fatalf("err=%v called=%v req=%+v", err, called, c.Req)
	}
	c = NewContext(context.Background(), &Request{URL: "original"}, []Handler{AsMutator(m)}, nil)
	if err := c.run(); err != nil || !called || c.Req.URL != "changed" {
		t.Fatalf("standalone mutation: err=%v called=%v req=%+v", err, called, c.Req)
	}
}
