// Package traffic connects HTTP entry points to caller selected passive plugins.
package traffic

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emhha/netloom"
	"github.com/emhha/netloom/httpdata"
	"github.com/emhha/netloom/passive"
)

// Source identifies the entry point that observed an exchange.
type Source string

const (
	SourceRequest Source = "request"
	SourceMITM    Source = "mitm"
)

// Config is copied by New. Engine and Registry remain owned by the caller.
type Config struct {
	Engine          *netloom.Engine
	Registry        *passive.Registry
	RequestPlugins  []string // nil selects all, empty selects none
	MITMPlugins     []string // nil selects all, empty selects none
	Project         string
	SessionID       string
	Proxies         ProxyConfig
	BodyLimit       int           // bytes per request and response; zero defaults to 128 KiB, maximum 1 MiB
	QueueSize       int           // pending reports for streaming and MITM; zero defaults to 32
	AnalysisTimeout time.Duration // zero defaults to five seconds

	// OnReport receives asynchronous reports serially. It must return promptly
	// and must not call Close. Required for analysis on streamed traffic.
	OnReport func(Report)
}

// Report contains findings and capture state for a single exchange. Errors in
// this report do not change the HTTP response or the transport's return error.
type Report struct {
	ID                 uint64 // unique within a Traffic instance
	Source             Source
	URL                string
	Method             string
	StatusCode         int
	RequestTruncated   bool
	ResponseTruncated  bool // capture or decoding exceeded its budget
	ResponseIncomplete bool // body failed or closed before EOF at capture time
	TransportError     error
	DecodeError        error
	AnalysisError      error
	Results            []passive.Result
}

// Traffic connects HTTP sends and proxy forwarding to one plugin registry.
// Call Close after stopping the producers and closing their response bodies.
type Traffic struct {
	cfg          Config
	requestProxy string
	mitmProxy    *string
	ids          atomic.Uint64
	dropped      atomic.Uint64
	mu           sync.RWMutex
	queue        chan observation
	done         chan struct{}
	closed       bool
}

type observation struct {
	report Report
	req    *httpdata.Request
	resp   *httpdata.Response
}

// New validates configuration locally and starts an analysis worker when a
// report callback is configured. It does not initiate network activity.
func New(cfg Config) (*Traffic, error) {
	if cfg.Registry == nil {
		return nil, fmt.Errorf("traffic: registry is required")
	}
	for _, plugins := range [][]string{cfg.RequestPlugins, cfg.MITMPlugins} {
		if err := cfg.Registry.Validate(plugins); err != nil {
			return nil, err
		}
	}
	cfg.RequestPlugins = slices.Clone(cfg.RequestPlugins)
	cfg.MITMPlugins = slices.Clone(cfg.MITMPlugins)
	if cfg.BodyLimit < 0 || cfg.BodyLimit > 1<<20 || cfg.QueueSize < 0 || cfg.AnalysisTimeout < 0 {
		return nil, fmt.Errorf("traffic: invalid capture or analysis limits")
	}
	if cfg.BodyLimit == 0 {
		cfg.BodyLimit = 128 << 10
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = 32
	}
	if cfg.AnalysisTimeout == 0 {
		cfg.AnalysisTimeout = 5 * time.Second
	}
	requestProxy, mitmProxy, err := resolveProxies(cfg.Proxies)
	if err != nil {
		return nil, err
	}
	cfg.Proxies = ProxyConfig{}
	t := &Traffic{cfg: cfg, requestProxy: requestProxy, mitmProxy: mitmProxy}
	if cfg.OnReport != nil {
		t.queue, t.done = make(chan observation, cfg.QueueSize), make(chan struct{})
		go t.run()
	}
	return t, nil
}

// Dropped reports the number of completed observations rejected by the
// asynchronous queue because it was full or closed.
func (t *Traffic) Dropped() uint64 { return t.dropped.Load() }

// Close drains accepted reports and waits for the worker. It does not close
// the Engine, MITM server, or transport. Synchronous Send remains available.
func (t *Traffic) Close() {
	t.mu.Lock()
	if !t.closed {
		t.closed = true
		if t.queue != nil {
			close(t.queue)
		}
	}
	t.mu.Unlock()
	if t.done != nil {
		<-t.done
	}
}

func (t *Traffic) submit(o observation) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.queue == nil {
		return
	}
	if !t.closed {
		select {
		case t.queue <- o:
			return
		default:
		}
	}
	t.dropped.Add(1)
}

func (t *Traffic) run() {
	defer close(t.done)
	for o := range t.queue {
		t.cfg.OnReport(t.analyze(context.Background(), o))
	}
}

func (t *Traffic) observe(source Source, req *httpdata.Request, resp *httpdata.Response, err error) observation {
	o := observation{req: req, resp: resp, report: Report{
		ID: t.ids.Add(1), Source: source, URL: req.URL, Method: req.Method, TransportError: err,
	}}
	if resp != nil {
		o.report.StatusCode = resp.StatusCode
		o.report.ResponseTruncated = resp.BodyTruncated
	}
	return o
}

func (t *Traffic) analyze(ctx context.Context, o observation) Report {
	ids := t.cfg.RequestPlugins
	if o.report.Source == SourceMITM {
		ids = t.cfg.MITMPlugins
	}
	if o.resp == nil || (ids != nil && len(ids) == 0) {
		return o.report
	}
	if encodings := o.resp.Header.Values("Content-Encoding"); len(o.resp.Body) > 0 && len(encodings) > 0 {
		body, truncated, err := passive.DecodeBody(o.resp.Body, strings.Join(encodings, ","), t.cfg.BodyLimit)
		o.resp.Body = body
		o.resp.BodyTruncated = o.resp.BodyTruncated || truncated || o.report.ResponseIncomplete
		o.report.ResponseTruncated = o.report.ResponseTruncated || (truncated && err == nil)
		o.report.DecodeError = err
	}
	o.resp.BodyTruncated = o.resp.BodyTruncated || o.report.ResponseIncomplete
	ctx, cancel := context.WithTimeout(ctx, t.cfg.AnalysisTimeout)
	defer cancel()
	o.report.Results, o.report.AnalysisError = t.cfg.Registry.Analyze(ctx, passive.Input{
		Site: passive.SiteKey(t.cfg.Project, o.req.URL), SessionID: t.cfg.SessionID, Request: o.req, Response: o.resp,
	}, ids)
	return o.report
}
