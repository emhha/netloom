package traffic

import (
	"context"
	"fmt"
	"slices"

	"github.com/emhha/netloom"
	"github.com/emhha/netloom/httpdata"
	"github.com/emhha/netloom/httpdata/netloomdata"
)

// Send executes one Engine request and analyzes any returned HTTP response.
// The returned error is the transport error. See Report for analysis failures.
func (t *Traffic) Send(ctx context.Context, req *netloom.Request, opts RequestOptions) (*netloom.Response, Report, error) {
	prepared, err := t.prepareRequest(req, opts)
	if err != nil {
		return nil, Report{}, err
	}
	resp, err := t.cfg.Engine.Send(ctx, prepared)
	return resp, t.analyze(ctx, t.runtimeObservation(prepared, resp, err)), err
}

// SendStream preserves Engine's streaming semantics. The report is delivered
// asynchronously when the caller reads through the capture limit or EOF, or
// closes Body. The caller must close Body even after reaching EOF.
func (t *Traffic) SendStream(ctx context.Context, req *netloom.Request, opts RequestOptions) (*netloom.StreamResponse, error) {
	if t.queue == nil {
		return nil, fmt.Errorf("traffic: OnReport is required for streaming")
	}
	prepared, err := t.prepareRequest(req, opts)
	if err != nil {
		return nil, err
	}
	stream, err := t.cfg.Engine.SendStream(ctx, prepared)
	if err != nil {
		t.submit(t.runtimeObservation(prepared, nil, err))
		return nil, err
	}
	o := t.runtimeObservation(prepared, stream.Response, nil)
	stream.Body = t.captureResponse(stream.Body, o)
	return stream, nil
}

// PrepareTask adds an analysis Handler and a proxy mutator to a copy of a Run
// task. Proxy selection follows existing mutators. Analysis observes successful
// Run responses before the task's existing response handlers. Reports use
// OnReport. Prepare a task once before submitting it to Engine.
func (t *Traffic) PrepareTask(task netloom.Task, opts RequestOptions) (netloom.Task, error) {
	if t.queue == nil {
		return netloom.Task{}, fmt.Errorf("traffic: OnReport is required for tasks")
	}
	if task.Req == nil {
		return netloom.Task{}, netloom.ErrNilRequest
	}
	for _, mutator := range task.Mutators {
		if _, prepared := mutator.(proxyMutator); prepared {
			return netloom.Task{}, fmt.Errorf("traffic: task is already prepared")
		}
	}
	if opts.Proxy != nil {
		value := *opts.Proxy
		if err := validateRequestProxy(value); err != nil {
			return netloom.Task{}, err
		}
		opts.Proxy = &value
	}
	task.Mutators = append(slices.Clone(task.Mutators), proxyMutator{traffic: t, opts: opts})
	task.Pipeline = append([]netloom.Handler{func(c *netloom.Context) error {
		if c.Resp != nil {
			t.submit(t.runtimeObservation(c.Req, c.Resp, c.Resp.Error))
		}
		return nil
	}}, task.Pipeline...)
	return task, nil
}

type proxyMutator struct {
	traffic *Traffic
	opts    RequestOptions
}

func (m proxyMutator) Mutate(req *netloom.Request) error {
	m.traffic.applyRequestProxy(req, m.opts)
	return nil
}

func (t *Traffic) prepareRequest(req *netloom.Request, opts RequestOptions) (*netloom.Request, error) {
	if req == nil {
		return nil, netloom.ErrNilRequest
	}
	if t.cfg.Engine == nil {
		return nil, fmt.Errorf("traffic: Engine is required for active requests")
	}
	prepared := *req
	t.applyRequestProxy(&prepared, opts)
	return &prepared, nil
}

func (t *Traffic) applyRequestProxy(req *netloom.Request, opts RequestOptions) {
	if opts.Proxy != nil {
		req.Proxy = *opts.Proxy
	} else if req.Proxy == "" {
		req.Proxy = t.requestProxy
	}
}

func (t *Traffic) runtimeObservation(req *netloom.Request, resp *netloom.Response, err error) observation {
	requestCopy := *req
	requestTruncated := len(req.Body) > t.cfg.BodyLimit
	requestCopy.Body = req.Body[:min(len(req.Body), t.cfg.BodyLimit)]
	if req.Upload != nil {
		requestTruncated = true
		if resp != nil && resp.UploadEvidence != nil {
			evidence := resp.UploadEvidence
			requestCopy.Body = evidence.Prefix[:min(len(evidence.Prefix), t.cfg.BodyLimit)]
			requestTruncated = evidence.Truncated || len(evidence.Prefix) > t.cfg.BodyLimit
		}
	}
	if len(req.Raw) != 0 {
		requestTruncated = true
	}
	request := netloomdata.Request(&requestCopy)
	if request.Method == "" {
		request.Method = "GET"
	}
	var response *httpdata.Response
	if resp != nil && resp.StatusCode != 0 {
		responseCopy := *resp
		responseCopy.Body = resp.Body[:min(len(resp.Body), t.cfg.BodyLimit)]
		responseCopy.BodyTruncated = resp.BodyTruncated || len(resp.Body) > t.cfg.BodyLimit
		response = netloomdata.Response(&responseCopy)
		response.URL = req.URL
		if err == nil {
			err = resp.Error
		}
	}
	o := t.observe(SourceRequest, request, response, err)
	o.report.RequestTruncated = requestTruncated
	o.report.ResponseIncomplete = response != nil && err != nil
	return o
}
