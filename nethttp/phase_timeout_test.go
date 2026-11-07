package nethttp

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBuildRequestPhaseTimeouts(t *testing.T) {
	for _, tc := range []struct {
		input      string
		wantNil    bool
		wantHeader time.Duration
	}{
		{`{"url":"https://example.com"}`, true, 0},
		{`{"url":"https://example.com","phase_timeouts":{}}`, false, 0},
		{`{"url":"https://example.com","phase_timeouts":{"connect_ms":100,"tls_handshake_ms":200,"response_header_ms":300,"body_idle_ms":400,"total_ms":500}}`, false, 300 * time.Millisecond},
	} {
		var in RequestInput
		if err := json.Unmarshal([]byte(tc.input), &in); err != nil {
			t.Fatal(err)
		}
		req, err := BuildRequest(in)
		if err != nil {
			t.Fatal(err)
		}
		if (req.PhaseTimeouts == nil) != tc.wantNil {
			t.Fatalf("policy=%+v", req.PhaseTimeouts)
		}
		if req.PhaseTimeouts != nil && req.PhaseTimeouts.ResponseHeader != tc.wantHeader {
			t.Fatalf("wrong duration units: %+v", req.PhaseTimeouts)
		}
		if tc.wantHeader != 0 && (req.PhaseTimeouts.Connect != 100*time.Millisecond || req.PhaseTimeouts.TLSHandshake != 200*time.Millisecond || req.PhaseTimeouts.BodyIdle != 400*time.Millisecond || req.PhaseTimeouts.Total != 500*time.Millisecond) {
			t.Fatalf("lost phase fields: %+v", req.PhaseTimeouts)
		}
	}
	for _, p := range []*PhaseTimeoutsInput{{ConnectMS: -1}, {TLSHandshakeMS: -1}, {ResponseHeaderMS: -1}, {BodyIdleMS: -1}, {TotalMS: -1}, {TotalMS: 1<<63 - 1}, {ConnectMS: 1<<63 - 1}} {
		if _, err := BuildRequest(RequestInput{URL: "https://example.com", PhaseTimeouts: p}); err == nil {
			t.Fatalf("invalid policy accepted: %+v", p)
		}
	}
}
