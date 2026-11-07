package netloom

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestPhasePoolWaitUsesAttemptOrTotalNotConnectTimer(t *testing.T) {
	for _, total := range []bool{false, true} {
		name := "attempt"
		if total {
			name = "total"
		}
		t.Run(name, func(t *testing.T) {
			server := phaseServer(t, "2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
			e := phaseEngine(t, PhaseTimeouts{}, true)
			held, err := e.SendStream(context.Background(), &Request{URL: server.URL, HTTPVersion: "2"})
			if err != nil {
				t.Fatal(err)
			}
			defer held.Body.Close()
			request := &Request{URL: server.URL, HTTPVersion: "2", Timeout: 60 * time.Millisecond, PhaseTimeouts: &PhaseTimeouts{Connect: time.Nanosecond, TLSHandshake: time.Nanosecond, ResponseHeader: time.Nanosecond}}
			want := PhasePool
			if total {
				request.Timeout = time.Second
				request.PhaseTimeouts.Total = 60 * time.Millisecond
				want = PhaseTotal
			}
			_, err = e.Send(context.Background(), request)
			assertPhaseDeadline(t, err, want)
			if count, idle := poolSize(e.tlsT.(*tlsTransport).pool); count != 1 || idle != 0 {
				t.Fatalf("waiting cancellation stole active lease: %d/%d", count, idle)
			}
			if _, err = io.ReadAll(held.Body); err != nil {
				t.Fatal(err)
			}
			_ = held.Body.Close()
			r, err := e.Send(context.Background(), &Request{URL: server.URL, HTTPVersion: "2"})
			if err != nil || r == nil || string(r.Body) != "ok" {
				t.Fatalf("pool unusable after canceled wait: %+v %v", r, err)
			}
		})
	}
}
