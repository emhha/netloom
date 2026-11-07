package netloom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestPhaseBodyContextFailureKeepsStage(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, mode := range []string{"attempt", "caller-deadline", "total", "cancel-cause", "engine-close"} {
			if !stream && (mode == "cancel-cause" || mode == "engine-close") {
				continue
			}
			name := mode
			if stream {
				name += "/stream"
			}
			t.Run(name, func(t *testing.T) {
				server := phaseServer(t, "2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Length", "10")
					_, _ = io.WriteString(w, "a")
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				}))
				policy := PhaseTimeouts{BodyIdle: time.Second}
				if mode == "total" {
					policy.Total = 100 * time.Millisecond
				}
				e := phaseEngine(t, policy, true)
				req := &Request{URL: server.URL, HTTPVersion: "2", Timeout: 2 * time.Second}
				if mode == "attempt" {
					req.Timeout = 100 * time.Millisecond
				}
				ctx := context.Background()
				if mode == "caller-deadline" {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
					defer cancel()
				}
				marker := errors.New("explicit caller cause")
				var cancelCause context.CancelCauseFunc
				if mode == "cancel-cause" {
					ctx, cancelCause = context.WithCancelCause(ctx)
					defer cancelCause(nil)
				}
				wantPhase := PhaseBody
				if mode == "total" {
					wantPhase = PhaseTotal
				}
				var err error
				if stream {
					s, sendErr := e.SendStream(ctx, req)
					if sendErr != nil {
						t.Fatal(sendErr)
					}
					defer s.Body.Close()
					buf := make([]byte, 1)
					if _, readErr := io.ReadFull(s.Body, buf); readErr != nil {
						t.Fatal(readErr)
					}
					if mode == "cancel-cause" {
						cancelCause(marker)
					}
					if mode == "engine-close" {
						if closeErr := e.Close(); closeErr != nil {
							t.Fatal(closeErr)
						}
					}
					_, err = io.ReadAll(s.Body)
					_ = s.Body.Close()
					var pe *PhaseError
					if !errors.As(s.Status().Error, &pe) || pe.Phase != wantPhase {
						t.Fatalf("status lost stage: %+v", s.Status())
					}
				} else {
					response, sendErr := e.Send(ctx, req)
					err = sendErr
					if response == nil || string(response.Body) != "a" {
						t.Fatalf("lost partial body: %+v %v", response, err)
					}
					var pe *PhaseError
					if !errors.As(response.Error, &pe) || pe.Phase != wantPhase {
						t.Fatalf("response lost stage: %+v", response)
					}
				}
				if mode == "cancel-cause" || mode == "engine-close" {
					var pe *PhaseError
					if !errors.Is(err, context.Canceled) || !errors.As(err, &pe) || pe.Phase != PhaseBody {
						t.Fatalf("lost canceled body stage: %v", err)
					}
					if mode == "cancel-cause" && !errors.Is(err, marker) {
						t.Fatalf("lost caller cause: %v", err)
					}
				} else {
					assertPhaseDeadline(t, err, wantPhase)
				}
			})
		}
	}
}
