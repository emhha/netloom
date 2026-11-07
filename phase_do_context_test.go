package netloom

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPhaseDoCallerCauseAndSenderStage(t *testing.T) {
	for _, mode := range []string{"before-admission", "in-flight", "sender-stage"} {
		t.Run(mode, func(t *testing.T) {
			marker := errors.New("stop redirect chain")
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			if mode == "before-admission" {
				cancel(marker)
			}
			response := &Response{StatusCode: 200}
			sender := redirectSender(func(ctx context.Context, r *Request) (*Response, error) {
				if mode == "before-admission" {
					t.Error("sent canceled request")
				}
				cancel(marker)
				if mode == "sender-stage" {
					return response, &PhaseError{Phase: PhaseBody, Err: ctx.Err()}
				}
				return response, ctx.Err()
			})
			exchange, err := Do(ctx, sender, &Request{URL: "https://example.test"}, RedirectPolicy{})
			if !errors.Is(err, context.Canceled) || !errors.Is(err, marker) {
				t.Fatalf("lost caller cause/identity: %v", err)
			}
			if mode != "before-admission" && (exchange == nil || exchange.Response != response) {
				t.Fatal("lost captured response")
			}
			if mode == "sender-stage" {
				var pe *PhaseError
				if !errors.As(err, &pe) || pe.Phase != PhaseBody {
					t.Fatalf("lost sender stage: %v", err)
				}
			}
		})
	}
}

func TestPhaseDoTotalCoversRedirectValidation(t *testing.T) {
	calls := 0
	sender := redirectSender(func(context.Context, *Request) (*Response, error) { calls++; return &Response{StatusCode: 200}, nil })
	_, err := Do(context.Background(), sender, &Request{URL: "https://example.test", PhaseTimeouts: &PhaseTimeouts{Total: 20 * time.Millisecond}}, RedirectPolicy{ValidateURL: func(ctx context.Context, _ string) error { <-ctx.Done(); return ctx.Err() }})
	assertPhaseDeadline(t, err, PhaseTotal)
	if calls != 0 {
		t.Fatal("sent request after validation exhausted total budget")
	}
}
