package netloom

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestNetworkSkippedBlockedCandidateDoesNotDisableRetry(t *testing.T) {
	temporary := errors.New("temporary allowed dial failure")
	for _, ips := range [][]string{{"127.0.0.1", "192.0.2.1"}, {"192.0.2.1", "127.0.0.1"}} {
		attempts := 0
		dial := mappedDialContext(func(context.Context, string, string) (net.Conn, error) {
			attempts++
			if attempts == 1 {
				return nil, temporary
			}
			a, b := net.Pipe()
			_ = b.Close()
			return a, nil
		}, nil, false)
		transport := networkRetryTransport{dial: dial, options: networkIPs(ips...)}
		scheduler := newScheduler(Config{Retries: 1}, transport, transport, nil)
		_, err := scheduler.sendWithRetry(context.Background(), &Request{URL: "https://logical.test"})
		if err != nil || attempts != 2 {
			t.Fatalf("allowed candidate retry suppressed by blocked neighbor: attempts=%d err=%v", attempts, err)
		}
	}
}

type networkRetryTransport struct {
	dial    func(context.Context, string, string) (net.Conn, error)
	options *NetworkOptions
}

func (t networkRetryTransport) RoundTrip(ctx context.Context, req *Request) (*Response, error) {
	copy := *req
	copy.Network = t.options
	ctx, err := withNetworkOptions(ctx, &copy)
	if err != nil {
		return nil, err
	}
	conn, err := t.dial(ctx, "tcp", "logical.test:443")
	if conn != nil {
		_ = conn.Close()
	}
	if err != nil {
		return nil, err
	}
	return &Response{}, nil
}
