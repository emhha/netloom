package netloom

import (
	"context"
	"errors"
	"testing"
)

func TestNetworkCanonicalLogicalGuardBeforePool(t *testing.T) {
	tr := newTLSTransport(1024)
	for _, host := range []string{"127.0.0.1", "127.0.0.1.", "0.0.0.0.", "169.254.1.1.", "[::ffff:127.0.0.1]"} {
		t.Run(host, func(t *testing.T) {
			// The mapping itself is valid and public; it must not hide a forbidden
			// logical IP under an equivalent spelling, even before cache lookup.
			req := &Request{URL: "https://" + host, Network: &NetworkOptions{AddressFamily: AddressFamilyIPv4}}
			ctx, err := withNetworkOptions(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			lease, err := tr.acquireClient(ctx, req)
			if lease != nil || !errors.Is(err, ErrBlockedAddress) {
				t.Fatalf("logical address escaped guard: %v", err)
			}
		})
	}
}
