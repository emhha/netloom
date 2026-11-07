package netloom

import (
	"context"
	"sync"
	"time"

	"github.com/bogdanfinn/fhttp/httptrace"
	tls "github.com/bogdanfinn/utls"
)

// Missing measurements remain nil; custom TLS/proxy dialers do not emit every
// trace hook. Never make a second connection to fill timing or certificate data.
type Timings struct {
	QueueMS     float64  `json:"queue_ms"`
	HeadersMS   float64  `json:"headers_ms"`
	BodyMS      float64  `json:"body_ms"`
	TotalMS     float64  `json:"total_ms"`
	DNSMS       *float64 `json:"dns_ms,omitempty"`
	ConnectMS   *float64 `json:"connect_ms,omitempty"`
	TLSMS       *float64 `json:"tls_ms,omitempty"`
	FirstByteMS *float64 `json:"first_byte_ms,omitempty"`
}
type observationKey struct{}

func recordMeasured(ctx context.Context, phase string, start time.Time) {
	if o, ok := ctx.Value(observationKey{}).(*observation); ok {
		o.mu.Lock()
		defer o.mu.Unlock()
		value := milliseconds(time.Since(start))
		if phase == "dns" {
			o.timings.DNSMS = &value
		} else {
			if o.timings.ConnectMS != nil {
				value += *o.timings.ConnectMS
			}
			o.timings.ConnectMS = &value
		}
	}
}

type observation struct {
	mu                             sync.Mutex
	start, dns, connect, handshake time.Time
	timings                        Timings
	tls                            *TLSInfo
}

func milliseconds(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
func measured(start time.Time) *float64 {
	if start.IsZero() {
		return nil
	}
	v := milliseconds(time.Since(start))
	return &v
}
func observe(ctx context.Context, start time.Time) (context.Context, *observation) {
	o := &observation{start: start}
	trace := &httptrace.ClientTrace{
		DNSStart:     func(httptrace.DNSStartInfo) { o.mu.Lock(); defer o.mu.Unlock(); o.dns = time.Now() },
		DNSDone:      func(httptrace.DNSDoneInfo) { o.mu.Lock(); defer o.mu.Unlock(); o.timings.DNSMS = measured(o.dns) },
		ConnectStart: func(string, string) { o.mu.Lock(); defer o.mu.Unlock(); o.connect = time.Now() },
		ConnectDone: func(string, string, error) {
			o.mu.Lock()
			defer o.mu.Unlock()
			o.timings.ConnectMS = measured(o.connect)
		},
		TLSHandshakeStart: func() { o.mu.Lock(); defer o.mu.Unlock(); o.handshake = time.Now() },
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			o.mu.Lock()
			defer o.mu.Unlock()
			o.timings.TLSMS = measured(o.handshake)
			if err == nil {
				o.tls = buildTLSInfo(state)
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			if c, ok := info.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
				o.mu.Lock()
				o.tls = buildTLSInfo(c.ConnectionState())
				o.mu.Unlock()
			}
		},
		GotFirstResponseByte: func() { o.mu.Lock(); defer o.mu.Unlock(); o.timings.FirstByteMS = measured(o.start) },
	}
	return httptrace.WithClientTrace(context.WithValue(ctx, observationKey{}, o), trace), o
}
func (o *observation) snapshot() (Timings, *TLSInfo) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return cloneTimings(o.timings), o.tls
}

func cloneTimings(in Timings) Timings {
	clone := func(p *float64) *float64 {
		if p == nil {
			return nil
		}
		v := *p
		return &v
	}
	in.DNSMS = clone(in.DNSMS)
	in.ConnectMS = clone(in.ConnectMS)
	in.TLSMS = clone(in.TLSMS)
	in.FirstByteMS = clone(in.FirstByteMS)
	return in
}
