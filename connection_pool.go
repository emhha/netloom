package netloom

import (
	"container/list"
	"context"
	"fmt"
	"net/url"
	"reflect"
	"sync"
	"time"

	tls_client "github.com/bogdanfinn/tls-client"
)

// A client never crosses an origin and is never leased concurrently. This also
// bounds tls-client's per-address transport caches and avoids mutable per-client
// cookie/proxy/profile configuration. Busy entries are not eviction candidates.
type clientKey struct {
	origin, proxy, version string
	network                string
	proxyTimeoutMS         int
	verify, noGuard        bool
}

type pooledClient struct {
	client    tls_client.HttpClient
	scope     clientDialScope
	key       clientKey
	cacheable bool
	idleSince time.Time
	idle      *list.Element
}

type clientPool struct {
	mu          sync.Mutex
	entries     map[*pooledClient]struct{}
	idle        list.List // newest at front
	changed     chan struct{}
	max         int
	idleTimeout time.Duration
	closed      bool
}

func newClientPool(cfg ConnectionPoolConfig) (*clientPool, error) {
	if cfg.MaxClients < 0 || cfg.IdleTimeout < 0 {
		return nil, fmt.Errorf("netloom: connection pool limits must not be negative")
	}
	if cfg.MaxClients == 0 {
		cfg.MaxClients = 64
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 30 * time.Second
	}
	return &clientPool{entries: make(map[*pooledClient]struct{}), changed: make(chan struct{}), max: cfg.MaxClients, idleTimeout: cfg.IdleTimeout}, nil
}

// proxyTimeoutMilliseconds matches the dependent client's CONNECT deadline.
// Clamp at the largest representable millisecond duration, avoiding overflow
// when the caller supplies a near-MaxInt64 duration.
func proxyTimeoutMilliseconds(timeout time.Duration) int {
	if timeout <= 0 {
		timeout = dialTimeout
	}
	ms := timeout / time.Millisecond
	if timeout%time.Millisecond != 0 && ms < time.Duration((1<<63-1)/int64(time.Millisecond)) {
		ms++
	}
	return int(ms)
}

func (t *tlsTransport) poolKey(req *Request) (clientKey, bool, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return clientKey{}, false, err
	}
	if u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return clientKey{}, false, fmt.Errorf("netloom: connection pool requires an HTTP(S) URL with a host")
	}
	version := req.HTTPVersion
	if version == "" || version == "2" {
		version = "auto"
	}
	plan, err := compileNetworkOptions(req.Network)
	if err != nil {
		return clientKey{}, false, err
	}
	if plan.enabled() && req.Proxy != "" {
		return clientKey{}, false, ErrNetworkProxyUnsupported
	}
	key := clientKey{origin: u.Scheme + "://" + u.Host, proxy: req.Proxy, version: version, verify: req.VerifyTLS, noGuard: t.noGuard, network: plan.identity}
	if req.Proxy != "" {
		key.proxyTimeoutMS = proxyTimeoutMilliseconds(req.Timeout)
	}
	// A profile's label or pointer cannot identify its maps, functions and
	// captured state. Likewise, TLSOptions may contain mutable roots/private
	// keys. Never pool these by an incomplete identity or serialize credentials.
	cacheable := !req.FreshConnection && req.TLSConfig == nil && reflect.ValueOf(req.Profile).IsZero() && req.HTTPVersion != "2-only"
	if req.Proxy != "" {
		proxyURL, err := url.Parse(req.Proxy)
		// Other schemes retain the dependency's dialer, which cannot safely
		// bridge background HTTP/2 reconnects to the current lease context.
		cacheable = cacheable && err == nil && proxyURL.Scheme == "http"
	}
	return key, cacheable, nil
}

type clientLease struct {
	client tls_client.HttpClient
	once   sync.Once
	done   func(bool)
}

func (l *clientLease) release(reuse bool) { l.once.Do(func() { l.done(reuse) }) }

func (t *tlsTransport) acquireClient(ctx context.Context, req *Request) (*clientLease, error) {
	if err := validateTLSRequest(req); err != nil {
		return nil, err
	}
	if err := validateNetworkLogicalTarget(ctx, req, t.noGuard); err != nil {
		return nil, err
	}
	if err := validateHTTPVersion(req.HTTPVersion); err != nil {
		return nil, err
	}
	if t.pool == nil {
		scope := &clientDialScope{}
		scope.begin(ctx)
		client, err := t.buildClient(req, scope)
		if err != nil {
			scope.end(false)
			return nil, err
		}
		return &clientLease{client: client, done: func(bool) { scope.end(false); client.CloseIdleConnections() }}, nil
	}
	key, cacheable, err := t.poolKey(req)
	if err != nil {
		return nil, err
	}
	p := t.pool
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, ErrEngineClosed
		}
		var retired []*pooledClient
		var match *pooledClient
		now := time.Now()
		for el := p.idle.Back(); el != nil; {
			prev := el.Prev()
			e := el.Value.(*pooledClient)
			if now.Sub(e.idleSince) >= p.idleTimeout {
				p.idle.Remove(el)
				delete(p.entries, e)
				retired = append(retired, e)
			} else if cacheable && e.key == key {
				match = e
			}
			el = prev
		}
		if match != nil {
			p.idle.Remove(match.idle)
			match.idle = nil
			p.mu.Unlock()
			closeClients(retired)
			match.scope.begin(ctx)
			return p.lease(match), nil
		}
		if len(p.entries) >= p.max && p.idle.Len() > 0 {
			e := p.idle.Back().Value.(*pooledClient)
			p.idle.Remove(e.idle)
			delete(p.entries, e)
			retired = append(retired, e)
		}
		if len(p.entries) < p.max {
			e := &pooledClient{key: key, cacheable: cacheable}
			p.entries[e] = struct{}{} // reserve capacity before building
			p.mu.Unlock()
			closeClients(retired)
			e.scope.begin(ctx)
			client, err := t.buildClient(req, &e.scope)
			e.client = client // exclusive lease; not visible in the idle list yet
			if err != nil {
				p.release(e, false)
				return nil, err
			}
			return p.lease(e), nil
		}
		changed := p.changed
		p.mu.Unlock()
		closeClients(retired)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

func (p *clientPool) lease(e *pooledClient) *clientLease {
	return &clientLease{client: e.client, done: func(reuse bool) { p.release(e, reuse) }}
}

func (p *clientPool) notifyLocked() { close(p.changed); p.changed = make(chan struct{}) }

func (p *clientPool) release(e *pooledClient, reuse bool) {
	// Retire old cancellation callbacks before publishing an idle lease.
	e.scope.end(reuse && e.cacheable)
	p.mu.Lock()
	keep := !p.closed && reuse && e.cacheable
	if keep {
		e.idleSince = time.Now()
		e.idle = p.idle.PushFront(e)
	} else {
		delete(p.entries, e)
	}
	p.notifyLocked()
	p.mu.Unlock()
	if !keep && e.client != nil {
		e.client.CloseIdleConnections()
	}
}

// close runs only after Engine's active operations have released their leases.
func (p *clientPool) close() {
	p.mu.Lock()
	p.closed = true
	var clients []*pooledClient
	for e := range p.entries {
		clients = append(clients, e)
	}
	clear(p.entries)
	p.idle.Init()
	p.notifyLocked()
	p.mu.Unlock()
	closeClients(clients)
}

func closeClients(clients []*pooledClient) {
	for _, entry := range clients {
		entry.scope.end(false)
		if entry.client != nil {
			entry.client.CloseIdleConnections()
		}
	}
}
