package netloom

import (
	"container/list"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	"golang.org/x/net/publicsuffix"
)

const (
	defaultSessionMaxHosts          = 256
	defaultSessionMaxCookiesPerHost = 64
	defaultSessionIdleTimeout       = 30 * time.Minute
	// Retained cookie name, value, domain and path together must fit this limit.
	maxSessionCookieBytes = 4096
	maxSessionHostBytes   = 1024
)

// SessionConfig bounds an in-memory cookie session. Zero fields select defaults;
// negative values are rejected. IdleTimeout expires entire idle host sessions,
// independently of individual cookie expiry. No background goroutine is used.
type SessionConfig struct {
	MaxHosts          int           // default 256
	MaxCookiesPerHost int           // default 64
	IdleTimeout       time.Duration // default 30 minutes
}

// Session is a concurrency-safe, bounded, host-isolated cookie session. It may
// be shared by multiple Engines through Config.Session. The zero value is ready
// to use with default limits. A Session must not be copied after first use.
// It has no persistence, global registry, filesystem access or background work.
type Session struct {
	mu       sync.Mutex
	cfg      SessionConfig
	hosts    map[string]*sessionHost
	lru      list.List
	sequence uint64
	now      func() time.Time // private deterministic clock for tests
}

// Preserve the transport's existing cookie-store identity and pointer sharing.
type cookieStore = Session

type sessionHost struct {
	key     string
	used    time.Time
	element *list.Element
	cookies map[string]*sessionCookie
}

type sessionCookie struct {
	jar     *cookiejar.Jar
	cookie  http.Cookie
	probe   url.URL
	created uint64
	used    uint64
	path    string
}

// NewSession creates a bounded, initially empty memory session. Oversized
// cookies (name+value+domain+path over 4096 bytes) are ignored, not truncated.
func NewSession(cfg SessionConfig) (*Session, error) {
	if cfg.MaxHosts < 0 || cfg.MaxCookiesPerHost < 0 || cfg.IdleTimeout < 0 {
		return nil, fmt.Errorf("netloom: session limits must not be negative")
	}
	s := &Session{cfg: cfg}
	s.initLocked()
	return s, nil
}

func (s *Session) initLocked() {
	if s.cfg.MaxHosts == 0 {
		s.cfg.MaxHosts = defaultSessionMaxHosts
	}
	if s.cfg.MaxCookiesPerHost == 0 {
		s.cfg.MaxCookiesPerHost = defaultSessionMaxCookiesPerHost
	}
	if s.cfg.IdleTimeout == 0 {
		s.cfg.IdleTimeout = defaultSessionIdleTimeout
	}
	if s.hosts == nil {
		s.hosts = make(map[string]*sessionHost)
	}
}

func (s *Session) timeLocked() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// Clear atomically removes all currently retained cookies. It does not cancel
// requests or retract already-generated Cookie headers. In-flight responses
// whose Set-Cookie is processed after Clear may populate the fresh session.
// Cached clients resolve the current store on each jar operation, so they never
// keep using an evicted or cleared jar.
func (s *Session) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hosts = nil
	s.lru.Init()
}

// ClearHost atomically removes the logical host session. host accepts a hostname,
// host:explicit-port (bracketed for IPv6), or an absolute HTTP(S) URL. Explicit
// ports remain separate; omission does not infer 80/443. Invalid inputs are no-ops.
// Like Clear, it does not block subsequent Set-Cookie from in-flight responses.
func (s *Session) ClearHost(host string) {
	if s == nil {
		return
	}
	var u *url.URL
	var err error
	if strings.Contains(host, "://") {
		u, err = url.Parse(host)
	} else if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		u = &url.URL{Host: "[" + host + "]"}
	} else {
		u, err = url.Parse("//" + host)
		if err == nil && (u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil) {
			return
		}
	}
	if err != nil {
		return
	}
	key := sessionHostKey(u)
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if h := s.hosts[key]; h != nil {
		s.removeHostLocked(h)
	}
}

func sessionHostKey(u *url.URL) string {
	if u == nil || (u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || len(u.Host) > maxSessionHostBytes {
		return ""
	}
	host := strings.Clone(strings.ToLower(u.Hostname()))
	if port := u.Port(); port != "" {
		return net.JoinHostPort(host, port)
	}
	return host
}

func (s *Session) removeHostLocked(h *sessionHost) { delete(s.hosts, h.key); s.lru.Remove(h.element) }
func (s *Session) expireLocked(now time.Time) {
	for e := s.lru.Back(); e != nil; {
		h := e.Value.(*sessionHost)
		if now.Sub(h.used) < s.cfg.IdleTimeout {
			break
		}
		prev := e.Prev()
		s.removeHostLocked(h)
		e = prev
	}
}
func (s *Session) touchLocked(h *sessionHost, now time.Time) {
	h.used = now
	s.lru.MoveToFront(h.element)
}
func (h *sessionHost) prune() {
	for key, c := range h.cookies {
		if len(c.jar.Cookies(&c.probe)) == 0 {
			delete(h.cookies, key)
		}
	}
}

// Cookies returns request cookies using RFC 6265 domain/path/secure/expiry
// rules, with the additional isolation boundary of host plus explicit port.
// Returned cookies are detached copies. Reads touch the host LRU/idle lifetime.
func (s *Session) Cookies(u *url.URL) []*http.Cookie {
	if s == nil {
		return nil
	}
	key := sessionHostKey(u)
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initLocked()
	now := s.timeLocked()
	s.expireLocked(now)
	h := s.hosts[key]
	if h == nil {
		return nil
	}
	h.prune()
	if len(h.cookies) == 0 {
		s.removeHostLocked(h)
		return nil
	}
	s.touchLocked(h, now)
	s.sequence++
	type selected struct {
		cookie  *http.Cookie
		path    string
		created uint64
	}
	var matches []selected
	for _, entry := range h.cookies {
		for _, cookie := range entry.jar.Cookies(u) {
			entry.used = s.sequence
			matches = append(matches, selected{cookie, entry.path, entry.created})
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if len(matches[i].path) != len(matches[j].path) {
			return len(matches[i].path) > len(matches[j].path)
		}
		return matches[i].created < matches[j].created
	})
	out := make([]*http.Cookie, 0, len(matches))
	for _, match := range matches {
		out = append(out, match.cookie)
	}
	return out
}

// SetCookies accepts RFC cookies for u. Every retained cookie has a bounded
// representation; count overflow evicts least-recently used cookies within the
// host. Host overflow evicts the least-recently used host, including its cookies.
// Cookie Raw/RawExpires/Unparsed fields are not retained. Response cookies may
// repopulate the store after a concurrent Clear; see Clear's reset contract.
func (s *Session) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if s == nil || len(cookies) == 0 {
		return
	}
	key := sessionHostKey(u)
	if key == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initLocked()
	now := s.timeLocked()
	s.expireLocked(now)
	h := s.hosts[key]
	if h != nil {
		h.prune()
		s.touchLocked(h, now)
	}
	for _, input := range cookies {
		if input == nil || len(input.Name)+len(input.Value)+len(input.Domain)+len(input.Path) > maxSessionCookieBytes {
			continue
		}
		// Keep only bounded semantic fields, never raw headers or arbitrary attributes.
		c := http.Cookie{Name: strings.Clone(input.Name), Value: strings.Clone(input.Value), Quoted: input.Quoted, Domain: strings.Clone(input.Domain), Path: strings.Clone(input.Path), Expires: input.Expires.UTC(), MaxAge: input.MaxAge, Secure: input.Secure, HttpOnly: input.HttpOnly, SameSite: input.SameSite}
		path := c.Path
		if path == "" || path[0] != '/' {
			path = defaultSessionCookiePath(u.Path)
		}
		if len(path)+len(c.Name)+len(c.Value)+len(c.Domain) > maxSessionCookieBytes {
			continue
		}
		path = strings.Clone(path)
		domain := strings.TrimPrefix(strings.ToLower(c.Domain), ".")
		if domain == "" {
			domain = strings.ToLower(u.Hostname())
		}
		identity := domain + "\x00" + path + "\x00" + c.Name
		// One-cookie RFC jars delegate acceptance/expiry/security rules to fhttp,
		// while this outer representation makes all retained state count-bounded.
		jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		// A parsed URL's short host/default-path may still be a substring of an
		// arbitrarily large input. Never let the delegated jar retain that URL.
		storeURL := url.URL{Scheme: u.Scheme, Host: strings.Clone(u.Host), Path: path}
		stored := c
		stored.Path = path
		// fhttp's older jar multiplies MaxAge by time.Second without overflow
		// protection. Very large valid lifetimes must not wrap into expiration.
		if int64(stored.MaxAge) > int64((1<<63-1)/time.Second) {
			stored.MaxAge = 0
			stored.Expires = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
		}
		jar.SetCookies(&storeURL, []*http.Cookie{&stored})
		probe := url.URL{Scheme: "https", Host: storeURL.Host, Path: path}
		accepted := jar.Cookies(&probe)
		if len(accepted) == 0 {
			// An expired/deletion cookie may remove the same existing identity, but an
			// invalid domain must never delete a valid cookie. Test a non-expiring clone.
			validation := stored
			validation.MaxAge = 0
			validation.Expires = time.Time{}
			jar.SetCookies(&storeURL, []*http.Cookie{&validation})
			if len(jar.Cookies(&probe)) > 0 && h != nil {
				delete(h.cookies, identity)
			}
			continue
		}
		if h == nil {
			for len(s.hosts) >= s.cfg.MaxHosts {
				s.removeHostLocked(s.lru.Back().Value.(*sessionHost))
			}
			h = &sessionHost{key: key, used: now, cookies: make(map[string]*sessionCookie)}
			h.element = s.lru.PushFront(h)
			s.hosts[key] = h
		}
		s.sequence++
		created := s.sequence
		if old := h.cookies[identity]; old != nil {
			created = old.created
		}
		h.cookies[identity] = &sessionCookie{jar: jar, cookie: c, probe: probe, created: created, used: s.sequence, path: path}
		for len(h.cookies) > s.cfg.MaxCookiesPerHost {
			var oldest string
			var victim *sessionCookie
			for id, entry := range h.cookies {
				if victim == nil || entry.used < victim.used || (entry.used == victim.used && entry.created < victim.created) {
					oldest = id
					victim = entry
				}
			}
			delete(h.cookies, oldest)
		}
	}
	if h != nil && len(h.cookies) == 0 {
		s.removeHostLocked(h)
	}
}

func defaultSessionCookiePath(path string) string {
	if path == "" || path[0] != '/' {
		return "/"
	}
	i := strings.LastIndex(path, "/")
	if i == 0 {
		return "/"
	}
	return path[:i]
}

// GetAllCookies satisfies tls-client's extended CookieJar interface. It returns
// detached bounded semantic cookies grouped by isolated logical host. It is a
// snapshot, not a live map. MaxAge in the snapshot is the originally accepted
// duration; sending/expiration decisions use the RFC jar's actual expiration.
func (s *Session) GetAllCookies() map[string][]*http.Cookie {
	out := make(map[string][]*http.Cookie)
	if s == nil {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initLocked()
	s.expireLocked(s.timeLocked())
	for key, h := range s.hosts {
		h.prune()
		if len(h.cookies) == 0 {
			s.removeHostLocked(h)
			continue
		}
		entries := make([]*sessionCookie, 0, len(h.cookies))
		for _, c := range h.cookies {
			entries = append(entries, c)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].created < entries[j].created })
		for _, entry := range entries {
			c := entry.cookie
			out[key] = append(out[key], &c)
		}
	}
	return out
}

// sessionJar is stable across cached client reuse but never captures a host's
// underlying jar. Eviction/Clear is therefore visible on its very next operation.
type sessionJar struct {
	session *Session
	host    string
}

func (j *sessionJar) Cookies(u *url.URL) []*http.Cookie {
	if sessionHostKey(u) != j.host {
		return nil
	}
	return j.session.Cookies(u)
}
func (j *sessionJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if sessionHostKey(u) == j.host {
		j.session.SetCookies(u, cookies)
	}
}
func (j *sessionJar) GetAllCookies() map[string][]*http.Cookie {
	all := j.session.GetAllCookies()
	out := make(map[string][]*http.Cookie)
	if cookies, ok := all[j.host]; ok {
		out[j.host] = cookies
	}
	return out
}
