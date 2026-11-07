package netloom

import (
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

// Request is the unit of work sent through a Transport. It is shared with
// pkg/probe, pkg/dirscan and pkg/fingerprint.
//
// Header is a github.com/bogdanfinn/fhttp header (aliased http throughout
// netloom); net/http is never used on the request path. HeaderOrder carries the
// browser header order and is applied via fhttp.HeaderOrderKey so the on-wire
// order matches the TLS fingerprint.
type Request struct {
	Method      string
	URL         string
	Header      http.Header
	HeaderOrder []string
	Body        []byte

	// Raw, when non-empty, routes the request through rawTransport: the bytes
	// are written verbatim over the (TLS) connection, enabling malformed
	// packets, request smuggling and CRLF injection. URL is then used only to
	// derive the dial target (host:port, scheme).
	Raw []byte

	// HTTPVersion is auto (or empty), 1.1, 2 (prefer with fallback), or
	// 2-only (HTTPS with mandatory H2 ALPN before sending HTTP bytes).
	HTTPVersion string
	// FreshConnection bypasses idle client reuse for this attempt and closes
	// its client afterward. It does not bypass pool capacity or the dial guard.
	FreshConnection bool
	TLSConfig       *TLSOptions `json:"-"`
	VerifyTLS       bool        // opt-in verification; scan callers retain their existing default

	// Profile carries the tls-client browser fingerprint (JA3/JA4, HTTP/2
	// SETTINGS, header order). The zero value selects profiles.DefaultClientProfile.
	Profile profiles.ClientProfile

	Proxy   string
	Timeout time.Duration
	// PhaseTimeouts overrides the entire Engine phase policy; nil inherits it.
	// A pointer to a zero policy disables configured phase/total timers.
	PhaseTimeouts *PhaseTimeouts
	Meta          map[string]any
}

// TLSInfo describes the peer certificate captured during the TLS handshake.
type TLSInfo struct {
	Subject           string
	Issuer            string
	SANs              []string
	NotBefore         time.Time
	NotAfter          time.Time
	FingerprintSHA256 string
	CipherSuite       string
	Version           string
}

// Response is the result of a Transport round trip plus Pipeline enrichment.
type Response struct {
	Timings        *Timings `json:"timings,omitempty"`
	RequestHeaders http.Header
	InitialURL     string
	Redirects      []RedirectHop
	TotalTime      time.Duration
	StatusCode     int
	Header         http.Header
	Body           []byte // truncated to Config.MaxBodySize
	BodyTruncated  bool   // true when bytes beyond MaxBodySize were discarded
	ResponseTime   time.Duration
	RedirectChain  []string
	TLS            *TLSInfo // filled by Transport after handshake; nil for non-TLS
	Error          error
	ContentLength  int64
	ContentType    string
	WebServer      string // Server response header
	Location       string
	CSP            string
	// Cookies are the cookies in the shared per-host jar for this request's
	// host after the round trip (including Set-Cookie just received), populated
	// only when per-host cookies are enabled. nil otherwise.
	Cookies []*http.Cookie

	// Pipeline-filled (Extractor handlers), not computed on every request.
	Title       string
	LineCount   int
	WordCount   int
	BodyPreview string
	BodyHash    string
	HeaderHash  string
	FaviconHash int32
	JARM        string

	IP          string // actual connected IP (Transport, after TCP connect)
	CNAME       string // canonical name (Transport, after DNS resolve)
	Scheme      string
	HTTPVersion string
}

// Artifact is a typed value extracted from a Response by an Extractor.
type Artifact struct {
	Type  string
	Value string
}

// Handler is a single stage of the onion Pipeline.
type Handler func(c *Context) error

// Task pairs a Request with the Pipeline that processes its Response.
type Task struct {
	Req      *Request
	Pipeline []Handler
	Meta     map[string]any
}

// Result wraps the finished Context of a Task.
type Result struct {
	Ctx *Context
}

// Mutator rewrites a Request before it is sent. Adapt with AsMutator.
type Mutator interface {
	Mutate(req *Request) error
}

// Extractor pulls Artifacts out of a Response. Adapt with AsExtractor.
type Extractor interface {
	Name() string
	Extract(resp *Response) ([]Artifact, error)
}

// Matcher decides whether a Response is interesting. Adapt with AsMatcher.
type Matcher interface {
	Name() string
	Match(resp *Response) bool
}

// tlsConnState is the utls ConnectionState the Transport captures after the
// tls-client handshake to build a TLSInfo. Aliased here to keep buildTLSInfo
// testable and to isolate the utls dependency.
type tlsConnState = tls.ConnectionState
