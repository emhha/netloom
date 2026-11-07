package nethttp

import "github.com/emhha/netloom"

// PhaseTimeoutsInput uses explicit millisecond units, unlike native Go durations.
// Omission inherits Engine settings; an empty object disables all phase budgets.
type PhaseTimeoutsInput struct {
	ConnectMS        int64 `json:"connect_ms,omitempty"`
	TLSHandshakeMS   int64 `json:"tls_handshake_ms,omitempty"`
	ResponseHeaderMS int64 `json:"response_header_ms,omitempty"`
	BodyIdleMS       int64 `json:"body_idle_ms,omitempty"`
	TotalMS          int64 `json:"total_ms,omitempty"`
}

// TLSInput exposes TLS test controls only; trust roots and client credentials
// remain native Go TLSOptions and are never accepted through this JSON object.
// Omission inherits the existing profile behavior; an empty object retains an
// explicit, nonnil TLS configuration without enabling additional controls.
type TLSInput struct {
	MinVersion       netloom.TLSVersion `json:"min_version,omitempty"`
	MaxVersion       netloom.TLSVersion `json:"max_version,omitempty"`
	ServerName       string             `json:"server_name,omitempty"`
	PinnedPublicKeys []string           `json:"pinned_public_keys,omitempty"`
}

// RetryInput uses explicit millisecond delays. Omission retains Engine retry
// behavior; an empty object explicitly disables retries. Observer callbacks are
// native-only and cannot be supplied through this structured input.
type RetryInput struct {
	MaxRetries        int      `json:"max_retries,omitempty"`
	Methods           []string `json:"methods,omitempty"`
	StatusCodes       []int    `json:"status_codes,omitempty"`
	BaseDelayMS       int64    `json:"base_delay_ms,omitempty"`
	MaxDelayMS        int64    `json:"max_delay_ms,omitempty"`
	RespectRetryAfter bool     `json:"respect_retry_after,omitempty"`
}

// AuthInput supports only explicit Basic/Digest origin credentials. Native
// authentication extensions are intentionally not exposed through JSON.
type AuthInput struct {
	Scheme        netloom.AuthScheme `json:"scheme"`
	Username      string             `json:"username"`
	Password      string             `json:"password"`
	MaxChallenges int                `json:"max_challenges,omitempty"`
}

type RequestInput struct {
	Upload             *netloom.Upload         `json:"-"`
	StreamingMultipart []netloom.UploadPart    `json:"-"`
	Retry              *RetryInput             `json:"retry,omitempty"`
	Auth               *AuthInput              `json:"auth,omitempty"`
	CaptureRequestBody int                     `json:"capture_request_body,omitempty"`
	MaxResponseBytes   int64                   `json:"max_response_bytes,omitempty"`
	Stream             bool                    `json:"stream,omitempty"`
	Method             string                  `json:"method"`
	URL                string                  `json:"url"`
	Headers            map[string]string       `json:"headers,omitempty"`
	Body               string                  `json:"body,omitempty"`
	TimeoutSeconds     int                     `json:"timeout_seconds,omitempty"`
	PhaseTimeouts      *PhaseTimeoutsInput     `json:"phase_timeouts,omitempty"`
	Network            *netloom.NetworkOptions `json:"network,omitempty"`
	HeaderValues       map[string][]string     `json:"header_values,omitempty"`
	BodyEncoding       string                  `json:"body_encoding,omitempty"`
	Query              []NameValue             `json:"query,omitempty"`
	Form               []NameValue             `json:"form,omitempty"`
	Multipart          []MultipartPart         `json:"multipart,omitempty"`
	BasicAuth          *BasicCredentials       `json:"basic_auth,omitempty"`
	FollowRedirects    bool                    `json:"follow_redirects,omitempty"`
	MaxRedirects       int                     `json:"max_redirects,omitempty"`
	HTTPVersion        string                  `json:"http_version,omitempty"`
	FreshConnection    bool                    `json:"fresh_connection,omitempty"`
	TLS                *TLSInput               `json:"tls,omitempty"`
	TLSProfile         string                  `json:"tls_profile,omitempty"`
	InsecureTLS        bool                    `json:"insecure_tls,omitempty"`
}
