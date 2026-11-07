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

type RequestInput struct {
	MaxResponseBytes int64                   `json:"max_response_bytes,omitempty"`
	Stream           bool                    `json:"stream,omitempty"`
	Method           string                  `json:"method"`
	URL              string                  `json:"url"`
	Headers          map[string]string       `json:"headers,omitempty"`
	Body             string                  `json:"body,omitempty"`
	TimeoutSeconds   int                     `json:"timeout_seconds,omitempty"`
	PhaseTimeouts    *PhaseTimeoutsInput     `json:"phase_timeouts,omitempty"`
	Network          *netloom.NetworkOptions `json:"network,omitempty"`
	HeaderValues     map[string][]string     `json:"header_values,omitempty"`
	BodyEncoding     string                  `json:"body_encoding,omitempty"`
	Query            []NameValue             `json:"query,omitempty"`
	Form             []NameValue             `json:"form,omitempty"`
	Multipart        []MultipartPart         `json:"multipart,omitempty"`
	BasicAuth        *BasicCredentials       `json:"basic_auth,omitempty"`
	FollowRedirects  bool                    `json:"follow_redirects,omitempty"`
	MaxRedirects     int                     `json:"max_redirects,omitempty"`
	HTTPVersion      string                  `json:"http_version,omitempty"`
	FreshConnection  bool                    `json:"fresh_connection,omitempty"`
	TLSProfile       string                  `json:"tls_profile,omitempty"`
	InsecureTLS      bool                    `json:"insecure_tls,omitempty"`
}
