package netloom

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"

	utls "github.com/bogdanfinn/utls"
)

// ErrorKind is a stable, coarse classification of a request or transport
// failure. It is intended for display and policy decisions, not as a
// replacement for errors.Is/errors.As on the original error.
//
// Classification never guesses: when the observed error chain does not prove a
// more specific kind, Classify returns ErrorKindUnknown.
type ErrorKind string

const (
	// ErrorKindDNS identifies a name-resolution failure (*net.DNSError).
	ErrorKindDNS ErrorKind = "dns"
	// ErrorKindConnectRefused identifies a refused TCP connection
	// (syscall.ECONNREFUSED).
	ErrorKindConnectRefused ErrorKind = "connect_refused"
	// ErrorKindConnectTimeout identifies a timeout observed in the connect
	// phase. DNS timeouts are reported as ErrorKindDNS instead.
	ErrorKindConnectTimeout ErrorKind = "connect_timeout"
	// ErrorKindTLSVerify identifies certificate or public-key verification
	// failures during a TLS handshake.
	ErrorKindTLSVerify ErrorKind = "tls_verify"
	// ErrorKindTLSHandshake identifies a TLS failure other than verification,
	// including record-header, alert and connection failures during handshake.
	ErrorKindTLSHandshake ErrorKind = "tls_handshake"
	// ErrorKindProxy identifies invalid proxy configuration or a proxy policy
	// this transport does not support.
	ErrorKindProxy ErrorKind = "proxy"
	// ErrorKindBlockedAddress identifies a target rejected by the dial guard
	// because it is loopback, unspecified or link-local.
	ErrorKindBlockedAddress ErrorKind = "blocked_address"
	// ErrorKindRedirectLimit identifies a redirect chain that exceeded its
	// configured hop budget.
	ErrorKindRedirectLimit ErrorKind = "redirect_limit"
	// ErrorKindResponseHeaderTimeout identifies a timeout while waiting for the
	// complete final response headers.
	ErrorKindResponseHeaderTimeout ErrorKind = "response_header_timeout"
	// ErrorKindBodyRead identifies a non-timeout failure while reading a
	// response body (for example an unexpected EOF or a connection reset).
	ErrorKindBodyRead ErrorKind = "body_read"
	// ErrorKindBodyTimeout identifies a blocked body read that hit its idle
	// budget.
	ErrorKindBodyTimeout ErrorKind = "body_timeout"
	// ErrorKindBodyLimit identifies a response body size limit reported as an
	// error, such as *net/http.MaxBytesError. The built-in buffered reader caps
	// oversized bodies without returning an error and reports that through
	// Response.BodyTruncated instead.
	ErrorKindBodyLimit ErrorKind = "body_limit"
	// ErrorKindAuthUnsupported identifies an authentication challenge the
	// configured authenticator does not support.
	ErrorKindAuthUnsupported ErrorKind = "auth_unsupported"
	// ErrorKindHTTP2Unavailable identifies a request that required HTTP/2 but
	// could not negotiate it.
	ErrorKindHTTP2Unavailable ErrorKind = "http2_unavailable"
	// ErrorKindQueueFull identifies a full or unavailable task queue.
	ErrorKindQueueFull ErrorKind = "queue_full"
	// ErrorKindEngineClosed identifies work submitted after Engine.Close.
	ErrorKindEngineClosed ErrorKind = "engine_closed"
	// ErrorKindInvalidRequest identifies a caller input or lifecycle misuse
	// proven by a known sentinel (for example ErrNilRequest, ErrUploadLength or
	// ErrBodyNotReplayable).
	ErrorKindInvalidRequest ErrorKind = "invalid_request"
	// ErrorKindTimeout identifies a deadline that is proven by the error chain
	// but does not belong to one of the phase-specific timeout kinds.
	ErrorKindTimeout ErrorKind = "timeout"
	// ErrorKindUnknown means the error chain did not prove a more specific
	// classification. It is not an assertion that the failure is unknown.
	ErrorKindUnknown ErrorKind = "unknown"
)

// Classify returns a stable kind for err, the observed Phase when the error
// chain contains a *PhaseError, and whether the error chain proves a timeout.
//
// The phase is taken from the first *PhaseError found with errors.As; kind
// detection then inspects the complete chain with errors.Is/errors.As so that
// joined and wrapped errors are preserved. A DNS timeout is reported as
// ErrorKindDNS with timeout true, because the DNS failure is the more specific
// fact. A caller cancellation without a deadline is not classified as a
// read/handshake failure and returns ErrorKindUnknown.
//
// Classify is purely observational: it changes no error, retry, redirect,
// timeout or connection-reuse behavior. It never adds URL, header, body or
// credential data to an error.
func Classify(err error) (kind ErrorKind, phase Phase, timeout bool) {
	if err == nil {
		return ErrorKindUnknown, "", false
	}

	var phaseErr *PhaseError
	if errors.As(err, &phaseErr) {
		phase = phaseErr.Phase
	}
	timeout = isTimeoutError(err)

	// A plain cancellation says nothing about which lower-level operation
	// failed. Do not turn it into a body/connect/TLS diagnosis.
	if !timeout && errors.Is(err, context.Canceled) {
		return ErrorKindUnknown, phase, false
	}

	// Explicit sentinels are the strongest available evidence. They take
	// precedence over the phase because a blocked address or protocol policy
	// failure is more specific than the operation that surfaced it.
	switch {
	case errors.Is(err, ErrBlockedAddress):
		return ErrorKindBlockedAddress, phase, timeout
	case errors.Is(err, ErrRedirectLimit):
		return ErrorKindRedirectLimit, phase, timeout
	case errors.Is(err, ErrAuthUnsupported):
		return ErrorKindAuthUnsupported, phase, timeout
	case errors.Is(err, ErrHTTP2Unavailable):
		return ErrorKindHTTP2Unavailable, phase, timeout
	case errors.Is(err, ErrQueueFull):
		return ErrorKindQueueFull, phase, timeout
	case errors.Is(err, ErrEngineClosed):
		return ErrorKindEngineClosed, phase, timeout
	case errors.Is(err, ErrInvalidProxy), errors.Is(err, ErrNetworkProxyUnsupported):
		return ErrorKindProxy, phase, timeout
	case errors.Is(err, ErrTLSPinMismatch):
		return ErrorKindTLSVerify, phase, timeout
	case errors.Is(err, ErrNilRequest),
		errors.Is(err, ErrBodyNotReplayable),
		errors.Is(err, ErrUploadLength),
		errors.Is(err, ErrAuthOptions),
		errors.Is(err, ErrMutatorAfterSend),
		errors.Is(err, ErrNetworkBindingInvalid),
		errors.Is(err, ErrNetworkBindingUnsupported),
		errors.Is(err, ErrTLSOptionsUnsupported),
		errors.Is(err, ErrTLSProfileConflict):
		return ErrorKindInvalidRequest, phase, timeout
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ErrorKindDNS, phase, timeout
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return ErrorKindConnectRefused, phase, timeout
	}

	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return ErrorKindBodyLimit, phase, timeout
	}

	if isTLSVerifyError(err) {
		return ErrorKindTLSVerify, phase, timeout
	}
	if isTLSHandshakeError(err) {
		return ErrorKindTLSHandshake, phase, timeout
	}

	switch phase {
	case PhaseConnect:
		if timeout {
			return ErrorKindConnectTimeout, phase, true
		}
	case PhaseResponseHeader:
		if timeout {
			return ErrorKindResponseHeaderTimeout, phase, true
		}
	case PhaseBody:
		if timeout {
			return ErrorKindBodyTimeout, phase, true
		}
		return ErrorKindBodyRead, phase, false
	case PhaseTLS:
		return ErrorKindTLSHandshake, phase, timeout
	}

	if timeout {
		return ErrorKindTimeout, phase, true
	}
	return ErrorKindUnknown, phase, false
}

// Message returns a single-line, display-oriented summary of err without a
// leading library name. When err contains a *PhaseError, its Phase is kept as
// a prefix and the wrapped cause supplies the remaining text; otherwise the
// cleaned error text is used.
//
// Message removes a leading "netloom: " prefix (and known internal library
// qualifiers), replaces line breaks with "; ", and does not truncate the
// result. It never appends request URLs, headers, bodies or credentials of its
// own. It is a formatting helper over the existing error text, not a general
// redaction layer for errors created outside this package.
//
// Message returns "" for a nil error.
func Message(err error) string {
	if err == nil {
		return ""
	}
	var phaseErr *PhaseError
	if errors.As(err, &phaseErr) {
		msg := cleanErrorMessage(phaseErr.Err)
		if phaseErr.Phase == "" {
			return msg
		}
		if msg == "" {
			return string(phaseErr.Phase)
		}
		return string(phaseErr.Phase) + ": " + msg
	}
	return cleanErrorMessage(err)
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isTLSVerifyError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var certificateInvalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var systemRoots x509.SystemRootsError
	var stdVerification *stdtls.CertificateVerificationError
	var utlsVerification *utls.CertificateVerificationError
	return errors.As(err, &unknownAuthority) ||
		errors.As(err, &certificateInvalid) ||
		errors.As(err, &hostname) ||
		errors.As(err, &systemRoots) ||
		errors.As(err, &stdVerification) ||
		errors.As(err, &utlsVerification)
}

func isTLSHandshakeError(err error) bool {
	var stdRecord stdtls.RecordHeaderError
	var utlsRecord utls.RecordHeaderError
	var stdAlert stdtls.AlertError
	var utlsAlert utls.AlertError
	return errors.As(err, &stdRecord) ||
		errors.As(err, &utlsRecord) ||
		errors.As(err, &stdAlert) ||
		errors.As(err, &utlsAlert)
}

// cleanErrorMessage removes this package's visible prefixes and normalizes
// line breaks without interpreting or truncating the underlying text.
func cleanErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	text := stripLibraryPrefixes(err.Error())
	text = strings.ReplaceAll(text, "netloom: ", "")
	text = strings.NewReplacer("\r\n", "; ", "\n", "; ", "\r", "; ", "\u2028", "; ", "\u2029", "; ").Replace(text)
	return strings.TrimSpace(text)
}

// stripLibraryPrefixes removes wrapper prefixes such as
// "netloom.Engine.Send: " and "netloom: " without touching payload text that
// merely starts with "netloom." (for example a dial target).
func stripLibraryPrefixes(text string) string {
	for {
		text = strings.TrimLeft(text, " \t")
		if strings.HasPrefix(text, "netloom: ") {
			text = text[len("netloom: "):]
			continue
		}
		if strings.HasPrefix(text, "netloom.") {
			if end := strings.Index(text, ": "); end > len("netloom.") && isLibraryQualifier(text[:end]) {
				text = text[end+2:]
				continue
			}
		}
		return text
	}
}

func isLibraryQualifier(text string) bool {
	if !strings.HasPrefix(text, "netloom.") || len(text) == len("netloom.") {
		return false
	}
	for _, r := range text[len("netloom."):] {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}
