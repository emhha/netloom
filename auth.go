package netloom

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strings"
	"unicode/utf8"

	http "github.com/bogdanfinn/fhttp"
)

// AuthScheme selects an explicit origin authentication mechanism. No mechanism
// is enabled implicitly and proxy authentication is never handled here.
type AuthScheme string

const (
	AuthBasic  AuthScheme = "basic"
	AuthDigest AuthScheme = "digest"
)

var (
	ErrAuthOptions     = errors.New("netloom: invalid authentication options")
	ErrAuthChallenge   = errors.New("netloom: invalid or unsafe authentication challenge")
	ErrAuthUnsupported = errors.New("netloom: unsupported authentication challenge")
)

// AuthOptions holds request-local origin credentials. Basic is preemptive and
// therefore requires explicit opt-in; use HTTPS to protect its plaintext secret.
// Digest waits for a same-origin 401 challenge. MaxChallenges limits challenge
// replays, not total requests: zero defaults to two and explicit values are 1..2.
//
// Use either Scheme plus credentials, or Authenticator, never both. Treat these
// options and extension implementations as immutable during requests. A shared
// Authenticator must be concurrency-safe; Clone does not clone caller closures.
// Credentials, nonces and generated Authorization values are never cached.
type AuthOptions struct {
	Scheme        AuthScheme
	Username      string
	Password      string
	MaxChallenges int
	Authenticator ChallengeAuthenticator
}

// AuthChallenge is an immutable snapshot for a trusted authentication extension.
// Header is a fresh response-header clone. Attempt starts at one; URL and Method
// identify the current logical origin request, not a proxy or redirected target.
type AuthChallenge struct {
	URL     string
	Method  string
	Header  http.Header
	Attempt int
}

// ChallengeAuthenticator returns a complete Authorization field value for a
// same-origin WWW-Authenticate challenge. It must honor ctx and must not persist
// credentials or follow redirects. Returned errors are intentionally replaced
// with a generic error so extension error text cannot disclose credentials.
type ChallengeAuthenticator interface {
	Authenticate(context.Context, AuthChallenge) (string, error)
}

func (a *AuthOptions) Validate() error {
	if a == nil {
		return nil
	}
	if a.MaxChallenges < 0 || a.MaxChallenges > 2 {
		return ErrAuthOptions
	}
	if a.Authenticator != nil {
		if a.Scheme != "" || a.Username != "" || a.Password != "" {
			return ErrAuthOptions
		}
		return nil
	}
	if a.Scheme != AuthBasic && a.Scheme != AuthDigest {
		return ErrAuthOptions
	}
	if len(a.Username) > 4096 || len(a.Password) > 4096 || !utf8.ValidString(a.Username) || !utf8.ValidString(a.Password) || authControl(a.Username) || authControl(a.Password) {
		return ErrAuthOptions
	}
	if a.Scheme == AuthBasic && strings.Contains(a.Username, ":") {
		return ErrAuthOptions
	}
	return nil
}

// Clone snapshots values, retaining only the caller-owned immutable extension.
func (a *AuthOptions) Clone() *AuthOptions {
	if a == nil {
		return nil
	}
	copy := *a
	return &copy
}

func validateAuthRequest(req *Request) error {
	if req.Auth == nil {
		return nil
	}
	if err := req.Auth.Validate(); err != nil {
		return err
	}
	if len(req.Raw) > 0 {
		return ErrAuthOptions
	}
	for name := range req.Header {
		if strings.EqualFold(name, "Authorization") {
			return ErrAuthOptions
		}
	}
	u, err := HTTPURL(req.URL)
	if err != nil || u.User != nil {
		return ErrAuthOptions
	}
	return nil
}

// doAuthenticatedRequest wraps an origin-only, nonredirecting send callback.
// Each replay clones headers and reopens the body exclusively via GetBody. It
// closes intermediate challenge bodies without draining (a zero-byte bound),
// avoiding unbounded reads before the caller's response-body policy is applied.
// Terminal HTTP 401 responses remain ordinary responses, not network failures.
// Protocol errors return the final response and an error; its body still belongs
// to the caller, which must consume or close it even when error is nonnil.
func doAuthenticatedRequest(ctx context.Context, req *Request, hreq *http.Request, send func(*http.Request) (*http.Response, error)) (*http.Response, error) {
	if req.Auth == nil {
		return send(hreq)
	}
	if err := validateAuthRequest(req); err != nil {
		return nil, err
	}
	if hreq == nil || hreq.URL == nil || !SameOrigin(req.URL, hreq.URL.String()) {
		return nil, ErrAuthChallenge
	}
	for name := range hreq.Header {
		if strings.EqualFold(name, "Authorization") {
			return nil, ErrAuthOptions
		}
	}
	options := req.Auth.Clone()
	current := hreq.Clone(ctx)
	if current.Header == nil {
		current.Header = make(http.Header)
	}
	if options.Scheme == AuthBasic {
		current.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(options.Username+":"+options.Password)))
		if err := requestContextError(ctx); err != nil {
			closeAuthRequestBody(current)
			return nil, err
		}
		response, err := send(current)
		closeAuthRequestBody(current)
		if cause := requestContextError(ctx); cause != nil {
			if err != nil {
				return response, errors.Join(err, cause)
			}
			return response, cause
		}
		return response, err
	}
	limit := options.MaxChallenges
	if limit == 0 {
		limit = 2
	}
	counts := make(map[string]uint32)
	for round := 0; ; round++ {
		if err := requestContextError(ctx); err != nil {
			closeAuthRequestBody(current)
			return nil, err
		}
		if current.URL == nil || !SameOrigin(req.URL, current.URL.String()) {
			closeAuthRequestBody(current)
			return nil, ErrAuthChallenge
		}
		response, err := send(current)
		closeAuthRequestBody(current)
		if cause := requestContextError(ctx); cause != nil {
			if err != nil {
				return response, errors.Join(err, cause)
			}
			return response, cause
		}
		if err != nil || response == nil {
			return response, err
		}
		if response.StatusCode != http.StatusUnauthorized || round >= limit {
			return response, nil
		}
		if current.URL == nil || !SameOrigin(req.URL, current.URL.String()) || response.Request != nil && (response.Request.URL == nil || !SameOrigin(req.URL, response.Request.URL.String())) {
			return response, ErrAuthChallenge
		}
		values := response.Header.Values("WWW-Authenticate")
		if len(values) == 0 {
			return response, nil
		}
		challenges, err := parseAuthChallenges(values)
		if err != nil {
			return response, err
		}
		var authorization string
		if options.Authenticator != nil {
			authorization, err = options.Authenticator.Authenticate(ctx, AuthChallenge{URL: hreq.URL.String(), Method: hreq.Method, Header: response.Header.Clone(), Attempt: round + 1})
			if cause := requestContextError(ctx); cause != nil {
				return response, cause
			}
			if err != nil || authorization == "" || len(authorization) > 16384 || authControl(authorization) || strings.TrimSpace(authorization) != authorization {
				return response, ErrAuthChallenge
			}
		} else {
			challenge, selectErr := selectDigestChallenge(challenges, hreq.URL)
			if selectErr != nil {
				return response, selectErr
			}
			if round > 0 && !challenge.stale {
				return response, nil
			}
			counts[challenge.nonce]++
			authorization, err = digestAuthorization(options, challenge, hreq, counts[challenge.nonce])
			if err != nil {
				return response, err
			}
		}
		var bodyErr error
		next := hreq.Clone(ctx)
		if hreq.Body != nil && hreq.Body != http.NoBody {
			if hreq.GetBody == nil {
				return response, ErrBodyNotReplayable
			}
			next.Body, bodyErr = hreq.GetBody()
			if bodyErr != nil {
				if next.Body != nil && next.Body != http.NoBody {
					_ = next.Body.Close()
				}
				return response, bodyErr
			}
			if next.Body == nil {
				return response, ErrBodyNotReplayable
			}
		}
		if cause := requestContextError(ctx); cause != nil {
			if next.Body != nil && next.Body != http.NoBody {
				_ = next.Body.Close()
			}
			return response, cause
		}
		if response.Body != nil {
			_ = response.Body.Close()
		}
		next.Header = hreq.Header.Clone()
		if next.Header == nil {
			next.Header = make(http.Header)
		}
		next.Header.Set("Authorization", authorization)
		current = next
	}
}

func closeAuthRequestBody(request *http.Request) {
	if request.Body != nil && request.Body != http.NoBody {
		_ = request.Body.Close()
	}
}

func authControl(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return true
		}
	}
	return false
}

type parsedAuthChallenge struct {
	scheme string
	params map[string]string
}

// parseAuthChallenges recognizes comma-separated challenges and auth-params,
// without confusing commas/escaped quotes within quoted-string values. Every
// field, directive count and total input is bounded before allocating output.
func parseAuthChallenges(values []string) ([]parsedAuthChallenge, error) {
	total := 0
	var output []parsedAuthChallenge
	for _, input := range values {
		total += len(input)
		if total > 16384 {
			return nil, ErrAuthChallenge
		}
		for i := 0; i < len(input); i++ {
			if input[i] < 0x20 && input[i] != '\t' || input[i] == 0x7f {
				return nil, ErrAuthChallenge
			}
		}
		i := 0
		skip := func() {
			for i < len(input) && (input[i] == ' ' || input[i] == '\t') {
				i++
			}
		}
		token := func() string {
			start := i
			for i < len(input) && authToken(input[i]) {
				i++
			}
			return input[start:i]
		}
		skip()
		if i == len(input) {
			return nil, ErrAuthChallenge
		}
		for i < len(input) {
			scheme := token()
			if scheme == "" {
				return nil, ErrAuthChallenge
			}
			challenge := parsedAuthChallenge{scheme: strings.ToLower(scheme), params: make(map[string]string)}
			if i < len(input) && input[i] != ',' && input[i] != ' ' && input[i] != '\t' {
				return nil, ErrAuthChallenge
			}
			skip()
			for i < len(input) && input[i] != ',' {
				if len(challenge.params) == 0 && challenge.scheme != "digest" && challenge.scheme != "basic" {
					end := i
					valid := true
					for end < len(input) && input[end] != ',' {
						if !authToken68(input[end]) {
							valid = false
							break
						}
						end++
					}
					if valid && end > i {
						i = end
						break
					}
				}
				start := i
				key := token()
				skip()
				if key == "" {
					return nil, ErrAuthChallenge
				}
				if i == len(input) || input[i] != '=' {
					// Token68 is opaque to this implementation (e.g. Negotiate). It is
					// allowed only as the entire challenge, never after auth-params.
					if len(challenge.params) != 0 {
						return nil, ErrAuthChallenge
					}
					i = start
					for i < len(input) && input[i] != ',' {
						if !authToken68(input[i]) {
							return nil, ErrAuthChallenge
						}
						i++
					}
					break
				}
				i++
				skip()
				var value string
				if i < len(input) && input[i] == '"' {
					i++
					var decoded strings.Builder
					closed := false
					for i < len(input) {
						b := input[i]
						i++
						if b == '"' {
							closed = true
							break
						}
						if b == '\\' {
							if i == len(input) {
								return nil, ErrAuthChallenge
							}
							b = input[i]
							i++
						}
						if b < 0x20 || b == 0x7f {
							return nil, ErrAuthChallenge
						}
						decoded.WriteByte(b)
						if decoded.Len() > 4096 {
							return nil, ErrAuthChallenge
						}
					}
					if !closed {
						return nil, ErrAuthChallenge
					}
					value = decoded.String()
				} else {
					value = token()
					if value == "" {
						return nil, ErrAuthChallenge
					}
				}
				if len(value) > 4096 || len(challenge.params) >= 32 {
					return nil, ErrAuthChallenge
				}
				key = strings.ToLower(key)
				if _, exists := challenge.params[key]; exists {
					return nil, ErrAuthChallenge
				}
				challenge.params[key] = value
				skip()
				if i == len(input) {
					break
				}
				if input[i] != ',' {
					return nil, ErrAuthChallenge
				}
				// A comma followed by token '=' continues this challenge; otherwise
				// it starts another scheme. Leave that comma for the outer loop.
				comma := i
				i++
				skip()
				_ = token()
				skip()
				isParam := i < len(input) && input[i] == '='
				i = comma
				if !isParam {
					break
				}
				i++
				skip()
			}
			output = append(output, challenge)
			if len(output) > 16 {
				return nil, ErrAuthChallenge
			}
			skip()
			if i == len(input) {
				break
			}
			if input[i] != ',' {
				return nil, ErrAuthChallenge
			}
			i++
			skip()
			if i == len(input) {
				return nil, ErrAuthChallenge
			}
		}
	}
	return output, nil
}

func authToken(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b))
}
func authToken68(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || strings.ContainsRune("-._~+/=", rune(b))
}

type digestChallenge struct {
	realm, nonce, opaque, algorithm, qop string
	hasOpaque, stale, sess               bool
	newHash                              func() hash.Hash
	strength                             int
}

func selectDigestChallenge(challenges []parsedAuthChallenge, target *url.URL) (*digestChallenge, error) {
	var selected *digestChallenge
	for _, parsed := range challenges {
		if parsed.scheme != "digest" {
			continue
		}
		p := parsed.params
		realm, hasRealm := p["realm"]
		nonce := p["nonce"]
		if !hasRealm || nonce == "" {
			return nil, ErrAuthChallenge
		}
		challenge := &digestChallenge{realm: realm, nonce: nonce, opaque: p["opaque"]}
		_, challenge.hasOpaque = p["opaque"]
		if charset, exists := p["charset"]; exists && !strings.EqualFold(charset, "UTF-8") {
			continue
		}
		if !utf8.ValidString(realm) || !utf8.ValidString(nonce) {
			return nil, ErrAuthChallenge
		}
		if userhash, exists := p["userhash"]; exists && !strings.EqualFold(userhash, "false") {
			continue
		}
		if stale, exists := p["stale"]; exists {
			if !strings.EqualFold(stale, "true") && !strings.EqualFold(stale, "false") {
				return nil, ErrAuthChallenge
			}
			challenge.stale = strings.EqualFold(stale, "true")
		}
		if domain, exists := p["domain"]; exists {
			for _, part := range strings.Fields(domain) {
				u, err := url.Parse(part)
				if err != nil {
					return nil, ErrAuthChallenge
				}
				resolved := target.ResolveReference(u)
				if !SameOrigin(target.String(), resolved.String()) {
					return nil, ErrAuthChallenge
				}
			}
		}
		algorithm := p["algorithm"]
		if algorithm == "" {
			algorithm = "MD5"
		}
		algorithm = strings.ToUpper(algorithm)
		challenge.sess = strings.HasSuffix(algorithm, "-SESS")
		base := strings.TrimSuffix(algorithm, "-SESS")
		switch base {
		case "SHA-512-256":
			challenge.newHash = sha512.New512_256
			challenge.strength = 3
		case "SHA-256":
			challenge.newHash = sha256.New
			challenge.strength = 2
		case "MD5":
			challenge.newHash = md5.New
			challenge.strength = 1
		default:
			continue
		}
		challenge.algorithm = base
		if challenge.sess {
			challenge.algorithm += "-sess"
		}
		if qop, exists := p["qop"]; exists {
			for _, value := range strings.Split(qop, ",") {
				if strings.EqualFold(strings.TrimSpace(value), "auth") {
					challenge.qop = "auth"
				}
			}
			if challenge.qop == "" {
				continue
			}
		}
		if selected == nil || challenge.strength > selected.strength {
			selected = challenge
		}
	}
	if selected == nil {
		return nil, ErrAuthUnsupported
	}
	return selected, nil
}

func digestAuthorization(options *AuthOptions, challenge *digestChallenge, request *http.Request, count uint32) (string, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", ErrAuthChallenge
	}
	cnonce := hex.EncodeToString(nonceBytes)
	hashText := func(value string) string {
		h := challenge.newHash()
		_, _ = h.Write([]byte(value))
		return hex.EncodeToString(h.Sum(nil))
	}
	ha1 := hashText(options.Username + ":" + challenge.realm + ":" + options.Password)
	if challenge.sess {
		ha1 = hashText(ha1 + ":" + challenge.nonce + ":" + cnonce)
	}
	method := request.Method
	if method == "" {
		method = http.MethodGet
	}
	uri := request.URL.RequestURI()
	ha2 := hashText(method + ":" + uri)
	nc := fmt.Sprintf("%08x", count)
	digest := hashText(ha1 + ":" + challenge.nonce + ":" + ha2)
	if challenge.qop != "" {
		digest = hashText(ha1 + ":" + challenge.nonce + ":" + nc + ":" + cnonce + ":" + challenge.qop + ":" + ha2)
	}
	fields := []string{"username=" + authQuote(options.Username), "realm=" + authQuote(challenge.realm), "nonce=" + authQuote(challenge.nonce), "uri=" + authQuote(uri), "algorithm=" + challenge.algorithm, "response=" + authQuote(digest)}
	if challenge.hasOpaque {
		fields = append(fields, "opaque="+authQuote(challenge.opaque))
	}
	if challenge.qop != "" {
		fields = append(fields, "qop=auth", "nc="+nc, "cnonce="+authQuote(cnonce))
	} else if challenge.sess {
		fields = append(fields, "cnonce="+authQuote(cnonce))
	}
	return "Digest " + strings.Join(fields, ", "), nil
}

func authQuote(value string) string {
	return "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(value) + "\""
}
