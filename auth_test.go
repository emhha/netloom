package netloom

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls "github.com/bogdanfinn/utls"
)

type authExtensionFunc func(context.Context, AuthChallenge) (string, error)

func (f authExtensionFunc) Authenticate(ctx context.Context, c AuthChallenge) (string, error) {
	return f(ctx, c)
}

func TestAuthOptions(t *testing.T) {
	extension := authExtensionFunc(func(context.Context, AuthChallenge) (string, error) { return "Bearer opaque", nil })
	for _, options := range []*AuthOptions{nil, {Scheme: AuthBasic}, {Scheme: AuthDigest, Username: "usér:account", Password: "p\\\"word"}, {Authenticator: extension}, {Scheme: AuthDigest, MaxChallenges: 2}} {
		if err := options.Validate(); err != nil {
			t.Fatal("valid options rejected")
		}
	}
	for _, options := range []*AuthOptions{{}, {Scheme: "negotiate"}, {Scheme: AuthBasic, Username: "user:account"}, {Scheme: AuthBasic, Password: "secret\n"}, {Scheme: AuthDigest, Username: "user\x00"}, {Scheme: AuthDigest, Password: string([]byte{0xff})}, {Scheme: AuthDigest, MaxChallenges: -1}, {Scheme: AuthDigest, MaxChallenges: 3}, {Scheme: AuthBasic, Authenticator: extension}, {Authenticator: extension, Username: "user"}, {Scheme: AuthDigest, Username: strings.Repeat("u", 4097)}} {
		if !errors.Is(options.Validate(), ErrAuthOptions) {
			t.Fatal("invalid options accepted")
		}
	}
	original := &AuthOptions{Scheme: AuthDigest, Username: "original"}
	copy := original.Clone()
	copy.Username = "copy"
	if original.Username != "original" {
		t.Fatal("options clone aliases source")
	}
	for _, request := range []*Request{{URL: "http://example.com", Raw: []byte("GET /"), Auth: original}, {URL: "http://example.com", Header: fhttp.Header{"authorization": nil}, Auth: original}, {URL: "http://user:pass@example.com", Auth: original}} {
		if !errors.Is(validateAuthRequest(request), ErrAuthOptions) {
			t.Fatal("unsafe request options accepted")
		}
	}
}

func TestAuthChallengeParser(t *testing.T) {
	input := []string{`Negotiate YWJjZA==, Basic realm="fallback", Digest realm="a,b\"c", nonce="opaque\\nonce", algorithm=SHA-256, qop="auth-int, auth", opaque=""`}
	parsed, err := parseAuthChallenges(input)
	if err != nil || len(parsed) != 3 {
		t.Fatal("valid mixed challenges rejected")
	}
	if parsed[2].params["realm"] != "a,b\"c" || parsed[2].params["nonce"] != "opaque\\nonce" {
		t.Fatal("quoted values not correctly decoded")
	}
	target, _ := url.Parse("https://example.com/private")
	selected, err := selectDigestChallenge(parsed, target)
	if err != nil || selected.algorithm != "SHA-256" || selected.qop != "auth" {
		t.Fatal("supported digest not selected")
	}
	for _, input := range []string{`Digest realm="x", nonce="n", NONCE="m"`, `Digest realm="unterminated`, `Digest realm="x", nonce=`, `Digest realm="x", nonce="n",`, `Digest realm="x" nonce="n"`, `Digest realm="x", nonce="n\`, "Digest realm=\"x\t\", nonce=n", "Digest realm=x, nonce=n\r\nOther: x", strings.Repeat("x", 16385), strings.Repeat(`Basic realm="x",`, 17) + `Basic realm="x"`} {
		if _, err := parseAuthChallenges([]string{input}); !errors.Is(err, ErrAuthChallenge) {
			t.Fatal("malformed or over-bound challenge accepted")
		}
	}
	params := `Digest realm="x", nonce="n"`
	for i := 0; i < 32; i++ {
		params += fmt.Sprintf(", p%d=x", i)
	}
	if _, err := parseAuthChallenges([]string{params}); !errors.Is(err, ErrAuthChallenge) {
		t.Fatal("too many directives accepted")
	}
	for _, tc := range []struct {
		value string
		want  error
	}{
		{`Digest nonce="n"`, ErrAuthChallenge},
		{`Digest realm="x", nonce=""`, ErrAuthChallenge},
		{`Digest realm="x", nonce=n, domain="https://other.example/"`, ErrAuthChallenge},
		{`Digest realm="x", nonce=n, stale=maybe`, ErrAuthChallenge},
		{`Digest realm="x", nonce=n, qop="auth-int"`, ErrAuthUnsupported},
		{`Digest realm="x", nonce=n, algorithm=SHA-1`, ErrAuthUnsupported},
		{`Digest realm="x", nonce=n, charset=ISO-8859-1`, ErrAuthUnsupported},
		{`Digest realm="x", nonce=n, userhash=true`, ErrAuthUnsupported},
		{`Bearer realm="x"`, ErrAuthUnsupported},
	} {
		parsed, err := parseAuthChallenges([]string{tc.value})
		if err != nil {
			t.Fatal("parser incorrectly rejected syntax before policy check")
		}
		if _, err := selectDigestChallenge(parsed, target); !errors.Is(err, tc.want) {
			t.Fatal("unsupported or unsafe digest accepted")
		}
	}
	parsed, err = parseAuthChallenges([]string{`Digest realm="x", nonce=n, algorithm=MD5`, `Digest realm="x", nonce=n, algorithm=SHA-512-256`})
	if err != nil {
		t.Fatal(err)
	}
	selected, err = selectDigestChallenge(parsed, target)
	if err != nil || selected.algorithm != "SHA-512-256" {
		t.Fatal("did not select strongest supported challenge")
	}
}

func authTestClient(t *testing.T, server *httptest.Server) *fhttp.Client {
	t.Helper()
	transport := &fhttp.Transport{}
	if server.Certificate() != nil {
		roots := x509.NewCertPool()
		roots.AddCert(server.Certificate())
		transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &fhttp.Client{Transport: transport, CheckRedirect: func(*fhttp.Request, []*fhttp.Request) error { return fhttp.ErrUseLastResponse }}
}

func authTestDigest(t *testing.T, value, method, uri, algorithm, qop, username, password, realm, nonce string) map[string]string {
	t.Helper()
	parsed, err := parseAuthChallenges([]string{value})
	if err != nil || len(parsed) != 1 || parsed[0].scheme != "digest" {
		t.Error("invalid generated digest syntax")
		return nil
	}
	p := parsed[0].params
	if p["username"] != username || p["realm"] != realm || p["nonce"] != nonce || p["uri"] != uri || !strings.EqualFold(p["algorithm"], algorithm) || p["qop"] != qop {
		t.Error("generated digest fields do not match challenged request")
	}
	var newHash func() hash.Hash
	switch strings.TrimSuffix(strings.ToUpper(algorithm), "-SESS") {
	case "MD5":
		newHash = md5.New
	case "SHA-256":
		newHash = sha256.New
	case "SHA-512-256":
		newHash = sha512.New512_256
	default:
		t.Fatal("invalid test hash")
	}
	digest := func(s string) string {
		h := newHash()
		_, _ = io.WriteString(h, s)
		return hex.EncodeToString(h.Sum(nil))
	}
	a1 := digest(username + ":" + realm + ":" + password)
	if strings.HasSuffix(strings.ToLower(algorithm), "-sess") {
		a1 = digest(a1 + ":" + nonce + ":" + p["cnonce"])
	}
	a2 := digest(method + ":" + uri)
	expected := digest(a1 + ":" + nonce + ":" + a2)
	if qop != "" {
		expected = digest(a1 + ":" + nonce + ":" + p["nc"] + ":" + p["cnonce"] + ":" + qop + ":" + a2)
		if len(p["cnonce"]) != 32 || len(p["nc"]) != 8 {
			t.Error("nonce counter/cnonce format invalid")
		}
	}
	if p["response"] != expected {
		t.Error("digest hash verification failed")
	}
	return p
}

func TestAuthDigestLocalHandshake(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, algorithm := range []string{"MD5", "MD5-sess", "SHA-256", "SHA-256-sess", "SHA-512-256", "SHA-512-256-sess", "legacy"} {
			t.Run(strconv.FormatBool(secure)+"/"+algorithm, func(t *testing.T) {
				var calls atomic.Int32
				chosen := algorithm
				qop := "auth"
				if algorithm == "legacy" {
					chosen = "MD5"
					qop = ""
				}
				username, password, realm := "usér\\\"name", "private password", "test, realm"
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					attempt := calls.Add(1)
					body, err := io.ReadAll(r.Body)
					if err != nil || string(body) != "request payload" {
						t.Error("request body did not replay intact")
					}
					if attempt == 1 {
						if r.Header.Get("Authorization") != "" {
							t.Error("Digest sent credentials before challenge")
						}
						challenge := `Digest realm="test, realm", nonce="nonce", opaque="opaque", charset=UTF-8, algorithm=` + chosen
						if qop != "" {
							challenge += `, qop="auth-int, auth"`
						}
						w.Header().Set("WWW-Authenticate", challenge)
						w.WriteHeader(401)
						_, _ = io.WriteString(w, "intermediate")
						return
					}
					p := authTestDigest(t, r.Header.Get("Authorization"), r.Method, r.URL.RequestURI(), chosen, qop, username, password, realm, "nonce")
					if p["opaque"] != "opaque" || qop != "" && p["nc"] != "00000001" {
						t.Error("opaque or initial nonce-count invalid")
					}
					_, _ = io.WriteString(w, "authenticated")
				})
				var server *httptest.Server
				if secure {
					server = httptest.NewTLSServer(handler)
				} else {
					server = httptest.NewServer(handler)
				}
				defer server.Close()
				client := authTestClient(t, server)
				request := &Request{URL: server.URL + "/private?x=1", Auth: &AuthOptions{Scheme: AuthDigest, Username: username, Password: password}}
				hreq, err := fhttp.NewRequestWithContext(context.Background(), "POST", request.URL, strings.NewReader("request payload"))
				if err != nil {
					t.Fatal(err)
				}
				hreq.Header.Set("X-Original", "retained")
				response, err := doAuthenticatedRequest(context.Background(), request, hreq, client.Do)
				if err != nil || response == nil {
					t.Fatal("actual digest handshake failed")
				}
				defer response.Body.Close()
				body, _ := io.ReadAll(response.Body)
				if string(body) != "authenticated" || calls.Load() != 2 {
					t.Fatal("unexpected digest exchange result")
				}
				if hreq.Header.Get("Authorization") != "" || request.Header.Get("Authorization") != "" {
					t.Fatal("generated credentials mutated caller headers")
				}
			})
		}
	}
}

func TestAuthEngineBufferedAndStream(t *testing.T) {
	for _, scheme := range []AuthScheme{AuthBasic, AuthDigest} {
		for _, mode := range []string{"1.1/buffer", "1.1/stream", "2/buffer", "2/stream", "2-only/buffer", "2-only/stream"} {
			for _, controlled := range []bool{false, true} {
				t.Run(string(scheme)+"/"+mode+"/controlled="+strconv.FormatBool(controlled), func(t *testing.T) {
					var calls atomic.Int32
					server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						body, err := io.ReadAll(r.Body)
						if err != nil || string(body) != "payload" {
							t.Error("Engine upload replay changed body")
						}
						if r.Header.Get("Authorization") == "" {
							w.Header().Set("WWW-Authenticate", `Digest realm="realm", nonce="nonce", qop=auth, algorithm=SHA-256`)
							w.WriteHeader(401)
							return
						}
						if scheme == AuthDigest {
							authTestDigest(t, r.Header.Get("Authorization"), r.Method, r.URL.RequestURI(), "SHA-256", "auth", "user", "secret", "realm", "nonce")
						} else {
							u, p, ok := r.BasicAuth()
							if !ok || u != "user" || p != "secret" {
								t.Error("Engine Basic header invalid")
							}
						}
						_, _ = io.WriteString(w, "authenticated")
					}))
					server.EnableHTTP2 = true
					server.StartTLS()
					defer server.Close()
					engine, err := New(Config{Retries: -1, RatePerSecond: 10000, ConnectionPool: &ConnectionPoolConfig{MaxClients: 1}})
					if err != nil {
						t.Fatal(err)
					}
					defer engine.Close()
					engine.tlsT.(*tlsTransport).noGuard = true
					roots := x509.NewCertPool()
					roots.AddCert(server.Certificate())
					parts := strings.Split(mode, "/")
					req := &Request{URL: server.URL + "/private", Method: "POST", Body: []byte("payload"), HTTPVersion: parts[0], VerifyTLS: true, TLSConfig: &TLSOptions{Roots: roots}, Auth: &AuthOptions{Scheme: scheme, Username: "user", Password: "secret"}}
					if controlled {
						req.TLSConfig.MinVersion = TLSVersion12
						req.TLSConfig.ServerName = "example.com"
					}
					var body []byte
					var headers fhttp.Header
					if parts[1] == "stream" {
						response, sendErr := engine.SendStream(context.Background(), req)
						if sendErr != nil || response == nil {
							t.Fatalf("Engine streaming authentication failed: %v", sendErr)
						}
						body, err = io.ReadAll(response.Body)
						response.Body.Close()
						headers = response.Response.RequestHeaders
					} else {
						response, sendErr := engine.Send(context.Background(), req)
						if sendErr != nil || response == nil {
							t.Fatalf("Engine buffered authentication failed: %v", sendErr)
						}
						body = response.Body
						headers = response.RequestHeaders
					}
					expectedCalls := int32(1)
					if scheme == AuthDigest {
						expectedCalls = 2
					}
					if err != nil || string(body) != "authenticated" || calls.Load() != expectedCalls {
						t.Fatal("Engine authentication exchange result incorrect")
					}
					if headers.Get("Authorization") != "" || req.Header.Get("Authorization") != "" {
						t.Fatal("generated authorization escaped into evidence or caller state")
					}
				})
			}
		}
	}
}

func TestAuthBasicLocalHandshake(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "secret" {
			t.Error("explicit Basic credentials not sent")
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	client := authTestClient(t, server)
	req := &Request{URL: server.URL, Auth: &AuthOptions{Scheme: AuthBasic, Username: "user", Password: "secret"}}
	hreq, _ := fhttp.NewRequest("GET", req.URL, nil)
	response, err := doAuthenticatedRequest(context.Background(), req, hreq, client.Do)
	if err != nil || response == nil || response.StatusCode != 204 || calls.Load() != 1 {
		t.Fatal("Basic handshake failed")
	}
	response.Body.Close()
	if hreq.Header.Get("Authorization") != "" {
		t.Fatal("Basic mutated source header")
	}
}

type authCloseBody struct {
	io.Reader
	once   sync.Once
	closed atomic.Int32
}

func (b *authCloseBody) Close() error { b.once.Do(func() { b.closed.Add(1) }); return nil }
func authTestResponse(request *fhttp.Request, status int, header string) *fhttp.Response {
	response := &fhttp.Response{StatusCode: status, Header: make(fhttp.Header), Body: &authCloseBody{Reader: strings.NewReader("evidence")}, Request: request}
	if header != "" {
		response.Header.Set("WWW-Authenticate", header)
	}
	return response
}

func TestAuthDigestStaleAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		stale   bool
		limit   int
		want    int
		success bool
	}{{"stale-retry", true, 0, 3, true}, {"stale-bounded", true, 0, 3, false}, {"bad-credentials", false, 0, 2, false}, {"explicit-one-round", true, 1, 2, false}} {
		t.Run(tc.name, func(t *testing.T) {
			req := &Request{URL: "https://example.com/private", Auth: &AuthOptions{Scheme: AuthDigest, Username: "user", Password: "secret", MaxChallenges: tc.limit}}
			hreq, _ := fhttp.NewRequest("GET", req.URL, nil)
			calls := 0
			var prior []*authCloseBody
			response, err := doAuthenticatedRequest(context.Background(), req, hreq, func(r *fhttp.Request) (*fhttp.Response, error) {
				calls++
				if calls > 1 {
					p := authTestDigest(t, r.Header.Get("Authorization"), "GET", "/private", "SHA-256", "auth", "user", "secret", "realm", "nonce")
					if p["nc"] != fmt.Sprintf("%08x", calls-1) {
						t.Error("same-nonce stale counter did not advance")
					}
				}
				if tc.success && calls == 3 {
					return authTestResponse(r, 200, ""), nil
				}
				challenge := `Digest realm="realm", nonce="nonce", algorithm=SHA-256, qop=auth`
				if calls > 1 {
					challenge += ", stale=" + strconv.FormatBool(tc.stale)
				}
				result := authTestResponse(r, 401, challenge)
				prior = append(prior, result.Body.(*authCloseBody))
				return result, nil
			})
			if err != nil || response == nil || calls != tc.want {
				t.Fatal("challenge budget/stale handling incorrect")
			}
			for _, body := range prior[:len(prior)-1] {
				if body.closed.Load() != 1 {
					t.Fatal("intermediate challenge body leaked")
				}
			}
			response.Body.Close()
		})
	}
}

func TestAuthReplayAndUnsafeResponses(t *testing.T) {
	challenge := `Digest realm="realm", nonce="nonce", qop=auth, algorithm=SHA-256`
	req := &Request{URL: "https://example.com/private", Auth: &AuthOptions{Scheme: AuthDigest, Username: "user", Password: "secret"}}
	for _, tc := range []struct {
		name    string
		status  int
		header  string
		foreign bool
		want    error
	}{{"foreign-origin", 401, challenge, true, ErrAuthChallenge}, {"auth-int-only", 401, `Digest realm="r", nonce="n", qop=auth-int`, false, ErrAuthUnsupported}, {"duplicate", 401, `Digest realm="r", nonce="n", nonce="m"`, false, ErrAuthChallenge}, {"domain", 401, `Digest realm="r", nonce=n, domain="https://other.example/"`, false, ErrAuthChallenge}, {"proxy-status", 407, challenge, false, nil}, {"proxy-header-only", 401, "", false, nil}} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			hreq, _ := fhttp.NewRequest("GET", req.URL, nil)
			response, err := doAuthenticatedRequest(context.Background(), req, hreq, func(r *fhttp.Request) (*fhttp.Response, error) {
				calls++
				result := authTestResponse(r, tc.status, tc.header)
				if tc.foreign {
					foreign := r.Clone(r.Context())
					foreign.URL, _ = url.Parse("https://other.example/private")
					result.Request = foreign
				}
				result.Header.Set("Proxy-Authenticate", challenge)
				return result, nil
			})
			if !errors.Is(err, tc.want) || calls != 1 || response == nil {
				t.Fatal("unsafe challenge caused credential replay or incorrect result")
			}
			response.Body.Close()
		})
	}
	t.Run("one-shot", func(t *testing.T) {
		original := &authCloseBody{Reader: strings.NewReader("once")}
		hreq, _ := fhttp.NewRequest("POST", req.URL, original)
		calls := 0
		response, err := doAuthenticatedRequest(context.Background(), req, hreq, func(r *fhttp.Request) (*fhttp.Response, error) {
			calls++
			_, _ = io.ReadAll(r.Body)
			return authTestResponse(r, 401, challenge), nil
		})
		if !errors.Is(err, ErrBodyNotReplayable) || calls != 1 || response == nil || original.closed.Load() != 1 {
			t.Fatal("one-shot request replayed or source leaked")
		}
		response.Body.Close()
	})
	t.Run("reopen-failure", func(t *testing.T) {
		hreq, _ := fhttp.NewRequest("POST", req.URL, strings.NewReader("body"))
		marker := errors.New("body factory failed")
		hreq.GetBody = func() (io.ReadCloser, error) { return nil, marker }
		response, err := doAuthenticatedRequest(context.Background(), req, hreq, func(r *fhttp.Request) (*fhttp.Response, error) { return authTestResponse(r, 401, challenge), nil })
		if !errors.Is(err, marker) || response == nil {
			t.Fatal("reopen error lost")
		}
		response.Body.Close()
	})
}

func TestAuthExtensionAndCancellation(t *testing.T) {
	var hooks int
	req := &Request{URL: "https://example.com/private", Auth: &AuthOptions{Authenticator: authExtensionFunc(func(ctx context.Context, c AuthChallenge) (string, error) {
		hooks++
		if c.Attempt != 1 || c.URL != "https://example.com/private" || c.Method != "GET" {
			t.Error("extension challenge metadata incorrect")
		}
		c.Header.Set("X-Secret", "modified")
		return "Bearer opaque", nil
	})}}
	hreq, _ := fhttp.NewRequest("GET", req.URL, nil)
	calls := 0
	var intermediate *fhttp.Response
	response, err := doAuthenticatedRequest(context.Background(), req, hreq, func(r *fhttp.Request) (*fhttp.Response, error) {
		calls++
		if calls == 1 {
			intermediate = authTestResponse(r, 401, `Bearer realm="realm"`)
			return intermediate, nil
		}
		if r.Header.Get("Authorization") != "Bearer opaque" {
			t.Error("extension authorization not applied")
		}
		return authTestResponse(r, 200, ""), nil
	})
	if err != nil || calls != 2 || hooks != 1 || response == nil || intermediate.Header.Get("X-Secret") != "" {
		t.Fatal("extension challenge/header isolation failed")
	}
	response.Body.Close()
	for _, value := range []string{"", "Bearer secret\r\nInjected: yes"} {
		req.Auth.Authenticator = authExtensionFunc(func(context.Context, AuthChallenge) (string, error) { return value, nil })
		response, err := doAuthenticatedRequest(context.Background(), req, hreq, func(r *fhttp.Request) (*fhttp.Response, error) {
			return authTestResponse(r, 401, `Bearer realm="realm"`), nil
		})
		if !errors.Is(err, ErrAuthChallenge) {
			t.Fatal("invalid extension authorization accepted")
		}
		response.Body.Close()
	}
	req.Auth.Authenticator = authExtensionFunc(func(context.Context, AuthChallenge) (string, error) {
		return "", errors.New("credential-material-must-not-escape")
	})
	response, err = doAuthenticatedRequest(context.Background(), req, hreq, func(r *fhttp.Request) (*fhttp.Response, error) {
		return authTestResponse(r, 401, `Bearer realm="realm"`), nil
	})
	if !errors.Is(err, ErrAuthChallenge) || strings.Contains(err.Error(), "credential-material") {
		t.Fatal("extension error disclosed secret")
	}
	response.Body.Close()
	ctx, cancel := context.WithCancelCause(context.Background())
	marker := errors.New("caller stop")
	req.Auth.Authenticator = authExtensionFunc(func(context.Context, AuthChallenge) (string, error) { cancel(marker); return "Bearer opaque", nil })
	response, err = doAuthenticatedRequest(ctx, req, hreq, func(r *fhttp.Request) (*fhttp.Response, error) {
		return authTestResponse(r, 401, `Bearer realm="realm"`), nil
	})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, marker) {
		t.Fatal("extension cancellation cause lost")
	}
	response.Body.Close()
}

func TestAuthCancellationDuringRealReplay(t *testing.T) {
	replayed := make(chan struct{})
	closed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="realm", nonce="nonce", qop=auth, algorithm=SHA-256`)
			w.WriteHeader(401)
			return
		}
		close(replayed)
		<-r.Context().Done()
		close(closed)
	}))
	defer server.Close()
	client := authTestClient(t, server)
	req := &Request{URL: server.URL, Auth: &AuthOptions{Scheme: AuthDigest, Username: "user", Password: "secret"}}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	hreq, _ := fhttp.NewRequestWithContext(ctx, "GET", req.URL, nil)
	done := make(chan error, 1)
	go func() {
		response, err := doAuthenticatedRequest(ctx, req, hreq, client.Do)
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		done <- err
	}()
	select {
	case <-replayed:
	case <-time.After(time.Second):
		t.Fatal("authenticated replay did not start")
	}
	marker := errors.New("caller stop")
	cancel(marker)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("actual replay cancellation lost")
		}
	case <-time.After(time.Second):
		t.Fatal("actual replay ignored cancellation")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("authenticated replay socket remained open")
	}
}
