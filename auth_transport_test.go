package netloom

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const authTransportChallenge = `Digest realm="realm", nonce="nonce", algorithm=SHA-256, qop=auth, charset=UTF-8`

type authTransportReader struct {
	io.Reader
	closed *atomic.Int32
}

func (r *authTransportReader) Close() error { r.closed.Add(1); return nil }

func authTransportRequest(server *httptest.Server, version string, controlled bool) *Request {
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	request := &Request{URL: server.URL + "/private", Method: "POST", HTTPVersion: version, VerifyTLS: true, TLSConfig: &TLSOptions{Roots: roots}, Auth: &AuthOptions{Scheme: AuthDigest, Username: "user", Password: "secret"}}
	if controlled {
		request.TLSConfig.ServerName = "example.com"
		request.TLSConfig.MinVersion = TLSVersion12
	}
	return request
}

func authTransportSend(ctx context.Context, e *Engine, request *Request, stream bool) (*Response, error) {
	if !stream {
		return e.Send(ctx, request)
	}
	response, err := e.SendStream(ctx, request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, err
	}
	if response == nil {
		return nil, errors.New("authentication stream returned no response")
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	snapshot := *response.Response
	snapshot.Body = body
	if readErr != nil {
		return &snapshot, readErr
	}
	return &snapshot, closeErr
}

func TestAuthTransportUploadReplayAndOwnership(t *testing.T) {
	for _, version := range []string{"1.1", "2", "2-only"} {
		for _, stream := range []bool{false, true} {
			for _, controlled := range []bool{false, true} {
				for _, replayable := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/stream%v/controlled%v/replay%v", version, stream, controlled, replayable), func(t *testing.T) {
						var hits, opens, closes atomic.Int32
						const payload = "authentication upload payload"
						server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							if r.URL.Path == "/recover" {
								_, _ = io.WriteString(w, "recovered")
								return
							}
							hits.Add(1)
							body, err := io.ReadAll(r.Body)
							if err != nil || string(body) != payload {
								t.Error("authentication replay did not reproduce body")
							}
							if version != "1.1" && r.ProtoMajor != 2 {
								t.Error("authentication changed required HTTP protocol")
							}
							if r.Header.Get("Authorization") == "" {
								w.Header().Set("WWW-Authenticate", authTransportChallenge)
								w.WriteHeader(401)
								_, _ = io.WriteString(w, "challenge evidence")
								return
							}
							authTestDigest(t, r.Header.Get("Authorization"), r.Method, r.URL.RequestURI(), "SHA-256", "auth", "user", "secret", "realm", "nonce")
							_, _ = io.WriteString(w, "authenticated")
						}))
						server.EnableHTTP2 = true
						server.StartTLS()
						defer server.Close()
						engine := pooledEngine(t, 1)
						defer engine.Close()
						request := authTransportRequest(server, version, controlled)
						var upload *Upload
						var err error
						if replayable {
							upload, err = NewReplayableUpload(int64(len(payload)), func(context.Context) (io.ReadCloser, error) {
								if opens.Load() > closes.Load() {
									return nil, errors.New("previous authentication upload still open")
								}
								opens.Add(1)
								return &authTransportReader{Reader: strings.NewReader(payload), closed: &closes}, nil
							})
						} else {
							upload, err = NewUpload(&authTransportReader{Reader: strings.NewReader(payload), closed: &closes}, int64(len(payload)))
							opens.Store(1)
						}
						if err != nil {
							t.Fatal(err)
						}
						request.Upload = upload
						response, err := authTransportSend(context.Background(), engine, request, stream)
						if replayable {
							if err != nil || response == nil || response.StatusCode != 200 || string(response.Body) != "authenticated" {
								t.Fatalf("replayable authentication failed: %v", err)
							}
							if hits.Load() != 2 || opens.Load() != 2 || closes.Load() != 2 {
								t.Fatal("authentication upload attempts/readers not exactly owned")
							}
						} else {
							if !errors.Is(err, ErrBodyNotReplayable) || hits.Load() != 1 || opens.Load() != 1 || closes.Load() != 1 {
								t.Fatal("one-shot body replayed or ownership lost")
							}
							if stream {
								if response != nil {
									t.Fatal("authentication failure returned live stream")
								}
							} else if response == nil || response.StatusCode != 401 || string(response.Body) != "challenge evidence" {
								t.Fatal("buffered one-shot failure lost final401 evidence")
							}
						}
						if request.Header.Get("Authorization") != "" || response != nil && response.RequestHeaders.Get("Authorization") != "" {
							t.Fatal("authentication material persisted in caller/evidence headers")
						}
						if count, _ := poolSize(engine.tlsT.(*tlsTransport).pool); count != 0 {
							t.Fatal("authentication request retained one-off client lease")
						}
						recovered := *request
						recovered.URL = server.URL + "/recover"
						recovered.Method = "GET"
						recovered.Upload = nil
						recovered.Auth = nil
						followup, err := engine.Send(context.Background(), &recovered)
						if err != nil || followup == nil || string(followup.Body) != "recovered" {
							t.Fatal("authentication request did not release one-slot capacity")
						}
					})
				}
			}
		}
	}
}

func TestAuthTransportProtocolFailurePreservesEvidence(t *testing.T) {
	for _, version := range []string{"1.1", "2", "2-only"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream%v", version, stream), func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Header.Get("Authorization") != "" {
						t.Error("unsupported challenge caused credentials to be sent")
					}
					w.Header().Set("WWW-Authenticate", `Digest realm="realm", nonce="nonce", qop=auth-int`)
					w.WriteHeader(401)
					_, _ = io.WriteString(w, "unsupported evidence")
				}))
				server.EnableHTTP2 = true
				server.StartTLS()
				defer server.Close()
				engine := pooledEngine(t, 1)
				defer engine.Close()
				request := authTransportRequest(server, version, true)
				response, err := authTransportSend(context.Background(), engine, request, stream)
				if !errors.Is(err, ErrAuthUnsupported) || calls.Load() != 1 {
					t.Fatal("unsupported authentication mechanism retried or error lost")
				}
				if stream {
					if response != nil {
						t.Fatal("unsupported auth returned active stream")
					}
				} else if response == nil || response.StatusCode != 401 || string(response.Body) != "unsupported evidence" {
					t.Fatal("unsupported auth lost buffered evidence")
				}
				if count, _ := poolSize(engine.tlsT.(*tlsTransport).pool); count != 0 {
					t.Fatal("failed authentication retained lease")
				}
			})
		}
	}
}

func TestAuthTransportRedirectOriginScope(t *testing.T) {
	for _, scheme := range []AuthScheme{AuthBasic, AuthDigest} {
		for _, crossOrigin := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cross%v", scheme, crossOrigin), func(t *testing.T) {
				var sourceHits, targetHits atomic.Int32
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					targetHits.Add(1)
					if r.Header.Get("Authorization") != "" {
						t.Error("cross-origin redirect received authentication")
					}
					_, _ = io.WriteString(w, "completed")
				}))
				defer target.Close()
				source := httptest.NewUnstartedServer(nil)
				source.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					sourceHits.Add(1)
					if r.Header.Get("Authorization") == "" {
						if scheme == AuthBasic {
							t.Error("same-origin Basic credentials missing")
						}
						w.Header().Set("WWW-Authenticate", authTransportChallenge)
						w.WriteHeader(401)
						return
					}
					if scheme == AuthDigest {
						authTestDigest(t, r.Header.Get("Authorization"), r.Method, r.URL.RequestURI(), "SHA-256", "auth", "user", "secret", "realm", "nonce")
					} else {
						u, p, ok := r.BasicAuth()
						if !ok || u != "user" || p != "secret" {
							t.Error("redirect Basic credentials invalid")
						}
					}
					if r.URL.Path == "/start" {
						location := source.URL + "/final"
						if crossOrigin {
							location = target.URL + "/final"
						}
						w.Header().Set("Location", location)
						w.WriteHeader(302)
						return
					}
					_, _ = io.WriteString(w, "completed")
				})
				source.Start()
				defer source.Close()
				engine := pooledEngine(t, 1)
				defer engine.Close()
				options := &AuthOptions{Scheme: scheme, Username: "user", Password: "secret"}
				request := &Request{URL: source.URL + "/start", Auth: options}
				exchange, err := Do(context.Background(), engine, request, RedirectPolicy{Follow: true, MaxHops: 2})
				if err != nil || exchange == nil || exchange.Response == nil || string(exchange.Response.Body) != "completed" {
					t.Fatalf("authentication redirect failed: %v", err)
				}
				if (exchange.Request.Auth == nil) != crossOrigin || request.Auth != options || request.Auth.Username != "user" {
					t.Fatal("redirect authentication origin scope or caller snapshot changed")
				}
				expectedSource := int32(2)
				if scheme == AuthDigest {
					expectedSource = 4
				}
				if crossOrigin {
					expectedSource /= 2
				}
				if sourceHits.Load() != expectedSource || crossOrigin && targetHits.Load() != 1 || !crossOrigin && targetHits.Load() != 0 {
					t.Fatal("unexpected authentication redirect request count")
				}
			})
		}
	}
}

type authTransportConnectionKey struct{}

func TestAuthTransportSecondRoundPhaseAndCancellation(t *testing.T) {
	for _, version := range []string{"1.1", "2", "2-only"} {
		for _, stream := range []bool{false, true} {
			for _, controlled := range []bool{false, true} {
				for _, cancelCaller := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/stream%v/controlled%v/cancel%v", version, stream, controlled, cancelCaller), func(t *testing.T) {
						started := make(chan net.Conn, 1)
						closed := make(chan net.Conn, 8)
						handlerCanceled := make(chan struct{}, 1)
						server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							if r.URL.Path == "/recover" {
								_, _ = io.WriteString(w, "recovered")
								return
							}
							_, _ = io.Copy(io.Discard, r.Body)
							if r.Header.Get("Authorization") == "" {
								w.Header().Set("WWW-Authenticate", authTransportChallenge)
								w.WriteHeader(401)
								_, _ = io.WriteString(w, "challenge")
								return
							}
							started <- r.Context().Value(authTransportConnectionKey{}).(net.Conn)
							<-r.Context().Done()
							handlerCanceled <- struct{}{}
						}))
						server.EnableHTTP2 = true
						server.Config.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
							return context.WithValue(ctx, authTransportConnectionKey{}, conn)
						}
						server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
							if state == http.StateClosed {
								closed <- conn
							}
						}
						server.StartTLS()
						defer server.Close()
						engine := pooledEngine(t, 1)
						defer engine.Close()
						request := authTransportRequest(server, version, controlled)
						request.Body = []byte("payload")
						request.PhaseTimeouts = &PhaseTimeouts{ResponseHeader: 80 * time.Millisecond}
						if cancelCaller {
							request.PhaseTimeouts.ResponseHeader = time.Second
						}
						ctx, cancel := context.WithCancelCause(context.Background())
						defer cancel(nil)
						done := make(chan error, 1)
						go func() { _, err := authTransportSend(ctx, engine, request, stream); done <- err }()
						var conn net.Conn
						select {
						case conn = <-started:
						case <-time.After(2 * time.Second):
							t.Fatal("authenticated second round did not start")
						}
						marker := errors.New("authenticated second round caller stop")
						if cancelCaller {
							cancel(marker)
						}
						select {
						case err := <-done:
							var phaseError *PhaseError
							if !errors.As(err, &phaseError) || phaseError.Phase != PhaseResponseHeader {
								t.Fatalf("second challenge round lost header phase: %v", err)
							}
							if cancelCaller {
								if !errors.Is(err, context.Canceled) || !errors.Is(err, marker) {
									t.Fatal("authentication cancellation cause lost")
								}
							} else if !errors.Is(err, context.DeadlineExceeded) {
								t.Fatal("authentication response header deadline lost")
							}
						case <-time.After(2 * time.Second):
							t.Fatal("authenticated second round did not stop")
						}
						select {
						case <-handlerCanceled:
						case <-time.After(2 * time.Second):
							t.Fatal("authenticated request context remained live")
						}
						deadline := time.NewTimer(2 * time.Second)
						defer deadline.Stop()
						socketClosed := false
						for !socketClosed {
							select {
							case actual := <-closed:
								socketClosed = actual == conn
							case <-deadline.C:
								t.Fatal("authenticated request socket remained open")
							}
						}
						if count, _ := poolSize(engine.tlsT.(*tlsTransport).pool); count != 0 {
							t.Fatal("authentication phase failure retained client lease")
						}
						recoverRequest := *request
						recoverRequest.URL = server.URL + "/recover"
						recoverRequest.Auth = nil
						recoverRequest.Body = nil
						recoverRequest.Method = "GET"
						recoverRequest.PhaseTimeouts = &PhaseTimeouts{ResponseHeader: time.Second}
						recovered, err := engine.Send(context.Background(), &recoverRequest)
						if err != nil || recovered == nil || string(recovered.Body) != "recovered" {
							t.Fatal("authentication phase failure did not restore single-slot capacity")
						}
					})
				}
			}
		}
	}
}
