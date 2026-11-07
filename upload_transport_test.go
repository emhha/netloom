package netloom

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type trackedUploadReader struct {
	io.Reader
	closed atomic.Int32
}

func (r *trackedUploadReader) Close() error { r.closed.Add(1); return nil }

func TestUploadTransportMatrix(t *testing.T) {
	for _, proto := range []string{"1.1", "2", "2-only"} {
		for _, stream := range []bool{false, true} {
			for _, length := range []int64{-1, 0, 131072} {
				t.Run(fmt.Sprintf("%s/stream%v/len%d", proto, stream, length), func(t *testing.T) {
					size := length
					if size < 0 {
						size = 131072
					}
					data := bytes.Repeat([]byte("x"), int(size))
					var hits atomic.Int32
					server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						hits.Add(1)
						body, err := io.ReadAll(r.Body)
						if err != nil || !bytes.Equal(body, data) {
							t.Errorf("server body len=%d err=%v", len(body), err)
						}
						if r.ContentLength != length {
							t.Errorf("length=%d want=%d", r.ContentLength, length)
						}
						if proto != "1.1" && r.ProtoMajor != 2 {
							t.Errorf("protocol=%s", r.Proto)
						}
						_, _ = w.Write([]byte("ok"))
					}))
					server.EnableHTTP2 = true
					server.StartTLS()
					defer server.Close()
					e := pooledEngine(t, 1)
					reader := &trackedUploadReader{Reader: bytes.NewReader(data)}
					upload, err := NewUpload(reader, length)
					if err != nil {
						t.Fatal(err)
					}
					req := &Request{URL: server.URL, Method: "POST", HTTPVersion: proto, Upload: upload, CaptureRequestBody: 17}
					var response *Response
					if stream {
						s, err := e.SendStream(context.Background(), req)
						if err != nil {
							t.Fatal(err)
						}
						_, _ = io.Copy(io.Discard, s.Body)
						_ = s.Body.Close()
						response = s.Response
					} else {
						response, err = e.Send(context.Background(), req)
						if err != nil {
							t.Fatal(err)
						}
					}
					if hits.Load() != 1 || reader.closed.Load() != 1 {
						t.Fatalf("hits=%d closes=%d", hits.Load(), reader.closed.Load())
					}
					if size > 0 {
						ev := response.UploadEvidence
						if ev == nil || len(ev.Prefix) != 17 || ev.BytesRead != size || !ev.Truncated {
							t.Fatalf("evidence=%+v", ev)
						}
					}
					_, err = e.Send(context.Background(), req)
					if !errors.Is(err, ErrBodyNotReplayable) {
						t.Fatalf("reuse err=%v", err)
					}
				})
			}
		}
	}
}

func TestUploadKnownLengthShortAndPrefix(t *testing.T) {
	for _, tc := range []struct {
		data   string
		length int64
		want   string
		err    bool
	}{{"abc", 5, "abc", true}, {"abcdef", 3, "abc", false}} {
		t.Run(tc.data, func(t *testing.T) {
			var got string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				got = string(b)
				_, _ = w.Write([]byte("ok"))
			}))
			defer server.Close()
			e := pooledEngine(t, 1)
			reader := &trackedUploadReader{Reader: strings.NewReader(tc.data)}
			source, _ := NewUpload(reader, tc.length)
			_, err := e.Send(context.Background(), &Request{URL: server.URL, Method: "POST", Upload: source})
			if tc.err && err == nil {
				t.Fatal("short reader succeeded")
			}
			if !tc.err && (err != nil || got != tc.want) {
				t.Fatalf("got=%q err=%v", got, err)
			}
			if reader.closed.Load() != 1 {
				t.Fatal("reader not closed once")
			}
		})
	}
}

type stalledUploadReader struct {
	started              chan struct{}
	done                 chan struct{}
	startOnce, closeOnce sync.Once
}

func (r *stalledUploadReader) Read([]byte) (int, error) {
	r.startOnce.Do(func() { close(r.started) })
	<-r.done
	return 0, io.ErrClosedPipe
}
func (r *stalledUploadReader) Close() error { r.closeOnce.Do(func() { close(r.done) }); return nil }
func TestUploadCancellationAndSlotRecovery(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				_, _ = w.Write([]byte("ok"))
			}))
			defer server.Close()
			e := pooledEngine(t, 1)
			reader := &stalledUploadReader{started: make(chan struct{}), done: make(chan struct{})}
			source, _ := NewUpload(reader, -1)
			ctx, cancel := context.WithCancelCause(context.Background())
			cause := errors.New("cancel upload")
			result := make(chan error, 1)
			go func() {
				req := &Request{URL: server.URL, Method: "POST", Upload: source}
				if stream {
					s, err := e.SendStream(ctx, req)
					if s != nil {
						_ = s.Body.Close()
					}
					result <- err
				} else {
					_, err := e.Send(ctx, req)
					result <- err
				}
			}()
			select {
			case <-reader.started:
			case <-time.After(time.Second):
				t.Fatal("reader never started")
			}
			cancel(cause)
			select {
			case err := <-result:
				if !errors.Is(err, cause) {
					t.Fatalf("cause lost: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancel blocked")
			}
			select {
			case <-reader.done:
			case <-time.After(time.Second):
				t.Fatal("source not closed")
			}
			if _, err := e.Send(context.Background(), &Request{URL: server.URL}); err != nil {
				t.Fatalf("slot not recovered: %v", err)
			}
		})
	}
}

func TestUploadRedirectReplay(t *testing.T) {
	for _, status := range []int{302, 303, 307, 308} {
		for _, replay := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%v", status, replay), func(t *testing.T) {
				var finalHits, opens atomic.Int32
				var got string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					b, _ := io.ReadAll(r.Body)
					if r.URL.Path == "/" {
						w.Header().Set("Location", "/final")
						w.WriteHeader(status)
						return
					}
					finalHits.Add(1)
					got = r.Method + ":" + string(b)
				}))
				defer server.Close()
				e := pooledEngine(t, 2)
				var source *Upload
				if replay {
					source, _ = NewReplayableUpload(3, func(context.Context) (io.ReadCloser, error) {
						opens.Add(1)
						return io.NopCloser(strings.NewReader("abc")), nil
					})
				} else {
					source, _ = NewUpload(io.NopCloser(strings.NewReader("abc")), 3)
				}
				ex, err := Do(context.Background(), e, &Request{URL: server.URL, Method: "POST", Upload: source}, RedirectPolicy{Follow: true})
				if status >= 307 && !replay {
					if !errors.Is(err, ErrBodyNotReplayable) || ex.Response.StatusCode != status || finalHits.Load() != 0 {
						t.Fatalf("ex=%+v err=%v hits=%d", ex, err, finalHits.Load())
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				want := "GET:"
				if status >= 307 {
					want = "POST:abc"
				}
				if got != want {
					t.Fatalf("got %q want %q", got, want)
				}
				if replay && status >= 307 && opens.Load() != 2 {
					t.Fatalf("opens=%d", opens.Load())
				}
			})
		}
	}
}

func TestUploadPreflightDoesNotConsume(t *testing.T) {
	reader := &trackedUploadReader{Reader: strings.NewReader("abc")}
	source, _ := NewUpload(reader, 3)
	for _, req := range []*Request{{URL: "http://example.test", Upload: source, Body: []byte("x")}, {URL: "http://example.test", Upload: source, CaptureRequestBody: 1<<20 + 1}, {URL: "http://example.test", Upload: &Upload{}}} {
		if _, err := buildWireRequest(context.Background(), req); err == nil {
			t.Fatal("invalid source accepted")
		}
	}
	if reader.closed.Load() != 0 || source.used {
		t.Fatal("invalid preflight consumed source")
	}
}
