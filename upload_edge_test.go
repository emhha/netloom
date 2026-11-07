package netloom

import (
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
)

type nilUploadBody struct{}

func (*nilUploadBody) Read([]byte) (int, error) { panic("typed nil read") }
func (*nilUploadBody) Close() error             { panic("typed nil close") }
func TestUploadTypedNil(t *testing.T) {
	var body *nilUploadBody
	if _, err := NewUpload(body, 0); err == nil {
		t.Fatal("typed nil constructor accepted")
	}
	for _, factoryErr := range []error{nil, io.ErrUnexpectedEOF} {
		source, _ := NewReplayableUpload(0, func(context.Context) (io.ReadCloser, error) { return body, factoryErr })
		if _, err := source.openBody(context.Background()); err == nil {
			t.Fatal("typed nil factory accepted")
		}
	}
}

func TestUploadOneShotConcurrentClaim(t *testing.T) {
	var closes, opened, rejected atomic.Int32
	u, err := NewUpload(&multipartTransportBody{Reader: strings.NewReader("body"), closes: &closes}, 4)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, err := u.openBody(context.Background())
			if errors.Is(err, ErrBodyNotReplayable) {
				rejected.Add(1)
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			opened.Add(1)
			b, err := io.ReadAll(r)
			if err != nil || string(b) != "body" {
				t.Errorf("body=%q err=%v", b, err)
			}
			_ = r.Close()
		}()
	}
	close(start)
	wg.Wait()
	if opened.Load() != 1 || rejected.Load() != 31 || closes.Load() != 1 {
		t.Fatalf("opened=%d rejected=%d closes=%d", opened.Load(), rejected.Load(), closes.Load())
	}
}

func TestMultipartUploadTransport(t *testing.T) {
	for _, version := range []string{"1.1", "2", "2-only"} {
		for _, stream := range []bool{false, true} {
			for _, unknown := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/stream=%t/unknown=%t", version, stream, unknown), func(t *testing.T) {
					server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if (r.ContentLength < 0) != unknown {
							t.Errorf("ContentLength=%d unknown=%t", r.ContentLength, unknown)
						}
						m, err := r.MultipartReader()
						if err != nil {
							t.Error(err)
							w.WriteHeader(400)
							return
						}
						for _, want := range []struct{ name, file, data string }{{"name", "", "hello"}, {"file", "sample.txt", "multipart-stream"}} {
							part, err := m.NextPart()
							if err != nil {
								t.Error(err)
								return
							}
							b, err := io.ReadAll(part)
							if err != nil || part.FormName() != want.name || part.FileName() != want.file || string(b) != want.data {
								t.Errorf("part=%+v data=%q err=%v", part, b, err)
							}
						}
						if _, err := m.NextPart(); err != io.EOF {
							t.Errorf("end=%v", err)
						}
						_, _ = w.Write([]byte("ok"))
					}))
					server.EnableHTTP2 = true
					server.StartTLS()
					defer server.Close()
					var opens, closes atomic.Int32
					makePart := func(data string, length int64) *Upload {
						u, err := NewReplayableUpload(length, func(context.Context) (io.ReadCloser, error) {
							opens.Add(1)
							return &multipartTransportBody{Reader: strings.NewReader(data), closes: &closes}, nil
						})
						if err != nil {
							t.Fatal(err)
						}
						return u
					}
					length := int64(len("multipart-stream"))
					if unknown {
						length = -1
					}
					upload, contentType, err := NewMultipartUpload([]UploadPart{{Name: "name", Body: makePart("hello", 5)}, {Name: "file", FileName: "sample.txt", ContentType: "text/plain", Body: makePart("multipart-stream", length)}})
					if err != nil {
						t.Fatal(err)
					}
					req := &Request{URL: server.URL, Method: "POST", HTTPVersion: version, Upload: upload, Header: map[string][]string{"Content-Type": {contentType}}, CaptureRequestBody: 11}
					engine := pooledEngine(t, 1)
					var response *Response
					if stream {
						s, err := engine.SendStream(context.Background(), req)
						if err != nil {
							t.Fatal(err)
						}
						_, _ = io.Copy(io.Discard, s.Body)
						_ = s.Body.Close()
						response = s.Response
					} else {
						r, err := engine.Send(context.Background(), req)
						if err != nil {
							t.Fatal(err)
						}
						response = r
					}
					if response.StatusCode != 200 || opens.Load() != 2 || closes.Load() != 2 {
						t.Fatalf("status=%d opens=%d closes=%d", response.StatusCode, opens.Load(), closes.Load())
					}
					if response.UploadEvidence == nil || len(response.UploadEvidence.Prefix) != 11 || !response.UploadEvidence.Truncated {
						t.Fatalf("evidence=%+v", response.UploadEvidence)
					}
				})
			}
		}
	}
}

type multipartTransportBody struct {
	*strings.Reader
	closes *atomic.Int32
}

func (b *multipartTransportBody) Close() error { b.closes.Add(1); return nil }
