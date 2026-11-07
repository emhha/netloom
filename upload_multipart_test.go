package netloom

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func multipartTestReplay(t *testing.T, text string, length int64, opens *atomic.Int32) *Upload {
	t.Helper()
	u, err := NewReplayableUpload(length, func(context.Context) (io.ReadCloser, error) {
		if opens != nil {
			opens.Add(1)
		}
		return io.NopCloser(strings.NewReader(text)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func multipartTestRead(t *testing.T, u *Upload) []byte {
	t.Helper()
	body, err := u.openBody(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func multipartTestBoundary(t *testing.T, contentType string) string {
	t.Helper()
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" {
		t.Fatalf("invalid multipart type %q: %v", contentType, err)
	}
	return params["boundary"]
}

func TestMultipartUploadKnownLengthReplayAndParse(t *testing.T) {
	var opens atomic.Int32
	parts := []UploadPart{
		{Name: "field", Body: multipartTestReplay(t, "hello", 5, &opens)},
		{Name: "document", FileName: "a\"b.txt", ContentType: "text/plain; charset=utf-8", Body: multipartTestReplay(t, "file\x00data", 9, &opens)},
	}
	u, contentType, err := NewMultipartUpload(parts)
	if err != nil {
		t.Fatal(err)
	}
	if opens.Load() != 0 {
		t.Fatal("constructor eagerly opened a source")
	}
	if !u.replayable || u.length < 0 {
		t.Fatalf("replayable=%t length=%d", u.replayable, u.length)
	}
	first := multipartTestRead(t, u)
	second := multipartTestRead(t, u)
	if !bytes.Equal(first, second) || int64(len(first)) != u.length || opens.Load() != 4 {
		t.Fatalf("unstable payload/length: bytes=%d declared=%d opens=%d", len(first), u.length, opens.Load())
	}
	parser := multipart.NewReader(bytes.NewReader(first), multipartTestBoundary(t, contentType))
	for i, want := range []string{"hello", "file\x00data"} {
		part, err := parser.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(part)
		if err != nil || string(data) != want {
			t.Fatalf("part %d: %q %v", i, data, err)
		}
		if part.FormName() != parts[i].Name || part.FileName() != parts[i].FileName {
			t.Fatalf("part metadata name=%q file=%q", part.FormName(), part.FileName())
		}
		if i == 1 && part.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Fatalf("content type=%q", part.Header.Get("Content-Type"))
		}
	}
	if _, err := parser.NextPart(); err != io.EOF {
		t.Fatalf("trailing multipart: %v", err)
	}
}

func TestMultipartUploadUnknownAndOneShot(t *testing.T) {
	body, err := NewUpload(io.NopCloser(strings.NewReader("unknown")), -1)
	if err != nil {
		t.Fatal(err)
	}
	u, ct, err := NewMultipartUpload([]UploadPart{{Name: "unknown", Body: body}, {Name: "empty", Body: multipartTestReplay(t, "", 0, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	if u.length != -1 || u.replayable {
		t.Fatalf("length=%d replayable=%t", u.length, u.replayable)
	}
	payload := multipartTestRead(t, u)
	parser := multipart.NewReader(bytes.NewReader(payload), multipartTestBoundary(t, ct))
	part, err := parser.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(part)
	if err != nil || string(data) != "unknown" {
		t.Fatalf("payload=%q err=%v", data, err)
	}
	if _, err := u.openBody(context.Background()); !errors.Is(err, ErrBodyNotReplayable) {
		t.Fatalf("one-shot reopen: %v", err)
	}
	// Unknown size is independent of replayability.
	replay, _, err := NewMultipartUpload([]UploadPart{{Name: "r", Body: multipartTestReplay(t, "again", -1, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	if replay.length != -1 || !replay.replayable || !bytes.Equal(multipartTestRead(t, replay), multipartTestRead(t, replay)) {
		t.Fatal("unknown replayable multipart changed behavior")
	}
}

func TestMultipartUploadOpenCancellationIsIndependent(t *testing.T) {
	var opens atomic.Int32
	u, _, err := NewMultipartUpload([]UploadPart{{Name: "source", Body: multipartTestReplay(t, "payload", 7, &opens)}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, err := u.openBody(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := u.openBody(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	data, err := io.ReadAll(second)
	_ = second.Close()
	if err != nil || int64(len(data)) != u.length || opens.Load() != 1 || ctx.Err() != nil {
		t.Fatalf("closing one open affected another: length=%d opens=%d error=%v parent=%v", len(data), opens.Load(), err, ctx.Err())
	}
}

func TestMultipartUploadSnapshotsAndNoEagerOpen(t *testing.T) {
	var opens atomic.Int32
	source := multipartTestReplay(t, "original", 8, &opens)
	parts := []UploadPart{{Name: "original", FileName: "original.bin", Body: source}}
	u, ct, err := NewMultipartUpload(parts)
	if err != nil {
		t.Fatal(err)
	}
	parts[0] = UploadPart{Name: "changed", FileName: "changed", Body: multipartTestReplay(t, "changed", 7, nil)}
	opened, err := u.openBody(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if opens.Load() != 0 {
		t.Fatal("opening multipart eagerly opened part")
	}
	data, err := io.ReadAll(opened)
	_ = opened.Close()
	if err != nil {
		t.Fatal(err)
	}
	parser := multipart.NewReader(bytes.NewReader(data), multipartTestBoundary(t, ct))
	part, err := parser.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(part)
	if err != nil || part.FormName() != "original" || part.FileName() != "original.bin" || string(payload) != "original" || part.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("metadata/source not snapshotted: %+v %q %v", part.Header, payload, err)
	}
}

type multipartTestStall struct {
	started  chan struct{}
	released chan struct{}
	returned chan struct{}
	start    sync.Once
	close    sync.Once
	end      sync.Once
}

func (s *multipartTestStall) Read([]byte) (int, error) {
	s.start.Do(func() { close(s.started) })
	<-s.released
	s.end.Do(func() { close(s.returned) })
	return 0, io.ErrClosedPipe
}
func (s *multipartTestStall) Close() error { s.close.Do(func() { close(s.released) }); return nil }

func multipartTestWait(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestMultipartUploadCancellationAndCloseStalledSource(t *testing.T) {
	for _, mode := range []string{"context", "close"} {
		t.Run(mode, func(t *testing.T) {
			stalled := &multipartTestStall{started: make(chan struct{}), released: make(chan struct{}), returned: make(chan struct{})}
			part, err := NewUpload(stalled, -1)
			if err != nil {
				t.Fatal(err)
			}
			var later atomic.Int32
			u, _, err := NewMultipartUpload([]UploadPart{{Name: "stalled", Body: part}, {Name: "later", Body: multipartTestReplay(t, "must not open", 13, &later)}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			opened, err := u.openBody(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			done := make(chan error, 1)
			go func() { _, err := io.Copy(io.Discard, opened); done <- err }()
			multipartTestWait(t, stalled.started, "source Read")
			marker := errors.New("multipart caller cancellation")
			if mode == "context" {
				cancel(marker)
			} else {
				_ = opened.Close()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("aborted multipart reported success")
				}
				if mode == "context" && (!errors.Is(err, marker) || !errors.Is(err, context.Canceled)) {
					t.Fatalf("lost caller cause: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("multipart consumer did not unblock")
			}
			multipartTestWait(t, stalled.returned, "stalled source Read return")
			if later.Load() != 0 {
				t.Fatal("opened later source after cancellation")
			}
		})
	}
}

func TestMultipartUploadCloseBeforeReadAndBlockedProducer(t *testing.T) {
	for _, mode := range []string{"before-read", "context-before-read", "blocked-pipe", "context-blocked-pipe"} {
		t.Run(mode, func(t *testing.T) {
			var opens atomic.Int32
			u, _, err := NewMultipartUpload([]UploadPart{{Name: "source", Body: multipartTestReplay(t, strings.Repeat("x", 1<<20), 1<<20, &opens)}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opened, err := u.openBody(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "blocked-pipe" || mode == "context-blocked-pipe" {
				var one [1]byte
				if _, err := opened.Read(one[:]); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(mode, "context-") {
				cancel()
			} else {
				_ = opened.Close()
			}
			done := make(chan struct{})
			go func() { _, _ = io.Copy(io.Discard, opened); _ = opened.Close(); close(done) }()
			multipartTestWait(t, done, "closed multipart reader")
			if opens.Load() != 0 {
				t.Fatal("source opened without consuming its metadata")
			}
		})
	}
}

type multipartTestReadCloser struct {
	io.Reader
	onClose func() error
}

func (r *multipartTestReadCloser) Close() error { return r.onClose() }

func TestMultipartUploadSequentialOwnershipAndCloseErrors(t *testing.T) {
	var firstClosed atomic.Bool
	first, err := NewReplayableUpload(5, func(context.Context) (io.ReadCloser, error) {
		return &multipartTestReadCloser{Reader: strings.NewReader("first"), onClose: func() error { firstClosed.Store(true); return nil }}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewReplayableUpload(6, func(context.Context) (io.ReadCloser, error) {
		if !firstClosed.Load() {
			return nil, errors.New("second part opened before first closed")
		}
		return io.NopCloser(strings.NewReader("second")), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _, err := NewMultipartUpload([]UploadPart{{Name: "first", Body: first}, {Name: "second", Body: second}})
	if err != nil {
		t.Fatal(err)
	}
	_ = multipartTestRead(t, u)
	marker := errors.New("multipart source close failed")
	badClose, err := NewUpload(&multipartTestReadCloser{Reader: strings.NewReader("x"), onClose: func() error { return marker }}, 1)
	if err != nil {
		t.Fatal(err)
	}
	u, _, err = NewMultipartUpload([]UploadPart{{Name: "bad-close", Body: badClose}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := u.openBody(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(body)
	_ = body.Close()
	if !errors.Is(err, marker) {
		t.Fatalf("lost part Close error: %v", err)
	}
}

type multipartTestFailReader struct {
	err    error
	closed atomic.Bool
}

func (r *multipartTestFailReader) Read([]byte) (int, error) { return 0, r.err }
func (r *multipartTestFailReader) Close() error             { r.closed.Store(true); return nil }

func TestMultipartUploadPropagatesSourceErrorsAndLengths(t *testing.T) {
	marker := errors.New("multipart source failed")
	failing := &multipartTestFailReader{err: marker}
	source, _ := NewUpload(failing, -1)
	for _, tc := range []struct {
		name   string
		source *Upload
		want   error
	}{
		{"read", source, marker},
		{"open", func() *Upload {
			u, _ := NewReplayableUpload(-1, func(context.Context) (io.ReadCloser, error) { return nil, marker })
			return u
		}(), marker},
		{"short", multipartTestReplay(t, "x", 2, nil), ErrUploadLength},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, _, err := NewMultipartUpload([]UploadPart{{Name: "fail", Body: tc.source}})
			if err != nil {
				t.Fatal(err)
			}
			opened, err := u.openBody(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, opened)
			_ = opened.Close()
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want %v", err, tc.want)
			}
		})
	}
	if !failing.closed.Load() {
		t.Fatal("failed source not closed")
	}
	// Declared length caps each part without consuming extra source bytes.
	u, ct, err := NewMultipartUpload([]UploadPart{{Name: "truncated", Body: multipartTestReplay(t, "abcdef", 3, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	payload := multipartTestRead(t, u)
	p := multipart.NewReader(bytes.NewReader(payload), multipartTestBoundary(t, ct))
	part, err := p.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(part)
	if err != nil || string(data) != "abc" || int64(len(payload)) != u.length {
		t.Fatalf("length enforcement: %q %v", data, err)
	}
}

func TestMultipartUploadMetadataBounds(t *testing.T) {
	source := multipartTestReplay(t, "", 0, nil)
	for _, tc := range []struct {
		name  string
		parts []UploadPart
	}{
		{"nil-body", []UploadPart{{Name: "x"}}},
		{"empty-name", []UploadPart{{Body: source}}},
		{"name-injection", []UploadPart{{Name: "x\r\nInjected: yes", Body: source}}},
		{"filename-injection", []UploadPart{{Name: "x", FileName: "x\x00.txt", Body: source}}},
		{"control", []UploadPart{{Name: "x\t", Body: source}}},
		{"type-injection", []UploadPart{{Name: "x", ContentType: "text/plain\r\nX: y", Body: source}}},
		{"bad-type", []UploadPart{{Name: "x", ContentType: "bad", Body: source}}},
		{"bad-params", []UploadPart{{Name: "x", ContentType: "text/plain; x=\"", Body: source}}},
		{"long-field", []UploadPart{{Name: strings.Repeat("x", maxMultipartFieldBytes+1), Body: source}}},
		{"too-many", make([]UploadPart, maxMultipartParts+1)},
		{"overflow", []UploadPart{{Name: "x", Body: multipartTestReplay(t, "", math.MaxInt64, nil)}}},
		{"total-metadata", func() []UploadPart {
			parts := make([]UploadPart, 32)
			for i := range parts {
				parts[i] = UploadPart{Name: strings.Repeat("x", 4096), Body: source}
			}
			return parts
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := NewMultipartUpload(tc.parts); err == nil {
				t.Fatal("invalid multipart metadata accepted")
			}
		})
	}
	u, ct, err := NewMultipartUpload(nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := multipartTestRead(t, u)
	if int64(len(payload)) != u.length || !u.replayable {
		t.Fatal("empty multipart length/replayability")
	}
	parser := multipart.NewReader(bytes.NewReader(payload), multipartTestBoundary(t, ct))
	if _, err := parser.NextPart(); err != io.EOF {
		t.Fatalf("empty multipart: %v", err)
	}
}
