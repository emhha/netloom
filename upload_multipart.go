package netloom

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
	"sync"
	"unicode"
)

// UploadPart describes an in-memory multipart header and a streaming source.
// FileName is wire metadata only: no filename or path is ever opened. Sources
// retain their Upload ownership and replay rules; their Close must unblock Read.
type UploadPart struct {
	Name        string
	FileName    string
	ContentType string
	Body        *Upload
}

const (
	maxMultipartParts      = 128
	maxMultipartFieldBytes = 4096
	maxMultipartMetadata   = 64 << 10
)

type multipartUploadPart struct {
	prefix []byte
	body   *Upload
}

// NewMultipartUpload snapshots bounded metadata without opening or reading a
// source. It returns a multipart/form-data content type with a generated boundary
// that remains identical across reopens. Length is exact if every part has a
// known length; otherwise it is unknown. The result is replayable only when every
// source is replayable. Empty multipart bodies are supported.
func NewMultipartUpload(parts []UploadPart) (*Upload, string, error) {
	if len(parts) > maxMultipartParts {
		return nil, "", fmt.Errorf("netloom: multipart accepts at most %d parts", maxMultipartParts)
	}
	var metadata bytes.Buffer
	writer := multipart.NewWriter(&metadata)
	contentType := writer.FormDataContentType()
	snapshot := make([]multipartUploadPart, 0, len(parts))
	var length int64
	known := true
	for _, part := range parts {
		if part.Body != nil && part.Body.length < 0 {
			known = false
		}
	}
	replayable := true
	metadataBytes := 0
	for i, part := range parts {
		if part.Name == "" || part.Body == nil || part.Body.open == nil || part.Body.length < -1 {
			return nil, "", fmt.Errorf("netloom: multipart part %d needs a name and body", i)
		}
		for _, field := range []string{part.Name, part.FileName, part.ContentType} {
			if len(field) > maxMultipartFieldBytes || strings.IndexFunc(field, unicode.IsControl) >= 0 {
				return nil, "", fmt.Errorf("netloom: multipart part %d has invalid or oversized metadata", i)
			}
		}
		header := make(textproto.MIMEHeader)
		params := map[string]string{"name": part.Name}
		if part.FileName != "" {
			params["filename"] = part.FileName
		}
		header.Set("Content-Disposition", mime.FormatMediaType("form-data", params))
		if part.ContentType != "" {
			mediaType, params, err := mime.ParseMediaType(part.ContentType)
			if err != nil || !strings.Contains(mediaType, "/") {
				return nil, "", fmt.Errorf("netloom: multipart part %d has invalid content type", i)
			}
			value := mime.FormatMediaType(mediaType, params)
			if value == "" {
				return nil, "", fmt.Errorf("netloom: multipart part %d has invalid content type", i)
			}
			header.Set("Content-Type", value)
		} else if part.FileName != "" {
			header.Set("Content-Type", "application/octet-stream")
		}
		if _, err := writer.CreatePart(header); err != nil {
			return nil, "", fmt.Errorf("netloom: multipart headers: %w", err)
		}
		prefix := append([]byte(nil), metadata.Bytes()...)
		metadata.Reset()
		metadataBytes += len(prefix)
		if metadataBytes > maxMultipartMetadata {
			return nil, "", fmt.Errorf("netloom: multipart metadata exceeds %d bytes", maxMultipartMetadata)
		}
		if known {
			if length > math.MaxInt64-int64(len(prefix)) {
				return nil, "", fmt.Errorf("netloom: multipart length overflows int64")
			}
			length += int64(len(prefix))
			if length > math.MaxInt64-part.Body.length {
				return nil, "", fmt.Errorf("netloom: multipart length overflows int64")
			}
			length += part.Body.length
		}
		replayable = replayable && part.Body.replayable
		snapshot = append(snapshot, multipartUploadPart{prefix: prefix, body: part.Body})
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	tail := append([]byte(nil), metadata.Bytes()...)
	if metadataBytes+len(tail) > maxMultipartMetadata {
		return nil, "", fmt.Errorf("netloom: multipart metadata exceeds %d bytes", maxMultipartMetadata)
	}
	if known {
		if length > math.MaxInt64-int64(len(tail)) {
			return nil, "", fmt.Errorf("netloom: multipart length overflows int64")
		}
		length += int64(len(tail))
	} else {
		length = -1
	}
	opener := func(ctx context.Context) (io.ReadCloser, error) {
		return newMultipartUploadBody(ctx, snapshot, tail), nil
	}
	return &Upload{length: length, replayable: replayable, open: opener}, contentType, nil
}

// multipartUploadBody starts at first Read, not at construction/open. Its own
// child context owns both the pipe producer and any currently opened source.
// Closing either before Read or while a source stalls requires no draining.
type multipartUploadBody struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	stop   func() bool
	reader *io.PipeReader
	writer *io.PipeWriter
	parts  []multipartUploadPart
	tail   []byte
	start  sync.Once
	mu     sync.Mutex
	closed bool
	active io.ReadCloser
}

func newMultipartUploadBody(parent context.Context, parts []multipartUploadPart, tail []byte) *multipartUploadBody {
	ctx, cancel := context.WithCancelCause(parent)
	reader, writer := io.Pipe()
	body := &multipartUploadBody{ctx: ctx, cancel: cancel, reader: reader, writer: writer, parts: parts, tail: tail}
	body.stop = context.AfterFunc(ctx, func() { body.shutdown(requestContextError(ctx)) })
	return body
}

func (b *multipartUploadBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b.start.Do(func() {
		b.mu.Lock()
		closed := b.closed
		b.mu.Unlock()
		if !closed {
			go b.produce()
		}
	})
	return b.reader.Read(p)
}

func (b *multipartUploadBody) shutdown(err error) {
	if err == nil {
		err = io.ErrClosedPipe
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	active := b.active
	b.mu.Unlock()
	// Release pipe writes first, then unblock a stalled source Read. Do not hold
	// the active-source mutex while calling caller code.
	_ = b.reader.CloseWithError(err)
	_ = b.writer.CloseWithError(err)
	if active != nil {
		_ = active.Close()
	}
}

func (b *multipartUploadBody) Close() error {
	b.stop()
	b.cancel(context.Canceled)
	b.shutdown(io.ErrClosedPipe)
	return nil
}

func (b *multipartUploadBody) produce() {
	err := b.writeParts()
	if cause := requestContextError(b.ctx); cause != nil {
		err = cause
	}
	_ = b.writer.CloseWithError(err)
	// A completed producer no longer needs a parent cancellation subscription.
	// Stopping it before cancel avoids replacing the pipe's normal EOF/error.
	b.stop()
	b.cancel(context.Canceled)
}

func (b *multipartUploadBody) writeParts() error {
	for _, part := range b.parts {
		if _, err := b.writer.Write(part.prefix); err != nil {
			return err
		}
		if err := requestContextError(b.ctx); err != nil {
			return err
		}
		source, err := part.body.openBody(b.ctx)
		if err != nil {
			return err
		}
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			_ = source.Close()
			return io.ErrClosedPipe
		}
		b.active = source
		b.mu.Unlock()
		_, copyErr := io.Copy(b.writer, source)
		closeErr := source.Close()
		b.mu.Lock()
		b.active = nil
		b.mu.Unlock()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	_, err := b.writer.Write(b.tail)
	return err
}
