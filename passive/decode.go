package passive

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// DecodeBody bounds decompression separately from the bytes forwarded to a client.
func DecodeBody(body []byte, encoding string, limit int) ([]byte, bool, error) {
	if limit <= 0 {
		return nil, len(body) > 0, fmt.Errorf("passive.DecodeBody: invalid limit")
	}
	encodings := strings.Split(strings.ToLower(encoding), ",")
	truncated := false
	for i := len(encodings) - 1; i >= 0; i-- {
		name := strings.TrimSpace(encodings[i])
		if name == "" || name == "identity" {
			continue
		}
		var reader io.Reader
		var closer io.Closer
		var err error
		source := bytes.NewReader(body)
		switch name {
		case "gzip", "x-gzip":
			var gzipReader *gzip.Reader
			gzipReader, err = gzip.NewReader(source)
			reader, closer = gzipReader, gzipReader
		case "deflate":
			var zlibReader io.ReadCloser
			zlibReader, err = zlib.NewReader(source)
			if err != nil {
				zlibReader, err = flate.NewReader(bytes.NewReader(body)), nil
			}
			reader, closer = zlibReader, zlibReader
		case "br":
			reader = brotli.NewReader(source)
		case "zstd":
			decoder, decoderErr := zstd.NewReader(source, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(16<<20))
			err = decoderErr
			if err == nil {
				reader = decoder.IOReadCloser()
				closer = reader.(io.Closer)
			}
		default:
			return nil, true, fmt.Errorf("passive.DecodeBody: unsupported content encoding")
		}
		if err != nil {
			return nil, true, fmt.Errorf("passive.DecodeBody: invalid compressed response")
		}
		decoded, readErr := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
		if closer != nil {
			_ = closer.Close()
		}
		if len(decoded) > limit {
			decoded, truncated = decoded[:limit], true
		}
		body = decoded
		if readErr != nil {
			return body, true, fmt.Errorf("passive.DecodeBody: incomplete compressed response")
		}
		if truncated && i > 0 {
			return nil, true, fmt.Errorf("passive.DecodeBody: nested compressed response exceeds limit")
		}
	}
	if len(body) > limit {
		body, truncated = body[:limit], true
	}
	return body, truncated, nil
}
