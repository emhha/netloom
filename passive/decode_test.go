package passive

import (
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestDecodeBodyPreservesWireBytesAndBoundsAnalysis(t *testing.T) {
	input := bytes.Repeat([]byte("secret=sample;"), 4096)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(input); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	wire := append([]byte(nil), compressed.Bytes()...)
	body, truncated, err := DecodeBody(wire, "gzip", 1024)
	if err != nil || !truncated || !bytes.Equal(body, input[:1024]) || !bytes.Equal(wire, compressed.Bytes()) {
		t.Fatalf("decompression changed wire evidence or exceeded limit: %v", err)
	}
	compressed.Reset()
	brotliWriter := brotli.NewWriter(&compressed)
	if _, err := brotliWriter.Write(input); err != nil {
		t.Fatal(err)
	}
	if err := brotliWriter.Close(); err != nil {
		t.Fatal(err)
	}
	body, truncated, err = DecodeBody(compressed.Bytes(), "br", len(input))
	if err != nil || truncated || !bytes.Equal(body, input) {
		t.Fatalf("brotli not decoded: %v", err)
	}
	if _, _, err := DecodeBody([]byte("invalid"), "gzip", 1024); err == nil {
		t.Fatal("invalid compressed body accepted")
	}
}
