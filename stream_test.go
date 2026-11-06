//go:build integration

package netloom

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestSendStreamPreservesBodyAndHoldsConcurrencyUntilClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	payload := bytes.Repeat([]byte("x"), 3<<20)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Cookie") != "browser=original" {
			t.Error("browser cookie changed")
		}
		_, _ = w.Write(payload)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	engine, err := New(Config{Threads: 1, CookieJar: false, RatePerSecond: 1000})
	if err != nil {
		t.Fatal(err)
	}
	engine.tlsT.(*tlsTransport).noGuard = true
	request := &Request{URL: "http://" + listener.Addr().String(), Header: map[string][]string{"Cookie": {"browser=original"}}}
	first, err := engine.SendStream(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Body.Close() }()
	body, err := io.ReadAll(first.Body)
	if err != nil || !bytes.Equal(body, payload) {
		t.Fatalf("stream body truncated: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.SendStream(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("stream slot released before Close: %v", err)
	}
	_ = first.Body.Close()
	second, err := engine.SendStream(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, second.Body)
	_ = second.Body.Close()
	if err != nil || calls.Load() != 2 {
		t.Fatalf("stream did not release slot: calls=%d err=%v", calls.Load(), err)
	}
}
