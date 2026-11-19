package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"time"
)

// newFixtureProxy opens tunnels to one fixed local test listener.
func newFixtureProxy(target, origin string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != target {
			http.Error(w, "target is outside the demo", http.StatusForbidden)
			return
		}
		remote, err := net.DialTimeout("tcp", origin, time.Second)
		if err != nil {
			http.Error(w, "fixture unavailable", http.StatusBadGateway)
			return
		}
		defer remote.Close()
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := buffered.Flush(); err != nil {
			return
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = io.Copy(remote, buffered)
			_ = remote.Close()
		}()
		_, _ = io.Copy(client, remote)
		_ = client.Close()
		<-done
	}))
}
