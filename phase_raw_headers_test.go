package netloom

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestPhaseRawFinalHeadersAfterInformational(t *testing.T) {
	for _, stall := range []bool{false, true} {
		name := "final-response"
		if stall {
			name = "partial-final-header"
		}
		t.Run(name, func(t *testing.T) {
			addr := phaseRawServer(t, func(conn net.Conn) {
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				_, _ = io.WriteString(conn, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n")
				if stall {
					_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nX-Partial: ")
					_, _ = io.Copy(io.Discard, reader)
				} else {
					_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				}
			})
			transport := newRawTransport(1024)
			transport.noGuard = true
			start := time.Now()
			response, err := transport.RoundTrip(context.Background(), &Request{URL: "http://" + addr, Raw: []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"), Timeout: 2 * time.Second, PhaseTimeouts: &PhaseTimeouts{ResponseHeader: 80 * time.Millisecond}})
			if stall {
				assertPhaseDeadline(t, err, PhaseResponseHeader)
				if time.Since(start) > time.Second {
					t.Fatal("interim header stopped phase budget")
				}
			} else if err != nil || response == nil || response.StatusCode != 200 || string(response.Body) != "ok" {
				t.Fatalf("did not parse final response: %+v %v", response, err)
			}
		})
	}
}
