package geoip

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oschwald/geoip2-golang"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestInitIsOfflineAndFailedReloadPreservesData(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	s, _ := New(dir, WithHTTPClient(&http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected network") })}))
	defer s.Close()
	if err := s.Init(context.Background()); !errors.Is(err, ErrNoData) {
		t.Fatal(err)
	}
	data := `{"cdn":{"fixture":["192.0.2.0/24"]}}`
	if err := os.WriteFile(filepath.Join(dir, "sources_data.json"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sources_data.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Init(context.Background()); err == nil {
		t.Fatal("invalid reload accepted")
	}
	info, err := s.Lookup(context.Background(), "192.0.2.1")
	if err != nil || !info.IsCDN || info.CDNProvider != "fixture" {
		t.Fatalf("old state lost: %+v %v", info, err)
	}
	if calls != 0 {
		t.Fatal("Init performed network I/O")
	}
}

func TestExplicitUpdateAndFailurePreservePreviousFile(t *testing.T) {
	dir := t.TempDir()
	body := `{"cdn":{"fixture":["192.0.2.0/24"]}}`
	status := http.StatusOK
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://example.test/rules" {
			t.Error(r.URL)
		}
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	s, _ := New(dir, WithHTTPClient(client))
	defer s.Close()
	if err := s.Update(context.Background()); err == nil {
		t.Fatal("implicit update accepted")
	}
	source := DataSource{Name: "sources_data.json", URL: "https://example.test/rules"}
	if err := s.Update(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	status = http.StatusBadGateway
	if err := s.Update(context.Background(), source); err == nil {
		t.Fatal("failed download accepted")
	}
	data, err := os.ReadFile(filepath.Join(dir, source.Name))
	if err != nil || string(data) != body {
		t.Fatalf("previous file lost: %s %v", data, err)
	}
	info, err := s.Lookup(context.Background(), "192.0.2.1")
	if err != nil || !info.IsCDN {
		t.Fatalf("previous readers lost: %+v %v", info, err)
	}
	if err := s.Update(context.Background(), DataSource{Name: "../outside", URL: source.URL}); err == nil {
		t.Fatal("unsafe filename accepted")
	}
}

type generatedBody struct{ remaining int64 }

func (r *generatedBody) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	clear(p[:n])
	r.remaining -= int64(n)
	return n, nil
}
func (r *generatedBody) Close() error { return nil }

func TestDownloadOversizeIsNotSilentlyTruncated(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(dest, []byte("previous"), 0600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: -1, Header: http.Header{}, Body: &generatedBody{remaining: 1025}}, nil
	})}
	if err := downloadFileBounded(context.Background(), client, "https://example.test/data", dest, 1024); err == nil {
		t.Fatal("oversize download accepted")
	}
	data, _ := os.ReadFile(dest)
	if string(data) != "previous" {
		t.Fatal("oversized content replaced old file")
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(dest), ".geoip-download-*"))
	if len(leftovers) > 0 {
		t.Fatal("temporary file leaked", leftovers)
	}
}

type blockingCity struct {
	started, release chan struct{}
	closed           atomic.Bool
	once             sync.Once
}

func (b *blockingCity) City(net.IP) (*geoip2.City, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	if b.closed.Load() {
		return nil, errors.New("closed during lookup")
	}
	return &geoip2.City{}, nil
}
func (b *blockingCity) Close() error { b.closed.Store(true); return nil }

func TestCloseWaitsForLookup(t *testing.T) {
	reader := &blockingCity{started: make(chan struct{}), release: make(chan struct{})}
	s := &Service{cityDB: reader}
	lookup := make(chan error, 1)
	go func() { _, err := s.Lookup(context.Background(), "192.0.2.1"); lookup <- err }()
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("lookup did not start")
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned while lookup uses a reader")
	case <-time.After(20 * time.Millisecond):
	}
	close(reader.release)
	if err := <-lookup; err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish")
	}
	if !reader.closed.Load() {
		t.Fatal("reader was not closed")
	}
	if _, err := s.Lookup(context.Background(), "192.0.2.1"); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	s.Close()
}

func TestCancellationDoesNotReadResources(t *testing.T) {
	s, _ := New(filepath.Join(t.TempDir(), "absent"))
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Init(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.Lookup(ctx, "192.0.2.1"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := s.Update(ctx, DataSource{Name: "sources_data.json", URL: "https://example.test/data"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled operation created resources", err)
	}
}
