package geoip

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const maxDownloadSize = 200 << 20
const downloadTimeout = 60 * time.Second

// DataSource explicitly selects a resource URL and its canonical local name.
// No URLs or third-party mirror credentials are built into this package.
type DataSource struct{ Name, URL string }

// Update downloads only explicitly selected resources, then atomically reloads
// readers. Each file replacement is atomic; this is not a multi-file transaction.
// Calling Update without sources is an error, never an implicit download.
func (s *Service) Update(ctx context.Context, sources ...DataSource) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	if len(sources) == 0 {
		return fmt.Errorf("geoip.Update: explicit data sources are required")
	}
	seen := map[string]bool{}
	for _, source := range sources {
		switch source.Name {
		case "GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb", "GeoLite2-Country.mmdb", "sources_data.json":
		default:
			return fmt.Errorf("geoip.Update: invalid resource name %q", source.Name)
		}
		if seen[source.Name] {
			return fmt.Errorf("geoip.Update: duplicate resource %q", source.Name)
		}
		seen[source.Name] = true
		u, err := url.Parse(source.URL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("geoip.Update: invalid resource URL %q", source.URL)
		}
	}
	if err := os.MkdirAll(s.dataDir, 0700); err != nil {
		return err
	}
	client := s.client
	if client == nil {
		client = http.DefaultClient
	}
	for _, source := range sources {
		if err := downloadFile(ctx, client, source.URL, filepath.Join(s.dataDir, source.Name)); err != nil {
			return err
		}
	}
	return s.load(ctx)
}

func downloadFile(ctx context.Context, client *http.Client, sourceURL, destination string) error {
	return downloadFileBounded(ctx, client, sourceURL, destination, maxDownloadSize)
}

func downloadFileBounded(ctx context.Context, client *http.Client, sourceURL, destination string, limit int64) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("geoip download: HTTP %d", response.StatusCode)
	}
	if response.ContentLength > limit {
		return fmt.Errorf("geoip download exceeds %d bytes", limit)
	}
	file, err := os.CreateTemp(filepath.Dir(destination), ".geoip-download-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	count, copyErr := io.Copy(file, io.LimitReader(response.Body, limit+1))
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if count > limit {
		return fmt.Errorf("geoip download exceeds %d bytes", limit)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.Rename(file.Name(), destination)
}
