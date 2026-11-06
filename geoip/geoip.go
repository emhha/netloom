// Package geoip provides offline ASN, geolocation and CDN/WAF/cloud lookups.
// Resource directories and any downloads are explicitly selected by the caller.
package geoip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

// IPInfo describes IP ownership, geolocation and network classification.
type IPInfo struct {
	IP            string `json:"ip"`
	ASN           string `json:"asn"`
	Org           string `json:"org"`
	Country       string `json:"country"`
	CountryCode   string `json:"country_code"`
	City          string `json:"city"`
	IsCDN         bool   `json:"is_cdn"`
	CDNProvider   string `json:"cdn_provider"`
	IsWAF         bool   `json:"is_waf"`
	WAFProvider   string `json:"waf_provider"`
	IsCloud       bool   `json:"is_cloud"`
	CloudProvider string `json:"cloud_provider"`
}

var (
	ErrClosed = errors.New("geoip: service closed")
	ErrNoData = errors.New("geoip: no local data files available")
)

type cityReader interface {
	City(net.IP) (*geoip2.City, error)
	Close() error
}
type asnReader interface {
	ASN(net.IP) (*geoip2.ASN, error)
	Close() error
}
type countryReader interface {
	Country(net.IP) (*geoip2.Country, error)
	Close() error
}

// Service is safe for concurrent lookups, reloads and Close. Init only reads
// local files. Update is the sole explicit network/data-writing operation.
type Service struct {
	dataDir   string
	client    *http.Client
	opMu      sync.Mutex
	mu        sync.RWMutex
	closed    bool
	cityDB    cityReader
	asnDB     asnReader
	countryDB countryReader
	cdnRules  *cdnRules
}

type Option func(*Service)

// WithHTTPClient supplies proxy, trust and transport policy for explicit updates.
func WithHTTPClient(client *http.Client) Option {
	return func(s *Service) {
		if client != nil {
			s.client = client
		}
	}
}

// New selects an explicit resource directory, without accessing disk/network.
func New(dataDir string, options ...Option) (*Service, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("geoip.New: dataDir must not be empty")
	}
	s := &Service{dataDir: filepath.Clean(dataDir), client: http.DefaultClient}
	for _, option := range options {
		option(s)
	}
	return s, nil
}

// Init opens the available City/ASN/Country MMDBs and/or sources_data.json.
// Missing individual files are optional; corrupt files fail the reload and keep
// the previous readers. An empty resource directory returns ErrNoData.
func (s *Service) Init(ctx context.Context) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.load(ctx)
}

// load is serialized by opMu. Readers remain live until all lookups finish.
func (s *Service) load(ctx context.Context) error {
	if s.dataDir == "" {
		return fmt.Errorf("geoip: explicit data directory is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	readers := map[string]*geoip2.Reader{}
	keep := false
	defer func() {
		if !keep {
			for _, reader := range readers {
				_ = reader.Close()
			}
		}
	}()
	for _, name := range []string{"GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb", "GeoLite2-Country.mmdb"} {
		path := filepath.Join(s.dataDir, name)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("geoip: stat %s: %w", name, err)
		}
		reader, err := geoip2.Open(path)
		if err != nil {
			return fmt.Errorf("geoip: open %s: %w", name, err)
		}
		readers[name] = reader
	}
	var rules *cdnRules
	cdnPath := filepath.Join(s.dataDir, "sources_data.json")
	if _, err := os.Stat(cdnPath); err == nil {
		rules, err = loadCDNRules(cdnPath)
		if err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(readers) == 0 && rules == nil {
		return ErrNoData
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeReaders()
	s.cityDB = nil
	s.asnDB = nil
	s.countryDB = nil
	if reader := readers["GeoLite2-City.mmdb"]; reader != nil {
		s.cityDB = reader
	}
	if reader := readers["GeoLite2-ASN.mmdb"]; reader != nil {
		s.asnDB = reader
	}
	if reader := readers["GeoLite2-Country.mmdb"]; reader != nil {
		s.countryDB = reader
	}
	s.cdnRules = rules
	keep = true
	return nil
}

func (s *Service) closeReaders() {
	if s.cityDB != nil {
		_ = s.cityDB.Close()
	}
	if s.asnDB != nil {
		_ = s.asnDB.Close()
	}
	if s.countryDB != nil {
		_ = s.countryDB.Close()
	}
}

// Close waits for in-flight lookups/reloads, then releases readers. Idempotent.
func (s *Service) Close() {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.closeReaders()
	s.cityDB = nil
	s.asnDB = nil
	s.countryDB = nil
	s.cdnRules = nil
}

// Lookup uses available local data. Before Init it retains the original
// best-effort behavior, returning an IP-only result if no data has been loaded.
func (s *Service) Lookup(ctx context.Context, ipStr string) (*IPInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("geoip.Service.Lookup: invalid IP %q", ipStr)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrClosed
	}
	info := &IPInfo{IP: ipStr}
	if s.asnDB != nil {
		if record, err := s.asnDB.ASN(ip); err == nil && record.AutonomousSystemNumber != 0 {
			info.ASN = fmt.Sprintf("AS%d", record.AutonomousSystemNumber)
			info.Org = record.AutonomousSystemOrganization
		}
	}
	if s.cityDB != nil {
		if record, err := s.cityDB.City(ip); err == nil {
			info.Country = record.Country.Names["en"]
			info.CountryCode = record.Country.IsoCode
			info.City = record.City.Names["en"]
		}
	}
	if info.CountryCode == "" && s.countryDB != nil {
		if record, err := s.countryDB.Country(ip); err == nil {
			info.Country = record.Country.Names["en"]
			info.CountryCode = record.Country.IsoCode
		}
	}
	match := s.cdnRules.detect(ip, info.ASN)
	switch match.category {
	case "cdn":
		info.IsCDN = true
		info.CDNProvider = match.provider
	case "waf":
		info.IsWAF = true
		info.WAFProvider = match.provider
	case "cloud":
		info.IsCloud = true
		info.CloudProvider = match.provider
	}
	return info, ctx.Err()
}

// LookupBatch preserves input order and returns the first error, with nil slots
// for failed lookups. Cancellation stops remaining work.
func (s *Service) LookupBatch(ctx context.Context, ips []string) ([]*IPInfo, error) {
	results := make([]*IPInfo, len(ips))
	var firstErr error
	for i, ip := range ips {
		if err := ctx.Err(); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			break
		}
		info, err := s.Lookup(ctx, ip)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("geoip.Service.LookupBatch[%d] %s: %w", i, ip, err)
			}
			continue
		}
		results[i] = info
	}
	return results, firstErr
}
