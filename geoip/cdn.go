package geoip

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
)

// inputCompiled is the deserialized form of sources_data.json from
// github.com/projectdiscovery/cdncheck.
type inputCompiled struct {
	CDN   map[string][]string `json:"cdn"`
	WAF   map[string][]string `json:"waf"`
	Cloud map[string][]string `json:"cloud"`
}

// cdnRules holds compiled CIDR lists for CDN/WAF/Cloud detection.
type cdnRules struct {
	trie *cidrTrie
}

// asnFallback maps ASN strings (e.g. "AS13335") to CDN provider names.
// Used when no CIDR matches; covers vendors absent from sources_data.json.
var asnFallback = map[string]string{
	"AS13335":  "Cloudflare",
	"AS15169":  "Google",
	"AS16625":  "Akamai",
	"AS20940":  "Akamai",
	"AS63949":  "Akamai",
	"AS23724":  "ChinaNetCenter",
	"AS55967":  "Baidu",
	"AS59019":  "Alibaba",
	"AS132203": "Tencent",
	"AS134543": "Huawei",
}

// loadCDNRules parses sources_data.json and compiles CIDR rules into a trie.
// Non-fatal parse errors (bad CIDRs) are logged as warnings and skipped.
func loadCDNRules(path string) (*cdnRules, error) {
	f, err := os.Open(path) //nolint:gosec // path is validated by caller
	if err != nil {
		return nil, fmt.Errorf("geoip.loadCDNRules open: %w", err)
	}
	defer func() { _ = f.Close() }()

	var input inputCompiled
	if err := json.NewDecoder(f).Decode(&input); err != nil {
		return nil, fmt.Errorf("geoip.loadCDNRules decode: %w", err)
	}

	trie := newCIDRTrie()
	compileCategory(trie, "cdn", input.CDN)
	compileCategory(trie, "waf", input.WAF)
	compileCategory(trie, "cloud", input.Cloud)

	return &cdnRules{trie: trie}, nil
}

// compileCategory inserts all CIDRs for a category into the trie.
// Invalid CIDRs are skipped with a warning.
func compileCategory(trie *cidrTrie, category string, providers map[string][]string) {
	keys := make([]string, 0, len(providers))
	for provider := range providers {
		keys = append(keys, provider)
	}
	sort.Strings(keys)
	for _, provider := range keys {
		cidrs := providers[provider]
		for _, cidrStr := range cidrs {
			cidrStr = strings.TrimSpace(cidrStr)
			// Some entries are bare IPs — normalise to /32 or /128.
			if !strings.Contains(cidrStr, "/") {
				ip := net.ParseIP(cidrStr)
				if ip == nil {
					slog.Warn("geoip: skipping invalid CIDR entry",
						"category", category, "provider", provider, "value", cidrStr)
					continue
				}
				if ip.To4() != nil {
					cidrStr += "/32"
				} else {
					cidrStr += "/128"
				}
			}
			_, network, err := net.ParseCIDR(cidrStr)
			if err != nil {
				slog.Warn("geoip: skipping bad CIDR",
					"category", category, "provider", provider, "cidr", cidrStr, "err", err)
				continue
			}
			trie.Insert(network, category, provider)
		}
	}
}

// detect returns the best CDN/WAF/Cloud match for ip.
// It first checks the CIDR trie (most-specific-wins + WAF>CDN>Cloud tie-break),
// then falls back to the ASN table for CDN identification.
func (r *cdnRules) detect(ip net.IP, asn string) providerMatch {
	if r == nil || r.trie == nil {
		return asnFallbackLookup(asn)
	}
	best := r.trie.Lookup(ip)
	if best.provider != "" {
		return best
	}
	return asnFallbackLookup(asn)
}

func asnFallbackLookup(asn string) providerMatch {
	if asn == "" {
		return providerMatch{}
	}
	// Normalise: ensure "AS" prefix.
	key := strings.ToUpper(strings.TrimSpace(asn))
	if !strings.HasPrefix(key, "AS") {
		key = "AS" + key
	}
	if p, ok := asnFallback[key]; ok {
		return providerMatch{category: "cdn", provider: p, bits: 0}
	}
	return providerMatch{}
}
