package geoip

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestTrieDefaultRoutes(t *testing.T) {
	tr := newCIDRTrie()
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		_, network, _ := net.ParseCIDR(cidr)
		tr.Insert(network, "cloud", "default")
	}
	for _, ip := range []string{"192.0.2.1", "2001:db8::1"} {
		if got := tr.Lookup(net.ParseIP(ip)); got.provider != "default" {
			t.Fatal(ip, got)
		}
	}
}

func TestProviderTieIsDeterministic(t *testing.T) {
	for range 30 {
		tr := newCIDRTrie()
		compileCategory(tr, "cdn", map[string][]string{"z": {"192.0.2.1"}, "a": {"192.0.2.1"}})
		if got := tr.Lookup(net.ParseIP("192.0.2.1")); got.provider != "a" {
			t.Fatal(got)
		}
	}
}

// ---- trie unit tests -------------------------------------------------------

func TestTrieInsertLookup_basic(t *testing.T) {
	tr := newCIDRTrie()
	_, n1, _ := net.ParseCIDR("1.1.0.0/16")
	_, n2, _ := net.ParseCIDR("1.1.1.0/24")
	tr.Insert(n1, "cloud", "CompanyA")
	tr.Insert(n2, "cdn", "CompanyB")

	// 1.1.1.1 must match /24 (more specific) even though /16 also matches.
	m := tr.Lookup(net.ParseIP("1.1.1.1"))
	if m.provider != "CompanyB" {
		t.Errorf("expected CompanyB (/24), got %q", m.provider)
	}
	if m.bits != 24 {
		t.Errorf("expected bits=24, got %d", m.bits)
	}

	// 1.1.2.1 only matches /16.
	m2 := tr.Lookup(net.ParseIP("1.1.2.1"))
	if m2.provider != "CompanyA" {
		t.Errorf("expected CompanyA (/16), got %q", m2.provider)
	}
}

func TestTrieLookup_noMatch(t *testing.T) {
	tr := newCIDRTrie()
	_, n, _ := net.ParseCIDR("10.0.0.0/8")
	tr.Insert(n, "cdn", "Internal")

	m := tr.Lookup(net.ParseIP("192.168.1.1"))
	if m.provider != "" {
		t.Errorf("expected no match, got %q", m.provider)
	}
}

func TestTrieTieBreak_categoryPriority(t *testing.T) {
	tr := newCIDRTrie()
	// Same prefix length for two different categories — WAF must win.
	_, nCDN, _ := net.ParseCIDR("2.2.2.0/24")
	_, nWAF, _ := net.ParseCIDR("2.2.2.0/24")
	tr.Insert(nCDN, "cdn", "CDNProvider")
	tr.Insert(nWAF, "waf", "WAFProvider")

	m := tr.Lookup(net.ParseIP("2.2.2.5"))
	if m.category != "waf" {
		t.Errorf("expected waf to win tie-break, got category=%q provider=%q", m.category, m.provider)
	}
}

func TestTrieIPv6(t *testing.T) {
	tr := newCIDRTrie()
	_, n, _ := net.ParseCIDR("2001:db8::/32")
	tr.Insert(n, "cloud", "IPv6Cloud")

	m := tr.Lookup(net.ParseIP("2001:db8::1"))
	if m.provider != "IPv6Cloud" {
		t.Errorf("expected IPv6Cloud, got %q", m.provider)
	}

	m2 := tr.Lookup(net.ParseIP("2001:db9::1"))
	if m2.provider != "" {
		t.Errorf("expected no match, got %q", m2.provider)
	}
}

// ---- CDN rules unit tests --------------------------------------------------

func TestLoadCDNRules_invalidCIDRSkipped(t *testing.T) {
	data := inputCompiled{
		CDN: map[string][]string{
			"Cloudflare": {"1.1.1.0/24", "not-a-cidr"},
		},
	}
	raw, _ := json.Marshal(data)
	dir := t.TempDir()
	path := filepath.Join(dir, "sources_data.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	rules, err := loadCDNRules(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Valid CIDR must still resolve.
	m := rules.detect(net.ParseIP("1.1.1.1"), "")
	if m.provider != "Cloudflare" {
		t.Errorf("expected Cloudflare, got %q", m.provider)
	}
}

func TestDetect_WAFBeforeCDN(t *testing.T) {
	data := inputCompiled{
		CDN: map[string][]string{"CDNProv": {"3.3.3.0/24"}},
		WAF: map[string][]string{"WAFProv": {"3.3.3.0/24"}},
	}
	raw, _ := json.Marshal(data)
	dir := t.TempDir()
	path := filepath.Join(dir, "sources_data.json")
	_ = os.WriteFile(path, raw, 0o600)

	rules, _ := loadCDNRules(path)
	m := rules.detect(net.ParseIP("3.3.3.1"), "")
	if m.category != "waf" {
		t.Errorf("WAF should beat CDN at same prefix; got category=%q", m.category)
	}
}

func TestDetect_asnFallback(t *testing.T) {
	// Empty rules — should fall back to ASN table.
	data := inputCompiled{
		CDN:   map[string][]string{},
		WAF:   map[string][]string{},
		Cloud: map[string][]string{},
	}
	raw, _ := json.Marshal(data)
	dir := t.TempDir()
	path := filepath.Join(dir, "sources_data.json")
	_ = os.WriteFile(path, raw, 0o600)

	rules, _ := loadCDNRules(path)
	m := rules.detect(net.ParseIP("1.2.3.4"), "AS13335")
	if m.provider != "Cloudflare" {
		t.Errorf("expected Cloudflare from ASN fallback, got %q", m.provider)
	}
}

func TestDetect_nilRules(t *testing.T) {
	var r *cdnRules
	m := r.detect(net.ParseIP("1.2.3.4"), "AS13335")
	if m.provider != "Cloudflare" {
		t.Errorf("nil rules should fall through to ASN fallback; got %q", m.provider)
	}
}
