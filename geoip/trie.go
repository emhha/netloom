// Package geoip provides IP intelligence lookups: ASN, geolocation,
// CDN/WAF/Cloud provider detection. It has zero business-layer dependencies.
package geoip

import (
	"net"
)

// providerMatch records a CIDR match result with its prefix length and category.
type providerMatch struct {
	category string // "cdn" | "waf" | "cloud"
	provider string
	bits     int // prefix length — higher is more specific
}

// categoryPriority returns a tie-break integer for same-length prefix conflicts.
// WAF > CDN > Cloud.
func categoryPriority(cat string) int {
	switch cat {
	case "waf":
		return 3
	case "cdn":
		return 2
	case "cloud":
		return 1
	default:
		return 0
	}
}

// beats reports whether candidate should replace current best under the
// most-specific-wins / WAF>CDN>Cloud tie-break rule.
func (c providerMatch) beats(best providerMatch) bool {
	if c.bits > best.bits {
		return true
	}
	if c.bits == best.bits && categoryPriority(c.category) > categoryPriority(best.category) {
		return true
	}
	return false
}

// ---- binary radix trie (IPv4 + IPv6) ----------------------------------------

// trieNode is one bit-level node in the radix trie.
type trieNode struct {
	children [2]*trieNode
	// leaf fields; valid only when provider != ""
	provider string
	category string
	bits     int
}

// cidrTrie is a bit-level binary trie supporting longest-prefix-match.
// Separate roots for IPv4 (32-bit) and IPv6 (128-bit).
type cidrTrie struct {
	root4 *trieNode // IPv4
	root6 *trieNode // IPv6
}

func newCIDRTrie() *cidrTrie {
	return &cidrTrie{root4: &trieNode{}, root6: &trieNode{}}
}

// Insert adds a CIDR to the trie. On prefix collision the entry with the
// higher-priority category wins (WAF > CDN > Cloud).
func (t *cidrTrie) Insert(network *net.IPNet, category, provider string) {
	ip := network.IP
	ones, bits := network.Mask.Size()
	if bits == 0 {
		return
	}

	var root *trieNode
	var key []byte
	if bits == 32 {
		root = t.root4
		key = ip.To4()
		if key == nil {
			return
		}
	} else {
		root = t.root6
		key = ip.To16()
		if key == nil {
			return
		}
	}

	node := root
	for i := 0; i < ones; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (key[byteIdx] >> uint(bitIdx)) & 1
		if node.children[bit] == nil {
			node.children[bit] = &trieNode{}
		}
		node = node.children[bit]
	}

	// At the leaf: only overwrite if new entry has higher priority.
	if node.provider == "" || categoryPriority(category) > categoryPriority(node.category) {
		node.provider = provider
		node.category = category
		node.bits = ones
	}
}

// Lookup returns the best (most-specific) match for ip, or a zero providerMatch.
func (t *cidrTrie) Lookup(ip net.IP) providerMatch {
	var root *trieNode
	var key []byte

	if v4 := ip.To4(); v4 != nil {
		root = t.root4
		key = v4
	} else {
		v6 := ip.To16()
		if v6 == nil {
			return providerMatch{}
		}
		root = t.root6
		key = v6
	}

	var best providerMatch
	node := root
	if node.provider != "" {
		best = providerMatch{category: node.category, provider: node.provider, bits: node.bits}
	}
	for i := 0; i < len(key)*8; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (key[byteIdx] >> uint(bitIdx)) & 1
		node = node.children[bit]
		if node == nil {
			break
		}
		if node.provider != "" {
			cand := providerMatch{category: node.category, provider: node.provider, bits: node.bits}
			if cand.beats(best) {
				best = cand
			}
		}
	}
	return best
}
