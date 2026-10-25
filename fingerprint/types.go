// Package fingerprint implements multi-engine web technology fingerprinting.
//
// It provides webfinger (AST + Aho-Corasick), native EHole/FingerprintHub matching,
// optional Wappalyzer matching,
// and captured icon hash matching over immutable HTTP snapshots. It issues no requests.
//
// Source profiles require enabled files to load successfully. Legacy optional
// YAML/Wappalyzer inputs retain graceful degradation on missing rule files.
package fingerprint

import (
	"netrt.local/netrt/httpdata"
)

// Artifact is a fingerprint detection result for a single technology.
type Artifact struct {
	Type       string   // "cms" | "framework" | "server" | "language" | "waf" | "cdn" | ...
	Name       string   // technology name, e.g. "WordPress", "Nginx", "PHP"
	Version    string   // optional version string, e.g. "6.2"
	Confidence float64  // 0-100
	Source     string   // "webfinger" | "wappalyzer" | "custom" | "ehole" | "fingerprinthub"
	Implies    []string // implied technologies, e.g. ["PHP", "MySQL"] for WordPress
}

// Field identifies which part of the response an AC automaton covers.
type Field uint8

const (
	FieldBody      Field = iota
	FieldHeader          // serialized header blob (lowercase keys)
	FieldTitle           //nolint // resp.Title
	FieldServer          // resp.WebServer
	FieldCookie          // Set-Cookie header values
	FieldMeta            // <meta> tag content
	FieldScript          // <script> inline content
	FieldScriptSrc       // <script src="..."> URLs
	FieldCert            // TLS certificate Subject (not AC-indexed, matched inline)
)

// MatchContext is built once per response and shared across all matchers.
// Hits is pre-populated by NewMatchContext via AC scanning for the four main
// fields (body/header/title/server); subsequent AST nodes only do O(1) lookups.
type MatchContext struct {
	// Request is optional captured request metadata, never a request to send.
	Request  *httpdata.Request
	Response *httpdata.Response

	// Hits[field][keyword] = true when the keyword was found in that field.
	Hits map[Field]map[string]bool

	// HeaderBlob is the serialized (lowercase-key) header blob used by the
	// HeaderAC scan. Stored here so Wappalyzer can also reuse it.
	HeaderBlob []byte

	// BodyUTF8 is the body decoded to UTF-8 (GBK/GB2312 → UTF-8 conversion
	// if needed). Not nil; falls back to resp.Body on decode error.
	BodyUTF8 []byte

	// HTMLResult is the HTML parsed once by Engine.Match and shared by matchers.
	HTMLResult *HTMLParserResult
}

// Extractor is implemented by each fingerprint engine. It matches a MatchContext
// and returns all detected technologies. The interface is intentionally internal
// to this package; callers use Engine.Match.
type fingerprintExtractor interface {
	name() string
	match(ctx *MatchContext) []Artifact
}
