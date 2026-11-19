// Frozen pre-AC implementation for independent equivalence and benchmarks.
// Keep production optimizations out of this baseline.
package serialization

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/emhha/netloom/passive"
)

// serializationLinear identifies serialization clues in captured HTTP exchanges.
// Its zero value is ready to use. It never deserializes objects or sends probes.
type serializationLinear struct{}

// serializationLinearFinding describes evidence, not an exploitable entry point.
// Evidence is a static rule label, never a captured payload or credential.
type serializationLinearFinding struct {
	Format   string `json:"format"`
	Rule     string `json:"rule"`
	Strength string `json:"strength"`
	Scope    string `json:"scope"`
	Encoding string `json:"encoding"`
	Evidence string `json:"evidence"`
}

func (serializationLinear) Metadata() passive.Metadata {
	return passive.Metadata{ID: "serialization", Version: "1", Description: "纯被动序列化格式及反序列化报错线索，不判定漏洞"}
}

// CacheKey disables reuse: scanning is bounded, and captured credentials are not
// retained as part of an extra cache key construction.
func (serializationLinear) CacheKey(passive.Input) string { return "" }

const (
	serializationLinearBytes    = 1 << 20
	serializationLinearSurfaces = 128
	serializationLinearFindings = 64
)

type serializationLinearScan struct {
	ctx                 context.Context
	result              passive.Result
	findings            []serializationLinearFinding
	seen                map[string]bool
	remaining, surfaces int
}

func (serializationLinear) Analyze(ctx context.Context, in passive.Input) (passive.Result, error) {
	if err := ctx.Err(); err != nil {
		return passive.Result{}, err
	}
	if in.Request == nil || in.Response == nil {
		return passive.Result{}, fmt.Errorf("serialization: request and response are required")
	}
	s := serializationLinearScan{ctx: ctx, remaining: serializationLinearBytes, seen: make(map[string]bool)}
	s.result.Truncated = in.Response.BodyTruncated
	requestURL := s.bound(in.Request.URL)
	s.scan([]byte(requestURL), "request.url", "raw", true)
	if query := strings.IndexByte(requestURL, '?'); query >= 0 {
		s.fields([]byte(s.bound(strings.SplitN(requestURL[query+1:], "#", 2)[0])), "request.url")
	}
	s.headers(in.Request.Header, "request.header")
	s.scan(in.Request.Body, "request.body", "raw", true)
	contentType := in.Request.Header.Get("Content-Type")
	if len(contentType) <= 256 {
		contentType = strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0])
		if strings.EqualFold(contentType, "application/x-www-form-urlencoded") {
			s.fields(in.Request.Body, "request.body")
		}
	}
	s.headers(in.Response.Header, "response.header")
	s.scan([]byte(s.bound(in.Response.ContentType)), "response.content_type", "raw", false)
	s.scan(in.Response.Body, "response.body", "raw", true)
	data, err := json.Marshal(struct {
		Findings    []serializationLinearFinding `json:"findings"`
		PassiveOnly bool                         `json:"passive_only"`
	}{append([]serializationLinearFinding{}, s.findings...), true})
	s.result.Data = data
	if err != nil {
		return s.result, err
	}
	return s.result, ctx.Err()
}

// Bound strings before converting to byte slices or decoding them.
func (s *serializationLinearScan) bound(v string) string {
	if len(v) > s.remaining {
		s.result.Truncated = true
		return v[:s.remaining]
	}
	return v
}

func (s *serializationLinearScan) headers(headers map[string][]string, scope string) {
	if len(headers) == 0 || s.ctx.Err() != nil {
		return
	}
	// Reject oversized maps before allocating/sorting their keys. All other
	// header preprocessing, including empty values, is bounded as well.
	if len(headers) > serializationLinearSurfaces || s.remaining == 0 || s.surfaces >= serializationLinearSurfaces {
		s.result.Truncated = true
		return
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		if s.ctx.Err() != nil {
			return
		}
		if len(key) > s.remaining {
			s.result.Truncated = true
			return
		}
		s.remaining -= len(key)
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		name := "other"
		for _, known := range []string{"cookie", "set-cookie", "content-type", "soapaction"} {
			if strings.EqualFold(key, known) {
				name = known
				break
			}
		}
		values := headers[key]
		if len(values) > serializationLinearSurfaces {
			s.result.Truncated = true
			values = values[:serializationLinearSurfaces]
		}
		for _, value := range values {
			if s.ctx.Err() != nil {
				return
			}
			if s.remaining == 0 || s.surfaces >= serializationLinearSurfaces {
				s.result.Truncated = true
				return
			}
			if value == "" {
				s.surfaces++
				continue
			}
			s.scan([]byte(s.bound(value)), scope+"."+name, "raw", true)
		}
	}
}

// fields expands query/form values without allocating an unbounded parameter
// map. Names are neither emitted nor interpreted; '+' follows form semantics.
func (s *serializationLinearScan) fields(data []byte, scope string) {
	if len(data) > s.remaining {
		data = data[:s.remaining]
		s.result.Truncated = true
	}
	for count := 0; len(data) > 0; count++ {
		if s.ctx.Err() != nil {
			return
		}
		if count >= serializationLinearSurfaces || s.surfaces >= serializationLinearSurfaces || s.remaining == 0 {
			s.result.Truncated = true
			return
		}
		field, rest, found := bytes.Cut(data, []byte("&"))
		if found {
			data = rest
		} else {
			data = nil
		}
		_, value, ok := bytes.Cut(field, []byte("="))
		if !ok || len(value) == 0 {
			s.surfaces++
			continue
		}
		decoded, err := url.QueryUnescape(string(value))
		if err != nil {
			s.surfaces++
			continue
		}
		s.scan([]byte(decoded), scope, "url", false)
		s.base64([]byte(decoded), scope, "url+base64")
	}
}

func (s *serializationLinearScan) add(format, rule, strength, scope, encoding string) {
	// A response can be documentation, reflected input, or a sample download.
	if strings.HasPrefix(scope, "response.") && strength == "strong" && !strings.HasPrefix(rule, "error.") {
		strength = "medium"
	}
	key := scope + "\x00" + encoding + "\x00" + rule
	if s.seen[key] {
		return
	}
	if len(s.findings) >= serializationLinearFindings {
		s.result.Truncated = true
		return
	}
	s.seen[key] = true
	s.findings = append(s.findings, serializationLinearFinding{Format: format, Rule: rule, Strength: strength, Scope: scope, Encoding: encoding, Evidence: rule})
	s.result.Artifacts = append(s.result.Artifacts, passive.Artifact{Type: "serialization_hint", Value: format + " (" + strength + ")", Rule: rule, Scope: scope})
}

type serializationLinearMagic struct {
	prefix                 []byte
	format, rule, strength string
}

var serializationLinearMagics = []serializationLinearMagic{
	{[]byte{0xac, 0xed, 0, 5}, "java-object-stream", "magic.java", "strong"},
	{[]byte{0x80, 2}, "python-pickle", "magic.pickle2", "strong"},
	{[]byte{0x80, 3}, "python-pickle", "magic.pickle3", "strong"},
	{[]byte{0x80, 4}, "python-pickle", "magic.pickle4", "strong"},
	{[]byte{0x80, 5}, "python-pickle", "magic.pickle5", "strong"},
	{[]byte{0, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}, "dotnet-binaryformatter", "magic.binaryformatter", "strong"},
	{[]byte{'H', 2, 0}, "hessian2", "magic.hessian2", "strong"},
	{[]byte{0xda, 0xbb}, "dubbo", "magic.dubbo", "strong"},
	{[]byte("JRMI"), "java-rmi", "magic.rmi", "strong"},
	{[]byte{4, 8}, "ruby-marshal", "magic.ruby", "medium"},
	{[]byte{0xff, 1, 0x0f}, "dotnet-viewstate", "magic.viewstate", "medium"},
	{[]byte{0x1f, 0x8b, 8}, "compressed-data", "compression.gzip", "weak"},
}

type serializationLinearRule struct {
	re                   *regexp.Regexp
	format, id, strength string
}

func serialLinearRule(pattern, format, id, strength string) serializationLinearRule {
	return serializationLinearRule{re: regexp.MustCompile(pattern), format: format, id: id, strength: strength}
}

var serializationLinearRules = []serializationLinearRule{
	serialLinearRule(`(?:^|[^A-Za-z0-9_])[OC]:[0-9]+:"[^"\r\n]*":`, "php-serialized", "text.php-object", "strong"),
	serialLinearRule(`(?:^|[^A-Za-z0-9_])a:[0-9]+:\{`, "php-serialized", "text.php-array", "medium"),
	serialLinearRule(`(?:^|[^A-Za-z0-9_])s:[0-9]+:"`, "php-serialized", "text.php-string", "weak"),
	serialLinearRule(`phar://|__HALT_COMPILER\s*\(`, "php-phar", "text.phar", "medium"),
	serialLinearRule(`<java\s+version\s*=|class\s*=\s*"java\.lang\.ProcessBuilder"|<void\s+method\s*=`, "java-xml", "text.java-xml", "medium"),
	serialLinearRule(`<(?:dynamic-proxy|sorted-set|tree-map|converter)(?:\s|>)`, "java-xstream", "text.xstream", "medium"),
	serialLinearRule(`!!python/(?:object(?:/apply|/new)?|name):`, "python-yaml", "text.python-yaml", "strong"),
	serialLinearRule(`!!javax\.script\.ScriptEngineManager`, "java-yaml", "text.java-yaml", "strong"),
	serialLinearRule(`!![A-Za-z_][\w.]*|tag:yaml\.org,2002`, "yaml-tag", "text.yaml-tag", "weak"),
	serialLinearRule(`"@(?:type|class)"\s*:|\[\s*"[a-z][\w.]+"\s*,\s*\{`, "java-json", "text.java-json-type", "weak"),
	serialLinearRule(`"\$type"\s*:|TypeNameHandling`, "dotnet-json", "text.dotnet-json-type", "weak"),
	serialLinearRule(`c(?:__builtin__|builtins)\n|c(?:os|posix|nt)\nsystem\n`, "python-pickle", "text.pickle-global", "strong"),
	serialLinearRule(`__reduce__|\bGLOBAL\b`, "python-pickle", "text.pickle-name", "weak"),
	serialLinearRule(`_\$\$ND_FUNC\$\$_`, "node-serialize", "text.node-function", "strong"),
	serialLinearRule(`function\s*\([^)]*\)\s*\{[^\r\n]{0,256}child_process`, "node-function", "text.node-child-process", "medium"),
	serialLinearRule(`System\.Runtime\.Serialization`, "dotnet-serialization", "text.dotnet-namespace", "weak"),
	serialLinearRule(`(?i)\brememberMe\s*=`, "encrypted-cookie-candidate", "context.remember-me", "weak"),
	serialLinearRule(`__VIEWSTATE`, "dotnet-viewstate", "context.viewstate", "weak"),
	serialLinearRule(`application/x-java-serialized-object`, "java-object-stream", "context.java-content-type", "medium"),
	serialLinearRule(`application/x-hessian`, "hessian", "context.hessian-content-type", "medium"),
	serialLinearRule(`application/x-amf|/messagebroker/amf`, "amf", "context.amf", "weak"),
	serialLinearRule(`application/octet-stream`, "binary-data", "context.octet-stream", "weak"),
	serialLinearRule(`/(?:wls-wsat|_async)/|/invoker/JMXInvokerServlet`, "java-remoting", "context.java-path", "weak"),
	serialLinearRule(`^t3 [0-9]+\.[0-9]+`, "weblogic-t3", "magic.t3", "strong"),
}
var serializationLinearErrors = []serializationLinearRule{
	serialLinearRule(`StreamCorruptedException|InvalidClassException|java\.io\.ObjectInputStream`, "java-object-stream", "error.java", "medium"),
	serialLinearRule(`unserialize\(\): Error at offset|__wakeup|__destruct`, "php-serialized", "error.php", "medium"),
	serialLinearRule(`UnpicklingError`, "python-pickle", "error.pickle", "medium"),
	serialLinearRule(`autoType is not support|set autoTypeSupport|ForbiddenClassException`, "java-json-or-xstream", "error.java-type", "medium"),
	serialLinearRule(`Global tag is not allowed|ConstructorException|Invalid element qName:`, "yaml-or-java-xml", "error.tag", "medium"),
	serialLinearRule(`InvalidDefinitionException[^\r\n]{0,256}subtype resolution was not allowed`, "java-json", "error.jackson", "medium"),
	serialLinearRule(`SerializationException|System\.Runtime\.Serialization`, "dotnet-serialization", "error.dotnet", "medium"),
}
var serializationLinearBase64 = regexp.MustCompile(`[A-Za-z0-9+/_-]{2,}={0,2}`)

func (s *serializationLinearScan) scan(data []byte, scope, encoding string, expand bool) {
	if len(data) == 0 || s.ctx.Err() != nil {
		return
	}
	if s.surfaces >= serializationLinearSurfaces || s.remaining == 0 {
		s.result.Truncated = true
		return
	}
	s.surfaces++
	if len(data) > s.remaining {
		data = data[:s.remaining]
		s.result.Truncated = true
	}
	s.remaining -= len(data)
	for _, magic := range serializationLinearMagics {
		if bytes.HasPrefix(data, magic.prefix) {
			s.add(magic.format, magic.rule, magic.strength, scope, encoding)
		}
	}
	// zlib uses a two-byte header with a mod-31 checksum, not merely "eJ".
	if len(data) >= 2 && data[0]&15 == 8 && data[0]>>4 <= 7 && (int(data[0])*256+int(data[1]))%31 == 0 {
		s.add("compressed-data", "compression.zlib", "weak", scope, encoding)
	}
	for _, rule := range serializationLinearRules {
		if rule.re.Match(data) {
			s.add(rule.format, rule.id, rule.strength, scope, encoding)
		}
	}
	if strings.HasPrefix(scope, "response.") {
		for _, rule := range serializationLinearErrors {
			if rule.re.Match(data) {
				s.add(rule.format, rule.id, rule.strength, scope, encoding)
			}
		}
	}
	if !expand {
		return
	}
	// Decode one URL/form layer only. '+' is preserved in cookies and non-form
	// bodies so ordinary Base64 is not silently corrupted.
	if bytes.Contains(data, []byte("%")) || (scope == "request.url" && bytes.Contains(data, []byte("+"))) {
		decoded, err := url.PathUnescape(string(data))
		if err == nil && decoded != string(data) {
			s.scan([]byte(decoded), scope, "url", false)
			s.base64([]byte(decoded), scope, "url+base64")
		}
	}
	s.base64(data, scope, "base64")
}

func (s *serializationLinearScan) base64(data []byte, scope, encoding string) {
	// Limit token enumeration as well as decoded bytes. This prevents large
	// collections of small tokens from turning into unbounded decoding work.
	matches := serializationLinearBase64.FindAllIndex(data, serializationLinearSurfaces+1)
	if len(matches) > serializationLinearSurfaces {
		s.result.Truncated = true
		matches = matches[:serializationLinearSurfaces]
	}
	for _, at := range matches {
		if s.ctx.Err() != nil {
			return
		}
		if s.remaining == 0 || s.surfaces >= serializationLinearSurfaces {
			s.result.Truncated = true
			return
		}
		// A padded match must end at a delimiter, not in the middle of a
		// malformed token such as gAQ=== or gAQ=A.
		if at[1] < len(data) && bytes.ContainsRune([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-="), rune(data[at[1]])) {
			continue
		}
		token := data[at[0]:at[1]]
		if len(token) < 4 {
			continue
		}
		if len(token) > s.remaining {
			s.result.Truncated = true
			continue
		}
		raw := strings.TrimRight(string(token), "=")
		if len(token)-len(raw) > 2 || (len(raw)%4 == 1) {
			continue
		}
		var decoded []byte
		var err error
		decoder := base64.RawStdEncoding.Strict()
		if strings.ContainsAny(raw, "-_") {
			decoder = base64.RawURLEncoding.Strict()
		}
		if len(raw) != len(token) {
			decoder = base64.StdEncoding.Strict()
			if strings.ContainsAny(raw, "-_") {
				decoder = base64.URLEncoding.Strict()
			}
		}
		decoded, err = decoder.DecodeString(string(token))
		if err != nil {
			continue
		}
		// Non-recursive: never interpret a decoded object or decode nested Base64.
		s.scan(decoded, scope, encoding, false)
	}
}
