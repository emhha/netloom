package plugins

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

// Serialization identifies serialization clues in captured HTTP exchanges.
// Its zero value is ready to use. It never deserializes objects or sends probes.
type Serialization struct{}

// SerializationFinding describes evidence, not an exploitable entry point.
// Evidence is a static rule label, never a captured payload or credential.
type SerializationFinding struct {
	Format   string `json:"format"`
	Rule     string `json:"rule"`
	Strength string `json:"strength"`
	Scope    string `json:"scope"`
	Encoding string `json:"encoding"`
	Evidence string `json:"evidence"`
}

func (Serialization) Metadata() passive.Metadata {
	return passive.Metadata{ID: "serialization", Version: "1", Description: "纯被动序列化格式及反序列化报错线索，不判定漏洞"}
}

// CacheKey disables reuse: scanning is bounded, and captured credentials are not
// retained as part of an extra cache key construction.
func (Serialization) CacheKey(passive.Input) string { return "" }

const (
	serializationBytes    = 1 << 20
	serializationSurfaces = 128
	serializationFindings = 64
)

type serializationScan struct {
	ctx                 context.Context
	result              passive.Result
	findings            []SerializationFinding
	seen                map[string]bool
	remaining, surfaces int
}

func (Serialization) Analyze(ctx context.Context, in passive.Input) (passive.Result, error) {
	if err := ctx.Err(); err != nil {
		return passive.Result{}, err
	}
	if in.Request == nil || in.Response == nil {
		return passive.Result{}, fmt.Errorf("serialization: request and response are required")
	}
	s := serializationScan{ctx: ctx, remaining: serializationBytes, seen: make(map[string]bool)}
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
		Findings    []SerializationFinding `json:"findings"`
		PassiveOnly bool                   `json:"passive_only"`
	}{append([]SerializationFinding{}, s.findings...), true})
	s.result.Data = data
	if err != nil {
		return s.result, err
	}
	return s.result, ctx.Err()
}

// Bound strings before converting to byte slices or decoding them.
func (s *serializationScan) bound(v string) string {
	if len(v) > s.remaining {
		s.result.Truncated = true
		return v[:s.remaining]
	}
	return v
}

func (s *serializationScan) headers(headers map[string][]string, scope string) {
	if len(headers) == 0 || s.ctx.Err() != nil {
		return
	}
	// Reject oversized maps before allocating/sorting their keys. All other
	// header preprocessing, including empty values, is bounded as well.
	if len(headers) > serializationSurfaces || s.remaining == 0 || s.surfaces >= serializationSurfaces {
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
		if len(values) > serializationSurfaces {
			s.result.Truncated = true
			values = values[:serializationSurfaces]
		}
		for _, value := range values {
			if s.ctx.Err() != nil {
				return
			}
			if s.remaining == 0 || s.surfaces >= serializationSurfaces {
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
func (s *serializationScan) fields(data []byte, scope string) {
	if len(data) > s.remaining {
		data = data[:s.remaining]
		s.result.Truncated = true
	}
	for count := 0; len(data) > 0; count++ {
		if s.ctx.Err() != nil {
			return
		}
		if count >= serializationSurfaces || s.surfaces >= serializationSurfaces || s.remaining == 0 {
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

func (s *serializationScan) add(format, rule, strength, scope, encoding string) {
	// A response can be documentation, reflected input, or a sample download.
	if strings.HasPrefix(scope, "response.") && strength == "strong" && !strings.HasPrefix(rule, "error.") {
		strength = "medium"
	}
	key := scope + "\x00" + encoding + "\x00" + rule
	if s.seen[key] {
		return
	}
	if len(s.findings) >= serializationFindings {
		s.result.Truncated = true
		return
	}
	s.seen[key] = true
	s.findings = append(s.findings, SerializationFinding{Format: format, Rule: rule, Strength: strength, Scope: scope, Encoding: encoding, Evidence: rule})
	s.result.Artifacts = append(s.result.Artifacts, passive.Artifact{Type: "serialization_hint", Value: format + " (" + strength + ")", Rule: rule, Scope: scope})
}

type serializationMagic struct {
	prefix                 []byte
	format, rule, strength string
}

var serializationMagics = []serializationMagic{
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

type serializationRule struct {
	re                   *regexp.Regexp
	format, id, strength string
	triggers             []string
	literal              bool
}

func serialRule(pattern, format, id, strength string) serializationRule {
	rule := serializationRule{re: regexp.MustCompile(pattern), format: format, id: id, strength: strength, triggers: serializationTriggers[pattern]}
	if literals, ok := serializationLiteralChoices(pattern); ok {
		rule.triggers, rule.literal = literals, true
	}
	return rule
}

var serializationRules = []serializationRule{
	serialRule(`(?:^|[^A-Za-z0-9_])[OC]:[0-9]+:"[^"\r\n]*":`, "php-serialized", "text.php-object", "strong"),
	serialRule(`(?:^|[^A-Za-z0-9_])a:[0-9]+:\{`, "php-serialized", "text.php-array", "medium"),
	serialRule(`(?:^|[^A-Za-z0-9_])s:[0-9]+:"`, "php-serialized", "text.php-string", "weak"),
	serialRule(`phar://|__HALT_COMPILER\s*\(`, "php-phar", "text.phar", "medium"),
	serialRule(`<java\s+version\s*=|class\s*=\s*"java\.lang\.ProcessBuilder"|<void\s+method\s*=`, "java-xml", "text.java-xml", "medium"),
	serialRule(`<(?:dynamic-proxy|sorted-set|tree-map|converter)(?:\s|>)`, "java-xstream", "text.xstream", "medium"),
	serialRule(`!!python/(?:object(?:/apply|/new)?|name):`, "python-yaml", "text.python-yaml", "strong"),
	serialRule(`!!javax\.script\.ScriptEngineManager`, "java-yaml", "text.java-yaml", "strong"),
	serialRule(`!![A-Za-z_][\w.]*|tag:yaml\.org,2002`, "yaml-tag", "text.yaml-tag", "weak"),
	serialRule(`"@(?:type|class)"\s*:|\[\s*"[a-z][\w.]+"\s*,\s*\{`, "java-json", "text.java-json-type", "weak"),
	serialRule(`"\$type"\s*:|TypeNameHandling`, "dotnet-json", "text.dotnet-json-type", "weak"),
	serialRule(`c(?:__builtin__|builtins)\n|c(?:os|posix|nt)\nsystem\n`, "python-pickle", "text.pickle-global", "strong"),
	serialRule(`__reduce__|\bGLOBAL\b`, "python-pickle", "text.pickle-name", "weak"),
	serialRule(`_\$\$ND_FUNC\$\$_`, "node-serialize", "text.node-function", "strong"),
	serialRule(`function\s*\([^)]*\)\s*\{[^\r\n]{0,256}child_process`, "node-function", "text.node-child-process", "medium"),
	serialRule(`System\.Runtime\.Serialization`, "dotnet-serialization", "text.dotnet-namespace", "weak"),
	serialRule(`(?i)\brememberMe\s*=`, "encrypted-cookie-candidate", "context.remember-me", "weak"),
	serialRule(`__VIEWSTATE`, "dotnet-viewstate", "context.viewstate", "weak"),
	serialRule(`application/x-java-serialized-object`, "java-object-stream", "context.java-content-type", "medium"),
	serialRule(`application/x-hessian`, "hessian", "context.hessian-content-type", "medium"),
	serialRule(`application/x-amf|/messagebroker/amf`, "amf", "context.amf", "weak"),
	serialRule(`application/octet-stream`, "binary-data", "context.octet-stream", "weak"),
	serialRule(`/(?:wls-wsat|_async)/|/invoker/JMXInvokerServlet`, "java-remoting", "context.java-path", "weak"),
	serialRule(`^t3 [0-9]+\.[0-9]+`, "weblogic-t3", "magic.t3", "strong"),
}
var serializationErrors = []serializationRule{
	serialRule(`StreamCorruptedException|InvalidClassException|java\.io\.ObjectInputStream`, "java-object-stream", "error.java", "medium"),
	serialRule(`unserialize\(\): Error at offset|__wakeup|__destruct`, "php-serialized", "error.php", "medium"),
	serialRule(`UnpicklingError`, "python-pickle", "error.pickle", "medium"),
	serialRule(`autoType is not support|set autoTypeSupport|ForbiddenClassException`, "java-json-or-xstream", "error.java-type", "medium"),
	serialRule(`Global tag is not allowed|ConstructorException|Invalid element qName:`, "yaml-or-java-xml", "error.tag", "medium"),
	serialRule(`InvalidDefinitionException[^\r\n]{0,256}subtype resolution was not allowed`, "java-json", "error.jackson", "medium"),
	serialRule(`SerializationException|System\.Runtime\.Serialization`, "dotnet-serialization", "error.dotnet", "medium"),
}
var serializationBase64 = regexp.MustCompile(`[A-Za-z0-9+/_-]{2,}={0,2}`)

func (s *serializationScan) scan(data []byte, scope, encoding string, expand bool) {
	if len(data) == 0 || s.ctx.Err() != nil {
		return
	}
	if s.surfaces >= serializationSurfaces || s.remaining == 0 {
		s.result.Truncated = true
		return
	}
	s.surfaces++
	if len(data) > s.remaining {
		data = data[:s.remaining]
		s.result.Truncated = true
	}
	s.remaining -= len(data)
	for _, magic := range serializationMagics {
		if bytes.HasPrefix(data, magic.prefix) {
			s.add(magic.format, magic.rule, magic.strength, scope, encoding)
		}
	}
	// zlib uses a two-byte header with a mod-31 checksum, not merely "eJ".
	if len(data) >= 2 && data[0]&15 == 8 && data[0]>>4 <= 7 && (int(data[0])*256+int(data[1]))%31 == 0 {
		s.add("compressed-data", "compression.zlib", "weak", scope, encoding)
	}
	serializationText.match(data, strings.HasPrefix(scope, "response."), func(rule serializationRule) {
		s.add(rule.format, rule.id, rule.strength, scope, encoding)
	})
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

func (s *serializationScan) base64(data []byte, scope, encoding string) {
	// Limit token enumeration as well as decoded bytes. This prevents large
	// collections of small tokens from turning into unbounded decoding work.
	matches := serializationBase64.FindAllIndex(data, serializationSurfaces+1)
	if len(matches) > serializationSurfaces {
		s.result.Truncated = true
		matches = matches[:serializationSurfaces]
	}
	for _, at := range matches {
		if s.ctx.Err() != nil {
			return
		}
		if s.remaining == 0 || s.surfaces >= serializationSurfaces {
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
