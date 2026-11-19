package serialization

import (
	"bytes"
	"context"
	"encoding/base64"
	"math/rand"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/emhha/netloom/passive"
)

// Include every branch, including non-canonical whitespace and case-folded
// input; the frozen baseline has its own rule table and decoding pipeline.
var serializationWitnesses = []string{
	`O:4:"Demo":0:{}`, `C:4:"Demo":0:{}`, `a:1:{}`, `s:3:"foo";`,
	`phar://x`, `__HALT_COMPILER ()`, `<java version="1">`, `class = "java.lang.ProcessBuilder"`, `<void method = "x">`,
	`<dynamic-proxy>`, `<sorted-set x>`, `<tree-map>`, `<converter x>`,
	`!!python/object:`, `!!python/object/apply:`, `!!python/object/new:`, `!!python/name:`,
	`!!javax.script.ScriptEngineManager`, `!!com.example.Type`, `tag:yaml.org,2002`,
	`"@type":`, `"@class" :`, `["com.example.Type", {`, `"$type":`, `TypeNameHandling`,
	"c__builtin__\n", "cbuiltins\n", "cos\nsystem\n", "cposix\nsystem\n", "cnt\nsystem\n", `__reduce__`, `GLOBAL`,
	`_$$ND_FUNC$$_`, `function(){ child_process`, `System.Runtime.Serialization`,
	`rememberMe=`, `REMEMBERME =`, `__VIEWSTATE`,
	`application/x-java-serialized-object`, `application/x-hessian`, `application/x-amf`, `/messagebroker/amf`,
	`application/octet-stream`, `/wls-wsat/a`, `/_async/a`, `/invoker/JMXInvokerServlet`, `t3 14.1`,
	`StreamCorruptedException`, `InvalidClassException`, `java.io.ObjectInputStream`,
	`unserialize(): Error at offset`, `__wakeup`, `__destruct`, `UnpicklingError`,
	`autoType is not support`, `set autoTypeSupport`, `ForbiddenClassException`,
	`Global tag is not allowed`, `ConstructorException`, `Invalid element qName:`,
	`InvalidDefinitionException: subtype resolution was not allowed`, `SerializationException`,
}

func TestSerializationACMatchesLinear(t *testing.T) {
	corpus := append([]string{"", "plain business text", "\x00\xff\xfe"}, serializationWitnesses...)
	corpus = append(corpus, strings.Join(serializationWitnesses, "\n"), strings.Repeat("<p>ordinary HTML content</p>\n", 4096))
	random := rand.New(rand.NewSource(19))
	for i := 0; i < 120; i++ {
		data := make([]byte, random.Intn(1024))
		random.Read(data)
		if i%2 == 0 {
			data = append(data, serializationWitnesses[i%len(serializationWitnesses)]...)
		}
		corpus = append(corpus, string(data))
	}
	covered := make(map[string]bool)
	for _, sample := range corpus {
		data := []byte(sample)
		for _, rule := range serializationText.rules {
			if rule.re.Match(data) {
				covered[rule.id] = true
			}
		}
		for _, response := range []bool{false, true} {
			var want, got []string
			for i, rule := range serializationText.rules {
				if !response && i >= serializationText.requestRules {
					break
				}
				if rule.re.Match(data) {
					want = append(want, rule.id)
				}
			}
			serializationText.match(data, response, func(rule serializationRule) { got = append(got, rule.id) })
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("text mismatch response=%t data=%q got=%v want=%v", response, sample, got, want)
			}
		}
		inputs := []passive.Input{serialInput(data), serialInput([]byte(base64.StdEncoding.EncodeToString(data)))}
		inputs[0].Response.Body = data
		for _, in := range inputs {
			got, err := (Plugin{}).Analyze(context.Background(), in)
			want, oldErr := (serializationLinear{}).Analyze(context.Background(), in)
			if err != nil || oldErr != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("pipeline mismatch data=%q\ngot=%+v\nwant=%+v\nerr=%v %v", sample, got, want, err, oldErr)
			}
		}
	}
	for _, rule := range serializationText.rules {
		if !covered[rule.id] {
			t.Errorf("no positive witness for %s", rule.id)
		}
	}
}

func TestSerializationLiteralChoicesAndFallback(t *testing.T) {
	for _, pattern := range []string{`hello`, `a|bb`, `(one|two)tail`, `alpha\.beta`, `商品`, `\x{FF}tail`, `ab\x00cd`} {
		words, ok := serializationLiteralChoices(pattern)
		if !ok || len(words) == 0 {
			t.Fatalf("literal pattern rejected: %s", pattern)
		}
		re := regexp.MustCompile(pattern)
		for _, word := range words {
			if !re.MatchString(word) {
				t.Fatalf("not a literal alternative: %s %q", pattern, word)
			}
		}
	}
	for _, pattern := range []string{`(?i)key`, `(?i:foo)bar`, `^hello`, `hello$`, `a*`, `a?`, `a|`, `()`, `[ab]`, `\bhi\b`, `hello.*world`, `\x{FFFD}`, ``} {
		if _, ok := serializationLiteralChoices(pattern); ok {
			t.Fatalf("unsafe direct AC path for %s", pattern)
		}
	}
	rule := serialRule(`(?i)key|ſensitive`, "test", "unknown-rule", "weak")
	matcher := newSerializationTextMatcher([]serializationRule{rule}, nil)
	for _, sample := range []string{"KEY", "key", "ſensitive", "not a hit"} {
		got := false
		matcher.match([]byte(sample), false, func(serializationRule) { got = true })
		if got != rule.re.MatchString(sample) {
			t.Fatalf("fallback changed Unicode/case match %q", sample)
		}
	}
	data := []byte("unrelated normal text")
	mask := serializationText.candidates(data, true)
	for i, rule := range serializationText.rules {
		if len(rule.triggers) > 0 && mask&(uint64(1)<<i) != 0 {
			t.Fatalf("unexpected candidate %s", rule.id)
		}
	}
}

func FuzzSerializationACEquivalence(f *testing.F) {
	for _, sample := range serializationWitnesses {
		f.Add([]byte(sample))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// This tests filtering and direct-literal substitution, without decoding
		// limits hiding mismatches in later rules.
		got := make(map[string]bool)
		serializationText.match(data, true, func(rule serializationRule) { got[rule.id] = true })
		for _, rule := range serializationText.rules {
			if got[rule.id] != rule.re.Match(data) {
				t.Fatalf("rule %s mismatch on %q", rule.id, data)
			}
		}
	})
}

func serializationBenchmarkCorpus() map[string][]byte {
	resize := func(unit string, size int) []byte { return bytes.Repeat([]byte(unit), size/len(unit)+1)[:size] }
	java := base64.StdEncoding.EncodeToString([]byte{0xac, 0xed, 0, 5, 0x73, 0x72})
	return map[string][]byte{
		"4KiB-nohit":     resize("<p>ordinary business content</p>\n", 4<<10),
		"64KiB-nohit":    resize("<p>ordinary business content</p>\n", 64<<10),
		"256KiB-nohit":   resize("<p>ordinary business content</p>\n", 256<<10),
		"64KiB-mixed":    append(resize("<p>ordinary business content</p>\n", (64<<10)-256), []byte(strings.Join(serializationWitnesses[:8], "\n"))...),
		"64KiB-dense":    resize("O:bad a:bad s:bad !!bad <java @class [ function child_process GLOBAL /_async/\n", 64<<10),
		"encoded-fields": []byte(strings.Repeat("payload="+java+"&", 64)),
	}
}

func BenchmarkSerializationText(b *testing.B) {
	for name, data := range serializationBenchmarkCorpus() {
		b.Run(name, func(b *testing.B) {
			b.Run("linear", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(data)))
				for b.Loop() {
					for _, r := range serializationText.rules {
						_ = r.re.Match(data)
					}
				}
			})
			b.Run("AC", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(data)))
				for b.Loop() {
					serializationText.match(data, true, func(serializationRule) {})
				}
			})
		})
	}
}

func BenchmarkSerializationAnalyze(b *testing.B) {
	for name, data := range serializationBenchmarkCorpus() {
		b.Run(name, func(b *testing.B) {
			in := serialInput(data)
			b.Run("linear", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := (serializationLinear{}).Analyze(context.Background(), in); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("AC", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := (Plugin{}).Analyze(context.Background(), in); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
