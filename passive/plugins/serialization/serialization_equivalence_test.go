package serialization

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/emhha/netloom/passive"
)

// Detect accidental edits in the frozen oracle, including identifier renames
// that leak into regex strings. This is deliberately not another optimized path.
func TestSerializationFrozenTables(t *testing.T) {
	for _, pair := range []struct {
		current []serializationRule
		frozen  []serializationLinearRule
	}{
		{serializationRules, serializationLinearRules}, {serializationErrors, serializationLinearErrors},
	} {
		if len(pair.current) != len(pair.frozen) {
			t.Fatal("rule table length changed")
		}
		for i, r := range pair.current {
			old := pair.frozen[i]
			if r.re.String() != old.re.String() || r.id != old.id || r.format != old.format || r.strength != old.strength {
				t.Fatalf("frozen rule %d differs: %q / %q", i, r.re.String(), old.re.String())
			}
		}
	}
	if serializationBytes != serializationLinearBytes || serializationSurfaces != serializationLinearSurfaces || serializationFindings != serializationLinearFindings {
		t.Fatal("frozen scan budgets differ")
	}
	if len(serializationMagics) != len(serializationLinearMagics) {
		t.Fatal("magic table length changed")
	}
	for i, m := range serializationMagics {
		old := serializationLinearMagics[i]
		if !bytes.Equal(m.prefix, old.prefix) || m.format != old.format || m.rule != old.rule || m.strength != old.strength {
			t.Fatalf("magic %d differs", i)
		}
	}
}

func assertSerializationEquivalent(t *testing.T, in passive.Input) passive.Result {
	t.Helper()
	got, err := (Plugin{}).Analyze(context.Background(), in)
	want, oldErr := (serializationLinear{}).Analyze(context.Background(), in)
	if err != nil || oldErr != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("pipeline mismatch\ngot=%+v\nwant=%+v\nerrors=%v / %v", got, want, err, oldErr)
	}
	return got
}

func TestSerializationACSurfacesAndLimits(t *testing.T) {
	all := strings.Join(serializationWitnesses, "\n")
	java := []byte{0xac, 0xed, 0, 5, 0xff, 0}
	for _, data := range [][]byte{[]byte(all), java, append([]byte{0xff, 0, 0xfe}, []byte(all)...)} {
		for _, encoded := range []string{string(data), base64.StdEncoding.EncodeToString(data), base64.RawURLEncoding.EncodeToString(data), url.PathEscape(string(data))} {
			in := serialInput([]byte(encoded))
			in.Request.URL = "https://example.test/?value=" + url.QueryEscape(encoded)
			in.Request.Header = http.Header{"Cookie": {encoded}, "X-Clue": {encoded}}
			in.Response.Header = http.Header{"X-Clue": {encoded}}
			in.Response.Body = []byte(encoded)
			assertSerializationEquivalent(t, in)
			in.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			in.Request.Body = []byte("value=" + url.QueryEscape(encoded) + "&second=" + url.QueryEscape(encoded))
			assertSerializationEquivalent(t, in)
		}
	}
	t.Run("finding-order-and-limit", func(t *testing.T) {
		// Different unknown header names deliberately collapse to "other".
		// Use known distinct scopes and a compact payload, otherwise decoding
		// the complete witness corpus exhausts surfaces before findings.
		payload := `O:4:"Demo":0:{} a:1:{} s:3:"foo"; !!com.x __VIEWSTATE _$$ND_FUNC$$_ phar://x __reduce__ GLOBAL`
		in := serialInput([]byte(payload))
		in.Request.Header = http.Header{}
		in.Response.Header = http.Header{}
		for _, name := range []string{"Cookie", "Set-Cookie", "Content-Type", "Soapaction"} {
			in.Request.Header[name] = []string{payload}
			in.Response.Header[name] = []string{payload}
		}
		in.Response.Body = []byte(payload)
		got := assertSerializationEquivalent(t, in)
		var out struct {
			Findings []Finding `json:"findings"`
		}
		if err := json.Unmarshal(got.Data, &out); err != nil {
			t.Fatal(err)
		}
		if !got.Truncated || len(out.Findings) != serializationFindings {
			t.Fatalf("finding cap not exercised: %d truncated=%t", len(out.Findings), got.Truncated)
		}
	})
	t.Run("byte-limit", func(t *testing.T) {
		in := serialInput(append(bytes.Repeat([]byte("!"), serializationBytes), []byte(all)...))
		if !assertSerializationEquivalent(t, in).Truncated {
			t.Fatal("byte limit not exercised")
		}
	})
	t.Run("surface-limit", func(t *testing.T) {
		in := serialInput(nil)
		in.Request.Header = http.Header{"X-Clue": make([]string, serializationSurfaces+1)}
		for i := range in.Request.Header["X-Clue"] {
			in.Request.Header["X-Clue"][i] = "!"
		}
		if !assertSerializationEquivalent(t, in).Truncated {
			t.Fatal("surface limit not exercised")
		}
	})
	t.Run("capture-truncation", func(t *testing.T) {
		in := serialInput([]byte(all))
		in.Response.BodyTruncated = true
		if !assertSerializationEquivalent(t, in).Truncated {
			t.Fatal("capture truncation lost")
		}
	})
}

func TestSerializationMatcherSetAndFallback(t *testing.T) {
	rules := []serializationRule{
		serialRule(`tail`, "a", "a", "weak"), serialRule(`he`, "b", "b", "weak"), serialRule(`she`, "c", "c", "weak"),
		serialRule(`he`, "d", "d", "weak"), serialRule(`(?i)k`, "fold", "text.phar", "weak"),
		serialRule(`\x{FFFD}`, "replacement", "replacement", "weak"),
		// Reusing an existing ID must not inherit its old regex's trigger assumptions.
		serialRule(`new\s+rule`, "changed", "text.php-array", "weak"),
	}
	matcher := newSerializationTextMatcher(rules, nil)
	for _, data := range [][]byte{[]byte("she he she tail tail"), []byte("K"), {0xff}, []byte("new rule"), []byte("no match")} {
		var got, want []string
		matcher.match(data, false, func(r serializationRule) { got = append(got, r.id) })
		for _, r := range rules {
			if r.re.Match(data) {
				want = append(want, r.id)
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("set/fallback mismatch %q: %v / %v", data, got, want)
		}
	}
	// All 64 bits must remain valid even when requestRules == 64.
	many := make([]serializationRule, 64)
	for i := range many {
		many[i] = serialRule(`hit`, "test", fmt.Sprint(i), "weak")
	}
	full := newSerializationTextMatcher(many, nil)
	count := 0
	full.match([]byte("hit hit"), false, func(serializationRule) { count++ })
	if count != 64 {
		t.Fatalf("64-bit boundary: %d", count)
	}
	t.Run("reject-overflow", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("missing overflow guard")
			}
		}()
		newSerializationTextMatcher(append(many, many[0]), nil)
	})
}

func TestSerializationACConcurrentAnalyze(t *testing.T) {
	in := serialInput([]byte(strings.Join(serializationWitnesses, "\n")))
	in.Response.Body = []byte("StreamCorruptedException System.Runtime.Serialization")
	want, err := (serializationLinear{}).Analyze(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Go(func() {
			for i := 0; i < 24; i++ {
				got, err := (Plugin{}).Analyze(context.Background(), in)
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Errorf("shared matcher pipeline differs: %v", err)
					return
				}
			}
		})
	}
	wg.Wait()
}

// Use the actual form/response paths; the older encoded-fields body benchmark
// intentionally has no form content type and cannot stand in for this path.
func BenchmarkSerializationPipeline(b *testing.B) {
	for _, kind := range []string{"json-response", "form-base64", "binary-response"} {
		in := serialInput(nil)
		switch kind {
		case "json-response":
			in.Response.Body = bytes.Repeat([]byte(`{"items":[{"name":"ordinary商品","id":123}],"next":null}`), 1100)
		case "form-base64":
			in.Request.Header = http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
			in.Request.Body = []byte(strings.Repeat("payload=rO0ABXNy&", 8))
		case "binary-response":
			in.Response.Body = append([]byte{0xac, 0xed, 0, 5}, bytes.Repeat([]byte{0, 0xff, 1, 0x80, 0xfe}, 12000)...)
		}
		got, err := (Plugin{}).Analyze(context.Background(), in)
		want, oldErr := (serializationLinear{}).Analyze(context.Background(), in)
		if err != nil || oldErr != nil || !reflect.DeepEqual(got, want) {
			b.Fatalf("%s benchmark fixtures differ: %v / %v", kind, err, oldErr)
		}
		for _, impl := range []struct {
			name    string
			analyze func(context.Context, passive.Input) (passive.Result, error)
		}{{"linear", (serializationLinear{}).Analyze}, {"AC", (Plugin{}).Analyze}} {
			b.Run(kind+"/"+impl.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := impl.analyze(context.Background(), in); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
