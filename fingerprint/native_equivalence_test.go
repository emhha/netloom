package fingerprint

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"netrt.local/netrt/httpdata"
)

func assertNativeEquivalent(t *testing.T, eh *EHoleMatcher, hub *FingerprintHubMatcher, request *httpdata.Request, response *httpdata.Response) {
	t.Helper()
	mc := NewMatchContext(response, nil)
	mc.Request = request
	mc.HTMLResult = parseHTML(mc.BodyUTF8, response.Header)
	if response.Title == "" {
		copy := *response
		copy.Title = mc.HTMLResult.Title
		mc.Response = &copy
	}
	ctx := context.Background()
	if eh != nil {
		want := linearEHoleMatch(eh, ctx, mc)
		got := eh.match(ctx, mc)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("EHole changed results: got=%+v want=%+v response=%+v", got, want, response)
		}
	}
	if hub != nil {
		want := linearHubMatch(hub, ctx, mc)
		got := hub.match(ctx, mc)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("FingerprintHub changed results: got=%+v want=%+v response=%+v", got, want, response)
		}
	}
}

func TestNativeIndexesMatchLinearCorpus(t *testing.T) {
	ehData, err := os.ReadFile("rules/ehole.json")
	if err != nil {
		t.Fatal(err)
	}
	hubData, err := os.ReadFile("rules/fingerprinthub_v4.json")
	if err != nil {
		t.Fatal(err)
	}
	eh, err := LoadEHoleJSON(ehData)
	if err != nil {
		t.Fatal(err)
	}
	hub, err := LoadFingerprintHubJSON(hubData)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []*httpdata.Response{
		{}, {Body: []byte("<title>LOGIN</title>one two 42")},
		{Body: []byte(`<meta name="generator" content="WordPress 6.8">/wp-content/`), Header: http.Header{"Server": {"nginx/1.26.0"}}},
		{FaviconHash: 617142232}, {FaviconHash: -123, FaviconMD5: "0123456789ABCDEF0123456789ABCDEF"},
		{Body: []byte("ſerver Kelvin İSTANBUL 华为 中文 LOGIN")},
	}
	// Sample actual keyword combinations across the complete EHole corpus.
	for i, r := range eh.rules {
		if r.Method == "keyword" && i%13 == 0 {
			text := strings.Join(r.Keyword, " :: ")
			fixtures = append(fixtures, &httpdata.Response{Body: []byte(text), Title: text, Header: http.Header{"X-Test": {text}}})
		}
	}
	// Sample multi-word and alternate matchers from the complete v4 corpus.
	for i, r := range hub.rules {
		if i%79 == 0 {
			for _, p := range r.HTTP {
				for _, m := range p.Matchers {
					if m.Type == "word" {
						text := strings.Join(m.Words, " :: ")
						fixtures = append(fixtures, &httpdata.Response{Body: []byte(text), Title: text, Header: http.Header{"Server": {text}}})
					}
				}
			}
		}
	}
	for i, response := range fixtures {
		assertNativeEquivalent(t, eh, hub, nil, response)
		if i%7 == 0 {
			assertNativeEquivalent(t, eh, hub, &httpdata.Request{URL: "https://example.test/admin", Method: "POST"}, response)
		}
	}
}

func TestNativeIndexesPreserveConditionsAndRegex(t *testing.T) {
	patterns := []string{`(?i)server`, `(?i)kelvin`, `a*`, `^$`, `foo|bar`, `(a)?b*`, `(?i)(login)+`, `(?i)中文`, `prefix(?:x|y)suffix`, `(?i)a(?-i:B)c`, `a{0,3}`, `a{2,3}`, `a\x{FFFD}b`, `\x{FFFD}`, `(?i)a\x{FFFD}b`}
	rules := []hubTemplate{}
	ehRules := []EHoleRule{}
	for i, pattern := range patterns {
		rule := hubTemplate{ID: pattern}
		rule.Info.Name = pattern
		rule.HTTP = []hubProbe{{Matchers: []hubMatcher{{Type: "regex", Regex: []string{pattern}, CaseInsensitive: i%2 == 0}}}}
		rules = append(rules, rule)
		negative := hubTemplate{ID: "not-" + pattern}
		negative.HTTP = []hubProbe{{Matchers: []hubMatcher{{Type: "regex", Regex: []string{pattern}, Negative: true, CaseInsensitive: i%2 == 0}}}}
		rules = append(rules, negative)
		ehRules = append(ehRules, EHoleRule{CMS: pattern, Method: "regular", Location: "body", Keyword: []string{pattern}})
	}
	// Include every combination of matcher/probe conditions, negation and fields.
	for _, condition := range []string{"and", "or"} {
		for _, group := range []string{"and", "or"} {
			for _, negative := range []bool{false, true} {
				for _, part := range []string{"body", "header", "title", "all"} {
					rule := hubTemplate{ID: condition + group + part}
					rule.Info.Name = rule.ID
					rule.HTTP = []hubProbe{{MatchersCondition: group, Matchers: []hubMatcher{
						{Type: "word", Words: []string{"LOGIN", "two"}, Condition: condition, Part: part, CaseInsensitive: true, Negative: negative},
						{Type: "regex", Regex: []string{"42", `a*`}, Condition: condition, Part: part},
					}}}
					rules = append(rules, rule)
				}
			}
		}
	}
	for _, condition := range []string{"and", "or"} {
		for _, negative := range []bool{false, true} {
			rule := hubTemplate{ID: "icon-" + condition}
			rule.HTTP = []hubProbe{{Matchers: []hubMatcher{{Type: "favicon", Hash: []string{"-123", "0123456789abcdef0123456789abcdef"}, Condition: condition, Negative: negative}}}}
			rules = append(rules, rule)
		}
	}
	data, _ := json.Marshal(rules)
	hub, err := LoadFingerprintHubJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = json.Marshal(map[string]any{"fingerprint": ehRules})
	eh, err := LoadEHoleJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	random := rand.New(rand.NewSource(47271))
	tokens := []string{"LOGIN", "two", "42", "server", "ſerver", "kelvin", "Kelvin", "İSTANBUL", "中文", "prefixxsuffix", "aBc", "abc", "bar", "b", "aaa", "a\xffb", "a�b"}
	for i := 0; i < 100; i++ {
		text := ""
		for j := 0; j < random.Intn(10); j++ {
			text += tokens[random.Intn(len(tokens))] + " "
		}
		r := &httpdata.Response{Body: []byte(text), Title: text, Header: http.Header{"X-Test": {text}}, BodyTruncated: i%11 == 0}
		if i%3 == 0 {
			r.FaviconHash = -123
		}
		if i%5 == 0 {
			r.FaviconMD5 = "0123456789ABCDEF0123456789ABCDEF"
		}
		assertNativeEquivalent(t, eh, hub, nil, r)
	}
	assertNativeEquivalent(t, eh, hub, nil, &httpdata.Response{})
}

func TestNativeIndexesConcurrentResponses(t *testing.T) {
	data := []byte(`[{"id":"first","http":[{"matchers":[{"type":"word","words":["first"],"case-insensitive":true}]}]},{"id":"second","http":[{"matchers":[{"type":"regex","regex":["(?i)server"]}]}]}]`)
	hub, err := LoadFingerprintHubJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				text := []string{"FIRST", "ſerver", "neither", "first server"}[(i+j)%4]
				mc := NewMatchContext(&httpdata.Response{Body: []byte(text)}, nil)
				if got, want := hub.match(context.Background(), mc), linearHubMatch(hub, context.Background(), mc); !reflect.DeepEqual(got, want) {
					t.Errorf("concurrent result changed: got=%v want=%v", got, want)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if len(hub.match(ctx, NewMatchContext(&httpdata.Response{Body: []byte("first")}, nil))) != 0 {
		t.Fatal("cancelled match produced results")
	}
}
