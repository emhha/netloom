package serialization

import (
	"math/bits"
	"regexp/syntax"

	"github.com/emhha/netloom/ac"
)

// Every listed alternative must contain at least one of its rule's triggers.
// Triggers are necessary (OR), never sufficient; unknown rules run as fallback.
// Case-folded regexes intentionally have no byte triggers: ASCII normalization
// is not in general equivalent to Go regexp's Unicode simple folding. Key by
// the exact regex, not rule ID: editing a rule must not silently retain stale
// necessary-word assumptions. Unknown patterns fall back to the regex.
var serializationTriggers = map[string][]string{
	`(?:^|[^A-Za-z0-9_])[OC]:[0-9]+:"[^"\r\n]*":`:                                     {"O:", "C:"},
	`(?:^|[^A-Za-z0-9_])a:[0-9]+:\{`:                                                  {"a:"},
	`(?:^|[^A-Za-z0-9_])s:[0-9]+:"`:                                                   {"s:"},
	`phar://|__HALT_COMPILER\s*\(`:                                                    {"phar://", "__HALT_COMPILER"},
	`<java\s+version\s*=|class\s*=\s*"java\.lang\.ProcessBuilder"|<void\s+method\s*=`: {"<java", "java.lang.ProcessBuilder", "<void"},
	`<(?:dynamic-proxy|sorted-set|tree-map|converter)(?:\s|>)`:                        {"<dynamic-proxy", "<sorted-set", "<tree-map", "<converter"},
	`!!python/(?:object(?:/apply|/new)?|name):`:                                       {"!!python/"},
	`!![A-Za-z_][\w.]*|tag:yaml\.org,2002`:                                            {"!!", "tag:yaml.org,2002"},
	`"@(?:type|class)"\s*:|\[\s*"[a-z][\w.]+"\s*,\s*\{`:                               {"@type", "@class", "["},
	`"\$type"\s*:|TypeNameHandling`:                                                   {"$type", "TypeNameHandling"},
	`c(?:__builtin__|builtins)\n|c(?:os|posix|nt)\nsystem\n`:                          {"c__builtin__\n", "cbuiltins\n", "cos\nsystem\n", "cposix\nsystem\n", "cnt\nsystem\n"},
	`__reduce__|\bGLOBAL\b`:                                                           {"__reduce__", "GLOBAL"},
	`function\s*\([^)]*\)\s*\{[^\r\n]{0,256}child_process`:                            {"child_process"},
	`/(?:wls-wsat|_async)/|/invoker/JMXInvokerServlet`:                                {"/wls-wsat/", "/_async/", "/invoker/JMXInvokerServlet"},
	`^t3 [0-9]+\.[0-9]+`:                                                              {"t3 "},
	`InvalidDefinitionException[^\r\n]{0,256}subtype resolution was not allowed`:      {"InvalidDefinitionException"},
}

type serializationTextMatcher struct {
	rules        []serializationRule
	matcher      *ac.Matcher
	masks        []uint64
	fallback     uint64
	requestRules int
}

var serializationText = newSerializationTextMatcher(serializationRules, serializationErrors)

func newSerializationTextMatcher(request, response []serializationRule) serializationTextMatcher {
	rules := append(append([]serializationRule{}, request...), response...)
	// The mask is intentionally fixed-sized: adding enough rules to overflow
	// must fail at construction, never silently drop detections.
	if len(rules) > 64 {
		panic("serialization: at most 64 text rules supported")
	}
	m := serializationTextMatcher{rules: rules, requestRules: len(request)}
	var keywords []string
	indices := make(map[string]int)
	for i, rule := range rules {
		bit := uint64(1) << i
		if len(rule.triggers) == 0 {
			m.fallback |= bit
			continue
		}
		for _, trigger := range rule.triggers {
			if trigger == "" {
				m.fallback |= bit
				continue
			}
			index, ok := indices[trigger]
			if !ok {
				index = len(keywords)
				indices[trigger] = index
				keywords = append(keywords, trigger)
				m.masks = append(m.masks, 0)
			}
			m.masks[index] |= bit
		}
	}
	m.matcher = ac.New(keywords)
	return m
}

func (m *serializationTextMatcher) candidates(data []byte, response bool) uint64 {
	mask := m.fallback
	m.matcher.Match(data, func(index int) { mask |= m.masks[index] })
	if !response {
		mask &= (uint64(1) << m.requestRules) - 1
	}
	return mask
}

func (m *serializationTextMatcher) match(data []byte, response bool, hit func(serializationRule)) {
	mask := m.candidates(data, response)
	// Visit in original rule order, independent of AC encounter order. Output
	// ordering, deduplication and finding-limit behavior therefore stay unchanged.
	for mask != 0 {
		index := bits.TrailingZeros64(mask)
		mask &= mask - 1
		rule := m.rules[index]
		if rule.literal || rule.re.Match(data) {
			hit(rule)
		}
	}
}

// A finite, non-empty union of case-sensitive literal strings can be matched
// exactly by AC, without a second regex pass. Everything else retains its regex.
// Reject RuneError because regexp treats invalid UTF-8 bytes as that rune,
// whereas AC is byte-exact. Bound Cartesian expansion during initialization.
func serializationLiteralChoices(pattern string) ([]string, bool) {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, false
	}
	var choices func(*syntax.Regexp) ([]string, bool)
	choices = func(re *syntax.Regexp) ([]string, bool) {
		switch re.Op {
		case syntax.OpLiteral:
			if re.Flags&syntax.FoldCase != 0 || len(re.Rune) == 0 {
				return nil, false
			}
			for _, r := range re.Rune {
				if r == '\uFFFD' {
					return nil, false
				}
			}
			return []string{string(re.Rune)}, true
		case syntax.OpCapture:
			return choices(re.Sub[0])
		case syntax.OpAlternate:
			var all []string
			for _, sub := range re.Sub {
				part, ok := choices(sub)
				if !ok || len(all)+len(part) > 64 {
					return nil, false
				}
				all = append(all, part...)
			}
			return all, len(all) > 0
		case syntax.OpConcat:
			all := []string{""}
			for _, sub := range re.Sub {
				part, ok := choices(sub)
				if !ok || len(all)*len(part) > 64 {
					return nil, false
				}
				next := make([]string, 0, len(all)*len(part))
				for _, prefix := range all {
					for _, suffix := range part {
						next = append(next, prefix+suffix)
					}
				}
				all = next
			}
			return all, len(all) > 0
		default:
			return nil, false
		}
	}
	return choices(parsed)
}
