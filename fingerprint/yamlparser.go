package fingerprint

import (
	"bufio"
	"bytes"
	"strings"
)

// parseWebfingerYAML parses the simple webfinger YAML format:
//
//	CmsName:
//	    - rule expression 1
//	    - rule expression 2
//
// It returns a map[cmsName][]ruleExpression. This format is a strict subset of
// YAML (no anchors, no multi-line scalars, no nested maps) so a hand-written
// parser is adequate and avoids an external dependency.
func parseWebfingerYAML(data []byte) (map[string][]string, error) {
	result := make(map[string][]string)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1<<20), 1<<20)

	var currentKey string

	for scanner.Scan() {
		line := scanner.Text()

		// Skip blank lines and comments.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// List item.
		if strings.HasPrefix(trimmed, "- ") {
			if currentKey == "" {
				continue
			}
			item := strings.TrimPrefix(trimmed, "- ")
			item = strings.TrimSpace(item)
			// Handle quoted values (YAML block scalar items may be quoted).
			item = unquoteYAMLScalar(item)
			if item != "" {
				result[currentKey] = append(result[currentKey], item)
			}
			continue
		}

		// Map key (ends with ':').
		if idx := strings.Index(trimmed, ":"); idx != -1 {
			key := strings.TrimSpace(trimmed[:idx])
			// Trailing content after ':' means inline value — not used in this format.
			if key != "" {
				currentKey = key
				if _, exists := result[currentKey]; !exists {
					result[currentKey] = nil
				}
			}
			continue
		}
	}

	return result, scanner.Err()
}

// unquoteYAMLScalar strips optional surrounding single or double quotes from a
// YAML scalar value. It handles the common case in webfinger rules where the
// rule strings themselves are not quoted at the YAML level (they look like
// `body="wp-content"` which is a plain YAML scalar).
func unquoteYAMLScalar(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') ||
			(s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
