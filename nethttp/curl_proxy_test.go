package nethttp

import (
	"strings"
	"testing"
)

func TestCurlUnsupportedOptionsDoNotEchoProxySecrets(t *testing.T) {
	for _, option := range []string{
		"-xhttp://user:secret@host:8080",
		"-x http://user:secret@host:8080",
		"--proxy=http://user:secret@host:8080",
		"--proxy http://user:secret@host:8080",
		"--unknown-secret",
		"-zunknown-secret",
	} {
		_, err := ParseCurl("curl " + option + " https://example.test/")
		if err == nil {
			t.Fatalf("accepted unsupported option %s", option)
		}
		for _, sensitive := range []string{"secret", "user", "host:8080", option} {
			if strings.Contains(err.Error(), sensitive) {
				t.Fatalf("unsafe curl error: %v", err)
			}
		}
	}
}
