package probe

import (
	"github.com/emhha/netloom"
	"sync"
)

// FingerprintMatcher is the interface that probe calls when
// Config.EnableFingerprint is true. It is defined here (caller side) and
// implemented by the fingerprint package. Keeping the definition on the caller
// side avoids an import cycle and satisfies the architecture guideline.
//
// The service layer wires a concrete implementation before calling Run:
//
//	probe.SetFingerprintMatcher(myFPEngine)
type FingerprintMatcher interface {
	// MatchResponse runs all fingerprint engines against the given response and
	// returns the names of all detected technologies.
	MatchResponse(resp *netloom.Response) []string
}

// globalFingerprintMatcher is the package-level matcher, set once at startup.
// nil = disabled (graceful degradation when no rules are loaded).
var globalFingerprintMatcher FingerprintMatcher
var fingerprintMatcherMu sync.RWMutex

// SetFingerprintMatcher installs a FingerprintMatcher for all subsequent Run
// calls. It is safe to call from init or from a service-layer setup function.
// Pass nil to disable fingerprint detection (default).
func SetFingerprintMatcher(m FingerprintMatcher) {
	fingerprintMatcherMu.Lock()
	defer fingerprintMatcherMu.Unlock()
	globalFingerprintMatcher = m
}

// matchFingerprints returns detected technology names for the given response.
// Returns nil when fingerprinting is disabled or no matcher is registered.
func matchFingerprints(resp *netloom.Response) []string {
	fingerprintMatcherMu.RLock()
	matcher := globalFingerprintMatcher
	fingerprintMatcherMu.RUnlock()
	if matcher == nil {
		return nil
	}
	return matcher.MatchResponse(resp)
}
