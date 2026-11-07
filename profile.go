package netloom

import (
	"github.com/bogdanfinn/tls-client/profiles"
	"maps"
	"slices"
)

// ProfileByName resolves a tls-client browser profile from its registry name
// (e.g. "chrome_131", "firefox_120", "safari_16_0"). An empty or unknown name
// falls back to profiles.DefaultClientProfile so callers never have to guard
// against a zero ClientProfile.
//
// It exists so upper layers (pkg/probe, pkg/dirscan) can keep configuring the
// fingerprint with a plain string while netloom owns the tls-client dependency.
func ProfileByName(name string) profiles.ClientProfile {
	if name == "" {
		return profiles.DefaultClientProfile
	}
	if p, ok := profiles.MappedTLSClients[name]; ok {
		return p
	}
	return profiles.DefaultClientProfile
}

func KnownProfile(name string) bool {
	if name == "" {
		return true
	}
	_, ok := profiles.MappedTLSClients[name]
	return ok
}

// cloneClientProfile snapshots exported profile collections. Factories and any
// captured state still have to be immutable, as do caller-supplied profiles.
func cloneClientProfile(p profiles.ClientProfile) profiles.ClientProfile {
	id := p.GetClientHelloId()
	if id.Seed != nil {
		seed := *id.Seed
		id.Seed = &seed
	}
	if id.Weights != nil {
		weights := *id.Weights
		id.Weights = &weights
	}
	header := p.GetHeaderPriority()
	if header != nil {
		h := *header
		header = &h
	}
	return profiles.NewClientProfile(id, maps.Clone(p.GetSettings()), slices.Clone(p.GetSettingsOrder()), slices.Clone(p.GetPseudoHeaderOrder()), p.GetConnectionFlow(), slices.Clone(p.GetPriorities()), header, p.GetStreamID(), p.GetAllowHTTP(), maps.Clone(p.GetHttp3Settings()), slices.Clone(p.GetHttp3SettingsOrder()), p.GetHttp3PriorityParam(), slices.Clone(p.GetHttp3PseudoHeaderOrder()), p.GetHttp3SendGreaseFrames())
}

// profileOrDefault returns p unless it is the zero ClientProfile, in which case
// profiles.DefaultClientProfile is substituted. A zero ClientProfile carries an
// empty ClientHelloID whose handshake spec is unusable, so this guard keeps
// callers from having to set a profile explicitly.
func profileOrDefault(p profiles.ClientProfile) profiles.ClientProfile {
	id := p.GetClientHelloId()
	// ClientHelloID.IsSet reports true when both Client and Version are empty,
	// i.e. the profile was never initialised.
	if id.IsSet() {
		return profiles.DefaultClientProfile
	}
	return p
}
