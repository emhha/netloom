package nethttp

import "testing"

func TestBuildRequestImplicitDefaultProfile(t *testing.T) {
	for _, name := range []string{"", "chrome_120"} {
		r, err := BuildRequest(RequestInput{URL: "https://example.test/", TLSProfile: name})
		if err != nil {
			t.Fatal(err)
		}
		id := r.Profile.GetClientHelloId()
		if implicit := id.IsSet(); implicit != (name == "") {
			t.Fatalf("profile=%q implicit=%v", name, implicit)
		}
	}
	if _, err := BuildRequest(RequestInput{URL: "https://example.test/", TLSProfile: "not-a-profile"}); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestBuildRequestFreshConnection(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		r, err := BuildRequest(RequestInput{URL: "https://example.test/", FreshConnection: fresh})
		if err != nil || r.FreshConnection != fresh {
			t.Fatalf("fresh=%v request=%+v err=%v", fresh, r, err)
		}
	}
}

func TestBuildRequestHTTPVersions(t *testing.T) {
	for _, version := range []string{"", "auto", "1.1", "2", "2-only"} {
		r, err := BuildRequest(RequestInput{URL: "https://example.test/", HTTPVersion: version})
		if err != nil || r.HTTPVersion != version {
			t.Fatalf("version=%q request=%+v err=%v", version, r, err)
		}
	}
	for _, in := range []RequestInput{
		{URL: "https://example.test/", HTTPVersion: "3"},
		{URL: "https://example.test/", HTTPVersion: "2.0"},
		{URL: "http://example.test/", HTTPVersion: "2-only"},
	} {
		if _, err := BuildRequest(in); err == nil {
			t.Fatalf("unsupported input accepted: %+v", in)
		}
	}
}
