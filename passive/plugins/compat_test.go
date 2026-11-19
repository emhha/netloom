package plugins_test

import (
	"testing"

	"github.com/emhha/netloom/passive/plugins"
	"github.com/emhha/netloom/passive/plugins/serialization"
)

func TestSerializationAliases(t *testing.T) {
	var legacy *plugins.Serialization = serialization.New()
	var finding serialization.Finding = plugins.SerializationFinding{Format: "example"}
	if legacy.Metadata().ID != "serialization" || finding.Format != "example" {
		t.Fatal("legacy serialization names do not reference the plugin types")
	}
}
