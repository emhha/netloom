package dirscan

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestWordlistUsesExplicitDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "wordlists", "categories")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "custom.txt"), []byte("# ignored\nadmin\n\napi/health\n"), 0600); err != nil {
		t.Fatal(err)
	}
	words, err := LoadWordlist(filepath.Join(root, "wordlists"), "CATEGORY:custom.txt")
	if err != nil || len(words) != 2 || words[0] != "admin" || words[1] != "api/health" {
		t.Fatalf("configured dictionary not loaded: %v %v", words, err)
	}
}

func TestPinnedDirsearchWordlists(t *testing.T) {
	base := filepath.Join("wordlists", "dirsearch", "db")
	for _, preset := range []ScanPreset{PresetQuick, PresetFull, PresetLeak, PresetBackup} {
		t.Run(string(preset), func(t *testing.T) {
			words, err := BuildWordlist(&Config{WordlistDir: base, Preset: preset})
			if err != nil || len(words) == 0 {
				t.Fatalf("pinned preset is unusable: count=%d err=%v", len(words), err)
			}
		})
	}
	words, err := BuildWordlist(&Config{WordlistDir: base, Preset: PresetFramework, Framework: "wordpress"})
	if err != nil || !slices.Contains(words, "wp-admin/") {
		t.Fatalf("pinned framework dictionary is unusable: %v", err)
	}
}
