package command

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strangemattersystems/hamnir/internal/config"
)

func TestInit(t *testing.T) {
	t.Parallel()

	t.Run("writes a loadable config", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "hamnir.yaml")

		var buf bytes.Buffer
		if err := Init(&buf, cfgPath, false); err != nil {
			t.Fatalf("Init: %v", err)
		}

		raw, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatalf("config not created: %v", err)
		}
		if strings.Contains(string(raw), signingKeyPlaceholder) {
			t.Error("placeholder not substituted")
		}

		cfg, err := config.Load(cfgPath)
		if err != nil {
			t.Fatalf("generated config does not load: %v", err)
		}
		if cfg.Key == nil {
			t.Error("generated config has no parsed signing key")
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Errorf("Init created %d entries, want just the config: %v", len(entries), entries)
		}
	})

	t.Run("refuses an existing file unless forced", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "hamnir.yaml")
		if err := os.WriteFile(cfgPath, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}

		// Without force: refuse and leave the existing file untouched.
		if err := Init(&bytes.Buffer{}, cfgPath, false); err == nil {
			t.Fatal("expected error when config exists")
		}
		if b, _ := os.ReadFile(cfgPath); string(b) != "old" {
			t.Errorf("existing config was modified: %q", b)
		}

		// With force: overwrite.
		if err := Init(&bytes.Buffer{}, cfgPath, true); err != nil {
			t.Fatalf("Init --force: %v", err)
		}
		if b, _ := os.ReadFile(cfgPath); string(b) == "old" {
			t.Error("config not overwritten with --force")
		}
	})

	t.Run("fails when the config dir cannot be created", func(t *testing.T) {
		t.Parallel()

		// A file where a parent directory is expected makes MkdirAll fail, so
		// Init must surface the error rather than write nothing silently.
		blocker := filepath.Join(t.TempDir(), "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := Init(&bytes.Buffer{}, filepath.Join(blocker, "hamnir.yaml"), false); err == nil {
			t.Fatal("Init into a path under a file should fail")
		}
	})

	// Guards the embedded template against losing the substitution target —
	// without it Init would silently emit a config whose signing_key is the
	// placeholder text.
	t.Run("template retains the placeholder", func(t *testing.T) {
		t.Parallel()

		if !strings.Contains(minimalConfig, "signing_key: "+signingKeyPlaceholder) {
			t.Fatal("init_config.yaml is missing the signing_key placeholder line")
		}
	})
}
