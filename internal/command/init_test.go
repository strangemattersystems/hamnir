package command

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/strangemattersystems/hamnir/internal/config"
)

func TestInit(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hamnir.yaml")
	keyPath := filepath.Join(dir, ".hamnir", "key.pem")

	var buf bytes.Buffer
	if err := Init(&buf, cfgPath, keyPath, false); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := os.Stat(cfgPath); err != nil {
		t.Errorf("config not created: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key not created: %v", err)
	}
	// The generated config must be valid per our own loader.
	if _, err := config.Load(cfgPath); err != nil {
		t.Errorf("generated config does not load: %v", err)
	}
}

func TestInit_refusesExisting(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hamnir.yaml")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cfgPath, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Without force: refuse and leave the existing file untouched.
	if err := Init(&bytes.Buffer{}, cfgPath, keyPath, false); err == nil {
		t.Fatal("expected error when config exists")
	}
	if b, _ := os.ReadFile(cfgPath); string(b) != "old" {
		t.Errorf("existing config was modified: %q", b)
	}
	if _, err := os.Stat(keyPath); err == nil {
		t.Error("key should not be created when Init refuses")
	}

	// With force: overwrite.
	if err := Init(&bytes.Buffer{}, cfgPath, keyPath, true); err != nil {
		t.Fatalf("Init --force: %v", err)
	}
	if b, _ := os.ReadFile(cfgPath); string(b) == "old" {
		t.Error("config not overwritten with --force")
	}
}
