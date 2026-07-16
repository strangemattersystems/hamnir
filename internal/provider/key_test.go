package provider

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateKey(t *testing.T) {
	t.Run("generates and reuses", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "sub", "key.pem")

		generated, err := LoadOrGenerateKey(p)
		if err != nil {
			t.Fatalf("first call (generate): %v", err)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("key was not persisted to %s: %v", p, err)
		}

		reloaded, err := LoadOrGenerateKey(p)
		if err != nil {
			t.Fatalf("second call (reload): %v", err)
		}
		if generated.N.Cmp(reloaded.N) != 0 {
			t.Fatal("expected the persisted key to be reused on reload")
		}
	})

	t.Run("rejects invalid key file", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "key.pem")
		if err := os.WriteFile(p, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrGenerateKey(p); !errors.Is(err, errInvalidKey) {
			t.Fatalf("want errInvalidKey, got %v", err)
		}
	})

	t.Run("surfaces read errors instead of regenerating", func(t *testing.T) {
		// A directory used as a key path should surface as a filesystem level
		// read error.
		dir := t.TempDir()
		_, err := LoadOrGenerateKey(dir)
		if err == nil {
			t.Fatal("expected an error when the path is not a regular file")
		}
		if errors.Is(err, errInvalidKey) {
			t.Fatalf("a read error should not be classified as an invalid key: %v", err)
		}
	})
}

func TestGenerateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "key.pem")

	key, err := GenerateKey(path)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if key == nil {
		t.Fatal("nil key")
	}

	loaded, err := LoadOrGenerateKey(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if loaded.N.Cmp(key.N) != 0 {
		t.Error("reloaded key differs from generated")
	}

	// A second call overwrites with a fresh key.
	key2, err := GenerateKey(path)
	if err != nil {
		t.Fatalf("GenerateKey overwrite: %v", err)
	}
	if key2.N.Cmp(key.N) == 0 {
		t.Error("expected a fresh key on overwrite")
	}
}
