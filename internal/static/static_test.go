package static

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/strangemattersystems/hamnir/internal/config"
)

func writeFile(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("<svg/>"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBase(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.Config
		want string
	}{
		{"browser_url wins", config.Config{Issuer: "http://hamnir:5556", BrowserURL: "http://localhost:5556/"}, "http://localhost:5556"},
		{"issuer fallback", config.Config{Issuer: "http://hamnir:5556"}, "http://hamnir:5556"},
		{"dynamic empty", config.Config{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Base(&tt.cfg); got != tt.want {
				t.Errorf("Base() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRewriteClaims(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "eve.svg")

	newCfg := func() *config.Config {
		return &config.Config{
			Static: config.Static{Prefix: "hamnir://", Paths: map[string]string{"avatars": dir}},
			Personas: []config.Persona{{Claims: map[string]any{
				"sub":     "usr_eve",
				"picture": "hamnir://avatars/eve.svg",
				"website": "https://example.test/eve", // absolute — untouched
				"name":    "Eve",                      // plain — untouched
			}}},
		}
	}

	t.Run("resolves against base", func(t *testing.T) {
		cfg := newCfg()
		if err := RewriteClaims(cfg, "http://localhost:5556"); err != nil {
			t.Fatal(err)
		}
		c := cfg.Personas[0].Claims
		if c["picture"] != "http://localhost:5556/.static/avatars/eve.svg" {
			t.Errorf("picture = %v", c["picture"])
		}
		if c["website"] != "https://example.test/eve" || c["name"] != "Eve" {
			t.Errorf("non-marker values were rewritten: %v", c)
		}
	})

	t.Run("nested value resolved", func(t *testing.T) {
		cfg := newCfg()
		cfg.Personas[0].Claims["profile"] = map[string]any{"avatar": "hamnir://avatars/eve.svg"}
		if err := RewriteClaims(cfg, "http://localhost:5556"); err != nil {
			t.Fatal(err)
		}
		got := cfg.Personas[0].Claims["profile"].(map[string]any)["avatar"]
		if got != "http://localhost:5556/.static/avatars/eve.svg" {
			t.Errorf("nested avatar = %v", got)
		}
	})

	t.Run("missing file errors", func(t *testing.T) {
		cfg := newCfg()
		cfg.Personas[0].Claims["picture"] = "hamnir://avatars/missing.svg"
		if err := RewriteClaims(cfg, "http://localhost:5556"); !errors.Is(err, ErrUnresolved) {
			t.Fatalf("err = %v, want ErrUnresolved", err)
		}
	})

	t.Run("unknown mount errors", func(t *testing.T) {
		cfg := newCfg()
		cfg.Personas[0].Claims["picture"] = "hamnir://nope/eve.svg"
		if err := RewriteClaims(cfg, "http://localhost:5556"); !errors.Is(err, ErrUnresolved) {
			t.Fatalf("err = %v, want ErrUnresolved", err)
		}
	})

	t.Run("empty base with reference errors", func(t *testing.T) {
		cfg := newCfg()
		if err := RewriteClaims(cfg, ""); !errors.Is(err, ErrNoBase) {
			t.Fatalf("err = %v, want ErrNoBase", err)
		}
	})

	t.Run("no references is a no-op", func(t *testing.T) {
		cfg := &config.Config{Personas: []config.Persona{{Claims: map[string]any{"sub": "s", "name": "x"}}}}
		if err := RewriteClaims(cfg, ""); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
