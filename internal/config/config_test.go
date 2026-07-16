package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hamnir.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	t.Run("minimal", func(t *testing.T) {
		p := writeTemp(t, `
personas:
  - claims: { sub: usr_alice, email: alice@example.test, name: Alice Morgan, roles: [client] }
`)
		cfg, err := Load(p)
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if len(cfg.Personas) != 1 {
			t.Fatalf("Personas = %d, want 1", len(cfg.Personas))
		}
		if cfg.Personas[0].Claims["sub"] != "usr_alice" {
			t.Fatalf("sub = %v, want usr_alice", cfg.Personas[0].Claims["sub"])
		}
	})

	t.Run("full", func(t *testing.T) {
		p := writeTemp(t, `
issuer: http://localhost:5556
clients:
  - id: isen
    redirect_uris: [http://localhost:8080/auth/callback]
groups:
  - id: standard
    label: Standard users
    colour: "#3fb950"
scopes:
  roles: [roles]
personas:
  - name: Alice
    group: standard
    claims: { sub: usr_alice, roles: [client] }
`)
		cfg, err := Load(p)
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if cfg.Issuer != "http://localhost:5556" {
			t.Fatalf("Issuer = %q", cfg.Issuer)
		}
		if cfg.Clients[0].ID != "isen" {
			t.Fatalf("Clients[0].ID = %q", cfg.Clients[0].ID)
		}
		if cfg.Groups[0].Colour != "#3fb950" {
			t.Fatalf("Groups[0].Colour = %q", cfg.Groups[0].Colour)
		}
		if got := cfg.Scopes["roles"]; len(got) != 1 || got[0] != "roles" {
			t.Fatalf("Scopes[roles] = %v", got)
		}
	})

	t.Run("surfaces validation errors", func(t *testing.T) {
		p := writeTemp(t, `
personas:
  - claims: { sub: dup }
  - claims: { sub: dup }
`)
		if _, err := Load(p); !errors.Is(err, errDuplicateSub) {
			t.Fatalf("Load() = %v, want errDuplicateSub", err)
		}
	})
}
