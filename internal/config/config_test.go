package config

import (
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

func TestLoadMinimal(t *testing.T) {
	p := writeTemp(t, `
personas:
  - claims: { sub: usr_alice, email: alice@example.test, name: Alice Morgan, roles: [client] }
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Personas) != 1 {
		t.Fatalf("want 1 persona, got %d", len(cfg.Personas))
	}
	if cfg.Personas[0].Claims["sub"] != "usr_alice" {
		t.Fatalf("sub = %v", cfg.Personas[0].Claims["sub"])
	}
}

func TestLoadFull(t *testing.T) {
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
		t.Fatalf("Load: %v", err)
	}
	if cfg.Issuer != "http://localhost:5556" {
		t.Fatalf("issuer = %q", cfg.Issuer)
	}
	if cfg.Clients[0].ID != "isen" {
		t.Fatalf("client id = %q", cfg.Clients[0].ID)
	}
	if cfg.Groups[0].Colour != "#3fb950" {
		t.Fatalf("colour = %q", cfg.Groups[0].Colour)
	}
	if got := cfg.Scopes["roles"]; len(got) != 1 || got[0] != "roles" {
		t.Fatalf("scopes[roles] = %v", got)
	}
}
