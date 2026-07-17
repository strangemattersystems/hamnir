package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// testSigningKey is generated once; RSA-2048 generation is too slow to repeat
// in every subtest.
var testSigningKey = sync.OnceValues(GenerateSigningKey)

// writeTemp writes body to a temp config file, appending a valid signing_key
// unless the body brings its own (so key-specific tests stay in control).
func writeTemp(t *testing.T, body string) string {
	t.Helper()
	if !strings.Contains(body, "signing_key:") {
		key, err := testSigningKey()
		if err != nil {
			t.Fatal(err)
		}
		body += "\nsigning_key: " + key + "\n"
	}
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

func TestLoad_StaticDefaultsAndNormalises(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	key, err := testSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	yaml := `
static:
  paths:
    /avatars: ./avatars
personas:
  - claims: { sub: usr_alice }
signing_key: ` + key + `
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Static.Prefix != "hamnir://" {
		t.Errorf("prefix = %q, want hamnir://", cfg.Static.Prefix)
	}
	if _, ok := cfg.Static.Paths["avatars"]; !ok {
		t.Errorf("leading slash not stripped from mount key: %v", cfg.Static.Paths)
	}

	t.Run("prefix defaults without paths", func(t *testing.T) {
		cfg, err := Load(writeTemp(t, "personas:\n  - claims: { sub: s }\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Static.Prefix != "hamnir://" {
			t.Errorf("prefix = %q, want hamnir://", cfg.Static.Prefix)
		}
	})
}

func TestLoad_NormalisesURLs(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		wantIssuer  string
		wantBrowser string
	}{
		{
			"trailing slashes trimmed",
			"issuer: http://localhost:5556/\nbrowser_url: http://localhost:9999/\npersonas:\n  - claims: { sub: s }\n",
			"http://localhost:5556", "http://localhost:9999",
		},
		{
			"already trimmed untouched",
			"issuer: http://localhost:5556\npersonas:\n  - claims: { sub: s }\n",
			"http://localhost:5556", "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(writeTemp(t, tt.yaml))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Issuer != tt.wantIssuer {
				t.Errorf("Issuer = %q, want %q", cfg.Issuer, tt.wantIssuer)
			}
			if cfg.BrowserURL != tt.wantBrowser {
				t.Errorf("BrowserURL = %q, want %q", cfg.BrowserURL, tt.wantBrowser)
			}
		})
	}
}

func TestLoad_ResolvesStaticClaims(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "eve.svg"), []byte("<svg/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	static := "static:\n  paths: { avatars: " + dir + " }\n"
	eve := "personas:\n  - claims: { sub: usr_eve, picture: hamnir://avatars/eve.svg }\n"

	tests := []struct {
		name    string
		yaml    string
		want    string
		wantErr error
	}{
		{
			"resolves against issuer", "issuer: http://hamnir:5556\n" + static + eve,
			"http://hamnir:5556/.static/avatars/eve.svg", nil,
		},
		{
			"browser_url wins", "issuer: http://hamnir:5556\nbrowser_url: http://localhost:5556\n" + static + eve,
			"http://localhost:5556/.static/avatars/eve.svg", nil,
		},
		{
			"non-marker untouched", "issuer: http://hamnir:5556\n" + static +
				"personas:\n  - claims: { sub: usr_eve, picture: https://example.test/eve.png }\n",
			"https://example.test/eve.png", nil,
		},
		{
			"missing file", "issuer: http://hamnir:5556\n" + static +
				"personas:\n  - claims: { sub: usr_eve, picture: hamnir://avatars/missing.svg }\n",
			"", ErrUnresolved,
		},
		{
			"unknown mount", "issuer: http://hamnir:5556\n" + static +
				"personas:\n  - claims: { sub: usr_eve, picture: hamnir://nope/eve.svg }\n",
			"", ErrUnresolved,
		},
		{"ref without static block", "issuer: http://hamnir:5556\n" + eve, "", ErrUnresolved},
		{"ref without base", static + eve, "", ErrNoBase},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(writeTemp(t, tt.yaml))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Load() err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := cfg.Personas[0].Claims["picture"]; got != tt.want {
				t.Errorf("picture = %v, want %q", got, tt.want)
			}
		})
	}

	t.Run("special characters escaped", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(dir, "eve avatar.svg"), []byte("<svg/>"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(writeTemp(t, "issuer: http://hamnir:5556\n"+static+
			"personas:\n  - claims: { sub: usr_eve, picture: 'hamnir://avatars/eve avatar.svg' }\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		got := cfg.Personas[0].Claims["picture"]
		if got != "http://hamnir:5556/.static/avatars/eve%20avatar.svg" {
			t.Errorf("picture = %v, want the escaped URL", got)
		}
	})

	t.Run("nested value resolved", func(t *testing.T) {
		cfg, err := Load(writeTemp(t, "issuer: http://hamnir:5556\n"+static+
			"personas:\n  - claims: { sub: usr_eve, profile: { avatar: hamnir://avatars/eve.svg } }\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		got := cfg.Personas[0].Claims["profile"].(map[string]any)["avatar"]
		if got != "http://hamnir:5556/.static/avatars/eve.svg" {
			t.Errorf("nested avatar = %v", got)
		}
	})
}

func TestLoad_Lifetimes(t *testing.T) {
	persona := "personas:\n  - claims: { sub: s }\n"

	t.Run("defaults when omitted", func(t *testing.T) {
		cfg, err := Load(writeTemp(t, persona))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Lifetimes != DefaultLifetimes {
			t.Errorf("Lifetimes = %+v, want DefaultLifetimes", cfg.Lifetimes)
		}
	})

	t.Run("explicit values parsed", func(t *testing.T) {
		cfg, err := Load(writeTemp(t, persona+
			"lifetimes:\n  access_token: 90s\n  id_token: 2h\n  refresh_token: 720h\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		want := Lifetimes{AccessToken: 90 * time.Second, IDToken: 2 * time.Hour, RefreshToken: 720 * time.Hour}
		if cfg.Lifetimes != want {
			t.Errorf("Lifetimes = %+v, want %+v", cfg.Lifetimes, want)
		}
	})

	t.Run("partial config keeps other defaults", func(t *testing.T) {
		cfg, err := Load(writeTemp(t, persona+"lifetimes:\n  access_token: 30s\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Lifetimes.AccessToken != 30*time.Second {
			t.Errorf("AccessToken = %v, want 30s", cfg.Lifetimes.AccessToken)
		}
		if cfg.Lifetimes.IDToken != DefaultLifetimes.IDToken || cfg.Lifetimes.RefreshToken != DefaultLifetimes.RefreshToken {
			t.Errorf("unset fields not defaulted: %+v", cfg.Lifetimes)
		}
	})

	t.Run("negative rejected", func(t *testing.T) {
		_, err := Load(writeTemp(t, persona+"lifetimes:\n  id_token: -5m\n"))
		if !errors.Is(err, errNegativeLifetime) {
			t.Fatalf("Load = %v, want errNegativeLifetime", err)
		}
	})

	t.Run("malformed duration rejected", func(t *testing.T) {
		if _, err := Load(writeTemp(t, persona+"lifetimes:\n  access_token: fast\n")); err == nil {
			t.Fatal("Load accepted a malformed duration")
		}
	})
}

func TestConfig_Validate_Clients(t *testing.T) {
	tests := []struct {
		name    string
		clients []Client
		wantErr error
	}{
		{"ok", []Client{{ID: "isen", RedirectURIs: []string{"http://app.test/cb"}}}, nil},
		{"missing id", []Client{{RedirectURIs: []string{"http://app.test/cb"}}}, errEmptyClientID},
		{"duplicate id", []Client{
			{ID: "isen", RedirectURIs: []string{"http://app.test/cb"}},
			{ID: "isen", RedirectURIs: []string{"http://other.test/cb"}},
		}, errDuplicateClientID},
		// A back-channel-only client (introspection/revocation) never
		// redirects; id + secret is a complete registration.
		{"redirect-less client ok", []Client{{ID: "introspector", Secret: "s3cret"}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Clients: tt.clients, Personas: []Persona{{Claims: map[string]any{"sub": "s"}}}}
			if err := cfg.Validate(); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_CollidingStaticMounts(t *testing.T) {
	yaml := "static:\n  paths:\n    avatars: ./team\n    /avatars: ./customers\npersonas:\n  - claims: { sub: s }\n"
	if _, err := Load(writeTemp(t, yaml)); !errors.Is(err, errDuplicateStaticMount) {
		t.Fatalf("Load() err = %v, want errDuplicateStaticMount", err)
	}
}

func TestConfig_Validate_Static(t *testing.T) {
	tests := []struct {
		name    string
		static  Static
		wantErr error
	}{
		{"ok", Static{Prefix: "hamnir://", Paths: map[string]string{"avatars": "./a"}}, nil},
		{"empty mount", Static{Prefix: "hamnir://", Paths: map[string]string{"": "./a"}}, errEmptyStaticMount},
		{"traversal mount", Static{Prefix: "hamnir://", Paths: map[string]string{"../x": "./a"}}, errStaticMountTraversal},
		{"slash mount", Static{Prefix: "hamnir://", Paths: map[string]string{"img/avatars": "./a"}}, errStaticMountSlash},
		{"empty dir", Static{Prefix: "hamnir://", Paths: map[string]string{"avatars": ""}}, errEmptyStaticDir},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Static: tt.static, Personas: []Persona{{Claims: map[string]any{"sub": "s"}}}}
			err := cfg.Validate()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
