package config

import (
	"errors"
	"io/fs"
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
	t.Parallel()

	t.Run("minimal", func(t *testing.T) {
		t.Parallel()

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
		t.Parallel()

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
		t.Parallel()

		p := writeTemp(t, `
personas:
  - claims: { sub: dup }
  - claims: { sub: dup }
`)
		if _, err := Load(p); !errors.Is(err, errDuplicateSub) {
			t.Fatalf("Load() = %v, want errDuplicateSub", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()

		_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Load() = %v, want fs.ErrNotExist", err)
		}
	})

	t.Run("rejects unknown field", func(t *testing.T) {
		t.Parallel()

		p := writeTemp(t, "bogus_field: 1\npersonas:\n  - claims: { sub: s }\n")
		if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "bogus_field") {
			t.Fatalf("Load() = %v, want error naming the unknown field", err)
		}
	})
}

func TestLoad_StaticDefaultsAndNormalises(t *testing.T) {
	t.Parallel()

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
		t.Parallel()

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
	t.Parallel()

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
			t.Parallel()

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
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{"eve.svg", "eve avatar.svg"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("<svg/>"), 0o600); err != nil {
			t.Fatal(err)
		}
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
		{
			"path traversal rejected", "issuer: http://hamnir:5556\n" + static +
				"personas:\n  - claims: { sub: usr_eve, picture: hamnir://avatars/../eve.svg }\n",
			"", ErrUnresolved,
		},
		{
			"malformed ref rejected", "issuer: http://hamnir:5556\n" + static +
				"personas:\n  - claims: { sub: usr_eve, picture: hamnir://avatars }\n",
			"", ErrUnresolved,
		},
		{"ref without static block", "issuer: http://hamnir:5556\n" + eve, "", ErrUnresolved},
		{"ref without base", static + eve, "", ErrNoBase},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

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
		t.Parallel()

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
		t.Parallel()

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

	t.Run("non-string claim preserved", func(t *testing.T) {
		t.Parallel()

		// Scalar claims that are not strings take rewriteValue's default branch
		// and pass through untouched.
		cfg, err := Load(writeTemp(t, "personas:\n  - claims: { sub: usr_eve, email_verified: true, age: 30 }\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if got := cfg.Personas[0].Claims["email_verified"]; got != true {
			t.Errorf("email_verified = %v, want true", got)
		}
	})
}

func TestLoad_Lifetimes(t *testing.T) {
	t.Parallel()

	persona := "personas:\n  - claims: { sub: s }\n"

	t.Run("defaults when omitted", func(t *testing.T) {
		t.Parallel()

		cfg, err := Load(writeTemp(t, persona))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Lifetimes != DefaultLifetimes {
			t.Errorf("Lifetimes = %+v, want DefaultLifetimes", cfg.Lifetimes)
		}
	})

	t.Run("explicit values parsed", func(t *testing.T) {
		t.Parallel()

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
		t.Parallel()

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
		t.Parallel()

		_, err := Load(writeTemp(t, persona+"lifetimes:\n  id_token: -5m\n"))
		if !errors.Is(err, errNegativeLifetime) {
			t.Fatalf("Load = %v, want errNegativeLifetime", err)
		}
	})

	t.Run("malformed duration rejected", func(t *testing.T) {
		t.Parallel()

		if _, err := Load(writeTemp(t, persona+"lifetimes:\n  access_token: fast\n")); err == nil {
			t.Fatal("Load accepted a malformed duration")
		}
	})
}

func TestConfig_Validate_Clients(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			cfg := &Config{Clients: tt.clients, Personas: []Persona{{Claims: map[string]any{"sub": "s"}}}}
			if err := cfg.Validate(); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_CollidingStaticMounts(t *testing.T) {
	t.Parallel()

	yaml := "static:\n  paths:\n    avatars: ./team\n    /avatars: ./customers\npersonas:\n  - claims: { sub: s }\n"
	if _, err := Load(writeTemp(t, yaml)); !errors.Is(err, errDuplicateStaticMount) {
		t.Fatalf("Load() err = %v, want errDuplicateStaticMount", err)
	}
}

func TestConfig_Validate_Static(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			cfg := &Config{Static: tt.static, Personas: []Persona{{Claims: map[string]any{"sub": "s"}}}}
			err := cfg.Validate()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_Audiences(t *testing.T) {
	t.Parallel()

	persona := "personas:\n  - claims: { sub: s }\n"

	t.Run("parsed at both levels", func(t *testing.T) {
		t.Parallel()

		cfg, err := Load(writeTemp(t, persona+
			"audiences: [https://api.example.test]\n"+
			"clients:\n  - id: isen\n    audiences: [https://reports.example.test, urn:example:report]\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if len(cfg.Audiences) != 1 || cfg.Audiences[0] != "https://api.example.test" {
			t.Errorf("Audiences = %v", cfg.Audiences)
		}
		if len(cfg.Clients[0].Audiences) != 2 {
			t.Errorf("client Audiences = %v", cfg.Clients[0].Audiences)
		}
	})

	t.Run("absent stays nil, explicit empty stays non-nil", func(t *testing.T) {
		t.Parallel()

		cfg, err := Load(writeTemp(t, persona+
			"clients:\n  - id: inherit\n  - id: optout\n    audiences: []\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Clients[0].Audiences != nil {
			t.Errorf("absent field decoded non-nil: %v", cfg.Clients[0].Audiences)
		}
		if cfg.Clients[1].Audiences == nil {
			t.Error("explicit [] decoded as nil — opt-out is indistinguishable from inherit")
		}
	})

	tests := []struct {
		name    string
		yaml    string
		wantErr error
	}{
		{"empty global entry", "audiences: [\"\"]\n", errEmptyAudience},
		{"duplicate global entry", "audiences: [a, a]\n", errDuplicateAudience},
		{"empty client entry", "clients:\n  - id: c\n    audiences: [\"\"]\n", errEmptyAudience},
		{"duplicate client entry", "clients:\n  - id: c\n    audiences: [a, a]\n", errDuplicateAudience},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := Load(writeTemp(t, persona+tt.yaml)); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Load = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
