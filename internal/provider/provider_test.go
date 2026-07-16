package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/persona"
)

func TestCryptoKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("deterministic for a given key", func(t *testing.T) {
		first := cryptoKey(key)
		second := cryptoKey(key)
		if first != second {
			t.Fatal("cryptoKey must be stable for the same key")
		}
	})
}

// providerHandler exposes the provider's http.Handler for testing. *op.Provider
// implements http.Handler directly.
func providerHandler(p *op.Provider) http.Handler { return p }

func TestProvider(t *testing.T) {
	cfg := &config.Config{Personas: []config.Persona{
		{Claims: map[string]any{"sub": "usr_alice", "email": "a@b.test"}},
	}}
	key, err := LoadOrGenerateKey(filepath.Join(t.TempDir(), "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := NewStorage(cfg, persona.NewSet(cfg), key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProvider(cfg, st)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	srv := httptest.NewServer(providerHandler(p))
	defer srv.Close()

	t.Run("discovery", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discovery status %d", resp.StatusCode)
		}
		var doc struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		if doc.Issuer == "" || doc.JWKSURI == "" {
			t.Fatalf("discovery missing fields: %+v", doc)
		}
	})

	t.Run("jwks", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			JWKSURI string `json:"jwks_uri"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&doc)
		_ = resp.Body.Close()

		jwks, err := srv.Client().Get(doc.JWKSURI)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = jwks.Body.Close() }()
		var set struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.NewDecoder(jwks.Body).Decode(&set); err != nil {
			t.Fatal(err)
		}
		if len(set.Keys) == 0 {
			t.Fatal("jwks has no keys")
		}
	})
}

func TestNewProvider_BrowserURL(t *testing.T) {
	const issuer = "http://hamnir:5556"
	const browser = "http://localhost:5556"

	// op's WithCustom*Endpoint options mutate the package-global op.DefaultEndpoints
	// in place. hamnir runs a single provider per process so that is harmless at
	// runtime, but a test binary builds several providers — snapshot and restore the
	// global so this test is hermetic and cannot leak into others.
	snapshot := *op.DefaultEndpoints
	t.Cleanup(func() { *op.DefaultEndpoints = snapshot })

	tests := []struct {
		name          string
		browserURL    string
		wantFrontHost string // authorization_endpoint + end_session_endpoint
		wantBackHost  string // token_endpoint
	}{
		{"split when browser_url set", browser, "localhost:5556", "hamnir:5556"},
		{"unchanged when unset", "", "hamnir:5556", "hamnir:5556"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			*op.DefaultEndpoints = snapshot // reset the global before each case
			cfg := &config.Config{Issuer: issuer, BrowserURL: tt.browserURL}
			key, err := LoadOrGenerateKey(filepath.Join(t.TempDir(), "key.pem"))
			if err != nil {
				t.Fatal(err)
			}
			st, err := NewStorage(cfg, persona.NewSet(cfg), key)
			if err != nil {
				t.Fatal(err)
			}
			p, err := NewProvider(cfg, st)
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(providerHandler(p))
			defer srv.Close()

			resp, err := srv.Client().Get(srv.URL + "/.well-known/openid-configuration")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			var doc map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
				t.Fatal(err)
			}

			for field, want := range map[string]string{
				"authorization_endpoint": tt.wantFrontHost,
				"end_session_endpoint":   tt.wantFrontHost,
				"token_endpoint":         tt.wantBackHost,
			} {
				if got := endpointHost(t, doc[field]); got != want {
					t.Errorf("%s host = %q, want %q", field, got, want)
				}
			}
		})
	}
}

func endpointHost(t *testing.T, v any) string {
	t.Helper()
	s, _ := v.(string)
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u.Host
}
