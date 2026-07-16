package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/strangemattersystems/hamnir/internal/config"
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
	st, err := NewStorage(cfg, key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProvider(cfg, st)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	srv := httptest.NewServer(providerHandler(p))
	defer srv.Close()

	t.Run("serves discovery with issuer and jwks_uri", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
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

	t.Run("serves a non-empty jwks", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			JWKSURI string `json:"jwks_uri"`
		}
		json.NewDecoder(resp.Body).Decode(&doc)
		resp.Body.Close()

		jwks, err := srv.Client().Get(doc.JWKSURI)
		if err != nil {
			t.Fatal(err)
		}
		defer jwks.Body.Close()
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
