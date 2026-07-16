package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/provider"
)

func TestNew(t *testing.T) {
	cfg := &config.Config{Personas: []config.Persona{
		{Name: "Alice", Claims: map[string]any{"sub": "usr_alice"}},
	}}
	key, err := provider.LoadOrGenerateKey(filepath.Join(t.TempDir(), "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(cfg, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	t.Run("serves discovery", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discovery status %d", resp.StatusCode)
		}
	})

	t.Run("serves login picker", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/login?authRequestID=x")
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login status %d", resp.StatusCode)
		}
	})
}
