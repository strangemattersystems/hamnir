package server

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/strangemattersystems/hamnir/internal/config"
)

func TestNew(t *testing.T) {
	cfg := &config.Config{Personas: []config.Persona{
		{Name: "Alice", Claims: map[string]any{"sub": "usr_alice"}},
	}}
	srv, _ := newServer(t, cfg)

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

func TestNew_ServesStatic(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "eve.svg"), []byte("<svg/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Issuer:   "http://hamnir:5556",
		Static:   config.Static{Prefix: "hamnir://", Paths: map[string]string{"avatars": dir}},
		Personas: []config.Persona{{Claims: map[string]any{"sub": "usr_eve"}}},
	}
	srv, _ := newServer(t, cfg)

	tests := []struct {
		name string
		path string
		want int
	}{
		{"served", "/.static/avatars/eve.svg", http.StatusOK},
		{"missing", "/.static/avatars/nope.svg", http.StatusNotFound},
		{"no listing", "/.static/avatars/", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := srv.Client().Get(srv.URL + tt.path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tt.want {
				t.Errorf("GET %s = %d, want %d", tt.path, resp.StatusCode, tt.want)
			}
			if tt.want == http.StatusOK && resp.Header.Get("Content-Type") != "image/svg+xml" {
				t.Errorf("content-type = %q, want image/svg+xml", resp.Header.Get("Content-Type"))
			}
		})
	}
}
