package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/server"
)

func TestNew(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{Personas: []config.Persona{
		{Name: "Alice", Claims: map[string]any{"sub": "usr_alice"}},
	}}
	srv, _ := newServer(t, cfg)

	t.Run("serves discovery", func(t *testing.T) {
		t.Parallel()

		resp, err := srv.Client().Get(srv.URL + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discovery status %d", resp.StatusCode)
		}
	})

	t.Run("serves login picker", func(t *testing.T) {
		t.Parallel()

		resp, err := srv.Client().Get(srv.URL + "/login?authRequestID=x")
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login status %d", resp.StatusCode)
		}
	})

	t.Run("serves /up with the version string", func(t *testing.T) {
		t.Parallel()

		resp, err := srv.Client().Get(srv.URL + "/up")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("/up status %d, want 200", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Errorf("content-type = %q, want text/plain", ct)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != testVersion {
			t.Errorf("body = %q, want %q", body, testVersion)
		}
	})

	t.Run("propagates a construction failure", func(t *testing.T) {
		t.Parallel()

		// A config with no signing key cannot build the token signer, so New
		// must surface the error rather than return a half-built handler.
		if _, err := server.New(&config.Config{Lifetimes: config.DefaultLifetimes}, testVersion); err == nil {
			t.Fatal("New with a nil signing key should fail")
		}
	})

	t.Run("serves static assets", func(t *testing.T) {
		t.Parallel()

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
				t.Parallel()

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
	})
}

func TestDiscoveryDocument(t *testing.T) {
	t.Parallel()

	srv, client := newServer(t, aliceConfig())
	resp, err := client.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status %d", resp.StatusCode)
	}
	var doc struct {
		ResponseTypes []string `json:"response_types_supported"`
		GrantTypes    []string `json:"grant_types_supported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}

	t.Run("advertises only the code response type", func(t *testing.T) {
		if !slices.Equal(doc.ResponseTypes, []string{"code"}) {
			t.Errorf("response_types_supported = %q, want [code]", doc.ResponseTypes)
		}
	})

	t.Run("does not advertise the implicit grant", func(t *testing.T) {
		if slices.Contains(doc.GrantTypes, "implicit") {
			t.Errorf("grant_types_supported advertises implicit: %q", doc.GrantTypes)
		}
	})

	t.Run("keeps the served grants", func(t *testing.T) {
		for _, want := range []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange", "urn:ietf:params:oauth:grant-type:device_code"} {
			if !slices.Contains(doc.GrantTypes, want) {
				t.Errorf("grant_types_supported missing %q (got %q)", want, doc.GrantTypes)
			}
		}
	})
}
