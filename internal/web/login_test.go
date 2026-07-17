package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/persona"
	"github.com/strangemattersystems/hamnir/internal/provider"
)

func newTestHandler(complete func(string, string) error) *Handler {
	cfg := &config.Config{
		Groups:   []config.Group{{ID: "standard", Label: "Standard", Colour: "#3fb950"}},
		Personas: []config.Persona{{Name: "Alice", Group: "standard", Claims: map[string]any{"sub": "usr_alice"}}},
	}
	return NewHandler(persona.NewSet(cfg), cfg, complete, "/authorize/callback")
}

func TestHandler(t *testing.T) {
	t.Run("renders picker", func(t *testing.T) {
		h := newTestHandler(func(_, _ string) error { return nil })
		mux := http.NewServeMux()
		h.Routes(mux)
		req := httptest.NewRequest(http.MethodGet, "/login?authRequestID=abc", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Alice") {
			t.Fatalf("expected picker with Alice, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("select redirects", func(t *testing.T) {
		var got string
		h := newTestHandler(func(_, sub string) error { got = sub; return nil })
		mux := http.NewServeMux()
		h.Routes(mux)
		form := url.Values{"authRequestID": {"abc"}, "sub": {"usr_alice"}}
		req := httptest.NewRequest(http.MethodPost, "/login/select", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if got != "usr_alice" {
			t.Fatalf("complete not called with usr_alice, got %q", got)
		}
		if rec.Code != http.StatusFound {
			t.Fatalf("expected redirect (302), got %d", rec.Code)
		}
		loc := rec.Header().Get("Location")
		if !strings.Contains(loc, "/authorize/callback") || !strings.Contains(loc, "abc") {
			t.Fatalf("unexpected redirect location %q", loc)
		}
	})

	t.Run("expired auth request gets a friendly 400", func(t *testing.T) {
		h := newTestHandler(func(_, _ string) error {
			return fmt.Errorf("auth request %q: %w", "abc", provider.ErrAuthRequestNotFound)
		})
		mux := http.NewServeMux()
		h.Routes(mux)
		form := url.Values{"authRequestID": {"abc"}, "sub": {"usr_alice"}}
		req := httptest.NewRequest(http.MethodPost, "/login/select", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for an expired auth request, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "expired") {
			t.Fatalf("expected a friendly expiry message, got %q", rec.Body.String())
		}
	})

	t.Run("unknown persona", func(t *testing.T) {
		h := newTestHandler(func(_, _ string) error { return nil })
		mux := http.NewServeMux()
		h.Routes(mux)
		form := url.Values{"authRequestID": {"abc"}, "sub": {"nobody"}}
		req := httptest.NewRequest(http.MethodPost, "/login/select", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for unknown persona, got %d", rec.Code)
		}
	})
}

func TestBuildPage_GroupOrder(t *testing.T) {
	groups := []config.Group{{ID: "admins", Label: "Admins"}, {ID: "customers", Label: "Customers"}}
	p := func(name, group string) config.Persona {
		return config.Persona{Name: name, Group: group, Claims: map[string]any{"sub": "usr_" + name}}
	}
	tests := []struct {
		name     string
		personas []config.Persona
		want     []string
	}{
		{"config order wins", []config.Persona{p("cara", "customers"), p("ada", "admins")}, []string{"Admins", "Customers"}},
		{"ungrouped appended last", []config.Persona{p("solo", ""), p("ada", "admins")}, []string{"Admins", ""}},
		{"personaless group omitted", []config.Persona{p("cara", "customers")}, []string{"Customers"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{Groups: groups, Personas: tt.personas}
			h := NewHandler(persona.NewSet(cfg), cfg, func(string, string) error { return nil }, "/cb")
			var got []string
			for _, g := range h.buildPage("x").Groups {
				got = append(got, g.Label)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("group labels = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildPage_Avatar(t *testing.T) {
	render := func(cfg *config.Config) string {
		h := NewHandler(persona.NewSet(cfg), cfg, func(string, string) error { return nil }, "/cb")
		var b strings.Builder
		if err := h.tmpl.ExecuteTemplate(&b, "picker.html.tmpl", h.buildPage("abc")); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	t.Run("with picture", func(t *testing.T) {
		cfg := &config.Config{Personas: []config.Persona{{Name: "Eve", Claims: map[string]any{
			"sub": "usr_eve", "picture": "http://h/.static/avatars/eve.svg",
		}}}}
		if out := render(cfg); !strings.Contains(out, `src="http://h/.static/avatars/eve.svg"`) {
			t.Errorf("expected avatar img, got:\n%s", out)
		}
	})

	t.Run("without picture shows initial placeholder", func(t *testing.T) {
		cfg := &config.Config{Personas: []config.Persona{{Name: "Bob", Claims: map[string]any{"sub": "usr_bob"}}}}
		out := render(cfg)
		if strings.Contains(out, `<img class="avatar"`) {
			t.Errorf("did not expect avatar img, got:\n%s", out)
		}
		if !strings.Contains(out, `class="avatar-placeholder"`) || !strings.Contains(out, ">B</span>") {
			t.Errorf("expected initial placeholder 'B', got:\n%s", out)
		}
	})
}
