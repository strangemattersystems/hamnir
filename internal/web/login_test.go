package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/persona"
)

func newTestHandler(complete func(string, string) error) *Handler {
	cfg := &config.Config{
		Groups:   []config.Group{{ID: "standard", Label: "Standard", Colour: "#3fb950"}},
		Personas: []config.Persona{{Name: "Alice", Group: "standard", Claims: map[string]any{"sub": "usr_alice"}}},
	}
	return NewHandler(persona.NewSet(cfg), cfg, complete, "/authorize/callback")
}

func TestHandler(t *testing.T) {
	t.Run("login renders personas", func(t *testing.T) {
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

	t.Run("select completes and redirects", func(t *testing.T) {
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

	t.Run("select rejects unknown persona", func(t *testing.T) {
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
