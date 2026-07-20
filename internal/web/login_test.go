package web

import (
	"errors"
	"fmt"
	"html/template"
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
	return NewHandler(persona.NewSet(cfg), cfg, complete, noHint, newFakeGate(), "/authorize/callback")
}

// newHandlerWith builds a picker Handler over the given personas and no groups.
func newHandlerWith(personas ...config.Persona) *Handler {
	cfg := &config.Config{Personas: personas}
	return NewHandler(persona.NewSet(cfg), cfg, func(string, string) error { return nil }, noHint, newFakeGate(), "/cb")
}

// noHint is the login-hint lookup for tests that don't exercise hints.
func noHint(string) (string, bool) { return "", false }

// newHintedHandler builds a picker Handler whose hint lookup returns a fixed
// hint/allowAuto pair, over the given personas and no groups.
func newHintedHandler(hint string, allowAuto bool, complete func(string, string) error, personas ...config.Persona) *Handler {
	cfg := &config.Config{Personas: personas}
	return NewHandler(persona.NewSet(cfg), cfg, complete, func(string) (string, bool) { return hint, allowAuto }, newFakeGate(), "/cb")
}

// fakeGate is an in-memory web.DeviceGate for handler tests.
type fakeGate struct {
	valid    map[string]bool
	approved map[string]string
	denied   map[string]bool
	err      error
}

func newFakeGate(codes ...string) *fakeGate {
	g := &fakeGate{valid: map[string]bool{}, approved: map[string]string{}, denied: map[string]bool{}}
	for _, c := range codes {
		g.valid[c] = true
	}
	return g
}

func (g *fakeGate) LookupDeviceUserCode(code string) error {
	if g.err != nil {
		return g.err
	}
	if !g.valid[code] {
		return provider.ErrDeviceCodeNotFound
	}
	return nil
}

func (g *fakeGate) ApproveDevice(code, sub string) error {
	if err := g.LookupDeviceUserCode(code); err != nil {
		return err
	}
	g.approved[code] = sub
	return nil
}

func (g *fakeGate) DenyDevice(code string) error {
	if err := g.LookupDeviceUserCode(code); err != nil {
		return err
	}
	g.denied[code] = true
	return nil
}

// newDeviceHandler builds a picker Handler over the given gate and personas.
func newDeviceHandler(gate DeviceGate, personas ...config.Persona) *Handler {
	cfg := &config.Config{Personas: personas}
	return NewHandler(persona.NewSet(cfg), cfg, func(string, string) error { return nil }, noHint, gate, "/cb")
}

// getLoginPage drives a GET of the picker and returns the recorded response.
func getLoginPage(h *Handler) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	h.Routes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login?authRequestID=abc", nil))
	return rec
}

// submitSelection drives a POST of the persona-selection form.
func submitSelection(h *Handler, form url.Values) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	h.Routes(mux)
	req := httptest.NewRequest(http.MethodPost, "/login/select", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestSearchText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		pname       string
		description string
		email       string
		sub         string
		want        string
	}{
		{"lowercases and joins the fields", "Ada Lovelace", "First Programmer", "", "USR_Ada", "ada lovelace first programmer usr_ada"},
		{"empty description leaves no gap", "Bob", "", "", "usr_bob", "bob usr_bob"},
		{"all empty yields empty", "", "", "", "", ""},
		{"email included and lowercased", "Ada", "", "Ada@Example.Test", "usr_ada", "ada ada@example.test usr_ada"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := searchText(tt.pname, tt.description, tt.email, tt.sub); got != tt.want {
				t.Errorf("searchText(%q, %q, %q, %q) = %q, want %q", tt.pname, tt.description, tt.email, tt.sub, got, tt.want)
			}
		})
	}
}

func TestHandler_getLogin(t *testing.T) {
	t.Parallel()

	t.Run("renders the picker", func(t *testing.T) {
		t.Parallel()

		rec := getLoginPage(newTestHandler(func(_, _ string) error { return nil }))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Alice") {
			t.Fatalf("expected picker with Alice, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("inlines the stylesheet", func(t *testing.T) {
		t.Parallel()

		out := getLoginPage(newTestHandler(func(_, _ string) error { return nil })).Body.String()
		if strings.Contains(out, `rel="stylesheet"`) {
			t.Error("stylesheet should be inlined, not served via a <link>")
		}
		if !strings.Contains(out, "<style>") || !strings.Contains(out, ".card") {
			t.Error("expected the stylesheet inlined into a <style> block")
		}
	})

	t.Run("cards carry a data-search haystack", func(t *testing.T) {
		t.Parallel()

		h := newHandlerWith(config.Persona{
			Name:        "Ada Lovelace",
			Description: "First Programmer",
			Claims:      map[string]any{"sub": "usr_ada"},
		})
		if out := getLoginPage(h).Body.String(); !strings.Contains(out, `data-search="ada lovelace first programmer usr_ada"`) {
			t.Errorf("expected lowercased data-search attribute, got:\n%s", out)
		}
	})

	t.Run("with a picture renders an avatar image", func(t *testing.T) {
		t.Parallel()

		h := newHandlerWith(config.Persona{Name: "Eve", Claims: map[string]any{
			"sub": "usr_eve", "picture": "http://h/.static/avatars/eve.svg",
		}})
		if out := getLoginPage(h).Body.String(); !strings.Contains(out, `src="http://h/.static/avatars/eve.svg"`) {
			t.Errorf("expected avatar img, got:\n%s", out)
		}
	})

	t.Run("without a picture shows the initial placeholder", func(t *testing.T) {
		t.Parallel()

		h := newHandlerWith(config.Persona{Name: "Bob", Claims: map[string]any{"sub": "usr_bob"}})
		out := getLoginPage(h).Body.String()
		if strings.Contains(out, `<img class="avatar"`) {
			t.Errorf("did not expect avatar img, got:\n%s", out)
		}
		if !strings.Contains(out, `class="avatar-placeholder"`) || !strings.Contains(out, ">B</span>") {
			t.Errorf("expected initial placeholder 'B', got:\n%s", out)
		}
	})

	t.Run("ships the search ui hidden with the script inlined", func(t *testing.T) {
		t.Parallel()

		out := getLoginPage(newTestHandler(func(_, _ string) error { return nil })).Body.String()
		if !strings.Contains(out, `<div class="search" hidden>`) {
			t.Error("expected the search box present but hidden by default")
		}
		if !strings.Contains(out, `<p class="no-match" role="status" hidden>`) {
			t.Error("expected the no-match line present but hidden by default")
		}
		if strings.Contains(out, `<script src=`) {
			t.Error("the script should be inlined, not served via src")
		}
		if !strings.Contains(out, "<script>") || !strings.Contains(out, "requestSubmit") {
			t.Error("expected search.js inlined into a <script> block")
		}
	})

	t.Run("render failure yields 500", func(t *testing.T) {
		t.Parallel()

		cfg := &config.Config{Personas: []config.Persona{{Name: "Alice", Claims: map[string]any{"sub": "usr_alice"}}}}
		h := &Handler{
			set:       persona.NewSet(cfg),
			cfg:       cfg,
			loginHint: noHint,
			tmpl:      template.Must(template.New("picker.html.tmpl").Parse("{{index .Groups 99}}")),
		}
		rec := httptest.NewRecorder()
		h.getLogin(rec, httptest.NewRequest(http.MethodGet, "/login?authRequestID=x", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("a render failure must yield 500, got %d (body %q)", rec.Code, rec.Body.String())
		}
	})

	t.Run("hinted unique match auto-logs-in", func(t *testing.T) {
		t.Parallel()

		var got string
		h := newHintedHandler("usr_alice", true, func(_, sub string) error { got = sub; return nil },
			config.Persona{Name: "Alice", Claims: map[string]any{"sub": "usr_alice"}})
		rec := getLoginPage(h)
		if rec.Code != http.StatusFound {
			t.Fatalf("expected auto-login redirect, got %d body=%s", rec.Code, rec.Body.String())
		}
		if got != "usr_alice" {
			t.Fatalf("complete not called with usr_alice, got %q", got)
		}
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "/cb?id=abc") {
			t.Fatalf("unexpected redirect location %q", loc)
		}
	})

	t.Run("suppressed auto-login prefills the search box", func(t *testing.T) {
		t.Parallel()

		called := false
		h := newHintedHandler("usr_alice", false, func(_, _ string) error { called = true; return nil },
			config.Persona{Name: "Alice", Claims: map[string]any{"sub": "usr_alice"}})
		rec := getLoginPage(h)
		if rec.Code != http.StatusOK || called {
			t.Fatalf("expected the picker without completion, got %d (complete called: %v)", rec.Code, called)
		}
		if !strings.Contains(rec.Body.String(), `value="usr_alice"`) {
			t.Errorf("expected prefilled search value, got:\n%s", rec.Body.String())
		}
	})

	t.Run("ambiguous hint prefills instead of logging in", func(t *testing.T) {
		t.Parallel()

		h := newHintedHandler("shared@example.test", true, func(_, _ string) error { return nil },
			config.Persona{Name: "A", Claims: map[string]any{"sub": "usr_a", "email": "shared@example.test"}},
			config.Persona{Name: "B", Claims: map[string]any{"sub": "shared@example.test"}})
		rec := getLoginPage(h)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `value="shared@example.test"`) {
			t.Fatalf("expected prefilled picker, got %d", rec.Code)
		}
	})

	t.Run("failed completion falls back to the prefilled picker", func(t *testing.T) {
		t.Parallel()

		h := newHintedHandler("usr_alice", true, func(_, _ string) error { return errors.New("done") },
			config.Persona{Name: "Alice", Claims: map[string]any{"sub": "usr_alice"}})
		rec := getLoginPage(h)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `value="usr_alice"`) {
			t.Fatalf("expected prefilled picker fallback, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("hint is escaped in the value attribute", func(t *testing.T) {
		t.Parallel()

		h := newHintedHandler(`"><script>`, false, func(_, _ string) error { return nil },
			config.Persona{Name: "Alice", Claims: map[string]any{"sub": "usr_alice"}})
		out := getLoginPage(h).Body.String()
		if strings.Contains(out, `"><script>`) {
			t.Fatalf("hint must be escaped, got:\n%s", out)
		}
		if !strings.Contains(out, `value="&#34;&gt;&lt;script&gt;"`) {
			t.Errorf("expected escaped value attribute, got:\n%s", out)
		}
	})

	t.Run("login picker still posts to /login/select", func(t *testing.T) {
		t.Parallel()

		out := getLoginPage(newTestHandler(func(_, _ string) error { return nil })).Body.String()
		if !strings.Contains(out, `action="/login/select"`) || !strings.Contains(out, `name="authRequestID"`) {
			t.Errorf("picker form target regressed:\n%s", out)
		}
	})
}

func TestHandler_hintedSub(t *testing.T) {
	t.Parallel()

	h := newHandlerWith(
		config.Persona{Name: "Alice", Claims: map[string]any{"sub": "usr_alice", "email": "Alice@Example.Test"}},
		config.Persona{Name: "Bob", Claims: map[string]any{"sub": "usr_bob"}},
		config.Persona{Name: "Eve", Claims: map[string]any{"sub": "alice@example.test"}},
	)
	tests := []struct {
		name string
		hint string
		want string
	}{
		{"sub matches exactly", "usr_bob", "usr_bob"},
		{"email matches ignoring case", "ALICE@example.test", "usr_alice"},
		{"ambiguous across fields", "alice@example.test", ""},
		{"no match", "nobody", ""},
		{"empty hint never matches", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := h.hintedSub(tt.hint); got != tt.want {
				t.Errorf("hintedSub(%q) = %q, want %q", tt.hint, got, tt.want)
			}
		})
	}
}

func TestHandler_postSelect(t *testing.T) {
	t.Parallel()

	t.Run("valid selection redirects to the callback", func(t *testing.T) {
		t.Parallel()

		var got string
		h := newTestHandler(func(_, sub string) error { got = sub; return nil })
		rec := submitSelection(h, url.Values{"authRequestID": {"abc"}, "sub": {"usr_alice"}})
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
		t.Parallel()

		h := newTestHandler(func(_, _ string) error {
			return fmt.Errorf("auth request %q: %w", "abc", provider.ErrAuthRequestNotFound)
		})
		rec := submitSelection(h, url.Values{"authRequestID": {"abc"}, "sub": {"usr_alice"}})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for an expired auth request, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "expired") {
			t.Fatalf("expected a friendly expiry message, got %q", rec.Body.String())
		}
	})

	t.Run("unknown persona is rejected", func(t *testing.T) {
		t.Parallel()

		h := newTestHandler(func(_, _ string) error { return nil })
		rec := submitSelection(h, url.Values{"authRequestID": {"abc"}, "sub": {"nobody"}})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for unknown persona, got %d", rec.Code)
		}
	})

	t.Run("malformed form is rejected with 400", func(t *testing.T) {
		t.Parallel()

		h := newTestHandler(func(_, _ string) error { return nil })
		mux := http.NewServeMux()
		h.Routes(mux)
		req := httptest.NewRequest(http.MethodPost, "/login/select", strings.NewReader("%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("a malformed form should be 400, got %d", rec.Code)
		}
	})

	t.Run("an unexpected completion error yields 500", func(t *testing.T) {
		t.Parallel()

		h := newTestHandler(func(_, _ string) error { return errors.New("boom") })
		rec := submitSelection(h, url.Values{"authRequestID": {"abc"}, "sub": {"usr_alice"}})
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("a non-sentinel completion error should be 500, got %d", rec.Code)
		}
	})
}

func TestInitial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"upper-cases the first rune", "bob", "B"},
		{"handles a multibyte first rune", "élan", "É"},
		{"empty name falls back to ?", "", "?"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := initial(tt.in); got != tt.want {
				t.Errorf("initial(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestHandler_buildPage(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			cfg := &config.Config{Groups: groups, Personas: tt.personas}
			h := NewHandler(persona.NewSet(cfg), cfg, func(string, string) error { return nil }, noHint, newFakeGate(), "/cb")
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

func TestHandler_device(t *testing.T) {
	t.Parallel()

	alice := config.Persona{Name: "Alice", Claims: map[string]any{"sub": "usr_alice"}}
	serve := func(h *Handler, method, target string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		mux := http.NewServeMux()
		h.Routes(mux)
		var req *http.Request
		if form != nil {
			req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req = httptest.NewRequest(method, target, nil)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	t.Run("entry form renders", func(t *testing.T) {
		t.Parallel()

		h := newDeviceHandler(newFakeGate(), alice)
		out := serve(h, http.MethodGet, "/device", nil).Body.String()
		if !strings.Contains(out, `name="user_code"`) {
			t.Errorf("expected the user-code form, got:\n%s", out)
		}
	})

	t.Run("valid prefilled code renders the picker at the device target", func(t *testing.T) {
		t.Parallel()

		h := newDeviceHandler(newFakeGate("BCDF-GHJK"), alice)
		out := serve(h, http.MethodGet, "/device?user_code=BCDF-GHJK", nil).Body.String()
		if !strings.Contains(out, `action="/device/select"`) || !strings.Contains(out, `value="BCDF-GHJK"`) {
			t.Errorf("expected the picker targeting /device/select, got:\n%s", out)
		}
		if !strings.Contains(out, `action="/device/deny"`) {
			t.Errorf("expected a deny action, got:\n%s", out)
		}
	})

	t.Run("invalid code re-renders the entry form with a message", func(t *testing.T) {
		t.Parallel()

		h := newDeviceHandler(newFakeGate(), alice)
		rec := serve(h, http.MethodGet, "/device?user_code=XXXX-XXXX", nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "code was not recognised") {
			t.Errorf("expected a friendly re-render, got %d:\n%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("select approves and renders the connected page", func(t *testing.T) {
		t.Parallel()

		g := newFakeGate("BCDF-GHJK")
		h := newDeviceHandler(g, alice)
		out := serve(h, http.MethodPost, "/device/select", url.Values{"userCode": {"BCDF-GHJK"}, "sub": {"usr_alice"}}).Body.String()
		if g.approved["BCDF-GHJK"] != "usr_alice" {
			t.Fatalf("approve not called, gate: %+v", g)
		}
		if !strings.Contains(out, "Device connected") {
			t.Errorf("expected the connected page, got:\n%s", out)
		}
	})

	t.Run("unknown persona is rejected before the gate", func(t *testing.T) {
		t.Parallel()

		g := newFakeGate("BCDF-GHJK")
		h := newDeviceHandler(g, alice)
		rec := serve(h, http.MethodPost, "/device/select", url.Values{"userCode": {"BCDF-GHJK"}, "sub": {"nobody"}})
		if rec.Code != http.StatusBadRequest || len(g.approved) != 0 {
			t.Fatalf("expected 400 and no approval, got %d %+v", rec.Code, g.approved)
		}
	})

	t.Run("deny renders the denied page", func(t *testing.T) {
		t.Parallel()

		g := newFakeGate("BCDF-GHJK")
		h := newDeviceHandler(g, alice)
		out := serve(h, http.MethodPost, "/device/deny", url.Values{"userCode": {"BCDF-GHJK"}}).Body.String()
		if !g.denied["BCDF-GHJK"] || !strings.Contains(out, "denied") {
			t.Errorf("expected denial, gate %+v, body:\n%s", g, out)
		}
	})

	t.Run("expired code on select re-renders the entry form", func(t *testing.T) {
		t.Parallel()

		g := newFakeGate("BCDF-GHJK")
		g.err = provider.ErrDeviceCodeExpired
		h := newDeviceHandler(g, alice)
		rec := serve(h, http.MethodPost, "/device/select", url.Values{"userCode": {"BCDF-GHJK"}, "sub": {"usr_alice"}})
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "expired") {
			t.Errorf("expected the expired message, got %d:\n%s", rec.Code, rec.Body.String())
		}
	})
}
