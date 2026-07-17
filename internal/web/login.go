// Package web serves hamnir's persona picker: the login page where a developer
// chooses which persona to authenticate as, and the form post that completes
// the pending authorization request.
package web

import (
	"bytes"
	"cmp"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"unicode"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/persona"
	"github.com/strangemattersystems/hamnir/internal/provider"
)

//go:embed templates/*.tmpl static/*
var assets embed.FS

// Handler serves the persona picker and completes the authorization request for
// the chosen persona. It is read-only after construction and safe for
// concurrent use.
type Handler struct {
	set         *persona.Set
	cfg         *config.Config
	complete    func(authRequestID, sub string) error
	callbackURL string
	tmpl        *template.Template
	css         template.CSS // the stylesheet, inlined into every page
}

type cardVM struct {
	Sub         string
	Name        string
	Initial     string
	Description string
	Picture     string
}

type groupVM struct {
	Label    string
	Colour   string
	Personas []cardVM
}

type pageVM struct {
	AuthRequestID string
	Groups        []groupVM
	CSS           template.CSS
}

// NewHandler builds a picker Handler. complete records the chosen persona on the
// pending auth request, and callbackURL is where a completed selection redirects
// to hand control back to the OpenID provider.
func NewHandler(set *persona.Set, cfg *config.Config, complete func(string, string) error, callbackURL string) *Handler {
	tmpl := template.Must(template.ParseFS(assets, "templates/*.tmpl"))
	css, err := assets.ReadFile("static/style.css")
	if err != nil {
		panic("web: embedded static/style.css: " + err.Error())
	}
	return &Handler{set: set, cfg: cfg, complete: complete, callbackURL: callbackURL, tmpl: tmpl, css: template.CSS(css)}
}

// Routes registers the picker's handlers on mux: the GET login page and the
// POST that completes a persona selection.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+provider.LoginPath, h.getLogin)
	mux.HandleFunc("POST "+provider.LoginPath+"/select", h.postSelect)
}

func (h *Handler) getLogin(w http.ResponseWriter, r *http.Request) {
	vm := h.buildPage(r.URL.Query().Get(provider.AuthRequestIDParam))
	// Render to a buffer first: the page is tiny, and a mid-render failure
	// must become a logged 500 rather than a silently truncated 200.
	var buf bytes.Buffer
	if err := h.tmpl.ExecuteTemplate(&buf, "picker.html.tmpl", vm); err != nil {
		slog.Error("render persona picker", "err", err)
		http.Error(w, "error rendering the login page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

func (h *Handler) postSelect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	authRequestID := r.FormValue("authRequestID")
	sub := r.FormValue("sub")
	if _, ok := h.set.BySub(sub); !ok {
		http.Error(w, "unknown persona", http.StatusBadRequest)
		return
	}
	if err := h.complete(authRequestID, sub); err != nil {
		if errors.Is(err, provider.ErrAuthRequestNotFound) || errors.Is(err, provider.ErrAuthRequestDone) {
			http.Error(w, "This login has expired or was already completed — return to your app and sign in again.", http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, h.callbackURL+"?id="+url.QueryEscape(authRequestID), http.StatusFound)
}

// buildPage groups the personas into picker sections: configured groups in
// their config order (omitting any without personas), then groups the config
// does not declare — in practice the ungrouped "" — in first-appearance order.
func (h *Handler) buildPage(authRequestID string) pageVM {
	byID := make(map[string]config.Group, len(h.cfg.Groups))
	for _, g := range h.cfg.Groups {
		byID[g.ID] = g
	}

	cards := map[string][]cardVM{}
	var extras []string
	for p := range h.set.All() {
		gid := p.Group
		if _, declared := byID[gid]; !declared && len(cards[gid]) == 0 {
			extras = append(extras, gid)
		}
		sub, _ := p.Claims["sub"].(string)
		picture, _ := p.Claims["picture"].(string)
		name := persona.DisplayName(p)
		cards[gid] = append(cards[gid], cardVM{
			Sub:         sub,
			Name:        name,
			Initial:     initial(name),
			Description: p.Description,
			Picture:     picture,
		})
	}

	vm := pageVM{AuthRequestID: authRequestID, CSS: h.css}
	for _, g := range h.cfg.Groups {
		if len(cards[g.ID]) > 0 {
			vm.Groups = append(vm.Groups, groupVM{
				Label:    cmp.Or(g.Label, g.ID),
				Colour:   g.Colour,
				Personas: cards[g.ID],
			})
		}
	}
	for _, gid := range extras {
		vm.Groups = append(vm.Groups, groupVM{Personas: cards[gid]})
	}
	return vm
}

// initial returns the first rune of name, upper-cased, for the avatar placeholder
// shown when a persona has no picture claim. Falls back to "?" for an empty name.
func initial(name string) string {
	for _, r := range name {
		return string(unicode.ToUpper(r))
	}
	return "?"
}
