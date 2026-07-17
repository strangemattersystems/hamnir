package web

import (
	"cmp"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"unicode"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/persona"
	"github.com/strangemattersystems/hamnir/internal/provider"
)

type Handler struct {
	set         *persona.Set
	cfg         *config.Config
	complete    func(authRequestID, sub string) error
	callbackURL string
	tmpl        *template.Template
}

type cardVM struct {
	Sub         string
	Name        string
	Initial     string
	Description string
	Colour      string
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
}

func NewHandler(set *persona.Set, cfg *config.Config, complete func(string, string) error, callbackURL string) *Handler {
	tmpl := template.Must(template.ParseFS(assets, "templates/*.tmpl"))
	return &Handler{set: set, cfg: cfg, complete: complete, callbackURL: callbackURL, tmpl: tmpl}
}

func (h *Handler) Routes(mux *http.ServeMux) {
	mux.Handle("/static/", http.FileServerFS(assets))
	mux.HandleFunc("GET "+provider.LoginPath, h.getLogin)
	mux.HandleFunc("POST "+provider.LoginPath+"/select", h.postSelect)
}

func (h *Handler) getLogin(w http.ResponseWriter, r *http.Request) {
	vm := h.buildPage(r.URL.Query().Get(provider.AuthRequestIDParam))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.ExecuteTemplate(w, "picker.html.tmpl", vm)
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
	for _, p := range h.set.All() {
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
			Colour:      byID[gid].Colour,
			Picture:     picture,
		})
	}

	vm := pageVM{AuthRequestID: authRequestID}
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
