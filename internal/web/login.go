package web

import (
	"html/template"
	"net/http"
	"net/url"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/persona"
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
	mux.HandleFunc("GET /login", h.getLogin)
	mux.HandleFunc("POST /login/select", h.postSelect)
}

func (h *Handler) getLogin(w http.ResponseWriter, r *http.Request) {
	vm := h.buildPage(r.URL.Query().Get("authRequestID"))
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, h.callbackURL+"?id="+url.QueryEscape(authRequestID), http.StatusFound)
}

func (h *Handler) buildPage(authRequestID string) pageVM {
	colourByGroup := map[string]string{}
	labelByGroup := map[string]string{}
	order := []string{}
	seen := map[string]bool{}
	for _, g := range h.cfg.Groups {
		label := g.Label
		if label == "" {
			label = g.ID
		}
		colourByGroup[g.ID] = g.Colour
		labelByGroup[g.ID] = label
	}
	cards := map[string][]cardVM{}
	for _, p := range h.set.All() {
		sub, _ := p.Claims["sub"].(string)
		gid := p.Group
		if !seen[gid] {
			seen[gid] = true
			order = append(order, gid)
		}
		picture, _ := p.Claims["picture"].(string)
		cards[gid] = append(cards[gid], cardVM{
			Sub:         sub,
			Name:        persona.DisplayName(p),
			Description: p.Description,
			Colour:      colourByGroup[gid],
			Picture:     picture,
		})
	}
	vm := pageVM{AuthRequestID: authRequestID}
	for _, gid := range order {
		vm.Groups = append(vm.Groups, groupVM{
			Label:    labelByGroup[gid],
			Colour:   colourByGroup[gid],
			Personas: cards[gid],
		})
	}
	return vm
}
