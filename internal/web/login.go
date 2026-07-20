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
	"strings"
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
	loginHint   func(authRequestID string) (hint string, allowAuto bool)
	device      DeviceGate
	callbackURL string
	tmpl        *template.Template
	css         template.CSS // the stylesheet, inlined into every page
	js          template.JS  // the picker script, inlined into every page
}

// DeviceGate is the slice of the provider's storage the device pages need:
// validating a user code and recording the user's decision.
type DeviceGate interface {
	LookupDeviceUserCode(userCode string) error
	ApproveDevice(userCode, sub string) error
	DenyDevice(userCode string) error
}

type cardVM struct {
	Sub         string
	Name        string
	Initial     string
	Description string
	Picture     string
	Search      string
}

type groupVM struct {
	Label    string
	Colour   string
	Personas []cardVM
}

type pageVM struct {
	FormAction   string // where a card submits: /login/select or /device/select
	RequestField string // hidden field name: authRequestID or userCode
	RequestValue string
	DenyAction   string // non-empty on the device picker: /device/deny
	Groups       []groupVM
	CSS          template.CSS
	JS           template.JS
	SearchQuery  string
}

// deviceEntryVM renders the device code-entry form: an optional problem
// message about a previously submitted code, and the inlined stylesheet.
type deviceEntryVM struct {
	Message string // one-line problem with the previous code, if any
	CSS     template.CSS
}

// deviceResultVM renders the terminal device page: the device was either
// connected (approved) or denied.
type deviceResultVM struct {
	Connected bool
	CSS       template.CSS
}

// NewHandler builds a picker Handler. complete records the chosen persona on
// the pending auth request, loginHint reports a request's login_hint and
// whether auto-selection is permitted, device validates and decides device
// user codes, and callbackURL is where a completed selection redirects to
// hand control back to the OpenID provider.
func NewHandler(set *persona.Set, cfg *config.Config, complete func(string, string) error, loginHint func(string) (string, bool), device DeviceGate, callbackURL string) *Handler {
	tmpl := template.Must(template.ParseFS(assets, "templates/*.tmpl"))
	raw, err := assets.ReadFile("static/style.css")
	if err != nil {
		panic("web: embedded static/style.css: " + err.Error())
	}
	css := template.CSS(raw) //nolint:gosec // G203: raw is our own embedded stylesheet, not user input.
	rawJS, err := assets.ReadFile("static/search.js")
	if err != nil {
		panic("web: embedded static/search.js: " + err.Error())
	}
	js := template.JS(rawJS) //nolint:gosec // G203: rawJS is our own embedded script, not user input.
	return &Handler{set: set, cfg: cfg, complete: complete, loginHint: loginHint, device: device, callbackURL: callbackURL, tmpl: tmpl, css: css, js: js}
}

// Routes registers the picker's and device flow's handlers on mux: the GET
// login and device pages, and the POSTs that complete a persona selection or
// a device decision.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+provider.LoginPath, h.getLogin)
	mux.HandleFunc("POST "+provider.LoginPath+"/select", h.postSelect)
	mux.HandleFunc("GET "+provider.DevicePath, h.getDevice)
	mux.HandleFunc("POST "+provider.DevicePath+"/select", h.postDeviceSelect)
	mux.HandleFunc("POST "+provider.DevicePath+"/deny", h.postDeviceDeny)
}

// render executes the named template into a buffer first: a mid-render
// failure becomes a logged 500 rather than a silently truncated 200.
func (h *Handler) render(w http.ResponseWriter, name string, vm any) {
	var buf bytes.Buffer
	if err := h.tmpl.ExecuteTemplate(&buf, name, vm); err != nil {
		slog.Error("render page", "template", name, "err", err)
		http.Error(w, "error rendering the page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

func (h *Handler) getLogin(w http.ResponseWriter, r *http.Request) {
	authRequestID := r.URL.Query().Get(provider.AuthRequestIDParam)

	// A login_hint that pins down exactly one persona logs straight in —
	// unless the RP's prompt insists on interaction. Failures (expired,
	// already done) degrade to the picker rather than an error page.
	hint, allowAuto := h.loginHint(authRequestID)
	if allowAuto {
		if sub := h.hintedSub(hint); sub != "" {
			if err := h.complete(authRequestID, sub); err == nil {
				http.Redirect(w, r, h.callbackURL+"?id="+url.QueryEscape(authRequestID), http.StatusFound)
				return
			}
		}
	}

	vm := h.buildPage(authRequestID)
	vm.SearchQuery = hint
	h.render(w, "picker.html.tmpl", vm)
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

// getDevice serves the device verification page: a user-code entry form, or
// the persona picker once ?user_code= names a pending authorization.
func (h *Handler) getDevice(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("user_code")
	if code == "" {
		h.render(w, "device.html.tmpl", deviceEntryVM{CSS: h.css})
		return
	}
	if err := h.device.LookupDeviceUserCode(code); err != nil {
		h.render(w, "device.html.tmpl", deviceEntryVM{Message: deviceMessage(err), CSS: h.css})
		return
	}
	vm := h.buildPage("")
	vm.FormAction = provider.DevicePath + "/select"
	vm.RequestField = "userCode"
	vm.RequestValue = code
	vm.DenyAction = provider.DevicePath + "/deny"
	h.render(w, "picker.html.tmpl", vm)
}

// postDeviceSelect approves the pending device authorization named by the
// posted userCode for the chosen persona.
func (h *Handler) postDeviceSelect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	userCode := r.FormValue("userCode")
	sub := r.FormValue("sub")
	if _, ok := h.set.BySub(sub); !ok {
		http.Error(w, "unknown persona", http.StatusBadRequest)
		return
	}
	if err := h.device.ApproveDevice(userCode, sub); err != nil {
		h.render(w, "device.html.tmpl", deviceEntryVM{Message: deviceMessage(err), CSS: h.css})
		return
	}
	h.render(w, "device_result.html.tmpl", deviceResultVM{Connected: true, CSS: h.css})
}

// postDeviceDeny records the user's refusal to connect the device named by
// the posted userCode.
func (h *Handler) postDeviceDeny(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	userCode := r.FormValue("userCode")
	if err := h.device.DenyDevice(userCode); err != nil {
		h.render(w, "device.html.tmpl", deviceEntryVM{Message: deviceMessage(err), CSS: h.css})
		return
	}
	h.render(w, "device_result.html.tmpl", deviceResultVM{Connected: false, CSS: h.css})
}

// deviceMessage maps gate errors to the one-liner shown above the code form.
func deviceMessage(err error) string {
	switch {
	case errors.Is(err, provider.ErrDeviceCodeExpired):
		return "That code has expired — request a new one on your device."
	case errors.Is(err, provider.ErrDeviceCodeHandled):
		return "That code was already used — request a new one on your device."
	default:
		return "That code was not recognised — check it and try again."
	}
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
		email, _ := p.Claims["email"].(string)
		name := persona.DisplayName(p)
		cards[gid] = append(cards[gid], cardVM{
			Sub:         sub,
			Name:        name,
			Initial:     initial(name),
			Description: p.Description,
			Picture:     picture,
			Search:      searchText(name, p.Description, email, sub),
		})
	}

	vm := pageVM{FormAction: provider.LoginPath + "/select", RequestField: "authRequestID", RequestValue: authRequestID, CSS: h.css, JS: h.js}
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

// searchText builds the haystack the picker's search box matches against:
// the persona's name, description, email and sub, lowercased and space-joined.
func searchText(name, description, email, sub string) string {
	return strings.ToLower(strings.Join(strings.Fields(name+" "+description+" "+email+" "+sub), " "))
}

// hintedSub resolves a login_hint to a persona: a persona is a candidate when
// its sub equals the hint exactly or its email claim equals it ignoring case.
// The sub is returned only when precisely one persona is a candidate.
func (h *Handler) hintedSub(hint string) string {
	if hint == "" {
		return ""
	}
	var sub string
	matches := 0
	for p := range h.set.All() {
		psub, _ := p.Claims["sub"].(string)
		email, _ := p.Claims["email"].(string)
		if psub == hint || (email != "" && strings.EqualFold(email, hint)) {
			sub = psub
			matches++
		}
	}
	if matches != 1 {
		return ""
	}
	return sub
}
