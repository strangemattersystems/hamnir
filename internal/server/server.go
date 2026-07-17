// Package server wires the OpenID provider, the persona picker, and static
// asset serving into a single http.Handler.
package server

import (
	"net/http"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/persona"
	"github.com/strangemattersystems/hamnir/internal/provider"
	"github.com/strangemattersystems/hamnir/internal/static"
	"github.com/strangemattersystems/hamnir/internal/web"
)

// New assembles the OIDC provider and the persona picker into a single
// http.Handler. The provider serves discovery, /authorize, /token, /keys,
// /userinfo, end-session and the auth callback at "/"; the picker's more
// specific routes (/login, /login/select) take precedence. cfg must come from
// config.Load, which normalises URLs and resolves hamnir:// style static claim
// references.
func New(cfg *config.Config) (http.Handler, error) {
	set := persona.NewSet(cfg)
	st, err := provider.NewStorage(cfg, set, cfg.Key)
	if err != nil {
		return nil, err
	}
	p, err := provider.NewProvider(cfg, st)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	// Presentation sniffing only matters in permissive mode, where the
	// fabricated client mirrors how the RP presented itself; with clients
	// configured the middleware would be pure per-request overhead.
	var ph http.Handler = p
	if len(cfg.Clients) == 0 {
		ph = provider.ObserveClientPresentation(p)
	}
	mux.Handle("/", ph)
	web.NewHandler(set, cfg, st.AuthenticateAndComplete, provider.AuthCallbackPath).Routes(mux)
	static.Register(mux, cfg.Static.Paths)
	return gzipHandler(mux), nil
}
