// Package server wires the OpenID provider, the persona picker, and static
// asset serving into a single http.Handler.
package server

import (
	"io"
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/persona"
	"github.com/strangemattersystems/hamnir/internal/provider"
	"github.com/strangemattersystems/hamnir/internal/static"
	"github.com/strangemattersystems/hamnir/internal/web"
)

// New assembles the OIDC provider and the persona picker into a single
// http.Handler. The provider serves discovery, /authorize, /token, /keys,
// /userinfo, end-session and the auth callback at "/"; the picker's more
// specific routes (/login, /login/select) take precedence. version is echoed
// verbatim by the /up liveness endpoint. cfg must come from config.Load, which
// normalises URLs and resolves hamnir:// style static claim references.
func New(cfg *config.Config, version string) (http.Handler, error) {
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
	// Exchange requests carry no server-side audience hook in op, so the
	// configured audiences are defaulted into the request itself.
	ph = st.DefaultExchangeAudience(ph)
	mux.Handle("/", ph)
	// op's discovery handler advertises response/grant types hamnir never
	// serves; this route shadows it with the corrected document.
	mux.HandleFunc("GET "+oidc.DiscoveryEndpoint, provider.Discovery(p, st))
	web.NewHandler(set, cfg, st.AuthenticateAndComplete, st.LoginHint, provider.AuthCallbackPath).Routes(mux)
	static.Register(mux, cfg.Static.Paths)
	mux.HandleFunc("GET /up", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, version)
	})
	return gzipHandler(mux), nil
}
