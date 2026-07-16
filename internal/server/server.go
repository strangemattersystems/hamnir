package server

import (
	"crypto/rsa"
	"net/http"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/persona"
	"github.com/strangemattersystems/hamnir/internal/provider"
	"github.com/strangemattersystems/hamnir/internal/web"
)

// New assembles the OIDC provider and the persona picker into a single
// http.Handler. The provider serves discovery, /authorize, /token, /keys,
// /userinfo, end-session and the auth callback at "/"; the picker's more
// specific routes (/login, /login/select, /static/) take precedence.
func New(cfg *config.Config, key *rsa.PrivateKey) (http.Handler, error) {
	set := persona.NewSet(cfg)
	st, err := provider.NewStorage(cfg, key)
	if err != nil {
		return nil, err
	}
	p, err := provider.NewProvider(cfg, st)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.Handle("/", p)
	web.NewHandler(set, cfg, st.AuthenticateAndComplete, provider.AuthCallbackPath).Routes(mux)
	return mux, nil
}
