// Command webapp is a minimal OpenID Connect relying party that logs in via
// hamnir. It performs a standard Authorization Code + PKCE flow and, on success,
// shows the claims from the verified ID token alongside the claims returned by a
// call to hamnir's userinfo endpoint.
package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// These OIDC client settings must match the "example-webapp" client registered
// in examples/hamnir.yaml: hamnir runs in strict client mode, so it rejects the
// authorization request unless the relying party presents them verbatim. They
// are hardcoded rather than env-configured because they are the app's identity,
// not deployment wiring — visible here beside the config they mirror. Where the
// app reaches hamnir is different: that is Compose-network topology, so it comes
// from the environment (see main).
const (
	clientID    = "example-webapp"                 // matches hamnir.yaml clients[].id
	redirectURI = "http://localhost:8080/callback" // matches hamnir.yaml clients[].redirect_uris
	addr        = ":8080"                          // listen address; mirrors the Compose ports mapping
)

//go:embed home.html
var homePage string

//go:embed claims.html
var claimsPage string

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	// we configured where to find the hamnir server in the docker-compose.yml file
	hamnirURL := os.Getenv("HAMNIR_URL")
	if hamnirURL == "" {
		slog.Error("HAMNIR_URL is not set")
		return 1
	}

	// we don't have an explicit healthcheck in the docker-compose.yml file, so we'll
	// manually wait for the hamnir server to be ready
	if err := blockUntilUp(ctx, hamnirURL); err != nil {
		slog.Error("could not connect to hamnir", "err", err)
		return 1
	}

	// discover hamnir's OIDC endpoints and build the OAuth2 client
	provider, err := oidc.NewProvider(ctx, hamnirURL)
	if err != nil {
		slog.Error("discover hamnir", "url", hamnirURL, "err", err)
		return 1
	}
	a := &app{
		provider: provider,
		oauth2: oauth2.Config{
			ClientID:    clientID,
			Endpoint:    provider.Endpoint(),
			RedirectURL: redirectURI,
			Scopes:      []string{oidc.ScopeOpenID, "email", "profile"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
		tmpl:     template.Must(template.New("claims").Parse(claimsPage)),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleHome)
	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/callback", a.handleCallback)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	slog.Info("listening", "addr", addr, "open", redirectURIBase(redirectURI))
	select {
	case err := <-serveErr:
		if err != nil {
			slog.Error("server stopped", "err", err)
			return 1
		}
		return 0
	case <-ctx.Done():
		slog.Info("shutdown signal received, draining", "timeout", (10 * time.Second).String())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", "err", err)
		return 1
	}
	slog.Info("shutdown complete")
	return 0
}

func blockUntilUp(ctx context.Context, hamnirURL string) error {
	readyCtx, readyCancel := context.WithTimeout(ctx, 10*time.Second)
	defer readyCancel()

	readyTicker := time.NewTicker(100 * time.Millisecond)
	defer readyTicker.Stop()

	slog.Info("waiting for hamnir to be ready", "url", hamnirURL)
	for {
		select {
		case <-readyCtx.Done():
			return fmt.Errorf("timeout waiting for hamnir to be ready: %w", readyCtx.Err())
		case <-readyTicker.C:
			resp, err := http.Get(hamnirURL + "/up")
			if err != nil {
				continue
			}
			defer func() { _ = resp.Body.Close() }()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			slog.Info("hamnir is ready", "version", string(body), "url", hamnirURL)
			return nil
		}
	}
}

type app struct {
	provider *oidc.Provider
	oauth2   oauth2.Config
	verifier *oidc.IDTokenVerifier
	tmpl     *template.Template
}

func (a *app) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, homePage)
}

// handleLogin starts the flow: mint state/nonce/PKCE, stash them in cookies,
// and redirect to hamnir's authorization endpoint. An optional ?hint= query
// parameter is forwarded as the standard login_hint so hamnir can skip or
// pre-seed the persona picker.
func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := randString()
	nonce := randString()
	verifier := oauth2.GenerateVerifier()
	setCookie(w, "state", state)
	setCookie(w, "nonce", nonce)
	setCookie(w, "pkce", verifier)
	opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)}
	if hint := r.URL.Query().Get("hint"); hint != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", hint))
	}
	http.Redirect(w, r, a.oauth2.AuthCodeURL(state, opts...), http.StatusFound)
}

// handleCallback completes the flow: validate state, exchange the code (with the PKCE verifier),
// verify the ID token, check the nonce, and render the claims.
func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		http.Error(w, "authorization error: "+e+" "+q.Get("error_description"), http.StatusBadRequest)
		return
	}
	if state, err := r.Cookie("state"); err != nil || q.Get("state") != state.Value {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	pkce, err := r.Cookie("pkce")
	if err != nil {
		http.Error(w, "missing pkce cookie", http.StatusBadRequest)
		return
	}
	token, err := a.oauth2.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(pkce.Value))
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusBadGateway)
		return
	}
	idToken, err := a.verifier.Verify(ctx, rawID)
	if err != nil {
		http.Error(w, "id_token verification failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if nonce, err := r.Cookie("nonce"); err != nil || idToken.Nonce != nonce.Value {
		http.Error(w, "nonce mismatch", http.StatusBadRequest)
		return
	}

	userInfo, err := a.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		http.Error(w, "userinfo request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	var userinfoClaims map[string]any
	if err := userInfo.Claims(&userinfoClaims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	prettyUserinfo, _ := json.MarshalIndent(userinfoClaims, "", "  ")

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pretty, _ := json.MarshalIndent(claims, "", "  ")

	clearCookie(w, "state")
	clearCookie(w, "nonce")
	clearCookie(w, "pkce")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = a.tmpl.Execute(w, map[string]any{
		"Subject":        idToken.Subject,
		"Name":           claims["name"],
		"Email":          claims["email"],
		"IDTokenClaims":  string(pretty),
		"UserinfoClaims": string(prettyUserinfo),
	})
}

func randString() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func redirectURIBase(redirectURI string) string {
	if u, err := url.Parse(redirectURI); err == nil {
		return u.Scheme + "://" + u.Host
	}
	return redirectURI
}

func setCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((10 * time.Minute).Seconds()),
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1})
}
