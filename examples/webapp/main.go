// Command webapp is a minimal OpenID Connect relying party that logs in via
// hamnir. It performs a standard Authorization Code + PKCE flow and, on success,
// shows the claims from the verified ID token.
//
// The one wrinkle is running inside Docker Compose: the browser reaches hamnir at
// a public URL (a published host port) while this container reaches it at an
// internal service name. See discoverAndConfigure for how the two are reconciled.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	var (
		internalURL = env("HAMNIR_INTERNAL_URL", "http://hamnir:5556")
		publicURL   = env("HAMNIR_PUBLIC_URL", "http://localhost:5556")
		clientID    = env("CLIENT_ID", "example-webapp")
		redirectURI = env("REDIRECT_URI", "http://localhost:8080/callback")
		addr        = env("ADDR", ":8080")
	)

	a, err := discoverAndConfigure(context.Background(), internalURL, publicURL, clientID, redirectURI)
	if err != nil {
		slog.Error("configure", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleHome)
	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/callback", a.handleCallback)

	slog.Info("listening", "addr", addr, "open", redirectURIBase(redirectURI))
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

type app struct {
	oauth2   oauth2.Config
	verifier *oidc.IDTokenVerifier
	tmpl     *template.Template
}

// discoverAndConfigure discovers hamnir and builds the OAuth2 config, reconciling
// the internal (container-reachable) and public (browser-reachable) URLs.
func discoverAndConfigure(ctx context.Context, internalURL, publicURL, clientID, redirectURI string) (*app, error) {
	// Discover via the INTERNAL url — reachable from this container. hamnir's
	// dynamic issuer echoes this url back as the issuer, so ID tokens minted at the
	// (internal) token endpoint verify against it.
	provider, err := discover(ctx, internalURL)
	if err != nil {
		return nil, fmt.Errorf("discover hamnir at %s: %w", internalURL, err)
	}

	// The browser cannot resolve the internal service name, so rewrite just the
	// host of the discovered authorization endpoint to the PUBLIC url. Token
	// exchange and JWKS stay on the internal url, which this container can reach.
	authEndpoint, err := url.Parse(provider.Endpoint().AuthURL)
	if err != nil {
		return nil, fmt.Errorf("parse authorization endpoint: %w", err)
	}
	pub, err := url.Parse(publicURL)
	if err != nil {
		return nil, fmt.Errorf("parse public url %q: %w", publicURL, err)
	}
	authEndpoint.Scheme, authEndpoint.Host = pub.Scheme, pub.Host

	return &app{
		oauth2: oauth2.Config{
			ClientID:    clientID,
			Endpoint:    oauth2.Endpoint{AuthURL: authEndpoint.String(), TokenURL: provider.Endpoint().TokenURL},
			RedirectURL: redirectURI,
			Scopes:      []string{oidc.ScopeOpenID, "email", "profile"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
		tmpl:     template.Must(template.New("claims").Parse(claimsPage)),
	}, nil
}

// discover retries discovery so the app tolerates starting before hamnir is ready
// (distroless has no shell, so a compose healthcheck can't curl — we wait here).
func discover(ctx context.Context, issuer string) (*oidc.Provider, error) {
	var lastErr error
	for range 30 {
		p, err := oidc.NewProvider(ctx, issuer)
		if err == nil {
			return p, nil
		}
		lastErr = err
		slog.Info("waiting for hamnir", "issuer", issuer, "err", err)
		time.Sleep(time.Second)
	}
	return nil, lastErr
}

func (a *app) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, homePage)
}

// handleLogin starts the flow: mint state, nonce and a PKCE verifier, stash them in
// short-lived cookies, and redirect the browser to hamnir's persona picker.
func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := randString()
	nonce := randString()
	verifier := oauth2.GenerateVerifier()
	setCookie(w, "state", state)
	setCookie(w, "nonce", nonce)
	setCookie(w, "pkce", verifier)
	url := a.oauth2.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, url, http.StatusFound)
}

// handleCallback completes the flow: validate state, exchange the code (with the
// PKCE verifier), verify the ID token, check the nonce, and render the claims.
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
		"Subject": idToken.Subject,
		"Name":    claims["name"],
		"Email":   claims["email"],
		"Claims":  string(pretty),
	})
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
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

// setCookie stores a short-lived transient value. SameSite=Lax lets the cookie ride
// the top-level redirect back from hamnir; HttpOnly keeps it out of page scripts.
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

const homePage = `<!doctype html>
<title>hamnir example app</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem; }
  a.btn { display: inline-block; padding: .6rem 1rem; background: #8b5cf6; color: #fff;
          border-radius: .5rem; text-decoration: none; font-weight: 600; }
</style>
<h1>hamnir example app</h1>
<p>This tiny relying party logs in via hamnir. Click below, pick a persona, and
   see the claims your app receives from the verified ID token.</p>
<p><a class="btn" href="/login">Log in with hamnir</a></p>
`

const claimsPage = `<!doctype html>
<title>Signed in — hamnir example</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem; }
  pre { background: #f4f4f5; padding: 1rem; border-radius: .5rem; overflow: auto; }
</style>
<h1>Signed in &#10003;</h1>
<p>You are <strong>{{if .Name}}{{.Name}}{{else}}{{.Subject}}{{end}}</strong>{{if .Email}} &lt;{{.Email}}&gt;{{end}}.</p>
<p>These are the claims from the verified ID token:</p>
<pre>{{.Claims}}</pre>
<p><a href="/login">Log in again</a></p>
`
