// Command webapp is a minimal OpenID Connect relying party that logs in via
// hamnir. It performs a standard Authorization Code + PKCE flow and, on success,
// shows the claims from the verified ID token alongside the claims returned by a
// call to hamnir's userinfo endpoint.
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
		hamnirURL   = env("HAMNIR_URL", "http://hamnir:5556")
		clientID    = env("CLIENT_ID", "example-webapp")
		redirectURI = env("REDIRECT_URI", "http://localhost:8080/callback")
		addr        = env("ADDR", ":8080")
	)

	a, err := discoverAndConfigure(context.Background(), hamnirURL, clientID, redirectURI)
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
	provider *oidc.Provider
	oauth2   oauth2.Config
	verifier *oidc.IDTokenVerifier
	tmpl     *template.Template
}

// discoverAndConfigure discovers hamnir at a single URL and builds the OAuth2
// config. hamnir advertises its authorization endpoint at a browser-reachable
// URL, so no endpoint rewriting is needed here.
func discoverAndConfigure(ctx context.Context, hamnirURL, clientID, redirectURI string) (*app, error) {
	provider, err := discover(ctx, hamnirURL)
	if err != nil {
		return nil, fmt.Errorf("discover hamnir at %s: %w", hamnirURL, err)
	}
	return &app{
		provider: provider,
		oauth2: oauth2.Config{
			ClientID:    clientID,
			Endpoint:    provider.Endpoint(),
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

// The example app is styled to look deliberately unlike hamnir: warm neutrals,
// rounded proportional type and soft shapes, versus hamnir's monospace, cold-gray
// and flat-square look. Seeing two distinct identities helps a user tell their own
// relying party apart from the identity provider. Both pages are self-contained
// (tokens inlined, no external fonts) and follow the OS light/dark preference.
const homePage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Example Application</title>
<style>
  :root {
    --ground: #fbfaf7; --ink: #1c1b1a; --muted: #6f6b64; --accent: #0f9d8f;
    --accent-strong: #0c8579; --accent-ink: #ffffff;
    --shadow: 0 1px 2px rgba(28,27,26,.05), 0 12px 32px -12px rgba(28,27,26,.18);
    --font-display: ui-rounded, "SF Pro Rounded", "Segoe UI", system-ui, sans-serif;
    --font-body: system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --ground: #17191a; --ink: #f2efe8; --muted: #9a968d; --accent: #2dd4bf;
      --accent-strong: #5fe6d4; --accent-ink: #0c2b27;
      --shadow: 0 1px 2px rgba(0,0,0,.3), 0 16px 40px -16px rgba(0,0,0,.6);
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; background: var(--ground); color: var(--ink);
    font-family: var(--font-body); display: flex; align-items: center;
    justify-content: center; padding: 2rem 1.25rem; }
  .hero { display: flex; flex-direction: column; align-items: center; text-align: center;
    gap: 1.1rem; }
  .hero h1 { font-family: var(--font-display); font-weight: 700;
    font-size: clamp(2rem, 5vw, 2.9rem); letter-spacing: -.02em; margin: 0;
    text-wrap: balance; }
  .hero p { max-width: 34rem; margin: 0; color: var(--muted); font-size: 1.06rem;
    line-height: 1.6; }
  .btn { display: inline-flex; align-items: center; gap: .55rem; margin-top: .6rem;
    padding: .8rem 1.4rem; background: var(--accent); color: var(--accent-ink);
    border-radius: 12px; text-decoration: none; font-family: var(--font-display);
    font-weight: 600; font-size: 1.02rem; box-shadow: var(--shadow);
    transition: transform .12s ease, background .12s ease; }
  .btn:hover { transform: translateY(-1px); background: var(--accent-strong); }
  .btn:focus-visible { outline: 3px solid var(--accent); outline-offset: 3px; }
  .foot { margin-top: 1.5rem; font-size: .82rem; color: var(--muted); }
  @media (prefers-reduced-motion: reduce) {
    .btn { transition: none; } .btn:hover { transform: none; }
  }
</style>
</head>
<body>
  <main class="hero">
    <h1>Example Application</h1>
    <p>A tiny demo app that signs you in with hamnir, then shows the identity claims
       it receives — from the verified ID token and the userinfo endpoint.</p>
    <a class="btn" href="/login">Log in with hamnir &rarr;</a>
    <div class="foot">Dev-only relying party · powered by hamnir</div>
  </main>
</body>
</html>
`

const claimsPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signed in — Example Application</title>
<style>
  :root {
    --ground: #fbfaf7; --surface: #ffffff; --ink: #1c1b1a; --muted: #6f6b64;
    --border: #ece9e2; --accent: #0f9d8f; --accent-strong: #0c8579;
    --code-bg: #f6f4ef;
    --shadow: 0 1px 2px rgba(28,27,26,.05), 0 12px 32px -12px rgba(28,27,26,.18);
    --font-display: ui-rounded, "SF Pro Rounded", "Segoe UI", system-ui, sans-serif;
    --font-body: system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --ground: #17191a; --surface: #1f2223; --ink: #f2efe8; --muted: #9a968d;
      --border: #2c2f30; --accent: #2dd4bf; --accent-strong: #5fe6d4;
      --code-bg: #14201f;
      --shadow: 0 1px 2px rgba(0,0,0,.3), 0 16px 40px -16px rgba(0,0,0,.6);
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--ground); color: var(--ink);
    font-family: var(--font-body); }
  .wrap { max-width: 44rem; margin: 0 auto; padding: 3rem 1.25rem 3.5rem; }
  .badge { display: inline-flex; align-items: center; gap: .45rem; padding: .3rem .7rem;
    background: color-mix(in srgb, var(--accent) 14%, transparent);
    color: var(--accent-strong); border-radius: 999px; font-size: .78rem;
    font-weight: 600; }
  .wrap h2 { font-family: var(--font-display); font-weight: 700; font-size: 1.8rem;
    letter-spacing: -.015em; margin: .8rem 0 .3rem; }
  .who { color: var(--muted); margin: 0 0 2rem; font-size: 1.02rem; }
  .who strong { color: var(--ink); }
  .panel { background: var(--surface); border: 1px solid var(--border);
    border-radius: 14px; padding: 1.1rem 1.2rem; margin-bottom: 1.1rem;
    box-shadow: var(--shadow); }
  .panel-head { display: flex; align-items: baseline; justify-content: space-between;
    gap: 1rem; margin-bottom: .7rem; }
  .panel-head h3 { font-family: var(--font-display); font-weight: 600;
    font-size: 1.02rem; margin: 0; }
  .panel-head span { font-size: .82rem; color: var(--muted); }
  pre { margin: 0; background: var(--code-bg); border-radius: 10px; padding: .9rem 1rem;
    overflow-x: auto; font-family: ui-monospace, "SF Mono", monospace;
    font-size: .84rem; line-height: 1.5; color: var(--ink); }
  .topbar { display: flex; align-items: center; justify-content: space-between;
    gap: 1rem; margin-bottom: .2rem; }
  .again { color: var(--accent-strong); font-weight: 600; text-decoration: none;
    white-space: nowrap; }
  .again:hover { text-decoration: underline; }
</style>
</head>
<body>
  <main class="wrap">
    <div class="topbar">
      <span class="badge">&#10003; Signed in</span>
      <a class="again" href="/login">Log in again &rarr;</a>
    </div>
    <h2>You&rsquo;re signed in</h2>
    <p class="who">You are <strong>{{if .Name}}{{.Name}}{{else}}{{.Subject}}{{end}}</strong>{{if .Email}} &lt;{{.Email}}&gt;{{end}}.</p>
    <div class="panel">
      <div class="panel-head">
        <h3>ID token claims</h3>
        <span>Verified locally against hamnir's JWKS</span>
      </div>
      <pre>{{.IDTokenClaims}}</pre>
    </div>
    <div class="panel">
      <div class="panel-head">
        <h3>Userinfo claims</h3>
        <span>Fetched server-to-server with the access token</span>
      </div>
      <pre>{{.UserinfoClaims}}</pre>
    </div>
  </main>
</body>
</html>
`
