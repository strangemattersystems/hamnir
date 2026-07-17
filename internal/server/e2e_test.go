package server

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/provider"
)

func TestEndToEnd(t *testing.T) {
	t.Run("auth code flow", func(t *testing.T) {
		srv, client := newServer(t, aliceConfig())
		ctx := oidc.ClientContext(context.Background(), client)
		rp, err := oidc.NewProvider(ctx, srv.URL)
		if err != nil {
			t.Fatalf("discovery: %v", err)
		}

		oauthCfg := oauth2.Config{
			ClientID:    "isen",
			Endpoint:    rp.Endpoint(),
			RedirectURL: "http://app.test/callback",
			Scopes:      []string{oidc.ScopeOpenID, "email", "profile"},
		}
		verifier := oauth2.GenerateVerifier()
		authURL := oauthCfg.AuthCodeURL("state123", oidc.Nonce("nonce123"), oauth2.S256ChallengeOption(verifier))

		// 1+2. Authorize → picker → select Alice; the redirect carries the code.
		code := codeFrom(authorizeAndSelect(t, client, srv.URL, authURL))
		if code == "" {
			t.Fatal("expected an auth code")
		}

		// 3. Exchange code + PKCE verifier.
		tok, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		rawID, _ := tok.Extra("id_token").(string)
		if rawID == "" {
			t.Fatal("no id_token in token response")
		}

		// 4. Verify the ID token against JWKS (independent RP verification).
		idTok, err := rp.Verifier(&oidc.Config{ClientID: "isen"}).Verify(ctx, rawID)
		if err != nil {
			t.Fatalf("verify id_token: %v", err)
		}
		var claims map[string]any
		if err := idTok.Claims(&claims); err != nil {
			t.Fatal(err)
		}
		if claims["sub"] != "usr_alice" || claims["email"] != "alice@example.test" {
			t.Fatalf("unexpected claims: %v", claims)
		}
		if _, ok := claims["roles"]; !ok {
			t.Fatalf("custom claim 'roles' should always be present: %v", claims)
		}
		if tok.RefreshToken == "" {
			t.Fatal("expected a refresh token by default")
		}

		// 5. Refresh grant returns a new access token.
		refreshed, err := oauthCfg.TokenSource(ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}).Token()
		if err != nil {
			t.Fatalf("refresh grant: %v", err)
		}
		if refreshed.AccessToken == "" {
			t.Fatal("refresh returned no access token")
		}
	})

	// confidential client without pkce: permissive mode must accept the other
	// standard client shape — client secret auth with no PKCE (any secret is
	// accepted since none is registered).
	t.Run("confidential client without pkce", func(t *testing.T) {
		srv, client := newServer(t, aliceConfig())
		ctx := oidc.ClientContext(context.Background(), client)
		rp, err := oidc.NewProvider(ctx, srv.URL)
		if err != nil {
			t.Fatalf("discovery: %v", err)
		}
		oauthCfg := oauth2.Config{
			ClientID:     "webapp",
			ClientSecret: "any-secret",
			Endpoint:     rp.Endpoint(),
			RedirectURL:  "http://app.test/callback",
			Scopes:       []string{oidc.ScopeOpenID, "email"},
		}
		authURL := oauthCfg.AuthCodeURL("state123", oidc.Nonce("nonce123"))

		code := codeFrom(authorizeAndSelect(t, client, srv.URL, authURL))
		if code == "" {
			t.Fatal("expected an auth code")
		}
		tok, err := oauthCfg.Exchange(ctx, code)
		if err != nil {
			t.Fatalf("exchange with client secret and no PKCE: %v", err)
		}
		rawID, _ := tok.Extra("id_token").(string)
		if rawID == "" {
			t.Fatal("no id_token in token response")
		}
		if _, err := rp.Verifier(&oidc.Config{ClientID: "webapp"}).Verify(ctx, rawID); err != nil {
			t.Fatalf("verify id_token: %v", err)
		}
	})

	// unauthenticated exchange rejected: a client presenting neither a secret
	// nor PKCE is non-conformant; real IdPs reject it, so hamnir does too.
	t.Run("no secret and no pkce rejected", func(t *testing.T) {
		srv, client := newServer(t, aliceConfig())
		ctx := oidc.ClientContext(context.Background(), client)
		rp, err := oidc.NewProvider(ctx, srv.URL)
		if err != nil {
			t.Fatalf("discovery: %v", err)
		}
		oauthCfg := oauth2.Config{
			ClientID:    "webapp",
			Endpoint:    rp.Endpoint(),
			RedirectURL: "http://app.test/callback",
			Scopes:      []string{oidc.ScopeOpenID},
		}
		authURL := oauthCfg.AuthCodeURL("state123")

		code := codeFrom(authorizeAndSelect(t, client, srv.URL, authURL))
		if code == "" {
			t.Fatal("expected an auth code")
		}
		if _, err := oauthCfg.Exchange(ctx, code); err == nil {
			t.Fatal("expected exchange with neither secret nor PKCE to be rejected")
		}
	})

	// logout redirect round-trip: permissive mode accepts any redirect_uri at
	// login, so RP-initiated logout must honour post_logout_redirect_uri the
	// same way, sending the browser back to the app with the state echoed.
	t.Run("logout redirect round-trip", func(t *testing.T) {
		srv, client := newServer(t, aliceConfig())
		ctx := oidc.ClientContext(context.Background(), client)
		rp, err := oidc.NewProvider(ctx, srv.URL)
		if err != nil {
			t.Fatalf("discovery: %v", err)
		}
		oauthCfg := oauth2.Config{
			ClientID:    "isen",
			Endpoint:    rp.Endpoint(),
			RedirectURL: "http://app.test/callback",
			Scopes:      []string{oidc.ScopeOpenID},
		}
		verifier := oauth2.GenerateVerifier()
		authURL := oauthCfg.AuthCodeURL("state123", oidc.Nonce("nonce123"), oauth2.S256ChallengeOption(verifier))

		code := codeFrom(authorizeAndSelect(t, client, srv.URL, authURL))
		if code == "" {
			t.Fatal("expected an auth code")
		}
		tok, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		rawID, _ := tok.Extra("id_token").(string)
		if rawID == "" {
			t.Fatal("no id_token in token response")
		}

		var disc struct {
			EndSession string `json:"end_session_endpoint"`
		}
		if err := rp.Claims(&disc); err != nil {
			t.Fatal(err)
		}
		logoutURL := disc.EndSession + "?id_token_hint=" + url.QueryEscape(rawID) +
			"&post_logout_redirect_uri=" + url.QueryEscape("http://app.test/loggedout") +
			"&state=st8"
		resp, err := client.Get(logoutURL)
		if err != nil {
			t.Fatalf("logout: %v", err)
		}
		_ = resp.Body.Close()
		loc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil || resp.StatusCode != http.StatusFound {
			t.Fatalf("expected redirect to post_logout_redirect_uri, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
		}
		if loc.Host != "app.test" || loc.Path != "/loggedout" || loc.Query().Get("state") != "st8" {
			t.Fatalf("unexpected post-logout redirect: %s", loc)
		}
	})

	// pkce mismatch: the token endpoint rejects a code exchange presenting the
	// wrong PKCE verifier — proof that PKCE is enforced, not merely accepted.
	t.Run("pkce mismatch", func(t *testing.T) {
		srv, client := newServer(t, aliceConfig())
		ctx := oidc.ClientContext(context.Background(), client)
		rp, err := oidc.NewProvider(ctx, srv.URL)
		if err != nil {
			t.Fatalf("discovery: %v", err)
		}
		oauthCfg := oauth2.Config{
			ClientID:    "isen",
			Endpoint:    rp.Endpoint(),
			RedirectURL: "http://app.test/callback",
			Scopes:      []string{oidc.ScopeOpenID},
		}
		verifier := oauth2.GenerateVerifier()
		authURL := oauthCfg.AuthCodeURL("state123", oauth2.S256ChallengeOption(verifier))

		code := codeFrom(authorizeAndSelect(t, client, srv.URL, authURL))
		if code == "" {
			t.Fatal("expected an auth code")
		}

		// Exchange with a DIFFERENT verifier than the challenge was derived from.
		wrong := oauth2.GenerateVerifier()
		if _, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(wrong)); err == nil {
			t.Fatal("expected exchange with a mismatched PKCE verifier to be rejected")
		}
	})

	// unregistered redirect: once a client is configured (strict mode), an
	// authorize request carrying a redirect_uri the client did not register is
	// refused — and the user is never redirected to it (no open redirect).
	t.Run("unregistered redirect", func(t *testing.T) {
		cfg := aliceConfig()
		cfg.Clients = []config.Client{{
			ID:           "isen",
			RedirectURIs: []string{"http://app.test/callback"},
		}}
		srv, client := newServer(t, cfg)
		ctx := oidc.ClientContext(context.Background(), client)
		rp, err := oidc.NewProvider(ctx, srv.URL)
		if err != nil {
			t.Fatalf("discovery: %v", err)
		}
		oauthCfg := oauth2.Config{
			ClientID:    "isen",
			Endpoint:    rp.Endpoint(),
			RedirectURL: "http://evil.test/callback", // NOT registered
			Scopes:      []string{oidc.ScopeOpenID},
		}
		verifier := oauth2.GenerateVerifier()
		authURL := oauthCfg.AuthCodeURL("state123", oauth2.S256ChallengeOption(verifier))

		resp, err := client.Get(authURL)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		body := readBody(t, resp)
		if id := between(body, `name="authRequestID" value="`, `"`); id != "" {
			t.Fatal("an unregistered redirect_uri must not reach the persona picker")
		}
		if resp.Request.URL.Host == "evil.test" {
			t.Fatal("must not redirect to an unregistered redirect_uri (open redirect)")
		}
	})

	// logout revokes refresh: after a full login, hitting the end-session
	// endpoint invalidates the session's refresh token so a later refresh grant
	// is rejected.
	t.Run("logout revokes refresh", func(t *testing.T) {
		srv, client := newServer(t, aliceConfig())
		ctx := oidc.ClientContext(context.Background(), client)
		rp, err := oidc.NewProvider(ctx, srv.URL)
		if err != nil {
			t.Fatalf("discovery: %v", err)
		}
		oauthCfg := oauth2.Config{
			ClientID:    "isen",
			Endpoint:    rp.Endpoint(),
			RedirectURL: "http://app.test/callback",
			Scopes:      []string{oidc.ScopeOpenID, "email"},
		}
		verifier := oauth2.GenerateVerifier()
		authURL := oauthCfg.AuthCodeURL("state123", oidc.Nonce("nonce123"), oauth2.S256ChallengeOption(verifier))

		code := codeFrom(authorizeAndSelect(t, client, srv.URL, authURL))
		if code == "" {
			t.Fatal("expected an auth code")
		}
		tok, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		rawID, _ := tok.Extra("id_token").(string)
		if rawID == "" || tok.RefreshToken == "" {
			t.Fatalf("expected id and refresh tokens; id=%q refresh=%q", rawID, tok.RefreshToken)
		}

		// The refresh token works before logout.
		if _, err := oauthCfg.TokenSource(ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}).Token(); err != nil {
			t.Fatalf("refresh before logout should succeed: %v", err)
		}

		// Log out via the end-session endpoint (discovered from the metadata).
		var disc struct {
			EndSession string `json:"end_session_endpoint"`
		}
		if err := rp.Claims(&disc); err != nil {
			t.Fatal(err)
		}
		if disc.EndSession == "" {
			t.Fatal("provider metadata has no end_session_endpoint")
		}
		logoutURL := disc.EndSession + "?id_token_hint=" + url.QueryEscape(rawID)
		resp, err := client.Get(logoutURL)
		if err != nil {
			t.Fatalf("logout: %v", err)
		}
		_ = resp.Body.Close()

		// After logout the refresh token must be rejected.
		if _, err := oauthCfg.TokenSource(ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}).Token(); err == nil {
			t.Fatal("refresh token should be rejected after logout")
		}
	})

	// revocation endpoint: RFC 7009 revocation of a refresh token must actually
	// invalidate it — a later refresh grant with the revoked token fails.
	t.Run("revoke endpoint invalidates refresh token", func(t *testing.T) {
		srv, client := newServer(t, aliceConfig())
		ctx := oidc.ClientContext(context.Background(), client)
		rp, err := oidc.NewProvider(ctx, srv.URL)
		if err != nil {
			t.Fatalf("discovery: %v", err)
		}
		oauthCfg := oauth2.Config{
			ClientID:    "isen",
			Endpoint:    rp.Endpoint(),
			RedirectURL: "http://app.test/callback",
			Scopes:      []string{oidc.ScopeOpenID},
		}
		verifier := oauth2.GenerateVerifier()
		authURL := oauthCfg.AuthCodeURL("state123", oauth2.S256ChallengeOption(verifier))

		code := codeFrom(authorizeAndSelect(t, client, srv.URL, authURL))
		tok, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if tok.RefreshToken == "" {
			t.Fatal("expected a refresh token")
		}

		var disc struct {
			Revocation string `json:"revocation_endpoint"`
		}
		if err := rp.Claims(&disc); err != nil {
			t.Fatal(err)
		}
		if disc.Revocation == "" {
			t.Fatal("provider metadata has no revocation_endpoint")
		}
		resp, err := client.PostForm(disc.Revocation, url.Values{
			"token":           {tok.RefreshToken},
			"token_type_hint": {"refresh_token"},
			"client_id":       {"isen"},
		})
		if err != nil {
			t.Fatalf("revoke: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("revoke status = %d, want 200", resp.StatusCode)
		}

		if _, err := oauthCfg.TokenSource(ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}).Token(); err == nil {
			t.Fatal("refresh token should be rejected after revocation")
		}
	})

	// rotation: a refresh grant rotates the token; replaying the previous
	// refresh token afterwards must fail, as against a real IdP.
	t.Run("rotation invalidates replayed refresh token", func(t *testing.T) {
		srv, client := newServer(t, aliceConfig())
		ctx := oidc.ClientContext(context.Background(), client)
		rp, err := oidc.NewProvider(ctx, srv.URL)
		if err != nil {
			t.Fatalf("discovery: %v", err)
		}
		oauthCfg := oauth2.Config{
			ClientID:    "isen",
			Endpoint:    rp.Endpoint(),
			RedirectURL: "http://app.test/callback",
			Scopes:      []string{oidc.ScopeOpenID},
		}
		verifier := oauth2.GenerateVerifier()
		authURL := oauthCfg.AuthCodeURL("state123", oauth2.S256ChallengeOption(verifier))

		code := codeFrom(authorizeAndSelect(t, client, srv.URL, authURL))
		tok, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		old := tok.RefreshToken

		rotated, err := oauthCfg.TokenSource(ctx, &oauth2.Token{RefreshToken: old}).Token()
		if err != nil {
			t.Fatalf("refresh grant: %v", err)
		}
		if rotated.RefreshToken == "" || rotated.RefreshToken == old {
			t.Fatalf("expected a rotated refresh token, got %q", rotated.RefreshToken)
		}

		// The rotated token works; the replaced one must not.
		if _, err := oauthCfg.TokenSource(ctx, &oauth2.Token{RefreshToken: rotated.RefreshToken}).Token(); err != nil {
			t.Fatalf("rotated refresh token should work: %v", err)
		}
		if _, err := oauthCfg.TokenSource(ctx, &oauth2.Token{RefreshToken: old}).Token(); err == nil {
			t.Fatal("replaying the pre-rotation refresh token should be rejected")
		}
	})

	// userinfo after logout: once the session is terminated the still-unexpired
	// access token must be rejected outright, not answered with stripped claims.
	t.Run("userinfo rejects token after logout", func(t *testing.T) {
		srv, client := newServer(t, aliceConfig())
		ctx := oidc.ClientContext(context.Background(), client)
		rp, err := oidc.NewProvider(ctx, srv.URL)
		if err != nil {
			t.Fatalf("discovery: %v", err)
		}
		oauthCfg := oauth2.Config{
			ClientID:    "isen",
			Endpoint:    rp.Endpoint(),
			RedirectURL: "http://app.test/callback",
			Scopes:      []string{oidc.ScopeOpenID, "email"},
		}
		verifier := oauth2.GenerateVerifier()
		authURL := oauthCfg.AuthCodeURL("state123", oidc.Nonce("nonce123"), oauth2.S256ChallengeOption(verifier))

		code := codeFrom(authorizeAndSelect(t, client, srv.URL, authURL))
		tok, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		rawID, _ := tok.Extra("id_token").(string)

		var disc struct {
			EndSession string `json:"end_session_endpoint"`
			Userinfo   string `json:"userinfo_endpoint"`
		}
		if err := rp.Claims(&disc); err != nil {
			t.Fatal(err)
		}

		userinfo := func() *http.Response {
			req, _ := http.NewRequest(http.MethodGet, disc.Userinfo, nil)
			req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("userinfo: %v", err)
			}
			return resp
		}

		if resp := userinfo(); resp.StatusCode != http.StatusOK || !strings.Contains(readBody(t, resp), "alice@example.test") {
			t.Fatalf("userinfo before logout should return the email claim (status %d)", resp.StatusCode)
		}

		resp, err := client.Get(disc.EndSession + "?id_token_hint=" + url.QueryEscape(rawID))
		if err != nil {
			t.Fatalf("logout: %v", err)
		}
		_ = resp.Body.Close()

		if resp := userinfo(); resp.StatusCode == http.StatusOK {
			t.Fatalf("userinfo after logout should be rejected, got 200: %s", readBody(t, resp))
		}
	})
}

// aliceConfig is the minimal permissive-mode config used across the end-to-end
// tests: a single persona, no clients (so any client_id/redirect_uri is accepted).
func aliceConfig() *config.Config {
	return &config.Config{Personas: []config.Persona{
		{Name: "Alice", Claims: map[string]any{
			"sub": "usr_alice", "email": "alice@example.test",
			"email_verified": true, "roles": []any{"coach"},
		}},
	}}
}

// newServer starts an httptest server for cfg with a cookie-jar client that stops
// following redirects at the app's callback host (app.test) so tests can read the
// authorization code out of the redirect.
func newServer(t *testing.T, cfg *config.Config) (*httptest.Server, *http.Client) {
	t.Helper()
	key, err := provider.LoadOrGenerateKey(filepath.Join(t.TempDir(), "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(cfg, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client := srv.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Host == "app.test" {
			return http.ErrUseLastResponse
		}
		return nil
	}
	return srv, client
}

// authorizeAndSelect drives the authorize request to the picker, then posts the
// selection of the Alice persona, returning the resulting response (whose
// redirect carries the authorization code).
func authorizeAndSelect(t *testing.T, client *http.Client, srvURL, authURL string) *http.Response {
	t.Helper()
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	body := readBody(t, resp)
	authRequestID := between(body, `name="authRequestID" value="`, `"`)
	if authRequestID == "" {
		t.Fatalf("authRequestID not found in picker HTML: %s", body)
	}
	sel, err := client.PostForm(srvURL+"/login/select", url.Values{
		"authRequestID": {authRequestID},
		"sub":           {"usr_alice"},
	})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	return sel
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	s = s[i+len(start):]
	before, _, ok := strings.Cut(s, end)
	if !ok {
		return ""
	}
	return before
}

func codeFrom(resp *http.Response) string {
	if loc := resp.Header.Get("Location"); loc != "" {
		if u, err := url.Parse(loc); err == nil {
			if c := u.Query().Get("code"); c != "" {
				return c
			}
		}
	}
	return resp.Request.URL.Query().Get("code")
}
