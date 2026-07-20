package server_test

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/strangemattersystems/hamnir/internal/config"
)

func TestAuthCodeFlow(t *testing.T) {
	t.Parallel()

	t.Run("auth code flow", func(t *testing.T) {
		t.Parallel()

		e := discover(t, aliceConfig())
		oauthCfg := e.app("isen", "", "email", "profile")
		verifier := oauth2.GenerateVerifier()
		code := e.obtainCode(t, oauthCfg, oidc.Nonce("nonce123"), oauth2.S256ChallengeOption(verifier))

		tok, err := oauthCfg.Exchange(e.ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		rawID, _ := tok.Extra("id_token").(string)
		if rawID == "" {
			t.Fatal("no id_token in token response")
		}

		// Verify the ID token against JWKS (independent RP verification).
		idTok, err := e.rp.Verifier(&oidc.Config{ClientID: "isen"}).Verify(e.ctx, rawID)
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

		// Refresh grant returns a new access token.
		refreshed, err := oauthCfg.TokenSource(e.ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}).Token()
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
		t.Parallel()

		e := discover(t, aliceConfig())
		oauthCfg := e.app("webapp", "any-secret", "email")
		code := e.obtainCode(t, oauthCfg, oidc.Nonce("nonce123"))

		tok, err := oauthCfg.Exchange(e.ctx, code)
		if err != nil {
			t.Fatalf("exchange with client secret and no PKCE: %v", err)
		}
		rawID, _ := tok.Extra("id_token").(string)
		if rawID == "" {
			t.Fatal("no id_token in token response")
		}
		if _, err := e.rp.Verifier(&oidc.Config{ClientID: "webapp"}).Verify(e.ctx, rawID); err != nil {
			t.Fatalf("verify id_token: %v", err)
		}
	})

	// unauthenticated exchange rejected: a client presenting neither a secret
	// nor PKCE is non-conformant; real IdPs reject it, so hamnir does too.
	t.Run("no secret and no pkce rejected", func(t *testing.T) {
		t.Parallel()

		e := discover(t, aliceConfig())
		oauthCfg := e.app("webapp", "")
		code := e.obtainCode(t, oauthCfg)

		if _, err := oauthCfg.Exchange(e.ctx, code); err == nil {
			t.Fatal("expected exchange with neither secret nor PKCE to be rejected")
		}
	})

	// pkce mismatch: the token endpoint rejects a code exchange presenting the
	// wrong PKCE verifier — proof that PKCE is enforced, not merely accepted.
	t.Run("pkce mismatch", func(t *testing.T) {
		t.Parallel()

		e := discover(t, aliceConfig())
		oauthCfg := e.app("isen", "")
		verifier := oauth2.GenerateVerifier()
		code := e.obtainCode(t, oauthCfg, oauth2.S256ChallengeOption(verifier))

		// Exchange with a DIFFERENT verifier than the challenge was derived from.
		wrong := oauth2.GenerateVerifier()
		if _, err := oauthCfg.Exchange(e.ctx, code, oauth2.VerifierOption(wrong)); err == nil {
			t.Fatal("expected exchange with a mismatched PKCE verifier to be rejected")
		}
	})

	// unregistered redirect: once a client is configured (strict mode), an
	// authorize request carrying a redirect_uri the client did not register is
	// refused — and the user is never redirected to it (no open redirect).
	t.Run("unregistered redirect", func(t *testing.T) {
		t.Parallel()

		cfg := aliceConfig()
		cfg.Clients = []config.Client{{
			ID:           "isen",
			RedirectURIs: []string{"http://app.test/callback"},
		}}
		e := discover(t, cfg)
		oauthCfg := e.app("isen", "")
		oauthCfg.RedirectURL = "http://evil.test/callback" // NOT registered
		verifier := oauth2.GenerateVerifier()
		authURL := oauthCfg.AuthCodeURL("state123", oauth2.S256ChallengeOption(verifier))

		resp, err := e.client.Get(authURL)
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

	t.Run("implicit response type rejected", func(t *testing.T) {
		t.Parallel()

		e := discover(t, aliceConfig())
		authURL := e.srv.URL + "/authorize?client_id=isen" +
			"&redirect_uri=" + url.QueryEscape("http://app.test/callback") +
			"&response_type=id_token&scope=openid&nonce=n123"
		resp, err := e.client.Get(authURL)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		// hamnir never issues anything for an implicit request: op rejects it
		// against the client's registered response types and delivers the
		// error in the fragment (the implicit flow's response mode).
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("expected an error redirect, got status %d", resp.StatusCode)
		}
		loc := resp.Header.Get("Location")
		if !strings.Contains(loc, "#error=unauthorized_client") || strings.Contains(loc, "code=") {
			t.Fatalf("expected a fragment error without a code, got %q", loc)
		}
	})
}

func TestLogoutAndRevocation(t *testing.T) {
	t.Parallel()

	// logout redirect round-trip: permissive mode accepts any redirect_uri at
	// login, so RP-initiated logout must honour post_logout_redirect_uri the
	// same way, sending the browser back to the app with the state echoed.
	t.Run("logout redirect round-trip", func(t *testing.T) {
		t.Parallel()

		e := discover(t, aliceConfig())
		oauthCfg := e.app("isen", "")
		verifier := oauth2.GenerateVerifier()
		code := e.obtainCode(t, oauthCfg, oidc.Nonce("nonce123"), oauth2.S256ChallengeOption(verifier))

		tok, err := oauthCfg.Exchange(e.ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		rawID, _ := tok.Extra("id_token").(string)
		if rawID == "" {
			t.Fatal("no id_token in token response")
		}

		logoutURL := e.disc.EndSession + "?id_token_hint=" + url.QueryEscape(rawID) +
			"&post_logout_redirect_uri=" + url.QueryEscape("http://app.test/loggedout") +
			"&state=st8"
		resp, err := e.client.Get(logoutURL)
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

	// logout revokes refresh: after a full login, hitting the end-session
	// endpoint invalidates the session's refresh token so a later refresh grant
	// is rejected.
	t.Run("logout revokes refresh", func(t *testing.T) {
		t.Parallel()

		e := discover(t, aliceConfig())
		oauthCfg := e.app("isen", "", "email")
		verifier := oauth2.GenerateVerifier()
		code := e.obtainCode(t, oauthCfg, oidc.Nonce("nonce123"), oauth2.S256ChallengeOption(verifier))

		tok, err := oauthCfg.Exchange(e.ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		rawID, _ := tok.Extra("id_token").(string)
		if rawID == "" || tok.RefreshToken == "" {
			t.Fatalf("expected id and refresh tokens; id=%q refresh=%q", rawID, tok.RefreshToken)
		}

		// The refresh token works before logout.
		if _, err := oauthCfg.TokenSource(e.ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}).Token(); err != nil {
			t.Fatalf("refresh before logout should succeed: %v", err)
		}

		resp, err := e.client.Get(e.disc.EndSession + "?id_token_hint=" + url.QueryEscape(rawID))
		if err != nil {
			t.Fatalf("logout: %v", err)
		}
		_ = resp.Body.Close()

		// After logout the refresh token must be rejected.
		if _, err := oauthCfg.TokenSource(e.ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}).Token(); err == nil {
			t.Fatal("refresh token should be rejected after logout")
		}
	})

	// revocation endpoint: RFC 7009 revocation of a refresh token must actually
	// invalidate it — a later refresh grant with the revoked token fails.
	t.Run("revoke endpoint invalidates refresh token", func(t *testing.T) {
		t.Parallel()

		e := discover(t, aliceConfig())
		oauthCfg := e.app("isen", "")
		verifier := oauth2.GenerateVerifier()
		code := e.obtainCode(t, oauthCfg, oauth2.S256ChallengeOption(verifier))

		tok, err := oauthCfg.Exchange(e.ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if tok.RefreshToken == "" {
			t.Fatal("expected a refresh token")
		}

		resp, err := e.client.PostForm(e.disc.Revocation, url.Values{
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

		if _, err := oauthCfg.TokenSource(e.ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}).Token(); err == nil {
			t.Fatal("refresh token should be rejected after revocation")
		}
	})

	// rotation: a refresh grant rotates the token; replaying the previous
	// refresh token afterwards must fail, as against a real IdP.
	t.Run("rotation invalidates replayed refresh token", func(t *testing.T) {
		t.Parallel()

		e := discover(t, aliceConfig())
		oauthCfg := e.app("isen", "")
		verifier := oauth2.GenerateVerifier()
		code := e.obtainCode(t, oauthCfg, oauth2.S256ChallengeOption(verifier))

		tok, err := oauthCfg.Exchange(e.ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		old := tok.RefreshToken

		rotated, err := oauthCfg.TokenSource(e.ctx, &oauth2.Token{RefreshToken: old}).Token()
		if err != nil {
			t.Fatalf("refresh grant: %v", err)
		}
		if rotated.RefreshToken == "" || rotated.RefreshToken == old {
			t.Fatalf("expected a rotated refresh token, got %q", rotated.RefreshToken)
		}

		// The rotated token works; the replaced one must not.
		if _, err := oauthCfg.TokenSource(e.ctx, &oauth2.Token{RefreshToken: rotated.RefreshToken}).Token(); err != nil {
			t.Fatalf("rotated refresh token should work: %v", err)
		}
		if _, err := oauthCfg.TokenSource(e.ctx, &oauth2.Token{RefreshToken: old}).Token(); err == nil {
			t.Fatal("replaying the pre-rotation refresh token should be rejected")
		}
	})

	// userinfo after logout: once the session is terminated the still-unexpired
	// access token must be rejected outright, not answered with stripped claims.
	t.Run("userinfo rejects token after logout", func(t *testing.T) {
		t.Parallel()

		e := discover(t, aliceConfig())
		oauthCfg := e.app("isen", "", "email")
		verifier := oauth2.GenerateVerifier()
		code := e.obtainCode(t, oauthCfg, oidc.Nonce("nonce123"), oauth2.S256ChallengeOption(verifier))

		tok, err := oauthCfg.Exchange(e.ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		rawID, _ := tok.Extra("id_token").(string)

		userinfo := func() *http.Response {
			req, _ := http.NewRequest(http.MethodGet, e.disc.Userinfo, nil)
			req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
			resp, err := e.client.Do(req)
			if err != nil {
				t.Fatalf("userinfo: %v", err)
			}
			return resp
		}

		if resp := userinfo(); resp.StatusCode != http.StatusOK || !strings.Contains(readBody(t, resp), "alice@example.test") {
			t.Fatalf("userinfo before logout should return the email claim (status %d)", resp.StatusCode)
		}

		resp, err := e.client.Get(e.disc.EndSession + "?id_token_hint=" + url.QueryEscape(rawID))
		if err != nil {
			t.Fatalf("logout: %v", err)
		}
		_ = resp.Body.Close()

		if resp := userinfo(); resp.StatusCode == http.StatusOK {
			t.Fatalf("userinfo after logout should be rejected, got 200: %s", readBody(t, resp))
		}
	})
}

func TestTokenClaims(t *testing.T) {
	t.Parallel()

	// A configured audience must reach the access token's aud verbatim, and the
	// id_token's aud must contain both it and the client_id (op appends the
	// client; spec-legal, deliberate).
	t.Run("configured audience", func(t *testing.T) {
		t.Parallel()

		cfg := aliceConfig()
		cfg.Audiences = []string{"https://api.example.test"}
		e := discover(t, cfg)
		oauthCfg := e.app("some-client", "")
		verifier := oauth2.GenerateVerifier()
		code := e.obtainCode(t, oauthCfg, oauth2.S256ChallengeOption(verifier))

		tok, err := oauthCfg.Exchange(e.ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}

		// Access token: aud is exactly the configured list (client_id replaced).
		var atClaims struct {
			Aud any `json:"aud"`
		}
		decodeJWTPayload(t, tok.AccessToken, &atClaims)
		if aud := audSlice(atClaims.Aud); len(aud) != 1 || aud[0] != "https://api.example.test" {
			t.Fatalf("access token aud = %v, want [https://api.example.test]", aud)
		}

		// ID token: aud contains the configured audience AND the client_id.
		rawID, _ := tok.Extra("id_token").(string)
		var idClaims struct {
			Aud any `json:"aud"`
		}
		decodeJWTPayload(t, rawID, &idClaims)
		aud := audSlice(idClaims.Aud)
		if !slices.Contains(aud, "https://api.example.test") || !slices.Contains(aud, "some-client") {
			t.Fatalf("id token aud = %v, want configured audience and client_id", aud)
		}
	})
}

func TestLoginHint(t *testing.T) {
	t.Parallel()

	t.Run("auto-login skips the picker", func(t *testing.T) {
		t.Parallel()

		e := discover(t, aliceConfig())
		oauthCfg := e.app("isen", "", "email")
		verifier := oauth2.GenerateVerifier()
		authURL := oauthCfg.AuthCodeURL("state123",
			oidc.Nonce("nonce123"),
			oauth2.S256ChallengeOption(verifier),
			oauth2.SetAuthURLParam("login_hint", "alice@example.test"))

		resp, err := e.client.Get(authURL)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		code := codeFrom(resp)
		if code == "" {
			t.Fatalf("expected the hinted flow to end at the app redirect with a code; final status %d, body: %s",
				resp.StatusCode, readBody(t, resp))
		}

		tok, err := oauthCfg.Exchange(e.ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		rawID, _ := tok.Extra("id_token").(string)
		var claims struct {
			Sub string `json:"sub"`
		}
		decodeJWTPayload(t, rawID, &claims)
		if claims.Sub != "usr_alice" {
			t.Fatalf("hinted login issued sub %q, want usr_alice", claims.Sub)
		}
	})

	t.Run("prompt=select_account forces the prefilled picker", func(t *testing.T) {
		t.Parallel()

		e := discover(t, aliceConfig())
		oauthCfg := e.app("isen", "", "email")
		authURL := oauthCfg.AuthCodeURL("state123",
			oauth2.SetAuthURLParam("login_hint", "alice@example.test"),
			oauth2.SetAuthURLParam("prompt", "select_account"))

		resp, err := e.client.Get(authURL)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		body := readBody(t, resp)
		if !strings.Contains(body, `name="authRequestID"`) {
			t.Fatalf("expected the picker page, got: %s", body)
		}
		if !strings.Contains(body, `value="alice@example.test"`) {
			t.Errorf("expected the search box prefilled with the hint, got: %s", body)
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
