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

func TestEndToEndAuthCodeFlow(t *testing.T) {
	cfg := &config.Config{Personas: []config.Persona{
		{Name: "Alice", Claims: map[string]any{
			"sub": "usr_alice", "email": "alice@example.test",
			"email_verified": true, "roles": []any{"coach"},
		}},
	}}
	key, err := provider.LoadOrGenerateKey(filepath.Join(t.TempDir(), "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(cfg, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	client := srv.Client()
	client.Jar = jar
	// Don't actually dial the app's callback host; stop there so we can read the code.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Host == "app.test" {
			return http.ErrUseLastResponse
		}
		return nil
	}

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

	// 1. Authorize → follow to the picker.
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "Alice") {
		t.Fatalf("expected picker, got: %s", body)
	}
	authRequestID := between(body, `name="authRequestID" value="`, `"`)
	if authRequestID == "" {
		t.Fatalf("authRequestID not found in picker HTML")
	}

	// 2. Select the persona → provider issues the code and redirects to app.test.
	sel, err := client.PostForm(srv.URL+"/login/select", url.Values{
		"authRequestID": {authRequestID},
		"sub":           {"usr_alice"},
	})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	code := codeFrom(sel)
	if code == "" {
		t.Fatalf("no auth code; final=%s location=%s", sel.Request.URL, sel.Header.Get("Location"))
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
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
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
	j := strings.Index(s, end)
	if j < 0 {
		return ""
	}
	return s[:j]
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
