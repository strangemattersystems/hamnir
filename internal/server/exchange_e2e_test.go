package server

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/strangemattersystems/hamnir/internal/config"
)

const (
	grantTypeExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccess   = "urn:ietf:params:oauth:token-type:access_token"
	tokenTypeID       = "urn:ietf:params:oauth:token-type:id_token"
	tokenTypeRefresh  = "urn:ietf:params:oauth:token-type:refresh_token"
)

// tokenConfig is aliceConfig plus a static exchange token on the persona.
func tokenConfig() *config.Config {
	cfg := aliceConfig()
	cfg.Personas[0].Tokens = []string{"alice-ci"}
	return cfg
}

// exchangeForm builds the RFC 8693 form for a static persona token; extra
// entries overlay the defaults.
func exchangeForm(token string, extra url.Values) url.Values {
	form := url.Values{
		"grant_type":         {grantTypeExchange},
		"subject_token":      {token},
		"subject_token_type": {tokenTypeAccess},
	}
	maps.Copy(form, extra)
	return form
}

// postExchange POSTs form to the token endpoint — with client Basic auth when
// clientID is non-empty — and decodes the JSON response.
func postExchange(t *testing.T, e env, clientID, secret string, form url.Values) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.rp.Endpoint().TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" {
		req.SetBasicAuth(clientID, secret)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode exchange response: %v", err)
	}
	return resp.StatusCode, body
}

// userinfoBody fetches userinfo with the given bearer token, returning the
// response status and raw body for the caller to assert on.
func userinfoBody(t *testing.T, e env, accessToken string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.disc.Userinfo, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	return resp.StatusCode, readBody(t, resp)
}

// TestTokenExchange drives programmatic login end to end: a static persona
// token POSTed to the standard token endpoint yields real hamnir tokens. No
// subtest sets browser_url, so parallel execution is safe (see TestEndToEnd).
func TestTokenExchange(t *testing.T) {
	t.Parallel()

	// discovery advertises the grant automatically: op switches it on because
	// Storage implements the exchange interfaces, so absence here means the
	// wiring regressed.
	t.Run("grant advertised in discovery", func(t *testing.T) {
		t.Parallel()

		e := discover(t, tokenConfig())
		if !slices.Contains(e.disc.GrantTypes, grantTypeExchange) {
			t.Fatalf("grant_types_supported = %v, want %s included", e.disc.GrantTypes, grantTypeExchange)
		}
	})

	t.Run("static token yields access token", func(t *testing.T) {
		t.Parallel()

		e := discover(t, tokenConfig())
		status, body := postExchange(t, e, "myapp", "", exchangeForm("alice-ci", url.Values{"scope": {"openid email"}}))
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %v)", status, body)
		}
		access, _ := body["access_token"].(string)
		if access == "" {
			t.Fatalf("no access_token: %v", body)
		}
		if it := body["issued_token_type"]; it != tokenTypeAccess {
			t.Fatalf("issued_token_type = %v, want %s", it, tokenTypeAccess)
		}
		if tt := body["token_type"]; tt != "Bearer" {
			t.Fatalf("token_type = %v, want Bearer", tt)
		}
		if rt, ok := body["refresh_token"].(string); ok && rt != "" {
			t.Fatal("refresh token issued without the refresh token type being requested")
		}
		status, got := userinfoBody(t, e, access)
		if status != http.StatusOK {
			t.Fatalf("userinfo status = %d, want 200 (body %q)", status, got)
		}
		if !strings.Contains(got, "alice@example.test") {
			t.Fatalf("userinfo = %q, want alice's email released", got)
		}
	})

	// omitted scope is processed with the documented default set (RFC 6749
	// §3.3) rather than failing the request.
	t.Run("omitted scope defaults to openid profile email", func(t *testing.T) {
		t.Parallel()

		e := discover(t, tokenConfig())
		status, body := postExchange(t, e, "myapp", "", exchangeForm("alice-ci", nil))
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %v)", status, body)
		}
		scope, _ := body["scope"].(string)
		for _, want := range []string{"openid", "profile", "email"} {
			if !strings.Contains(scope, want) {
				t.Fatalf("scope = %q, want %q included", scope, want)
			}
		}
		access, _ := body["access_token"].(string)
		status, got := userinfoBody(t, e, access)
		if status != http.StatusOK {
			t.Fatalf("userinfo status = %d, want 200 (body %q)", status, got)
		}
		if !strings.Contains(got, "alice@example.test") {
			t.Fatalf("userinfo = %q, want email released under default scopes", got)
		}
	})

	// RFC 8693 issues one token per call: an explicit requested_token_type
	// swaps the default access token for a verifiable id token.
	t.Run("id token requested", func(t *testing.T) {
		t.Parallel()

		e := discover(t, tokenConfig())
		status, body := postExchange(t, e, "myapp", "", exchangeForm("alice-ci", url.Values{
			"requested_token_type": {tokenTypeID},
			"scope":                {"openid email"},
		}))
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %v)", status, body)
		}
		if it := body["issued_token_type"]; it != tokenTypeID {
			t.Fatalf("issued_token_type = %v, want %s", it, tokenTypeID)
		}
		// RFC 8693 §2.2.1: token_type is N_A when the issued token is not an
		// access token; the token itself still travels in access_token.
		if tt := body["token_type"]; tt != "N_A" {
			t.Fatalf("token_type = %v, want N_A", tt)
		}
		raw, _ := body["access_token"].(string)
		idTok, err := e.rp.Verifier(&oidc.Config{ClientID: "myapp"}).Verify(e.ctx, raw)
		if err != nil {
			t.Fatalf("verify issued id_token: %v", err)
		}
		var claims map[string]any
		if err := idTok.Claims(&claims); err != nil {
			t.Fatal(err)
		}
		if claims["sub"] != "usr_alice" || claims["email"] != "alice@example.test" {
			t.Fatalf("unexpected claims: %v", claims)
		}
	})

	// refresh tokens are opt-in the RFC 8693 way: only an explicit refresh
	// requested_token_type yields one (offline_access deliberately has no
	// effect on exchanges).
	t.Run("requested refresh token type yields working refresh token", func(t *testing.T) {
		t.Parallel()

		e := discover(t, tokenConfig())
		status, body := postExchange(t, e, "myapp", "", exchangeForm("alice-ci", url.Values{
			"requested_token_type": {tokenTypeRefresh},
			"scope":                {"openid email"},
		}))
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %v)", status, body)
		}
		rt, _ := body["refresh_token"].(string)
		if rt == "" {
			t.Fatalf("no refresh_token when the refresh token type was requested: %v", body)
		}
		oauthCfg := e.app("myapp", "")
		refreshed, err := oauthCfg.TokenSource(e.ctx, &oauth2.Token{RefreshToken: rt}).Token()
		if err != nil {
			t.Fatalf("refresh grant on exchanged token: %v", err)
		}
		if refreshed.AccessToken == "" {
			t.Fatal("refresh returned no access token")
		}
	})

	// unknown subject tokens must fail closed as invalid_request, never mint
	// a session.
	t.Run("unknown token rejected", func(t *testing.T) {
		t.Parallel()

		e := discover(t, tokenConfig())
		status, body := postExchange(t, e, "myapp", "", exchangeForm("who-dis", nil))
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %v)", status, body)
		}
		if body["error"] != "invalid_request" {
			t.Fatalf("error = %v, want invalid_request", body["error"])
		}
	})

	// static tokens are opaque, so they are accepted only under the
	// access-token subject type; other types must not resolve them.
	t.Run("static token under wrong subject_token_type rejected", func(t *testing.T) {
		t.Parallel()

		e := discover(t, tokenConfig())
		form := exchangeForm("alice-ci", nil)
		form.Set("subject_token_type", tokenTypeID)
		status, body := postExchange(t, e, "myapp", "", form)
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %v)", status, body)
		}
	})

	// permissive mode extends to the exchange: no client auth needed, matching
	// how the code flow accepts any client when none are registered.
	t.Run("no client auth accepted in permissive mode", func(t *testing.T) {
		t.Parallel()

		e := discover(t, tokenConfig())
		status, body := postExchange(t, e, "", "", exchangeForm("alice-ci", nil))
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %v)", status, body)
		}
	})

	t.Run("registered clients", func(t *testing.T) {
		t.Parallel()

		cfg := tokenConfig()
		cfg.Clients = []config.Client{
			{ID: "tests", Secret: "s3cret"},
			{ID: "spa"},
		}
		e := discover(t, cfg)

		if status, body := postExchange(t, e, "tests", "s3cret", exchangeForm("alice-ci", nil)); status != http.StatusOK {
			t.Fatalf("confidential client: status = %d, want 200 (body %v)", status, body)
		}
		if status, _ := postExchange(t, e, "tests", "wrong", exchangeForm("alice-ci", nil)); status == http.StatusOK {
			t.Fatal("wrong secret must be rejected")
		}
		// Public clients use PKCE, which has no exchange equivalent; option 1
		// in the design keeps them rejected (see deferred-minors follow-up).
		if status, _ := postExchange(t, e, "spa", "", exchangeForm("alice-ci", nil)); status == http.StatusOK {
			t.Fatal("public client must be rejected")
		}
	})

	// an op-minted access token also works as a subject token: op resolves its
	// own tokens before falling back to the static-token verifier.
	t.Run("hamnir-issued access token as subject token", func(t *testing.T) {
		t.Parallel()

		e := discover(t, tokenConfig())
		oauthCfg := e.app("isen", "", "email")
		verifier := oauth2.GenerateVerifier()
		code := e.obtainCode(t, oauthCfg, oidc.Nonce("n0"), oauth2.S256ChallengeOption(verifier))
		tok, err := oauthCfg.Exchange(e.ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatalf("code exchange: %v", err)
		}

		status, body := postExchange(t, e, "myapp", "", exchangeForm(tok.AccessToken, url.Values{"scope": {"openid email"}}))
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %v)", status, body)
		}
		access, _ := body["access_token"].(string)
		uStatus, got := userinfoBody(t, e, access)
		if uStatus != http.StatusOK {
			t.Fatalf("userinfo status = %d, want 200 (body %q)", uStatus, got)
		}
		if !strings.Contains(got, "alice@example.test") {
			t.Fatalf("userinfo = %q, want alice via op-issued subject token", got)
		}
	})
}
