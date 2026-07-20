package server_test

import (
	"encoding/base64"
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
	tokenTypePersona  = "https://hamnir.dev/token-type/persona"
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
		"subject_token_type": {tokenTypePersona},
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

// jwtPayload decodes a JWT's claims without verifying it — these tests only
// inspect what the server minted; signature verification is covered where the
// RP library is driven.
func jwtPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// anyToStrings narrows a decoded JSON array to strings for comparison.
func anyToStrings(vals []any) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
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
// subtest sets browser_url, so parallel execution is safe (see the
// parallel-safety note atop harness_test.go).
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

	// configured audiences must reach exchanged tokens exactly as they reach
	// code-flow tokens: op offers no exchange-side audience hook, so hamnir
	// defaults the omitted RFC 8693 audience parameter from config before op
	// parses the request. Refresh rotation re-derives the same values, so the
	// audience no longer flips mid-session for the defaulted case.
	t.Run("configured audiences apply to exchanged tokens", func(t *testing.T) {
		t.Parallel()

		cfg := tokenConfig()
		cfg.Audiences = []string{"https://api.example.test"}
		e := discover(t, cfg)
		status, body := postExchange(t, e, "myapp", "", exchangeForm("alice-ci", url.Values{
			"requested_token_type": {tokenTypeRefresh},
			"scope":                {"openid email"},
		}))
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %v)", status, body)
		}
		access, _ := body["access_token"].(string)
		if aud, _ := jwtPayload(t, access)["aud"].([]any); !slices.Equal(anyToStrings(aud), []string{"https://api.example.test"}) {
			t.Fatalf("exchanged aud = %v, want configured audience", aud)
		}

		rt, _ := body["refresh_token"].(string)
		oauthCfg := e.app("myapp", "")
		refreshed, err := oauthCfg.TokenSource(e.ctx, &oauth2.Token{RefreshToken: rt}).Token()
		if err != nil {
			t.Fatalf("refresh grant: %v", err)
		}
		if aud, _ := jwtPayload(t, refreshed.AccessToken)["aud"].([]any); !slices.Equal(anyToStrings(aud), []string{"https://api.example.test"}) {
			t.Fatalf("refreshed aud = %v, want configured audience (no flip)", aud)
		}
	})

	// the RFC 8693 audience parameter stays the caller's override.
	t.Run("explicit audience wins over config", func(t *testing.T) {
		t.Parallel()

		cfg := tokenConfig()
		cfg.Audiences = []string{"https://api.example.test"}
		e := discover(t, cfg)
		status, body := postExchange(t, e, "myapp", "", exchangeForm("alice-ci", url.Values{
			"audience":             {"https://other.test"},
			"scope":                {"openid email"},
			"requested_token_type": {tokenTypeRefresh},
		}))
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %v)", status, body)
		}
		access, _ := body["access_token"].(string)
		if aud, _ := jwtPayload(t, access)["aud"].([]any); !slices.Equal(anyToStrings(aud), []string{"https://other.test"}) {
			t.Fatalf("aud = %v, want the explicit audience", aud)
		}

		// refresh rotation re-derives audiences from config (refresh JWTs
		// deliberately carry none), so the explicit audience is scoped to the
		// exchange that named it — pinned here as deliberate policy.
		rt, _ := body["refresh_token"].(string)
		oauthCfg := e.app("myapp", "")
		refreshed, err := oauthCfg.TokenSource(e.ctx, &oauth2.Token{RefreshToken: rt}).Token()
		if err != nil {
			t.Fatalf("refresh grant: %v", err)
		}
		if aud, _ := jwtPayload(t, refreshed.AccessToken)["aud"].([]any); !slices.Equal(anyToStrings(aud), []string{"https://api.example.test"}) {
			t.Fatalf("refreshed aud = %v, want configured audience (explicit audience does not survive refresh)", aud)
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
			t.Errorf("issued_token_type = %v, want %s", it, tokenTypeAccess)
		}
		if tt := body["token_type"]; tt != "Bearer" {
			t.Errorf("token_type = %v, want Bearer", tt)
		}
		if rt, ok := body["refresh_token"].(string); ok && rt != "" {
			t.Error("refresh token issued without the refresh token type being requested")
		}
		status, got := userinfoBody(t, e, access)
		if status != http.StatusOK {
			t.Fatalf("userinfo status = %d, want 200 (body %q)", status, got)
		}
		if !strings.Contains(got, "alice@example.test") {
			t.Fatalf("userinfo = %q, want alice's email released", got)
		}

		claims := jwtPayload(t, access)
		if _, ok := claims["email"]; ok {
			t.Fatal("access token must not embed userinfo-scope claims (code-flow parity)")
		}
		if _, ok := claims["roles"]; !ok {
			t.Fatalf("access token lost custom claims: %v", claims)
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
		// Split and sort rather than substring-match: a Contains check per
		// scope would falsely pass "openid2" against the "openid" want.
		scope, _ := body["scope"].(string)
		gotScopes := strings.Fields(scope)
		slices.Sort(gotScopes)
		wantScopes := []string{"email", "openid", "profile"}
		if !slices.Equal(gotScopes, wantScopes) {
			t.Fatalf("scope = %q, want exactly %v", scope, wantScopes)
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

	// programmatic sessions must be revocable like picker sessions.
	t.Run("revocation endpoint invalidates an exchanged refresh token", func(t *testing.T) {
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
			t.Fatalf("no refresh_token: %v", body)
		}

		resp, err := e.client.PostForm(e.disc.Revocation, url.Values{
			"token":           {rt},
			"token_type_hint": {"refresh_token"},
			"client_id":       {"myapp"},
		})
		if err != nil {
			t.Fatalf("revoke: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("revoke status = %d, want 200", resp.StatusCode)
		}

		oauthCfg := e.app("myapp", "")
		if _, err := oauthCfg.TokenSource(e.ctx, &oauth2.Token{RefreshToken: rt}).Token(); err == nil {
			t.Fatal("refresh token should be rejected after revocation")
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

	// static tokens are accepted only under hamnir's persona token type: the
	// standard access-token type means "issued by this server" (RFC 8693 §3),
	// which a configured static string is not.
	t.Run("static token under access token type rejected", func(t *testing.T) {
		t.Parallel()

		e := discover(t, tokenConfig())
		form := exchangeForm("alice-ci", nil)
		form.Set("subject_token_type", tokenTypeAccess)
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

		tests := []struct {
			name       string
			clientID   string
			secret     string
			wantStatus int
			wantError  string
		}{
			{name: "confidential client", clientID: "tests", secret: "s3cret", wantStatus: http.StatusOK, wantError: ""},
			// op maps every client-auth failure to invalid_client / 401
			// (pkg/op/error.go); pin the exact status and body, not just !=
			// 200, so a regression that returns e.g. a bare 400
			// invalid_request would be caught.
			{name: "wrong secret", clientID: "tests", secret: "wrong", wantStatus: http.StatusUnauthorized, wantError: "invalid_client"},
			// Public clients cannot authenticate at the token endpoint (PKCE
			// has no exchange equivalent), so they identify instead: client
			// id with an empty secret (RFC 6749 §2.3). Presenting a secret
			// none was registered for stays a misconfiguration.
			{name: "public client", clientID: "spa", secret: "", wantStatus: http.StatusOK, wantError: ""},
			{name: "public client with a secret", clientID: "spa", secret: "surprise", wantStatus: http.StatusUnauthorized, wantError: "invalid_client"},
			{name: "no client auth", clientID: "", secret: "", wantStatus: http.StatusUnauthorized, wantError: "invalid_client"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				status, body := postExchange(t, e, tt.clientID, tt.secret, exchangeForm("alice-ci", nil))
				if status != tt.wantStatus {
					t.Errorf("status = %d, want %d (body %v)", status, tt.wantStatus, body)
				}
				if got, _ := body["error"].(string); got != tt.wantError {
					t.Errorf("error = %q, want %q", got, tt.wantError)
				}
			})
		}
	})

	// audience resolution goes through the same per-client-override-beats-global
	// logic the code flow uses (see Storage.audienceFor); an exchange must see
	// it too since DefaultExchangeAudience calls that same method.
	t.Run("per-client audiences reach exchanged tokens", func(t *testing.T) {
		t.Parallel()

		cfg := tokenConfig()
		cfg.Audiences = []string{"https://api.example.test"}
		cfg.Clients = []config.Client{
			{ID: "tests", Secret: "s3cret", Audiences: []string{"https://client.example.test"}},
		}
		e := discover(t, cfg)
		status, body := postExchange(t, e, "tests", "s3cret", exchangeForm("alice-ci", nil))
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %v)", status, body)
		}
		access, _ := body["access_token"].(string)
		if aud, _ := jwtPayload(t, access)["aud"].([]any); !slices.Equal(anyToStrings(aud), []string{"https://client.example.test"}) {
			t.Fatalf("aud = %v, want the client's own audience", aud)
		}
	})

	// an op-minted access token also works as a subject token: op resolves its
	// own tokens before falling back to the static-token verifier. Their
	// standard types stay accurate — only static tokens use the persona type.
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

		form := exchangeForm(tok.AccessToken, url.Values{"scope": {"openid email"}})
		form.Set("subject_token_type", tokenTypeAccess)
		status, body := postExchange(t, e, "myapp", "", form)
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

	// malformed bodies must fail closed through the composed middleware stack:
	// the audience middleware parses first, and net/http caches the parsed
	// form but not the error, so it must answer the failure itself rather
	// than letting op see a silently-empty form.
	t.Run("malformed form rejected in both client modes", func(t *testing.T) {
		t.Parallel()

		registered := tokenConfig()
		registered.Clients = []config.Client{{ID: "app", Secret: "s3cret"}}
		wantBody := `{"error":"invalid_request","error_description":"error parsing form"}`
		for name, cfg := range map[string]*config.Config{"permissive": tokenConfig(), "registered": registered} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				e := discover(t, cfg)
				req, _ := http.NewRequest(http.MethodPost, e.rp.Endpoint().TokenURL, strings.NewReader("a=%zz"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				resp, err := e.client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body := readBody(t, resp)
				if resp.StatusCode != http.StatusBadRequest || body != wantBody {
					t.Fatalf("status = %d body = %q, want 400 %q", resp.StatusCode, body, wantBody)
				}
			})
		}
	})

	// a malformed Basic header on an exchange must fail closed: op's own
	// parse-error path panics on it upstream, so the middleware answers
	// first, carrying a WWW-Authenticate challenge on its 401 (RFC 6749
	// §5.2), not just the status.
	t.Run("malformed basic auth rejected", func(t *testing.T) {
		t.Parallel()

		e := discover(t, tokenConfig())
		form := exchangeForm("alice-ci", nil)
		req, _ := http.NewRequest(http.MethodPost, e.rp.Endpoint().TokenURL, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("a%zz:")))
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatalf("malformed basic auth: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
		if got := resp.Header.Get("WWW-Authenticate"); got != "Basic" {
			t.Errorf("WWW-Authenticate = %q, want %q", got, "Basic")
		}
	})

	// op registers /oauth/token method-agnostically and dispatches on
	// r.FormValue("grant_type"), which merges the query string — so a GET
	// exchange must get the same hardening a POST gets.
	t.Run("non-POST exchange hardening", func(t *testing.T) {
		t.Parallel()

		// Without this hardening, a malformed Basic header on a GET exchange
		// would reach op's own error path, which is missing a `return` and
		// panics on a nil request (see ParseTokenExchangeRequest/TokenExchange
		// in pkg/op/token_exchange.go) — asserting a clean 401 here, not a
		// connection error or 5xx, proves the panic is pre-answered on GET.
		t.Run("malformed basic auth is pre-answered, not a panic", func(t *testing.T) {
			t.Parallel()

			e := discover(t, tokenConfig())
			target := e.rp.Endpoint().TokenURL + "?" + exchangeForm("alice-ci", nil).Encode()
			req, _ := http.NewRequest(http.MethodGet, target, nil)
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("a%zz:")))
			resp, err := e.client.Do(req)
			if err != nil {
				t.Fatalf("GET exchange with malformed basic auth: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (a connection error or 5xx would mean op's nil-deref panic was reached)", resp.StatusCode)
			}
		})

		// Without this hardening, the audience-defaulting block was gated on
		// r.Method == http.MethodPost, so this same request sent by GET
		// silently skipped defaulting and minted a token with no aud.
		t.Run("well-formed GET exchange still gets audience defaulted", func(t *testing.T) {
			t.Parallel()

			cfg := tokenConfig()
			cfg.Audiences = []string{"https://api.example.test"}
			e := discover(t, cfg)
			form := exchangeForm("alice-ci", url.Values{"scope": {"openid email"}})
			target := e.rp.Endpoint().TokenURL + "?" + form.Encode()
			req, _ := http.NewRequest(http.MethodGet, target, nil)
			req.SetBasicAuth("myapp", "")
			resp, err := e.client.Do(req)
			if err != nil {
				t.Fatalf("GET exchange: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			var body map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %v)", resp.StatusCode, body)
			}
			access, _ := body["access_token"].(string)
			if aud, _ := jwtPayload(t, access)["aud"].([]any); !slices.Equal(anyToStrings(aud), []string{"https://api.example.test"}) {
				t.Fatalf("GET exchange aud = %v, want the configured audience (GET must not skip defaulting)", aud)
			}
		})
	})

	// exchange-minted sessions must be revocable via logout, not just the
	// revocation endpoint: touchSession registers them into the same
	// sessions map AuthenticateAndComplete uses for the picker, so logout
	// (which walks that map, not the refresh-token denylist directly) must
	// reach a session that was never created through the picker.
	t.Run("logout reaches a programmatic session", func(t *testing.T) {
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
			t.Fatalf("no refresh_token: %v", body)
		}

		// A second exchange for the same subject and client, this time
		// requesting an id_token to use as end_session's id_token_hint (RFC
		// 8693 §2.2.1: the issued token still rides in access_token).
		status, idBody := postExchange(t, e, "myapp", "", exchangeForm("alice-ci", url.Values{
			"requested_token_type": {tokenTypeID},
			"scope":                {"openid email"},
		}))
		if status != http.StatusOK {
			t.Fatalf("id token exchange: status = %d, want 200 (body %v)", status, idBody)
		}
		rawID, _ := idBody["access_token"].(string)

		resp, err := e.client.Get(e.disc.EndSession + "?id_token_hint=" + url.QueryEscape(rawID))
		if err != nil {
			t.Fatalf("logout: %v", err)
		}
		_ = resp.Body.Close()

		oauthCfg := e.app("myapp", "")
		if _, err := oauthCfg.TokenSource(e.ctx, &oauth2.Token{RefreshToken: rt}).Token(); err == nil {
			t.Fatal("refresh token should be rejected after logout reaches the exchange-minted session")
		}
	})

	// The exchange grant loosened AuthorizeClientIDSecret to admit public
	// clients by identification (empty secret); since op funnels
	// introspection through that same method (ClientIDFromRequest ->
	// ClientBasicAuth -> storage.AuthorizeClientIDSecret), that loosening
	// must not let a public client introspect tokens too (RFC 7662 §2.1
	// requires client authentication).
	t.Run("introspection stays scoped to confidential clients", func(t *testing.T) {
		t.Parallel()

		cfg := tokenConfig()
		cfg.Clients = []config.Client{
			{ID: "tests", Secret: "s3cret"},
			{ID: "spa"},
		}
		e := discover(t, cfg)
		if e.disc.Introspection == "" {
			t.Fatal("introspection_endpoint not advertised in discovery")
		}

		status, body := postExchange(t, e, "tests", "s3cret", exchangeForm("alice-ci", nil))
		if status != http.StatusOK {
			t.Fatalf("mint token: status = %d, want 200 (body %v)", status, body)
		}
		access, _ := body["access_token"].(string)

		introspect := func(t *testing.T, clientID, secret string) map[string]any {
			t.Helper()
			req, _ := http.NewRequest(http.MethodPost, e.disc.Introspection, strings.NewReader(url.Values{"token": {access}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(clientID, secret)
			resp, err := e.client.Do(req)
			if err != nil {
				t.Fatalf("introspect: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			var out map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				t.Fatalf("decode introspection response: %v", err)
			}
			return out
		}

		if out := introspect(t, "tests", "s3cret"); out["active"] != true {
			t.Fatalf("confidential client introspection = %v, want active", out)
		}
		if out := introspect(t, "spa", ""); out["active"] == true {
			t.Fatalf("public client introspection = %v, want inactive (RFC 7662 §2.1 regression)", out)
		}
	})

	// Standard OAuth client libraries send client_id (and client_secret) in
	// the token request body — Basic auth is not universal (RFC 6749 §3.2.1,
	// client_secret_post) — so the DefaultExchangeAudience middleware bridges
	// either into a Basic header before op ever parses the request.
	t.Run("body client_id bridges into Basic auth", func(t *testing.T) {
		t.Parallel()

		registeredClients := func() *config.Config {
			cfg := tokenConfig()
			cfg.Clients = []config.Client{
				{ID: "app", Secret: "s3cret"},
				{ID: "spa"},
			}
			return cfg
		}

		t.Run("public client identifies via body client_id, no Authorization header", func(t *testing.T) {
			t.Parallel()

			e := discover(t, registeredClients())
			status, body := postExchange(t, e, "", "", exchangeForm("alice-ci", url.Values{"client_id": {"spa"}}))
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %v) — proves the body client_id bridges into Basic auth", status, body)
			}
		})

		t.Run("confidential client via body client_id and client_secret", func(t *testing.T) {
			t.Parallel()

			e := discover(t, registeredClients())
			status, body := postExchange(t, e, "", "", exchangeForm("alice-ci", url.Values{"client_id": {"app"}, "client_secret": {"s3cret"}}))
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %v)", status, body)
			}
		})

		t.Run("wrong body client_secret rejected", func(t *testing.T) {
			t.Parallel()

			e := discover(t, registeredClients())
			status, body := postExchange(t, e, "", "", exchangeForm("alice-ci", url.Values{"client_id": {"app"}, "client_secret": {"wrong"}}))
			if status == http.StatusOK {
				t.Fatalf("wrong body client_secret must be rejected (body %v)", body)
			}
		})

		// a secret with characters op round-trips through QueryUnescape ("+",
		// "%") must survive the bridge intact, so the bridge URL-encodes each
		// credential before base64.
		t.Run("body client_secret with special characters", func(t *testing.T) {
			t.Parallel()

			cfg := tokenConfig()
			cfg.Clients = []config.Client{{ID: "app", Secret: "s3+cr%et"}}
			e := discover(t, cfg)
			status, body := postExchange(t, e, "", "", exchangeForm("alice-ci", url.Values{"client_id": {"app"}, "client_secret": {"s3+cr%et"}}))
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %v) — a special-char secret must survive the bridge", status, body)
			}
		})
	})
}
