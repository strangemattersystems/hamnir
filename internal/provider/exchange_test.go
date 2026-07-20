package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/persona"
)

// newExchangeStorage builds a Storage whose single persona carries a static
// exchange token.
func newExchangeStorage(t *testing.T) *Storage {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Personas: []config.Persona{{
			Claims: map[string]any{"sub": "usr_alice", "email": "alice@example.test"},
			Tokens: []string{"alice-ci"},
		}},
		Lifetimes: config.DefaultLifetimes,
	}
	st, err := NewStorage(cfg, persona.NewSet(cfg), key)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// fakeExchangeRequest implements op.TokenExchangeRequest for the fields the
// exchange methods touch; the embedded nil interface panics on anything else,
// which is exactly the failure we want if the implementation starts reading
// more than it should.
type fakeExchangeRequest struct {
	op.TokenExchangeRequest
	subject            string
	clientID           string
	exchangeSubject    string
	scopes             []string
	requestedTokenType oidc.TokenType
}

func (r *fakeExchangeRequest) GetSubject() string                    { return r.subject }
func (r *fakeExchangeRequest) GetClientID() string                   { return r.clientID }
func (r *fakeExchangeRequest) GetExchangeSubject() string            { return r.exchangeSubject }
func (r *fakeExchangeRequest) GetScopes() []string                   { return r.scopes }
func (r *fakeExchangeRequest) GetRequestedTokenType() oidc.TokenType { return r.requestedTokenType }
func (r *fakeExchangeRequest) SetSubject(sub string)                 { r.subject = sub }
func (r *fakeExchangeRequest) SetRequestedTokenType(tt oidc.TokenType) {
	r.requestedTokenType = tt
}
func (r *fakeExchangeRequest) SetCurrentScopes(s []string) { r.scopes = s }

func TestStorage_VerifyExchangeSubjectToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		token     string
		tokenType oidc.TokenType
		wantSub   string
		wantErr   error
	}{
		{name: "known token", token: "alice-ci", tokenType: PersonaTokenType, wantSub: "usr_alice"},
		{name: "unknown token", token: "nope", tokenType: PersonaTokenType, wantErr: errUnknownExchangeToken},
		{name: "access token type rejected", token: "alice-ci", tokenType: oidc.AccessTokenType, wantErr: errExchangeTokenType},
	}
	st := newExchangeStorage(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, sub, _, err := st.VerifyExchangeSubjectToken(context.Background(), tt.token, tt.tokenType)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if sub != tt.wantSub {
				t.Fatalf("subject = %q, want %q", sub, tt.wantSub)
			}
		})
	}
}

func TestStorage_VerifyExchangeActorToken(t *testing.T) {
	t.Parallel()

	st := newExchangeStorage(t)
	_, _, _, err := st.VerifyExchangeActorToken(context.Background(), "alice-ci", oidc.AccessTokenType)
	if !errors.Is(err, errNotSupported) {
		t.Fatalf("err = %v, want %v", err, errNotSupported)
	}
}

// TestPersonaTokenTypeRegistered guards the op upgrade path: op rejects
// subject token types missing from oidc.AllTokenTypes before any storage
// hook runs, so the init-time registration must survive library bumps.
func TestPersonaTokenTypeRegistered(t *testing.T) {
	t.Parallel()

	if !slices.Contains(oidc.AllTokenTypes, PersonaTokenType) {
		t.Fatalf("PersonaTokenType %q not registered in oidc.AllTokenTypes", PersonaTokenType)
	}
}

func TestStorage_ValidateTokenExchangeRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		req      *fakeExchangeRequest
		wantErr  bool
		wantSub  string
		wantType oidc.TokenType
		wantScp  []string
	}{
		{
			name:     "defaults applied",
			req:      &fakeExchangeRequest{exchangeSubject: "usr_alice"},
			wantSub:  "usr_alice",
			wantType: oidc.AccessTokenType,
			wantScp:  []string{"openid", "profile", "email"},
		},
		{
			name:     "offline_access does not change the default",
			req:      &fakeExchangeRequest{exchangeSubject: "usr_alice", scopes: []string{"openid", "offline_access"}},
			wantSub:  "usr_alice",
			wantType: oidc.AccessTokenType,
			wantScp:  []string{"openid", "offline_access"},
		},
		{
			name: "explicit values kept",
			req: &fakeExchangeRequest{
				exchangeSubject:    "usr_alice",
				scopes:             []string{"openid"},
				requestedTokenType: oidc.IDTokenType,
			},
			wantSub:  "usr_alice",
			wantType: oidc.IDTokenType,
			wantScp:  []string{"openid"},
		},
		{
			name:    "unsupported requested type",
			req:     &fakeExchangeRequest{exchangeSubject: "usr_alice", requestedTokenType: oidc.JWTTokenType},
			wantErr: true,
		},
		{
			name:    "persona type not issuable",
			req:     &fakeExchangeRequest{exchangeSubject: "usr_alice", requestedTokenType: PersonaTokenType},
			wantErr: true,
		},
	}
	st := newExchangeStorage(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := st.ValidateTokenExchangeRequest(context.Background(), tt.req)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.req.subject != tt.wantSub {
				t.Errorf("subject = %q, want %q", tt.req.subject, tt.wantSub)
			}
			if tt.req.requestedTokenType != tt.wantType {
				t.Errorf("requested type = %q, want %q", tt.req.requestedTokenType, tt.wantType)
			}
			if !slices.Equal(tt.req.scopes, tt.wantScp) {
				t.Errorf("scopes = %v, want %v", tt.req.scopes, tt.wantScp)
			}
		})
	}
}

// TestStorage_CreateAccessToken_Exchange covers requestInfo's exchange case and
// session registration: an exchange is a fresh login, so it must mint a session
// that logout/termination can later revoke.
func TestStorage_CreateAccessToken_Exchange(t *testing.T) {
	t.Parallel()

	st := newExchangeStorage(t)
	req := &fakeExchangeRequest{subject: "usr_alice", clientID: "myapp", scopes: []string{"openid"}}
	jti, _, err := st.CreateAccessToken(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	info, ok := st.accessTokens[jti]
	sessions := st.sessions["usr_alice"]
	st.mu.Unlock()
	if !ok {
		t.Fatalf("access token %q not stored", jti)
	}
	if info.SID == "" {
		t.Fatal("exchange-minted token has no session id")
	}
	if _, ok := sessions[info.SID]; !ok {
		t.Fatalf("session %q not registered for usr_alice", info.SID)
	}
	if sessions[info.SID].clientID != "myapp" {
		t.Fatalf("session client = %q, want myapp", sessions[info.SID].clientID)
	}
}

func TestStorage_DefaultExchangeAudience(t *testing.T) {
	t.Parallel()

	// Built once: the middleware only reads Storage, so sharing it across the
	// parallel subtests below is safe (matches TestStorage_VerifyExchangeSubjectToken).
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Audiences: []string{"https://api.example.test"},
		Personas:  []config.Persona{{Claims: map[string]any{"sub": "usr_alice"}}},
		Lifetimes: config.DefaultLifetimes,
	}
	st, err := NewStorage(cfg, persona.NewSet(cfg), key)
	if err != nil {
		t.Fatal(err)
	}

	exchangeGrant := string(oidc.GrantTypeTokenExchange)
	tests := []struct {
		name    string
		method  string
		form    url.Values
		basicID string
		wantAud []string
	}{
		{
			name:    "omitted audience defaulted from config",
			method:  http.MethodPost,
			form:    url.Values{"grant_type": {exchangeGrant}},
			basicID: "app",
			wantAud: []string{"https://api.example.test"},
		},
		{
			name:    "explicit audience untouched",
			method:  http.MethodPost,
			form:    url.Values{"grant_type": {exchangeGrant}, "audience": {"https://other.test"}},
			basicID: "app",
			wantAud: []string{"https://other.test"},
		},
		{
			name:    "other grants untouched",
			method:  http.MethodPost,
			form:    url.Values{"grant_type": {"refresh_token"}},
			basicID: "app",
			wantAud: nil,
		},
		{
			name:   "get requests untouched",
			method: http.MethodGet,
			form:   url.Values{"grant_type": {exchangeGrant}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var gotAud []string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAud = r.Form["audience"]
			})
			req := httptest.NewRequest(tt.method, "/oauth/token", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.basicID != "" {
				req.SetBasicAuth(tt.basicID, "")
			}
			st.DefaultExchangeAudience(next).ServeHTTP(httptest.NewRecorder(), req)
			if !slices.Equal(gotAud, tt.wantAud) {
				t.Fatalf("audience = %v, want %v", gotAud, tt.wantAud)
			}
		})
	}

	t.Run("malformed form answered with 400", func(t *testing.T) {
		t.Parallel()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("a=%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		st.DefaultExchangeAudience(next).ServeHTTP(rec, req)
		if nextCalled {
			t.Fatal("next handler must not run on a parse failure")
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "error parsing form") {
			t.Fatalf("body = %q, want the parse-failure response", rec.Body.String())
		}
	})

	// op's own Basic-auth unescape error path (ParseTokenExchangeRequest)
	// panics on a nil request downstream, so this middleware must answer the
	// request before op ever sees it.
	t.Run("malformed basic auth answered with 401", func(t *testing.T) {
		t.Parallel()

		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })
		form := url.Values{"grant_type": {exchangeGrant}}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("a%zz:")))
		rec := httptest.NewRecorder()
		st.DefaultExchangeAudience(next).ServeHTTP(rec, req)
		if nextCalled {
			t.Fatal("next handler must not run on a malformed basic auth header")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "invalid basic auth header") {
			t.Fatalf("body = %q, want the basic-auth-failure response", rec.Body.String())
		}
	})
}

// TestStorage_GetPrivateClaimsFromTokenExchangeRequest pins code-flow parity:
// exchanged access tokens must not embed claims released only through
// userinfo scopes (see withoutUserinfoScopes), while custom claims released
// through other scopes still ride along.
func TestStorage_GetPrivateClaimsFromTokenExchangeRequest(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Personas: []config.Persona{{
			Claims: map[string]any{
				"sub":   "usr_alice",
				"email": "alice@example.test",
				"roles": []any{"coach"},
			},
		}},
		Lifetimes: config.DefaultLifetimes,
	}
	st, err := NewStorage(cfg, persona.NewSet(cfg), key)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		scopes    []string
		wantEmail bool
	}{
		{name: "email scope requested", scopes: []string{"openid", "email"}, wantEmail: false},
		{name: "no userinfo scope requested", scopes: []string{"openid"}, wantEmail: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := &fakeExchangeRequest{subject: "usr_alice", scopes: tt.scopes}
			claims, err := st.GetPrivateClaimsFromTokenExchangeRequest(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := claims["email"]; ok != tt.wantEmail {
				t.Fatalf("email present = %v, want %v", ok, tt.wantEmail)
			}
			if _, ok := claims["roles"]; !ok {
				t.Fatalf("custom claim 'roles' dropped: %v", claims)
			}
		})
	}
}
