package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"slices"
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
		{name: "known token", token: "alice-ci", tokenType: oidc.AccessTokenType, wantSub: "usr_alice"},
		{name: "unknown token", token: "nope", tokenType: oidc.AccessTokenType, wantErr: errUnknownExchangeToken},
		{name: "wrong token type", token: "alice-ci", tokenType: oidc.IDTokenType, wantErr: errExchangeTokenType},
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
