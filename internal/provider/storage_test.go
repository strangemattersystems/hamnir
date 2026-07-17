package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/persona"
)

func newTestStorage(t *testing.T) *Storage {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Personas:  []config.Persona{{Claims: map[string]any{"sub": "usr_alice"}}},
		Lifetimes: config.DefaultLifetimes,
	}
	st, err := NewStorage(cfg, persona.NewSet(cfg), key)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// newTestStorageWithLifetimes is newTestStorage with configured token lifetimes.
func newTestStorageWithLifetimes(t *testing.T, lt config.Lifetimes) *Storage {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Personas:  []config.Persona{{Claims: map[string]any{"sub": "usr_alice"}}},
		Lifetimes: lt,
	}
	st, err := NewStorage(cfg, persona.NewSet(cfg), key)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// The signing key's JWKS kid must be derived from the key itself, not chosen
// per process: replicas and restarts sharing one configured key must
// advertise one consistent kid, or strict-kid verifiers reject tokens minted
// by a different process holding the same key.
func TestNewStorage_KeyID(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}

	newStorage := func(t *testing.T, key *rsa.PrivateKey) *Storage {
		t.Helper()
		st, err := NewStorage(cfg, persona.NewSet(cfg), key)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	t.Run("same key same id", func(t *testing.T) {
		first := newStorage(t, key1)
		second := newStorage(t, key1)
		if first.signing.id == "" {
			t.Fatal("signing key id must not be empty")
		}
		if first.signing.id != second.signing.id {
			t.Fatalf("signing key ids differ: %q vs %q", first.signing.id, second.signing.id)
		}
	})

	t.Run("different key different id", func(t *testing.T) {
		a := newStorage(t, key1)
		b := newStorage(t, key2)
		if a.signing.id == b.signing.id {
			t.Fatal("signing key ids must differ for different keys")
		}
	})
}

// The in-memory stores must not grow without bound over a long-running dev
// session: each write site sweeps entries that can no longer matter.
func TestStorage_Eviction(t *testing.T) {
	ctx := context.Background()

	t.Run("stale auth requests and codes", func(t *testing.T) {
		st := newTestStorage(t)
		old, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{ClientID: "c"}, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SaveAuthCode(ctx, old.GetID(), "code-old"); err != nil {
			t.Fatal(err)
		}
		st.mu.Lock()
		st.authRequests[old.GetID()].createdAt = time.Now().Add(-authRequestTTL - time.Minute)
		st.mu.Unlock()

		if _, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{ClientID: "c"}, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := st.AuthRequestByID(ctx, old.GetID()); err == nil {
			t.Fatal("stale auth request should have been evicted")
		}
		if _, err := st.AuthRequestByCode(ctx, "code-old"); err == nil {
			t.Fatal("the stale request's code should have been evicted with it")
		}
	})

	t.Run("expired access tokens", func(t *testing.T) {
		st := newTestStorage(t)
		jti, _ := st.storeAccessToken(TokenClaims{Sub: "usr_alice"})
		st.mu.Lock()
		st.accessTokens[jti].expiration = time.Now().Add(-time.Minute)
		st.mu.Unlock()

		st.storeAccessToken(TokenClaims{Sub: "usr_alice"})
		st.mu.Lock()
		_, ok := st.accessTokens[jti]
		st.mu.Unlock()
		if ok {
			t.Fatal("expired access token should have been evicted")
		}
	})

	t.Run("stale session ids", func(t *testing.T) {
		st := newTestStorage(t)
		first, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{ClientID: "c"}, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := st.AuthenticateAndComplete(first.GetID(), "usr_alice"); err != nil {
			t.Fatal(err)
		}
		st.mu.Lock()
		for _, sids := range st.sessions {
			for sid, sess := range sids {
				sess.lastSeen = time.Now().Add(-st.refresh.ttl - time.Minute)
				sids[sid] = sess
			}
		}
		st.mu.Unlock()

		second, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{ClientID: "c"}, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := st.AuthenticateAndComplete(second.GetID(), "usr_alice"); err != nil {
			t.Fatal(err)
		}
		st.mu.Lock()
		n := len(st.sessions["usr_alice"])
		st.mu.Unlock()
		if n != 1 {
			t.Fatalf("sids outliving every refresh token should be pruned; have %d, want 1", n)
		}
	})
}

// login drives an auth request for clientID through persona selection and
// returns the freshly minted sid.
func login(t *testing.T, st *Storage, clientID string) string {
	t.Helper()
	ctx := context.Background()
	req, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{ClientID: clientID}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AuthenticateAndComplete(req.GetID(), "usr_alice"); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	for sid, sess := range st.sessions["usr_alice"] {
		if sess.clientID == clientID {
			return sid
		}
	}
	t.Fatalf("no session recorded for client %q", clientID)
	return ""
}

// TestStorage_Sessions pins the session lifecycle: rotation keeps a session
// alive past the login-time horizon, and logout only terminates the
// requesting client's sessions.
func TestStorage_Sessions(t *testing.T) {
	ctx := context.Background()

	t.Run("rotation keeps the session alive", func(t *testing.T) {
		st := newTestStorage(t)
		sid := login(t, st, "isen")
		rt, err := st.refresh.Issue(TokenClaims{Sub: "usr_alice", ClientID: "isen", Scopes: []string{"openid"}, SID: sid})
		if err != nil {
			t.Fatal(err)
		}

		// Age the session past the prune horizon, as if the RP had been
		// silently refreshing for a day.
		st.mu.Lock()
		sess := st.sessions["usr_alice"][sid]
		sess.lastSeen = time.Now().Add(-st.refresh.ttl - time.Minute)
		st.sessions["usr_alice"][sid] = sess
		st.mu.Unlock()

		// A refresh grant rotates the token — the session is demonstrably live.
		req, err := st.TokenRequestByRefreshToken(ctx, rt)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := st.CreateAccessAndRefreshTokens(ctx, req.(*refreshRequest), rt); err != nil {
			t.Fatal(err)
		}

		// Another login triggers the prune; the rotated session must survive
		// so that logout can still revoke it.
		login(t, st, "other")
		st.mu.Lock()
		_, ok := st.sessions["usr_alice"][sid]
		st.mu.Unlock()
		if !ok {
			t.Fatal("session refreshed by rotation must not be pruned")
		}
	})

	t.Run("logout terminates only the requesting client", func(t *testing.T) {
		st := newTestStorage(t)
		sidA := login(t, st, "app-a")
		sidB := login(t, st, "app-b")
		rtA, err := st.refresh.Issue(TokenClaims{Sub: "usr_alice", ClientID: "app-a", SID: sidA})
		if err != nil {
			t.Fatal(err)
		}
		rtB, err := st.refresh.Issue(TokenClaims{Sub: "usr_alice", ClientID: "app-b", SID: sidB})
		if err != nil {
			t.Fatal(err)
		}
		jtiA, _ := st.storeAccessToken(TokenClaims{Sub: "usr_alice", ClientID: "app-a", SID: sidA})
		jtiB, _ := st.storeAccessToken(TokenClaims{Sub: "usr_alice", ClientID: "app-b", SID: sidB})

		if err := st.TerminateSession(ctx, "usr_alice", "app-a"); err != nil {
			t.Fatal(err)
		}

		if _, err := st.refresh.Parse(rtA); err == nil {
			t.Fatal("app-a's refresh token should be revoked")
		}
		if _, err := st.refresh.Parse(rtB); err != nil {
			t.Fatalf("app-b's refresh token should survive app-a's logout: %v", err)
		}
		st.mu.Lock()
		_, aOK := st.accessTokens[jtiA]
		_, bOK := st.accessTokens[jtiB]
		st.mu.Unlock()
		if aOK {
			t.Fatal("app-a's access token should be deleted")
		}
		if !bOK {
			t.Fatal("app-b's access token should survive app-a's logout")
		}
	})

	t.Run("logout without a client terminates everything", func(t *testing.T) {
		st := newTestStorage(t)
		sidA := login(t, st, "app-a")
		sidB := login(t, st, "app-b")
		rtA, err := st.refresh.Issue(TokenClaims{Sub: "usr_alice", ClientID: "app-a", SID: sidA})
		if err != nil {
			t.Fatal(err)
		}
		rtB, err := st.refresh.Issue(TokenClaims{Sub: "usr_alice", ClientID: "app-b", SID: sidB})
		if err != nil {
			t.Fatal(err)
		}

		if err := st.TerminateSession(ctx, "usr_alice", ""); err != nil {
			t.Fatal(err)
		}

		if _, err := st.refresh.Parse(rtA); err == nil {
			t.Fatal("app-a's refresh token should be revoked")
		}
		if _, err := st.refresh.Parse(rtB); err == nil {
			t.Fatal("app-b's refresh token should be revoked")
		}
	})
}

// TestStorage_AuthRequestLifecycle pins the auth-request state machine:
// selection completes a request exactly once, lookups hand op immutable
// snapshots, superseded codes die with their successor, and an idle picker
// is not evicted from under the user.
func TestStorage_AuthRequestLifecycle(t *testing.T) {
	ctx := context.Background()

	t.Run("replayed selection rejected", func(t *testing.T) {
		st := newTestStorage(t)
		req, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{ClientID: "c"}, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := st.AuthenticateAndComplete(req.GetID(), "usr_alice"); err != nil {
			t.Fatal(err)
		}
		if err := st.AuthenticateAndComplete(req.GetID(), "usr_alice"); !errors.Is(err, ErrAuthRequestDone) {
			t.Fatalf("replay err = %v, want ErrAuthRequestDone", err)
		}
	})

	t.Run("lookups return snapshots", func(t *testing.T) {
		st := newTestStorage(t)
		created, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{ClientID: "c"}, "")
		if err != nil {
			t.Fatal(err)
		}
		before, err := st.AuthRequestByID(ctx, created.GetID())
		if err != nil {
			t.Fatal(err)
		}
		if err := st.AuthenticateAndComplete(created.GetID(), "usr_alice"); err != nil {
			t.Fatal(err)
		}
		if before.Done() {
			t.Fatal("a previously returned request must not observe later writes")
		}
	})

	t.Run("superseded code dies with its successor", func(t *testing.T) {
		st := newTestStorage(t)
		req, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{ClientID: "c"}, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SaveAuthCode(ctx, req.GetID(), "code-1"); err != nil {
			t.Fatal(err)
		}
		if err := st.SaveAuthCode(ctx, req.GetID(), "code-2"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.AuthRequestByCode(ctx, "code-1"); err == nil {
			t.Fatal("superseded code must not be exchangeable")
		}
		if _, err := st.AuthRequestByCode(ctx, "code-2"); err != nil {
			t.Fatalf("latest code should resolve: %v", err)
		}
		st.mu.Lock()
		n := len(st.codes)
		st.mu.Unlock()
		if n != 1 {
			t.Fatalf("superseded code should be removed from the map; have %d entries", n)
		}
	})

	t.Run("idle picker outlives a meeting", func(t *testing.T) {
		st := newTestStorage(t)
		idle, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{ClientID: "c"}, "")
		if err != nil {
			t.Fatal(err)
		}
		st.mu.Lock()
		st.authRequests[idle.GetID()].createdAt = time.Now().Add(-time.Hour)
		st.mu.Unlock()

		if _, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{ClientID: "c"}, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := st.AuthRequestByID(ctx, idle.GetID()); err != nil {
			t.Fatal("an hour-old picker must still complete; only abandoned flows may be evicted")
		}
	})
}

// TestStorage_Revocation pins RFC 7009 semantics: only the client a token was
// issued to may revoke it, and any member of a rotation family — including a
// superseded token — identifies the session to kill.
func TestStorage_Revocation(t *testing.T) {
	ctx := context.Background()

	t.Run("cross-client refresh revocation refused", func(t *testing.T) {
		st := newTestStorage(t)
		sid := login(t, st, "app-a")
		rt, err := st.refresh.Issue(TokenClaims{Sub: "usr_alice", ClientID: "app-a", SID: sid})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := st.GetRefreshTokenInfo(ctx, "app-b", rt); err == nil {
			t.Fatal("another client must not resolve the token for revocation")
		}
		if oidcErr := st.RevokeToken(ctx, rt, "usr_alice", "app-b"); oidcErr == nil {
			t.Fatal("another client must not revoke the token")
		}
		if _, err := st.refresh.Parse(rt); err != nil {
			t.Fatalf("token must survive a foreign revocation attempt: %v", err)
		}
	})

	t.Run("cross-client access revocation refused", func(t *testing.T) {
		st := newTestStorage(t)
		jti, _ := st.storeAccessToken(TokenClaims{Sub: "usr_alice", ClientID: "app-a"})
		if oidcErr := st.RevokeToken(ctx, jti, "usr_alice", "app-b"); oidcErr == nil {
			t.Fatal("another client must not revoke the access token")
		}
		st.mu.Lock()
		_, ok := st.accessTokens[jti]
		st.mu.Unlock()
		if !ok {
			t.Fatal("access token must survive a foreign revocation attempt")
		}
	})

	t.Run("own token revokes the session", func(t *testing.T) {
		st := newTestStorage(t)
		sid := login(t, st, "app-a")
		rt, err := st.refresh.Issue(TokenClaims{Sub: "usr_alice", ClientID: "app-a", SID: sid})
		if err != nil {
			t.Fatal(err)
		}
		sub, tokenID, err := st.GetRefreshTokenInfo(ctx, "app-a", rt)
		if err != nil {
			t.Fatal(err)
		}
		if oidcErr := st.RevokeToken(ctx, tokenID, sub, "app-a"); oidcErr != nil {
			t.Fatalf("own revocation should succeed: %v", oidcErr)
		}
		if _, err := st.refresh.Parse(rt); !errors.Is(err, errRevokedSession) {
			t.Fatalf("want errRevokedSession after revocation, got %v", err)
		}
	})

	t.Run("superseded token still revokes its session", func(t *testing.T) {
		st := newTestStorage(t)
		sid := login(t, st, "app-a")
		old, err := st.refresh.Issue(TokenClaims{Sub: "usr_alice", ClientID: "app-a", SID: sid})
		if err != nil {
			t.Fatal(err)
		}
		rc, err := st.refresh.Parse(old)
		if err != nil {
			t.Fatal(err)
		}
		st.refresh.Revoke(rc.JTI) // rotation denylists the replaced token

		sub, tokenID, err := st.GetRefreshTokenInfo(ctx, "app-a", old)
		if err != nil {
			t.Fatalf("a superseded family member should still identify the session: %v", err)
		}
		if oidcErr := st.RevokeToken(ctx, tokenID, sub, "app-a"); oidcErr != nil {
			t.Fatalf("revocation via superseded token should succeed: %v", oidcErr)
		}
		sibling, err := st.refresh.Issue(TokenClaims{Sub: "usr_alice", ClientID: "app-a", SID: sid})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.refresh.Parse(sibling); !errors.Is(err, errRevokedSession) {
			t.Fatalf("the whole session should be revoked, got %v", err)
		}
	})
}

// unexpectedTokenRequest is an op.TokenRequest type hamnir never produces.
type unexpectedTokenRequest struct{}

func (unexpectedTokenRequest) GetSubject() string    { return "usr_alice" }
func (unexpectedTokenRequest) GetAudience() []string { return nil }
func (unexpectedTokenRequest) GetScopes() []string   { return []string{"openid"} }

// TestStorage_CreateAccessToken_UnexpectedRequest pins that an unknown token
// request type fails loudly instead of silently minting an anonymous token
// with no client id or session.
func TestStorage_CreateAccessToken_UnexpectedRequest(t *testing.T) {
	st := newTestStorage(t)
	if _, _, err := st.CreateAccessToken(context.Background(), unexpectedTokenRequest{}); err == nil {
		t.Fatal("an unexpected token request type must be rejected")
	}
}

// TestStorage_DeleteAuthRequest pins the code cleanup on token exchange: the
// exchanged request and its code both disappear.
func TestStorage_DeleteAuthRequest(t *testing.T) {
	ctx := context.Background()
	st := newTestStorage(t)
	req, err := st.CreateAuthRequest(ctx, &oidc.AuthRequest{ClientID: "c"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveAuthCode(ctx, req.GetID(), "code-1"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAuthRequest(ctx, req.GetID()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AuthRequestByCode(ctx, "code-1"); err == nil {
		t.Fatal("exchanged code should be gone")
	}
	st.mu.Lock()
	n := len(st.codes)
	st.mu.Unlock()
	if n != 0 {
		t.Fatalf("codes map should be empty, have %d entries", n)
	}
}

func TestNewStorage_ConfiguredLifetimes(t *testing.T) {
	lt := config.Lifetimes{
		AccessToken:  42 * time.Minute,
		IDToken:      7 * time.Minute,
		RefreshToken: 99 * time.Hour,
	}
	st := newTestStorageWithLifetimes(t, lt)

	if st.refresh.ttl != lt.RefreshToken {
		t.Errorf("refresh ttl = %v, want %v", st.refresh.ttl, lt.RefreshToken)
	}

	t.Run("access token expiry", func(t *testing.T) {
		_, exp := st.storeAccessToken(TokenClaims{})
		got := time.Until(exp)
		if got < lt.AccessToken-time.Minute || got > lt.AccessToken+time.Minute {
			t.Errorf("expiry in %v, want ~%v", got, lt.AccessToken)
		}
	})

	t.Run("id token lifetime on clients", func(t *testing.T) {
		c, err := st.GetClientByClientID(t.Context(), "any")
		if err != nil {
			t.Fatal(err)
		}
		if got := c.IDTokenLifetime(); got != lt.IDToken {
			t.Errorf("IDTokenLifetime = %v, want %v", got, lt.IDToken)
		}
	})
}

func TestStorage_AudienceFor(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Audiences: []string{"https://api.example.test"},
		Clients: []config.Client{
			{ID: "inherit"},
			{ID: "override", Audiences: []string{"urn:example:report"}},
			{ID: "optout", Audiences: []string{}},
		},
		Personas:  []config.Persona{{Claims: map[string]any{"sub": "usr_alice"}}},
		Lifetimes: config.DefaultLifetimes,
	}
	st, err := NewStorage(cfg, persona.NewSet(cfg), key)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		clientID string
		want     []string
	}{
		{"client inherits global", "inherit", []string{"https://api.example.test"}},
		{"client override wins", "override", []string{"urn:example:report"}},
		{"explicit empty opts out", "optout", nil},
		{"unknown client gets global", "permissive-anything", []string{"https://api.example.test"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := st.audienceFor(tt.clientID)
			if len(got) != len(tt.want) {
				t.Fatalf("audienceFor(%q) = %v, want %v", tt.clientID, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("audienceFor(%q) = %v, want %v", tt.clientID, got, tt.want)
				}
			}
		})
	}

	t.Run("nothing configured resolves nil", func(t *testing.T) {
		st := newTestStorage(t) // its cfg has no audiences anywhere
		if got := st.audienceFor("any"); got != nil {
			t.Fatalf("audienceFor = %v, want nil", got)
		}
	})

	t.Run("flows into auth request aud", func(t *testing.T) {
		req, err := st.CreateAuthRequest(t.Context(), &oidc.AuthRequest{ClientID: "override"}, "")
		if err != nil {
			t.Fatal(err)
		}
		if got := req.GetAudience(); len(got) != 1 || got[0] != "urn:example:report" {
			t.Fatalf("GetAudience = %v, want [urn:example:report]", got)
		}
	})

	t.Run("default aud unchanged without config", func(t *testing.T) {
		st := newTestStorage(t)
		req, err := st.CreateAuthRequest(t.Context(), &oidc.AuthRequest{ClientID: "c"}, "")
		if err != nil {
			t.Fatal(err)
		}
		if got := req.GetAudience(); len(got) != 1 || got[0] != "c" {
			t.Fatalf("GetAudience = %v, want [c]", got)
		}
	})
}
