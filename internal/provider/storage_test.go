package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	cfg := &config.Config{Personas: []config.Persona{{Claims: map[string]any{"sub": "usr_alice"}}}}
	st, err := NewStorage(cfg, persona.NewSet(cfg), key)
	if err != nil {
		t.Fatal(err)
	}
	return st
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
				sess.lastSeen = time.Now().Add(-refreshTokenTTL - time.Minute)
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
		sess.lastSeen = time.Now().Add(-refreshTokenTTL - time.Minute)
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
