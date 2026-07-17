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
			for sid := range sids {
				sids[sid] = time.Now().Add(-refreshTokenTTL - time.Minute)
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
