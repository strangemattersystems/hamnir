package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"
)

func TestRefreshTokenManager(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewRefreshTokenManager(key, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("round trip", func(t *testing.T) {
		tok, err := m.Issue(RefreshClaims{Sub: "usr_alice", ClientID: "isen", Scopes: []string{"openid", "roles"}, SID: "sid1"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		got, err := m.Parse(tok)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got.Sub != "usr_alice" || got.ClientID != "isen" || got.SID != "sid1" || len(got.Scopes) != 2 {
			t.Fatalf("round trip mismatch: %+v", got)
		}
	})

	t.Run("rejects expired", func(t *testing.T) {
		expired, err := NewRefreshTokenManager(key, -time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := expired.Issue(RefreshClaims{Sub: "s", SID: "x"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if _, err := m.Parse(tok); err == nil {
			t.Fatal("expected expired token to be rejected")
		}
	})

	t.Run("rejects wrong key", func(t *testing.T) {
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		otherM, err := NewRefreshTokenManager(other, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := otherM.Issue(RefreshClaims{Sub: "s", SID: "x"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if _, err := m.Parse(tok); err == nil {
			t.Fatal("expected verification with the wrong key to fail")
		}
	})

	t.Run("rejects revoked session", func(t *testing.T) {
		tok, err := m.Issue(RefreshClaims{Sub: "s", SID: "sid-revoked"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		m.Revoke("sid-revoked")
		if _, err := m.Parse(tok); !errors.Is(err, errRevokedSession) {
			t.Fatalf("want errRevokedSession, got %v", err)
		}
	})
}
