package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestRefreshTokenManager(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewRefreshTokenManager(key, time.Hour, "hamnir")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("round trip", func(t *testing.T) {
		tok, err := m.Issue(TokenClaims{Sub: "usr_alice", ClientID: "isen", Scopes: []string{"openid", "roles"}, SID: "sid1"})
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
		expired, err := NewRefreshTokenManager(key, -time.Hour, "hamnir")
		if err != nil {
			t.Fatal(err)
		}
		tok, err := expired.Issue(TokenClaims{Sub: "s", SID: "x"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if _, err := m.Parse(tok); !errors.Is(err, jwt.ErrExpired) {
			t.Fatalf("want jwt.ErrExpired, got %v", err)
		}
	})

	t.Run("rejects wrong key", func(t *testing.T) {
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		otherM, err := NewRefreshTokenManager(other, time.Hour, "hamnir")
		if err != nil {
			t.Fatal(err)
		}
		tok, err := otherM.Issue(TokenClaims{Sub: "s", SID: "x"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if _, err := m.Parse(tok); !errors.Is(err, jose.ErrCryptoFailure) {
			t.Fatalf("want jose.ErrCryptoFailure, got %v", err)
		}
	})

	t.Run("rejects revoked session", func(t *testing.T) {
		tok, err := m.Issue(TokenClaims{Sub: "s", SID: "sid-revoked"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		m.Revoke("sid-revoked")
		if _, err := m.Parse(tok); !errors.Is(err, errRevokedSession) {
			t.Fatalf("want errRevokedSession, got %v", err)
		}
	})

	t.Run("issues unique tokens for identical claims", func(t *testing.T) {
		rc := TokenClaims{Sub: "s", SID: "sid-uniq"}
		a, err := m.Issue(rc)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		b, err := m.Issue(rc)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if a == b {
			t.Fatal("two issued tokens must not be identical")
		}
	})

	t.Run("rejects revoked token id", func(t *testing.T) {
		tok, err := m.Issue(TokenClaims{Sub: "s", SID: "sid-jti"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		rc, err := m.Parse(tok)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if rc.JTI == "" {
			t.Fatal("issued token carries no jti")
		}
		m.Revoke(rc.JTI)
		if _, err := m.Parse(tok); !errors.Is(err, errRevokedToken) {
			t.Fatalf("want errRevokedToken, got %v", err)
		}
		// Other tokens in the same session stay valid.
		other, err := m.Issue(TokenClaims{Sub: "s", SID: "sid-jti"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if _, err := m.Parse(other); err != nil {
			t.Fatalf("sibling token should stay valid: %v", err)
		}
	})

	t.Run("refuses to issue without a session id", func(t *testing.T) {
		if _, err := m.Issue(TokenClaims{Sub: "s"}); !errors.Is(err, errMissingSID) {
			t.Fatalf("want errMissingSID, got %v", err)
		}
	})

	t.Run("rejects a token audienced to a client", func(t *testing.T) {
		// Simulate an op-issued access/id token: signed with the SAME key, but
		// audienced to a client rather than to hamnir. It must not be spendable
		// as a refresh token, or session revocation could be bypassed.
		signer, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: key},
			(&jose.SignerOptions{}).WithType("JWT"),
		)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		impostor, err := jwt.Signed(signer).Claims(jwt.Claims{
			Issuer:   "hamnir",
			Subject:  "usr_alice",
			Audience: jwt.Audience{"rinmah"}, // a client, not hamnir
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
		}).Claims(refreshTokenClaims{SID: "sid1"}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.Parse(impostor); !errors.Is(err, jwt.ErrInvalidAudience) {
			t.Fatalf("want ErrInvalidAudience, got %v", err)
		}
	})
}
