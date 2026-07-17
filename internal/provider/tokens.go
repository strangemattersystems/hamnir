package provider

import (
	"crypto/rsa"
	"errors"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var (
	errRevokedSession = errors.New("refresh session revoked")
	errRevokedToken   = errors.New("refresh token revoked")
	errMissingSID     = errors.New("refresh token missing session id")
)

const defaultRefreshAudience = "hamnir"

type TokenClaims struct {
	Sub      string
	ClientID string
	Scopes   []string
	SID      string
	JTI      string
}

type refreshTokenClaims struct {
	ClientID string   `json:"cid"`
	Scopes   []string `json:"scopes"`
	SID      string   `json:"sid"`
}

type RefreshTokenManager struct {
	signer   jose.Signer
	pub      *rsa.PublicKey
	ttl      time.Duration
	audience string

	mu      sync.RWMutex
	revoked map[string]time.Time // sid or jti -> when it was revoked
}

func NewRefreshTokenManager(key *rsa.PrivateKey, ttl time.Duration, audience string) (*RefreshTokenManager, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return nil, err
	}
	return &RefreshTokenManager{
		signer:   signer,
		pub:      &key.PublicKey,
		ttl:      ttl,
		audience: audience,
		revoked:  map[string]time.Time{},
	}, nil
}

func (m *RefreshTokenManager) Issue(rc TokenClaims) (string, error) {
	if rc.SID == "" {
		return "", errMissingSID
	}
	now := time.Now()
	registered := jwt.Claims{
		ID:        randID(),
		Issuer:    m.audience,
		Subject:   rc.Sub,
		Audience:  jwt.Audience{m.audience},
		IssuedAt:  jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(m.ttl)),
		NotBefore: jwt.NewNumericDate(now),
	}
	private := refreshTokenClaims{ClientID: rc.ClientID, Scopes: rc.Scopes, SID: rc.SID}
	return jwt.Signed(m.signer).Claims(registered).Claims(private).Serialize()
}

// Parse verifies and decodes a refresh token, rejecting revoked sessions and
// rotated-away (jti-denylisted) tokens. Grant flows must use this.
func (m *RefreshTokenManager) Parse(token string) (TokenClaims, error) {
	rc, err := m.decode(token)
	if err != nil {
		return TokenClaims{}, err
	}
	if m.isRevoked(rc.SID) {
		return TokenClaims{}, errRevokedSession
	}
	if rc.JTI != "" && m.isRevoked(rc.JTI) {
		return TokenClaims{}, errRevokedToken
	}
	return rc, nil
}

// decode verifies the signature, expiry, audience and structure without
// consulting the revocation denylist. Revocation flows use it directly so a
// superseded (rotated-away) token still identifies its session.
func (m *RefreshTokenManager) decode(token string) (TokenClaims, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return TokenClaims{}, err
	}
	var registered jwt.Claims
	var private refreshTokenClaims
	if err := parsed.Claims(m.pub, &registered, &private); err != nil {
		return TokenClaims{}, err
	}
	if err := registered.Validate(jwt.Expected{
		Issuer:      m.audience,
		AnyAudience: jwt.Audience{m.audience},
		Time:        time.Now(),
	}); err != nil {
		return TokenClaims{}, err
	}
	if private.SID == "" {
		return TokenClaims{}, errMissingSID
	}
	return TokenClaims{
		Sub:      registered.Subject,
		ClientID: private.ClientID,
		Scopes:   private.Scopes,
		SID:      private.SID,
		JTI:      registered.ID,
	}, nil
}

// Revoke bars the given session id or token id (jti). Entries older than the
// token TTL are pruned on each call: any token they could bar has expired on
// its own by then, so the denylist stays bounded.
func (m *RefreshTokenManager) Revoke(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, at := range m.revoked {
		if now.Sub(at) > m.ttl {
			delete(m.revoked, k)
		}
	}
	m.revoked[id] = now
}

func (m *RefreshTokenManager) isRevoked(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.revoked[id]
	return ok
}
