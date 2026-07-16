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
	errMissingSID     = errors.New("refresh token missing session id")
)

const defaultRefreshAudience = "hamnir"

type RefreshClaims struct {
	Sub      string
	ClientID string
	Scopes   []string
	SID      string
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
	revoked map[string]bool
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
		revoked:  map[string]bool{},
	}, nil
}

func (m *RefreshTokenManager) Issue(rc RefreshClaims) (string, error) {
	if rc.SID == "" {
		return "", errMissingSID
	}
	now := time.Now()
	registered := jwt.Claims{
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

func (m *RefreshTokenManager) Parse(token string) (RefreshClaims, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return RefreshClaims{}, err
	}
	var registered jwt.Claims
	var private refreshTokenClaims
	if err := parsed.Claims(m.pub, &registered, &private); err != nil {
		return RefreshClaims{}, err
	}
	if err := registered.Validate(jwt.Expected{
		Issuer:      m.audience,
		AnyAudience: jwt.Audience{m.audience},
		Time:        time.Now(),
	}); err != nil {
		return RefreshClaims{}, err
	}
	if private.SID == "" {
		return RefreshClaims{}, errMissingSID
	}
	if m.isRevoked(private.SID) {
		return RefreshClaims{}, errRevokedSession
	}
	return RefreshClaims{
		Sub:      registered.Subject,
		ClientID: private.ClientID,
		Scopes:   private.Scopes,
		SID:      private.SID,
	}, nil
}

func (m *RefreshTokenManager) Revoke(sid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked[sid] = true
}

func (m *RefreshTokenManager) isRevoked(sid string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.revoked[sid]
}
