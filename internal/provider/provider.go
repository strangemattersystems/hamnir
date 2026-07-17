// Package provider adapts hamnir's config and personas to the zitadel/oidc
// server (op): an in-memory [op.Storage], the client and request models op
// drives, and the constructors that assemble the OpenID provider.
package provider

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/text/language"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/strangemattersystems/hamnir/internal/config"
)

// AuthCallbackPath is the path the login UI must redirect back to (with the auth
// request id in the "id" query parameter) once a persona has been selected. It
// mirrors zitadel's default: the authorization endpoint ("/authorize") plus the
// "/callback" suffix. op exports an AuthCallbackURL helper that would avoid the
// mirroring, but it builds an absolute URL from the issuer in the request
// context, and the picker routes are mounted on the outer mux outside op's
// issuer middleware — so hamnir deliberately redirects via this relative path
// instead. Revisit if op's callback wiring changes on upgrade.
const AuthCallbackPath = "/authorize/callback"

// randID returns a hex-encoded, cryptographically-random identifier used for
// auth request ids, authorization codes and session ids.
func randID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// keyID returns a deterministic kid for the signing key: the RFC 7638
// SHA-256 JWK thumbprint of the public key, base64url-encoded. Identical
// keys yield identical kids, so all replicas sharing a config advertise one
// consistent JWKS and tokens survive restarts.
func keyID(key *rsa.PrivateKey) (string, error) {
	tp, err := (&jose.JSONWebKey{Key: &key.PublicKey}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

type signingKey struct {
	id  string
	key *rsa.PrivateKey
}

func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm {
	return jose.RS256
}

func (k *signingKey) Key() any {
	return k.key
}

func (k *signingKey) ID() string {
	return k.id
}

type publicKey struct {
	*signingKey
}

func (k *publicKey) Algorithm() jose.SignatureAlgorithm {
	return jose.RS256
}

func (k *publicKey) Use() string {
	return "sig"
}

func (k *publicKey) Key() any {
	return &k.key.PublicKey
}

// cryptoKeyLabel domain-separates the derived code-encryption key from the
// signing use of the same RSA key. Bump the version suffix if the derivation
// ever changes.
const cryptoKeyLabel = "hamnir/op-code-encryption/v1"

// cryptoKey derives the 32-byte symmetric key op uses to encrypt authorization
// codes. It is derived from PRIVATE key material (the private exponent D) — never
// the public modulus N, which is published in JWKS and so would make the key
// public — with a domain-separation label so it is independent of the key's
// signing use. Deriving from the signing key keeps it stable across restarts of a
// single instance without needing extra configuration.
func cryptoKey(key *rsa.PrivateKey) [32]byte {
	h := sha256.New()
	h.Write([]byte(cryptoKeyLabel))
	h.Write(key.D.Bytes())
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// NewProvider constructs the zitadel OpenID provider backed by the given Storage.
// When cfg.Issuer is empty the issuer is derived from each request's host
// (dynamic issuer); otherwise the configured static issuer is used.
func NewProvider(cfg *config.Config, s *Storage) (*op.Provider, error) {
	opConfig := &op.Config{
		CryptoKey:                cryptoKey(s.signing.key),
		DefaultLogoutRedirectURI: "/",
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		GrantTypeRefreshToken:    true,
		SupportedUILocales:       []language.Tag{language.English},
	}

	issuer := op.IssuerFromHost("")
	if cfg.Issuer != "" {
		issuer = op.StaticIssuer(cfg.Issuer)
	}

	// NOTE: op's WithCustom*Endpoint options mutate the package-global
	// op.DefaultEndpoints in place, so this is correct only because hamnir builds
	// a single provider per process.
	opts := []op.Option{op.WithAllowInsecure()}
	if cfg.BrowserURL != "" {
		opts = append(
			opts,
			op.WithCustomAuthEndpoint(op.NewEndpointWithURL("authorize", cfg.BrowserURL+"/authorize")),
			op.WithCustomEndSessionEndpoint(op.NewEndpointWithURL("end_session", cfg.BrowserURL+"/end_session")),
		)
	}

	return op.NewProvider(opConfig, s, issuer, opts...)
}
