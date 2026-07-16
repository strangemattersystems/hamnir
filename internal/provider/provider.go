package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/text/language"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/strangemattersystems/hamnir/internal/config"
)

// AuthCallbackPath is the path the login UI must redirect back to (with the auth
// request id in the "id" query parameter) once a persona has been selected. It
// mirrors zitadel's default: the authorization endpoint ("/authorize") plus the
// "/callback" suffix.
const AuthCallbackPath = "/authorize/callback"

// randID returns a hex-encoded, cryptographically-random identifier used for
// auth request ids, authorization codes and session ids.
func randID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
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
		CryptoKey:                cryptoKey(s.key),
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
		base := strings.TrimSuffix(cfg.BrowserURL, "/")
		opts = append(opts,
			op.WithCustomAuthEndpoint(op.NewEndpointWithURL("authorize", base+"/authorize")),
			op.WithCustomEndSessionEndpoint(op.NewEndpointWithURL("end_session", base+"/end_session")),
		)
	}

	return op.NewProvider(opConfig, s, issuer, opts...)
}
