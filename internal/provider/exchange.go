package provider

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Storage implements op's token exchange interfaces (RFC 8693), hamnir's
// programmatic login: a static token configured on a persona (tokens:) is
// presented as the subject_token and exchanged for real tokens for that
// persona. op enables and advertises the grant automatically because these
// interfaces are satisfied — the assertions below make that switch-on explicit
// and compile-checked.
var (
	_ op.TokenExchangeStorage               = (*Storage)(nil)
	_ op.TokenExchangeTokensVerifierStorage = (*Storage)(nil)
)

// PersonaTokenType is the RFC 8693 token type under which hamnir's static
// persona tokens (config tokens:) are presented as subject tokens. The
// standard access-token type is deliberately not accepted for them: RFC 8693
// §3 defines it as an access token issued by the authorization server, which
// a configured static credential is not, and invites other URIs for other
// token types. The URI is a stable identifier, not a resolvable URL.
const PersonaTokenType oidc.TokenType = "https://hamnir.dev/token-type/persona" //nolint:gosec // G101: a token *type* URI, not a credential value.

// op validates subject/actor/requested token types against the package-global
// oidc.AllTokenTypes before consulting any storage hook, so the persona type
// must be registered there for exchange requests to reach hamnir at all.
// Package init keeps the append race-free: it runs once, before any provider
// can serve. TestPersonaTokenTypeRegistered guards this across op upgrades.
func init() {
	oidc.AllTokenTypes = append(oidc.AllTokenTypes, PersonaTokenType)
}

var (
	errUnknownExchangeToken = errors.New("unknown subject token")
	errExchangeTokenType    = errors.New("static persona tokens must be presented as " + string(PersonaTokenType))
)

// defaultExchangeScopes is the scope set applied when an exchange request
// omits scope, per RFC 6749 §3.3 ("process the request using a pre-defined
// default value"). A bare subject_token exchange with no scope parameter
// still returns identity claims; refresh tokens remain opt-in via an
// explicit requested_token_type.
var defaultExchangeScopes = []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}

// VerifyExchangeSubjectToken resolves a subject_token op itself could not:
// hamnir's static persona tokens. They are hamnir credentials, not tokens op
// knows, so they carry hamnir's own token type (see PersonaTokenType).
func (s *Storage) VerifyExchangeSubjectToken(ctx context.Context, token string, tokenType oidc.TokenType) (string, string, map[string]any, error) {
	if tokenType != PersonaTokenType {
		return "", "", nil, errExchangeTokenType
	}
	sub, ok := s.exchangeTokens[token]
	if !ok {
		return "", "", nil, errUnknownExchangeToken
	}
	return token, sub, nil, nil
}

// VerifyExchangeActorToken rejects actor tokens: delegation is out of scope.
func (s *Storage) VerifyExchangeActorToken(ctx context.Context, token string, tokenType oidc.TokenType) (string, string, map[string]any, error) {
	return "", "", nil, fmt.Errorf("actor tokens: %w", errNotSupported)
}

// ValidateTokenExchangeRequest applies hamnir's exchange policy, which is
// deliberately permissive — impersonating a configured persona is the whole
// point of a dev IdP: the verified subject token picks the persona, omitted
// scopes take the documented default, and the requested token type defaults
// to an access token.
func (s *Storage) ValidateTokenExchangeRequest(ctx context.Context, request op.TokenExchangeRequest) error {
	request.SetSubject(request.GetExchangeSubject())
	// A refresh token is requested the RFC 8693 way — an explicit
	// requested_token_type of ...:refresh_token, the only signal op consults
	// for exchanges (offline_access has no effect here, unlike the code flow).
	if request.GetRequestedTokenType() == "" {
		request.SetRequestedTokenType(oidc.AccessTokenType)
	}
	// op validates the type is a known RFC 8693 urn but not that it is
	// issuable; its response builder mishandles the rest (e.g. ...:jwt), so
	// reject them here.
	switch request.GetRequestedTokenType() {
	case oidc.AccessTokenType, oidc.RefreshTokenType, oidc.IDTokenType:
	default:
		return oidc.ErrInvalidRequest().WithDescription("requested_token_type %s is not supported", string(request.GetRequestedTokenType()))
	}
	if len(request.GetScopes()) == 0 {
		request.SetCurrentScopes(slices.Clone(defaultExchangeScopes))
	}
	return nil
}

// CreateTokenExchangeRequest is op's post-validation persistence hook. op never
// reads the request back (storing is for audit only), so this is a no-op.
func (s *Storage) CreateTokenExchangeRequest(ctx context.Context, request op.TokenExchangeRequest) error {
	return nil
}

// GetPrivateClaimsFromTokenExchangeRequest releases the persona's claims into
// an exchanged access token, gated by scope exactly like the code flow.
func (s *Storage) GetPrivateClaimsFromTokenExchangeRequest(ctx context.Context, request op.TokenExchangeRequest) (map[string]any, error) {
	return s.GetPrivateClaimsFromScopes(ctx, request.GetSubject(), request.GetClientID(), request.GetScopes())
}

// SetUserinfoFromTokenExchangeRequest populates an exchanged id_token's claims,
// gated by scope exactly like the code flow.
func (s *Storage) SetUserinfoFromTokenExchangeRequest(ctx context.Context, userinfo *oidc.UserInfo, request op.TokenExchangeRequest) error {
	s.setUserinfo(userinfo, request.GetSubject(), request.GetScopes())
	return nil
}
