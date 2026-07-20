package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
	// op reports verifier failures to clients as a generic "subject_token is
	// invalid"; this message is for hamnir-side reading only.
	errExchangeTokenType = errors.New("static persona tokens must be presented as " + string(PersonaTokenType))
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
	// reject them here. The refresh type is honoured, but the response
	// envelope is op's own: issued_token_type reports refresh_token while the
	// refresh token itself rides in the response's refresh_token field, not
	// access_token (see the README's programmatic-login section).
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
	return s.GetPrivateClaimsFromScopes(ctx, request.GetSubject(), request.GetClientID(), withoutUserinfoScopes(request.GetScopes()))
}

// withoutUserinfoScopes drops the scopes whose claims belong in userinfo and
// the id_token rather than the access token, mirroring the unexported filter
// op applies before requesting private access-token claims on the code flow
// (op/token.go removeUserinfoScopes). Without it, access-token claims would
// differ between picker logins and exchanges for the same persona and scopes.
func withoutUserinfoScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		switch s {
		case oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopeAddress, oidc.ScopePhone:
			continue
		}
		out = append(out, s)
	}
	return out
}

// SetUserinfoFromTokenExchangeRequest populates an exchanged id_token's claims,
// gated by scope exactly like the code flow.
func (s *Storage) SetUserinfoFromTokenExchangeRequest(ctx context.Context, userinfo *oidc.UserInfo, request op.TokenExchangeRequest) error {
	s.setUserinfo(userinfo, request.GetSubject(), request.GetScopes())
	return nil
}

// DefaultExchangeAudience is hamnir's token-exchange hardening middleware. It
// defaults an omitted RFC 8693 audience parameter to the audiences configured
// for the requesting client, so configured audiences: reach exchanged tokens
// exactly as they reach code-flow and refresh tokens (op decodes an
// exchange's audience from the form only — there is no storage hook for it,
// unlike the subject, scopes and requested type, so the defaulting happens at
// the one seam hamnir owns, before op parses the request; RFC 8693 leaves the
// omitted-parameter policy to the server, and an explicit audience always
// wins). It also bridges a body client_id/client_secret into a Basic header
// (op reads exchange client identity from Basic only) and pre-answers
// malformed Basic credentials that would otherwise reach a panic in op (see
// the inline comments below).
//
// op's token endpoint accepts any HTTP method and reads grant_type from the
// merged form (query + body: net/http's FormValue), so exchange requests can
// arrive by GET as well as POST — the hardening here must not be gated on
// method, or a GET exchange (a) skips audience defaulting, minting a
// different aud than the same request sent by POST, and (b) with a malformed
// Basic header, reaches op's panic instead of being pre-answered. ParseForm on
// a GET only parses the query string (there being no body to consume), which
// is harmless. Mutating the parsed form works because ParseForm is idempotent
// and op decodes from the cached r.Form — the same property that obliges any
// early parser to answer parse failures itself (see answerFormParseError).
// An explicit audience applies only to the tokens minted by that exchange:
// refresh rotation re-derives audiences from config, hamnir's standing
// refresh policy.
func (s *Storage) DefaultExchangeAudience(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This middleware sits outermost, so it owns answering parse failures
		// (see answerFormParseError) — in registered mode nothing else between
		// here and op would.
		if err := r.ParseForm(); err != nil {
			answerFormParseError(w)
			return
		}
		if r.Form.Get("grant_type") == string(oidc.GrantTypeTokenExchange) {
			// op resolves the exchange client from the Basic header only, but
			// public clients identify with a body client_id (RFC 6749 §3.2.1)
			// and confidential clients may use client_secret_post. Bridge
			// either into a Basic header when the caller sent none, so
			// standard client libraries work the same against hamnir as
			// against a production IdP. A wrong or missing secret for a
			// confidential client still fails op's own check.
			if _, _, hasBasic := r.BasicAuth(); !hasBasic {
				if id := r.Form.Get("client_id"); id != "" {
					// URL-encode each credential: op QueryUnescapes them back out
					// (ParseTokenExchangeRequest), so a raw "+" or "%" in a secret
					// would otherwise be mangled before the comparison.
					cred := url.QueryEscape(id) + ":" + url.QueryEscape(r.Form.Get("client_secret"))
					r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cred)))
				}
			}
			// op unescapes Basic-auth credentials the same way
			// (ParseTokenExchangeRequest) — but its error path is missing a
			// return and panics on a nil request, so malformed credentials are
			// answered here before op can reach that path.
			clientID, secret, _ := r.BasicAuth()
			uID, errID := url.QueryUnescape(clientID)
			if _, errSecret := url.QueryUnescape(secret); errID != nil || errSecret != nil {
				answerBasicAuthError(w)
				return
			}
			if r.Form.Get("audience") == "" {
				for _, aud := range s.audienceFor(uID) {
					r.Form.Add("audience", aud)
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
