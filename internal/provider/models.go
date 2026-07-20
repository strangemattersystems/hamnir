package provider

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/strangemattersystems/hamnir/internal/config"
)

// LoginPath is the picker route unauthenticated /authorize requests are
// redirected to, with the auth request id in the AuthRequestIDParam query
// parameter. The web package registers its route and reads the parameter via
// these same constants, so the two halves of the handshake cannot drift.
const (
	LoginPath          = "/login"
	AuthRequestIDParam = "authRequestID"
)

// authRequest is hamnir's in-memory op.AuthRequest. It starts unauthenticated
// (done == false); AuthenticateAndComplete fills in the subject and session id.
type authRequest struct {
	id            string
	clientID      string
	redirectURI   string
	state         string
	nonce         string
	scopes        []string
	responseType  oidc.ResponseType
	responseMode  oidc.ResponseMode
	codeChallenge *oidc.CodeChallenge
	audiences     []string // resolved aud values; nil -> default [clientID]
	loginHint     string
	prompt        oidc.SpaceDelimitedArray
	createdAt     time.Time
	code          string // authorization code, once issued (reverse index into Storage.codes)

	subject  string
	sid      string
	authTime time.Time
	done     bool
}

var _ op.AuthRequest = (*authRequest)(nil)

func (a *authRequest) GetID() string  { return a.id }
func (a *authRequest) GetACR() string { return "" }
func (a *authRequest) GetAudience() []string {
	if len(a.audiences) > 0 {
		return a.audiences
	}
	return []string{a.clientID}
}
func (a *authRequest) GetAuthTime() time.Time                { return a.authTime }
func (a *authRequest) GetClientID() string                   { return a.clientID }
func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge { return a.codeChallenge }
func (a *authRequest) GetNonce() string                      { return a.nonce }
func (a *authRequest) GetRedirectURI() string                { return a.redirectURI }
func (a *authRequest) GetResponseType() oidc.ResponseType    { return a.responseType }
func (a *authRequest) GetResponseMode() oidc.ResponseMode    { return a.responseMode }
func (a *authRequest) GetScopes() []string                   { return a.scopes }
func (a *authRequest) GetState() string                      { return a.state }
func (a *authRequest) GetSubject() string                    { return a.subject }
func (a *authRequest) Done() bool                            { return a.done }

func (a *authRequest) GetAMR() []string {
	if a.done {
		return []string{"pwd"}
	}
	return nil
}

// refreshRequest is hamnir's op.RefreshTokenRequest, rebuilt from a parsed
// (self-contained) refresh token during the refresh grant.
type refreshRequest struct {
	TokenClaims
	audiences []string // resolved aud values; nil -> default [ClientID]
}

var _ op.RefreshTokenRequest = (*refreshRequest)(nil)

func (r *refreshRequest) GetAMR() []string { return []string{"pwd"} }

func (r *refreshRequest) GetAudience() []string {
	if len(r.audiences) > 0 {
		return r.audiences
	}
	return []string{r.ClientID}
}

func (r *refreshRequest) GetAuthTime() time.Time      { return time.Time{} }
func (r *refreshRequest) GetClientID() string         { return r.ClientID }
func (r *refreshRequest) GetScopes() []string         { return r.Scopes }
func (r *refreshRequest) GetSubject() string          { return r.Sub }
func (r *refreshRequest) SetCurrentScopes(s []string) { r.Scopes = s }

// client is hamnir's op.Client. It implements op.HasRedirectGlobs so permissive
// mode can accept any redirect_uri via a "**" glob; strict clients leave the
// glob list empty and rely on exact redirect matching.
type client struct {
	id                     string
	redirectURIs           []string
	postLogoutRedirectURIs []string
	applicationType        op.ApplicationType
	authMethod             oidc.AuthMethod
	grantTypes             []oidc.GrantType
	responseTypes          []oidc.ResponseType
	accessTokenType        op.AccessTokenType
	devMode                bool
	redirectGlobs          []string
	idTokenLifetime        time.Duration
}

var (
	_ op.Client           = (*client)(nil)
	_ op.HasRedirectGlobs = (*client)(nil)
)

func (c *client) GetID() string                       { return c.id }
func (c *client) RedirectURIs() []string              { return c.redirectURIs }
func (c *client) PostLogoutRedirectURIs() []string    { return c.postLogoutRedirectURIs }
func (c *client) ApplicationType() op.ApplicationType { return c.applicationType }
func (c *client) AuthMethod() oidc.AuthMethod         { return c.authMethod }
func (c *client) ResponseTypes() []oidc.ResponseType  { return c.responseTypes }
func (c *client) GrantTypes() []oidc.GrantType        { return c.grantTypes }
func (c *client) LoginURL(id string) string {
	return LoginPath + "?" + AuthRequestIDParam + "=" + id
}
func (c *client) AccessTokenType() op.AccessTokenType  { return c.accessTokenType }
func (c *client) IDTokenLifetime() time.Duration       { return c.idTokenLifetime }
func (c *client) DevMode() bool                        { return c.devMode }
func (c *client) IDTokenUserinfoClaimsAssertion() bool { return true }
func (c *client) ClockSkew() time.Duration             { return 0 }
func (c *client) RedirectURIGlobs() []string           { return c.redirectGlobs }
func (c *client) PostLogoutRedirectURIGlobs() []string { return nil }

func (c *client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}

// IsScopeAllowed accepts every scope, deliberately: hamnir does not gate scope
// acceptance — unknown scopes are echoed back and simply release no claims.
// The config's scope map gates claim release (persona.ReleaseClaims), not
// which scopes a client may request.
func (c *client) IsScopeAllowed(scope string) bool {
	return true
}

// permissiveClient synthesizes a dev-mode client that accepts any redirect_uri,
// mirroring the RP's presentation on the current request: a presented client
// secret makes it confidential (Basic — any secret is accepted since none is
// registered), otherwise it is public and op requires PKCE, so a client using
// neither is rejected just as a real IdP would. A requested post-logout
// redirect is registered verbatim so RP-initiated logout round-trips. Used
// when no clients are configured.
func permissiveClient(id string, p presentation, idTokenLifetime time.Duration) *client {
	authMethod := oidc.AuthMethodNone
	if p.clientSecret {
		authMethod = oidc.AuthMethodBasic
	}
	var postLogout []string
	if p.postLogoutRedirectURI != "" {
		postLogout = []string{p.postLogoutRedirectURI}
	}
	return &client{
		id:                     id,
		redirectURIs:           nil,
		postLogoutRedirectURIs: postLogout,
		applicationType:        op.ApplicationTypeWeb,
		authMethod:             authMethod,
		grantTypes:             []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeTokenExchange, oidc.GrantTypeDeviceCode},
		responseTypes:          []oidc.ResponseType{oidc.ResponseTypeCode},
		accessTokenType:        op.AccessTokenTypeJWT,
		devMode:                true,
		redirectGlobs:          []string{"**"},
		idTokenLifetime:        idTokenLifetime,
	}
}

// clientFromConfig builds a strict client from configuration. Clients with a
// secret are confidential (Basic auth); clients without are public and rely on
// PKCE. Redirect URIs are matched exactly.
func clientFromConfig(c config.Client, idTokenLifetime time.Duration) *client {
	authMethod := oidc.AuthMethodNone
	if c.Secret != "" {
		authMethod = oidc.AuthMethodBasic
	}
	return &client{
		id:                     c.ID,
		redirectURIs:           c.RedirectURIs,
		postLogoutRedirectURIs: c.PostLogoutRedirectURIs,
		applicationType:        op.ApplicationTypeWeb,
		authMethod:             authMethod,
		grantTypes:             []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeTokenExchange, oidc.GrantTypeDeviceCode},
		responseTypes:          []oidc.ResponseType{oidc.ResponseTypeCode},
		accessTokenType:        op.AccessTokenTypeJWT,
		devMode:                false,
		idTokenLifetime:        idTokenLifetime,
	}
}
