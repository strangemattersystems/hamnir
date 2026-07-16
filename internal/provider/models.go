package provider

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/strangemattersystems/hamnir/internal/config"
)

// loginPath is where unauthenticated /authorize requests are redirected so the
// user can pick a persona; the auth request id is passed as a query parameter.
const loginPath = "/login?authRequestID="

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
	createdAt     time.Time

	subject  string
	sid      string
	authTime time.Time
	done     bool
}

var _ op.AuthRequest = (*authRequest)(nil)

func (a *authRequest) GetID() string                         { return a.id }
func (a *authRequest) GetACR() string                        { return "" }
func (a *authRequest) GetAudience() []string                 { return []string{a.clientID} }
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
	subject  string
	clientID string
	scopes   []string
	sid      string
}

var _ op.RefreshTokenRequest = (*refreshRequest)(nil)

func (r *refreshRequest) GetAMR() []string            { return []string{"pwd"} }
func (r *refreshRequest) GetAudience() []string       { return []string{r.clientID} }
func (r *refreshRequest) GetAuthTime() time.Time      { return time.Time{} }
func (r *refreshRequest) GetClientID() string         { return r.clientID }
func (r *refreshRequest) GetScopes() []string         { return r.scopes }
func (r *refreshRequest) GetSubject() string          { return r.subject }
func (r *refreshRequest) SetCurrentScopes(s []string) { r.scopes = s }

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
}

var (
	_ op.Client           = (*client)(nil)
	_ op.HasRedirectGlobs = (*client)(nil)
)

func (c *client) GetID() string                        { return c.id }
func (c *client) RedirectURIs() []string               { return c.redirectURIs }
func (c *client) PostLogoutRedirectURIs() []string     { return c.postLogoutRedirectURIs }
func (c *client) ApplicationType() op.ApplicationType  { return c.applicationType }
func (c *client) AuthMethod() oidc.AuthMethod          { return c.authMethod }
func (c *client) ResponseTypes() []oidc.ResponseType   { return c.responseTypes }
func (c *client) GrantTypes() []oidc.GrantType         { return c.grantTypes }
func (c *client) LoginURL(id string) string            { return loginPath + id }
func (c *client) AccessTokenType() op.AccessTokenType  { return c.accessTokenType }
func (c *client) IDTokenLifetime() time.Duration       { return idTokenLifetime }
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

// IsScopeAllowed permits any custom scope defined in the config's scope map.
func (c *client) IsScopeAllowed(scope string) bool {
	return true
}

// permissiveClient synthesizes a public, PKCE, dev-mode client that accepts any
// redirect_uri. Used when no clients are configured.
func permissiveClient(id string) *client {
	return &client{
		id:              id,
		redirectURIs:    nil,
		applicationType: op.ApplicationTypeWeb,
		authMethod:      oidc.AuthMethodNone,
		grantTypes:      []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken},
		responseTypes:   []oidc.ResponseType{oidc.ResponseTypeCode},
		accessTokenType: op.AccessTokenTypeJWT,
		devMode:         true,
		redirectGlobs:   []string{"**"},
	}
}

// clientFromConfig builds a strict client from configuration. Clients with a
// secret are confidential (Basic auth); clients without are public and rely on
// PKCE. Redirect URIs are matched exactly.
func clientFromConfig(c config.Client) *client {
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
		grantTypes:             []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken},
		responseTypes:          []oidc.ResponseType{oidc.ResponseTypeCode},
		accessTokenType:        op.AccessTokenTypeJWT,
		devMode:                false,
	}
}
