package provider

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/persona"
)

const (
	// refreshTokenTTL is the lifetime of issued refresh tokens.
	refreshTokenTTL = 24 * time.Hour
	// accessTokenLifetime is the lifetime of issued access tokens.
	accessTokenLifetime = 5 * time.Minute
	// idTokenLifetime is the lifetime of issued id tokens.
	idTokenLifetime = time.Hour
	// authRequestTTL is how long an unexchanged /authorize flow may sit in the
	// picker before its auth request (and code) are considered abandoned.
	authRequestTTL = 15 * time.Minute
)

// errNotSupported is returned by op.Storage methods for flows hamnir does not
// implement (device authorization, token exchange, JWT-profile / client
// assertions, client-secret credential grants).
var errNotSupported = errors.New("not supported by hamnir")

var _ op.Storage = (*Storage)(nil)

// Storage is hamnir's in-memory implementation of op.Storage. Personas stand in
// for a user directory; refresh tokens are self-contained JWTs managed by the
// RefreshTokenManager rather than being stored here.
type Storage struct {
	cfg      *config.Config
	personas *persona.Set
	key      *rsa.PrivateKey
	refresh  *RefreshTokenManager
	signing  *signingKey

	mu           sync.Mutex
	authRequests map[string]*authRequest         // id -> request
	codes        map[string]string               // authorization code -> request id
	accessTokens map[string]*accessTokenInfo     // jti -> token metadata
	sessions     map[string]map[string]time.Time // subject -> active sid -> login time
}

// accessTokenInfo is the metadata retained for a JWT access token so that the
// userinfo and introspection endpoints can resolve claims from the token's jti.
type accessTokenInfo struct {
	TokenClaims
	expiration time.Time
}

// NewStorage builds a Storage over the given config, persona set and signing
// key, wiring up a fresh RefreshTokenManager. The set is shared with the login
// picker so both consult the same persona directory.
func NewStorage(cfg *config.Config, set *persona.Set, key *rsa.PrivateKey) (*Storage, error) {
	audience := cfg.Issuer
	if audience == "" {
		audience = defaultRefreshAudience
	}
	refresh, err := NewRefreshTokenManager(key, refreshTokenTTL, audience)
	if err != nil {
		return nil, err
	}
	return &Storage{
		cfg:      cfg,
		personas: set,
		key:      key,
		refresh:  refresh,
		signing:  &signingKey{id: randID(), key: key},

		authRequests: make(map[string]*authRequest),
		codes:        make(map[string]string),
		accessTokens: make(map[string]*accessTokenInfo),
		sessions:     make(map[string]map[string]time.Time),
	}, nil
}

// AuthenticateAndComplete is called by the login/persona picker once a persona
// has been chosen. It records the chosen subject and a fresh session id on the
// auth request and marks it done, allowing op to issue the authorization code
// when the browser is redirected back to AuthCallbackPath.
func (s *Storage) AuthenticateAndComplete(authRequestID, sub string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.authRequests[authRequestID]
	if !ok {
		return fmt.Errorf("auth request %q not found", authRequestID)
	}
	sid := randID()
	req.subject = sub
	req.sid = sid
	req.authTime = time.Now()
	req.done = true

	// Prune sids older than the refresh TTL: every token that could carry them
	// has expired, so they only exist to bloat the map and slow logout.
	now := req.authTime
	for subject, sids := range s.sessions {
		for old, at := range sids {
			if now.Sub(at) > refreshTokenTTL {
				delete(sids, old)
			}
		}
		if len(sids) == 0 {
			delete(s.sessions, subject)
		}
	}
	if s.sessions[sub] == nil {
		s.sessions[sub] = make(map[string]time.Time)
	}
	s.sessions[sub][sid] = req.authTime
	return nil
}

func (s *Storage) CreateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	if len(authReq.Prompt) == 1 && authReq.Prompt[0] == oidc.PromptNone {
		return nil, oidc.ErrLoginRequired()
	}

	req := &authRequest{
		id:            randID(),
		clientID:      authReq.ClientID,
		redirectURI:   authReq.RedirectURI,
		state:         authReq.State,
		nonce:         authReq.Nonce,
		scopes:        withOfflineAccess(authReq.Scopes),
		responseType:  authReq.ResponseType,
		responseMode:  authReq.ResponseMode,
		codeChallenge: codeChallenge(authReq),
		createdAt:     time.Now(),
		subject:       userID,
	}

	s.mu.Lock()
	// Evict abandoned flows (picker opened, persona never selected or code
	// never exchanged) so the maps stay bounded over a long-running server.
	now := time.Now()
	for id, r := range s.authRequests {
		if now.Sub(r.createdAt) > authRequestTTL {
			delete(s.authRequests, id)
			if r.code != "" {
				delete(s.codes, r.code)
			}
		}
	}
	s.authRequests[req.id] = req
	s.mu.Unlock()
	return req, nil
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.authRequests[id]
	if !ok {
		return nil, fmt.Errorf("auth request %q not found", id)
	}
	return req, nil
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.codes[code]
	if !ok {
		return nil, errors.New("authorization code invalid or expired")
	}
	req, ok := s.authRequests[id]
	if !ok {
		return nil, errors.New("authorization code invalid or expired")
	}
	return req, nil
}

func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.authRequests[id]
	if !ok {
		return fmt.Errorf("auth request %q not found", id)
	}
	req.code = code
	s.codes[code] = id
	return nil
}

func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req, ok := s.authRequests[id]; ok {
		delete(s.authRequests, id)
		if req.code != "" {
			delete(s.codes, req.code)
		}
	}
	return nil
}

func (s *Storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	info := requestInfo(request)
	jti, exp := s.storeAccessToken(info)
	return jti, exp, nil
}

func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshToken string, expiration time.Time, err error) {
	info := requestInfo(request)
	jti, exp := s.storeAccessToken(info)

	// hamnir issues refresh tokens by default (not gated on offline_access).
	// Tokens are self-contained JWTs; a refresh request rotates to a fresh token
	// carrying the same session id, which remains subject to sid revocation.
	rt, err := s.refresh.Issue(info)
	if err != nil {
		return "", "", time.Time{}, err
	}
	// Rotation: the refresh grant presented currentRefreshToken; now that its
	// replacement exists, revoke the old token's jti so a replay is rejected.
	if currentRefreshToken != "" {
		if rc, err := s.refresh.Parse(currentRefreshToken); err == nil && rc.JTI != "" {
			s.refresh.Revoke(rc.JTI)
		}
	}
	return jti, rt, exp, nil
}

func (s *Storage) storeAccessToken(info TokenClaims) (jti string, expiration time.Time) {
	jti = randID()
	now := time.Now()
	s.mu.Lock()
	// Evict expired tokens; nothing can resolve them any more.
	for old, i := range s.accessTokens {
		if i.expiration.Before(now) {
			delete(s.accessTokens, old)
		}
	}
	exp := now.Add(accessTokenLifetime)
	s.accessTokens[jti] = &accessTokenInfo{TokenClaims: info, expiration: exp}
	s.mu.Unlock()
	return jti, exp
}

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	// Parse verifies the signature and expiry and rejects revoked sessions.
	rc, err := s.refresh.Parse(refreshToken)
	if err != nil {
		return nil, err
	}
	return &refreshRequest{TokenClaims: rc}, nil
}

func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	s.mu.Lock()
	sids := s.sessions[userID]
	delete(s.sessions, userID)
	// Drop access tokens issued to this user.
	for jti, info := range s.accessTokens {
		if info.Sub == userID {
			delete(s.accessTokens, jti)
		}
	}
	s.mu.Unlock()

	for sid := range sids {
		s.refresh.Revoke(sid)
	}
	return nil
}

func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error) {
	rc, err := s.refresh.Parse(token)
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return rc.Sub, rc.SID, nil
}

func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	// Access token revocation: userID is set and tokenOrTokenID is the jti.
	s.mu.Lock()
	_, isAccess := s.accessTokens[tokenOrTokenID]
	if isAccess {
		delete(s.accessTokens, tokenOrTokenID)
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	// Otherwise it is a refresh token: either the raw JWT, or the session id
	// op resolved via GetRefreshTokenInfo. Revoke the session in both cases —
	// RFC 7009 wants related tokens invalidated too, and rotated descendants
	// share the sid. Revoking an id that never matches anything is harmless
	// (the denylist prunes by TTL).
	if rc, err := s.refresh.Parse(tokenOrTokenID); err == nil {
		s.refresh.Revoke(rc.SID)
		return nil
	}
	s.refresh.Revoke(tokenOrTokenID)
	return nil
}

func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	return s.signing, nil
}

func (s *Storage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	return []op.Key{&publicKey{s.signing}}, nil
}

func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	// Permissive mode: no configured clients, so accept any client_id with a
	// client shaped to match how the RP presented itself on this request.
	if len(s.cfg.Clients) == 0 {
		return permissiveClient(clientID, presentationFrom(ctx)), nil
	}
	for _, c := range s.cfg.Clients {
		if c.ID == clientID {
			return clientFromConfig(c), nil
		}
	}
	return nil, fmt.Errorf("client %q not found", clientID)
}

func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	// Permissive mode registers no secrets, so any presented secret is accepted.
	if len(s.cfg.Clients) == 0 {
		return nil
	}
	for _, c := range s.cfg.Clients {
		if c.ID == clientID {
			if c.Secret == "" {
				return errors.New("client is public; use PKCE")
			}
			if c.Secret != clientSecret {
				return errors.New("invalid client secret")
			}
			return nil
		}
	}
	return fmt.Errorf("client %q not found", clientID)
}

// SetUserinfoFromScopes is deprecated; claims are set via SetUserinfoFromRequest.
func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	return nil
}

// SetUserinfoFromRequest implements op.CanSetUserinfoFromRequest, populating the
// id_token claims for the chosen persona.
func (s *Storage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, request op.IDTokenRequest, scopes []string) error {
	s.setUserinfo(userinfo, request.GetSubject(), scopes)
	return nil
}

func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	s.mu.Lock()
	info, ok := s.accessTokens[tokenID]
	s.mu.Unlock()
	if !ok || info.expiration.Before(time.Now()) {
		return errors.New("token is invalid or has expired")
	}
	s.setUserinfo(userinfo, subject, info.Scopes)
	return nil
}

func (s *Storage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	s.mu.Lock()
	info, ok := s.accessTokens[tokenID]
	s.mu.Unlock()
	if !ok || info.expiration.Before(time.Now()) {
		return errors.New("token is invalid or has expired")
	}
	userInfo := new(oidc.UserInfo)
	s.setUserinfo(userInfo, subject, info.Scopes)
	introspection.SetUserInfo(userInfo)
	introspection.Scope = info.Scopes
	introspection.ClientID = info.ClientID
	introspection.Expiration = oidc.FromTime(info.expiration)
	return nil
}

func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	released := s.releasedClaims(userID, scopes)
	if len(released) == 0 {
		return nil, nil
	}
	return released, nil
}

// releasedClaims returns the subject's persona claims released for scopes,
// minus the reserved sub claim, which is always asserted as the registered
// subject claim instead. Nil when the subject matches no persona.
func (s *Storage) releasedClaims(subject string, scopes []string) map[string]any {
	p, ok := s.personas.BySub(subject)
	if !ok {
		return nil
	}
	released := persona.ReleaseClaims(p.Claims, scopes, s.cfg.Scopes)
	delete(released, "sub")
	return released
}

// setUserinfo resolves the persona for subject and copies its released claims
// (gated by scope) onto the userinfo object.
func (s *Storage) setUserinfo(userinfo *oidc.UserInfo, subject string, scopes []string) {
	userinfo.Subject = subject
	for k, v := range s.releasedClaims(subject, scopes) {
		userinfo.AppendClaims(k, v)
	}
}

func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, errNotSupported
}

func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return nil, errNotSupported
}

func (s *Storage) Health(ctx context.Context) error { return nil }

// requestInfo extracts the token claims from the concrete op.TokenRequest
// types hamnir produces (auth-code flow and refresh flow).
func requestInfo(req op.TokenRequest) TokenClaims {
	switch r := req.(type) {
	case *authRequest:
		return TokenClaims{Sub: r.subject, ClientID: r.clientID, SID: r.sid, Scopes: r.scopes}
	case *refreshRequest:
		return r.TokenClaims
	default:
		return TokenClaims{Sub: req.GetSubject(), Scopes: req.GetScopes()}
	}
}

// withOfflineAccess grants the offline_access scope by default so hamnir issues
// refresh tokens without the relying party having to request it. op gates
// refresh-token issuance on this scope being present in the granted set.
func withOfflineAccess(scopes []string) []string {
	if slices.Contains(scopes, oidc.ScopeOfflineAccess) {
		return scopes
	}
	return append(scopes[:len(scopes):len(scopes)], oidc.ScopeOfflineAccess)
}

func codeChallenge(authReq *oidc.AuthRequest) *oidc.CodeChallenge {
	if authReq.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{
		Challenge: authReq.CodeChallenge,
		Method:    authReq.CodeChallengeMethod,
	}
}
