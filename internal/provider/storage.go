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
	// picker before its auth request (and code) are considered abandoned. An
	// auth request is a few hundred bytes, so this is generous on purpose: a
	// picker tab left open across a workday must still complete, and a day of
	// abandoned flows is still bounded memory.
	authRequestTTL = 24 * time.Hour
)

// errNotSupported is returned by op.Storage methods for flows hamnir does not
// implement (device authorization, token exchange, JWT-profile / client
// assertions, client-secret credential grants).
var errNotSupported = errors.New("not supported by hamnir")

// ErrAuthRequestNotFound and ErrAuthRequestDone let the login UI distinguish
// a stale or replayed persona selection (user error, 400) from a server fault.
var (
	ErrAuthRequestNotFound = errors.New("auth request not found")
	ErrAuthRequestDone     = errors.New("auth request already completed")
)

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
	authRequests map[string]*authRequest       // id -> request
	codes        map[string]string             // authorization code -> request id
	accessTokens map[string]*accessTokenInfo   // jti -> token metadata
	sessions     map[string]map[string]session // subject -> active sid -> session
}

// session records which client a sid was minted for and when a token carrying
// it was last issued (login or refresh rotation), so termination can be scoped
// per client and pruning tracks actual token liveness.
type session struct {
	clientID string
	lastSeen time.Time
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
		sessions:     make(map[string]map[string]session),
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
		return fmt.Errorf("auth request %q: %w", authRequestID, ErrAuthRequestNotFound)
	}
	if req.done {
		return fmt.Errorf("auth request %q: %w", authRequestID, ErrAuthRequestDone)
	}
	sid := randID()
	req.subject = sub
	req.sid = sid
	req.authTime = time.Now()
	req.done = true

	// Prune sids not seen within the refresh TTL: lastSeen is refreshed on
	// every rotation, so expiry here means no live token can carry the sid.
	now := req.authTime
	for subject, sids := range s.sessions {
		for old, sess := range sids {
			if now.Sub(sess.lastSeen) > refreshTokenTTL {
				delete(sids, old)
			}
		}
		if len(sids) == 0 {
			delete(s.sessions, subject)
		}
	}
	if s.sessions[sub] == nil {
		s.sessions[sub] = make(map[string]session)
	}
	s.sessions[sub][sid] = session{clientID: req.clientID, lastSeen: req.authTime}
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
	return snapshot(req), nil
}

// snapshot returns a shallow copy of the request so callers never hold the
// live object: op reads requests outside s.mu, and handing out the stored
// pointer would race AuthenticateAndComplete's and SaveAuthCode's writes.
// Shallow is safe — the shared slice/pointer fields are never mutated after
// creation.
func snapshot(req *authRequest) *authRequest {
	cp := *req
	return &cp
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.authRequests[id]
	if !ok {
		return nil, fmt.Errorf("auth request %q: %w", id, ErrAuthRequestNotFound)
	}
	return snapshot(req), nil
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
	return snapshot(req), nil
}

func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.authRequests[id]
	if !ok {
		return fmt.Errorf("auth request %q: %w", id, ErrAuthRequestNotFound)
	}
	// A callback reload makes op issue a fresh code for the same request; the
	// superseded one must stop resolving (codes are single-use) and must not
	// linger in the map.
	if req.code != "" {
		delete(s.codes, req.code)
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
	// Rotation: the refresh grant presented currentRefreshToken (the very token
	// this request was built from, so its jti is already on info). Revoke the
	// replaced token and mark the session seen — the new token extends the
	// session's life, so the prune horizon must move with it.
	if currentRefreshToken != "" && info.JTI != "" {
		s.refresh.Revoke(info.JTI)
		s.touchSession(info)
	}
	return jti, rt, exp, nil
}

// touchSession upserts the session entry for a freshly rotated token. Upsert,
// not update: the sid may have been pruned or lost to a restart, and rotation
// proves the session is live, so re-registering it keeps logout able to
// revoke it.
func (s *Storage) touchSession(info TokenClaims) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[info.Sub] == nil {
		s.sessions[info.Sub] = make(map[string]session)
	}
	s.sessions[info.Sub][info.SID] = session{clientID: info.ClientID, lastSeen: time.Now()}
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

// TerminateSession ends the user's sessions with the given client (op derives
// clientID from the id_token_hint's azp). An empty clientID terminates all of
// the subject's sessions.
func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	matches := func(c string) bool { return clientID == "" || c == clientID }

	s.mu.Lock()
	var revoke []string
	sids := s.sessions[userID]
	for sid, sess := range sids {
		if matches(sess.clientID) {
			delete(sids, sid)
			revoke = append(revoke, sid)
		}
	}
	if len(sids) == 0 {
		delete(s.sessions, userID)
	}
	// Drop this client's access tokens for the user.
	for jti, info := range s.accessTokens {
		if info.Sub == userID && matches(info.ClientID) {
			delete(s.accessTokens, jti)
		}
	}
	s.mu.Unlock()

	for _, sid := range revoke {
		s.refresh.Revoke(sid)
	}
	return nil
}

func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error) {
	// decode, not Parse: a superseded (rotated-away) token still identifies
	// its session, so revocation works from any member of the rotation family.
	rc, err := s.refresh.decode(token)
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	// RFC 7009 §2.1: only the client the token was issued to may revoke it.
	if rc.ClientID != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	return rc.Sub, rc.SID, nil
}

func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	errWrongClient := oidc.ErrInvalidClient().WithDescription("token was not issued for this client")

	// Access token revocation: tokenOrTokenID is the jti.
	s.mu.Lock()
	if info, ok := s.accessTokens[tokenOrTokenID]; ok {
		if info.ClientID != clientID {
			s.mu.Unlock()
			return errWrongClient
		}
		delete(s.accessTokens, tokenOrTokenID)
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	// A raw refresh JWT (decode, so superseded family members count too):
	// revoke its whole session — rotated descendants share the sid.
	if rc, err := s.refresh.decode(tokenOrTokenID); err == nil {
		if rc.ClientID != clientID {
			return errWrongClient
		}
		s.refresh.Revoke(rc.SID)
		return nil
	}

	// Otherwise the session id op resolved via GetRefreshTokenInfo, which
	// already enforced ownership; cross-check the session record when we
	// still hold one. Revoking an id that matches nothing is harmless (the
	// denylist prunes by TTL).
	s.mu.Lock()
	sess, ok := s.sessions[userID][tokenOrTokenID]
	s.mu.Unlock()
	if ok && sess.clientID != clientID {
		return errWrongClient
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
