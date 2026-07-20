package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// Device flow (RFC 8628) state. op owns the /device_authorization endpoint
// and the token-endpoint polling; hamnir stores the requests and lets the
// /device pages approve or deny them.

// Sentinel errors let the device pages distinguish user-facing outcomes.
var (
	ErrDeviceCodeNotFound = errors.New("device code not found")
	ErrDeviceCodeExpired  = errors.New("device code expired")
	ErrDeviceCodeHandled  = errors.New("device code already handled")
)

// deviceRequest is a pending or decided device authorization.
type deviceRequest struct {
	clientID  string
	scopes    []string
	audiences []string // resolved aud values; nil -> default [clientID]
	expires   time.Time

	done     bool
	denied   bool
	subject  string
	authTime time.Time
}

// normalizeUserCode makes user-code matching forgiving per RFC 8628 §6.1:
// uppercase with separators (dashes, spaces) stripped.
func normalizeUserCode(code string) string {
	code = strings.ToUpper(code)
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, code)
}

// StoreDeviceAuthorization implements op.DeviceAuthorizationStorage. Expired
// requests are pruned here — user codes are low-entropy, so stale ones must
// not linger to collide (the upstream interface requires purging).
func (s *Storage) StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneDeviceRequestsLocked(time.Now())
	key := normalizeUserCode(userCode)
	if _, ok := s.deviceUserCodes[key]; ok {
		return op.ErrDuplicateUserCode
	}
	s.deviceRequests[deviceCode] = &deviceRequest{
		clientID: clientID,
		// hamnir issues refresh tokens by default (see withOfflineAccess and
		// CreateAuthRequest); op's needsRefreshToken gates a device grant's
		// refresh token on offline_access being present in these scopes, so
		// default it in here too, the same as the auth-code flow.
		scopes:    withOfflineAccess(scopes),
		audiences: s.audienceFor(clientID),
		expires:   expires,
	}
	s.deviceUserCodes[key] = deviceCode
	return nil
}

// GetDeviceAuthorizatonState implements op.DeviceAuthorizationStorage. The
// upstream method name is misspelled and kept verbatim for interface
// compliance. op polls this from the token endpoint and derives
// authorization_pending / expired_token / access_denied from the state.
func (s *Storage) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.deviceRequests[deviceCode]
	if !ok || req.clientID != clientID {
		return nil, fmt.Errorf("device code %q: %w", deviceCode, ErrDeviceCodeNotFound)
	}
	state := &op.DeviceAuthorizationState{
		ClientID: req.clientID,
		Audience: req.audiences,
		Scopes:   req.scopes,
		Expires:  req.expires,
		Done:     req.done,
		Denied:   req.denied,
	}
	if req.done {
		state.Subject = req.subject
		state.AMR = []string{"pwd"}
		state.AuthTime = req.authTime
	}
	return state, nil
}

// LookupDeviceUserCode reports whether userCode identifies a pending,
// unexpired device authorization — the /device page's validation step.
func (s *Storage) LookupDeviceUserCode(userCode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.pendingByUserCodeLocked(userCode)
	return err
}

// ApproveDevice records the chosen persona on the device authorization. No
// session is registered here — see the comment below.
func (s *Storage) ApproveDevice(userCode, sub string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, err := s.pendingByUserCodeLocked(userCode)
	if err != nil {
		return err
	}
	now := time.Now()
	req.subject = sub
	req.authTime = now
	req.done = true

	// No session is registered here: op.DeviceAuthorizationState cannot carry
	// a sid, so requestInfo mints one at token issuance and touchSession
	// registers it there — the same lifecycle as a token exchange.
	return nil
}

// DenyDevice marks the device authorization denied; op then answers the
// device's next poll with access_denied.
func (s *Storage) DenyDevice(userCode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, err := s.pendingByUserCodeLocked(userCode)
	if err != nil {
		return err
	}
	req.denied = true
	return nil
}

// pendingByUserCodeLocked resolves a normalised user code to its pending
// request, distinguishing unknown, expired and already-handled codes.
func (s *Storage) pendingByUserCodeLocked(userCode string) (*deviceRequest, error) {
	dc, ok := s.deviceUserCodes[normalizeUserCode(userCode)]
	if !ok {
		return nil, fmt.Errorf("user code %q: %w", userCode, ErrDeviceCodeNotFound)
	}
	req := s.deviceRequests[dc]
	if req.done || req.denied {
		return nil, fmt.Errorf("user code %q: %w", userCode, ErrDeviceCodeHandled)
	}
	if time.Now().After(req.expires) {
		return nil, fmt.Errorf("user code %q: %w", userCode, ErrDeviceCodeExpired)
	}
	return req, nil
}

// deviceOutcomeGrace is how long a device request outlives its expiry before
// pruning. op reads outcomes from the stored state — a decided (done/denied)
// state is terminal regardless of expiry, and an undecided expired state maps
// to expired_token — but a pruned request degrades to access_denied, which
// would misreport an approval that landed near the deadline. The grace
// comfortably exceeds op's 5s poll interval so the deciding poll always finds
// the state.
const deviceOutcomeGrace = time.Minute

// pruneDeviceRequestsLocked drops device requests once they are expired AND
// past the outcome grace, so a device's final poll can still read its result
// (tokens, access_denied or expired_token) before the entry disappears.
func (s *Storage) pruneDeviceRequestsLocked(now time.Time) {
	for dc, req := range s.deviceRequests {
		if now.After(req.expires.Add(deviceOutcomeGrace)) {
			delete(s.deviceRequests, dc)
		}
	}
	for uc, dc := range s.deviceUserCodes {
		if _, ok := s.deviceRequests[dc]; !ok {
			delete(s.deviceUserCodes, uc)
		}
	}
}
