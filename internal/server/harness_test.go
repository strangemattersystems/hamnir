package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/server"
)

// The end-to-end tests' subtests run in parallel, which is safe only because
// none sets browser_url: provider.NewProvider mutates op's package-global
// DefaultEndpoints in place ONLY for a browser_url split, so with none set
// every construction merely reads the global. A future browser_url case here
// must not be parallel.

// testVersion is the version line newServer wires into New, so the /up endpoint
// has a known string to echo.
const testVersion = "hamnir 9.9.9-test (rev deadbeef, built 2026-01-01T00:00:00Z)"

// env bundles one end-to-end scenario: the running server, a redirect-aware
// HTTP client, the RP-side discovery, and the discovered endpoints.
type env struct {
	srv    *httptest.Server
	client *http.Client
	ctx    context.Context
	rp     *oidc.Provider
	disc   discovery
}

type discovery struct {
	EndSession    string   `json:"end_session_endpoint"`
	Revocation    string   `json:"revocation_endpoint"`
	Userinfo      string   `json:"userinfo_endpoint"`
	Introspection string   `json:"introspection_endpoint"`
	GrantTypes    []string `json:"grant_types_supported"`
}

// discover boots a server for cfg and performs RP discovery against it.
func discover(t *testing.T, cfg *config.Config) env {
	t.Helper()
	srv, client := newServer(t, cfg)
	ctx := oidc.ClientContext(context.Background(), client)
	rp, err := oidc.NewProvider(ctx, srv.URL)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	var d discovery
	if err := rp.Claims(&d); err != nil {
		t.Fatal(err)
	}
	return env{srv: srv, client: client, ctx: ctx, rp: rp, disc: d}
}

// app returns the RP's oauth2 config; openid is always requested.
func (e env) app(clientID, secret string, scopes ...string) oauth2.Config {
	return oauth2.Config{
		ClientID:     clientID,
		ClientSecret: secret,
		Endpoint:     e.rp.Endpoint(),
		RedirectURL:  "http://app.test/callback",
		Scopes:       append([]string{oidc.ScopeOpenID}, scopes...),
	}
}

// obtainCode drives authorize → picker → select Alice and returns the
// authorization code from the app redirect.
func (e env) obtainCode(t *testing.T, cfg oauth2.Config, opts ...oauth2.AuthCodeOption) string {
	t.Helper()
	code := codeFrom(authorizeAndSelect(t, e.client, e.srv.URL, cfg.AuthCodeURL("state123", opts...)))
	if code == "" {
		t.Fatal("expected an auth code")
	}
	return code
}

// newServer starts an httptest server for cfg with a cookie-jar client that stops
// following redirects at the app's callback host (app.test) so tests can read the
// authorization code out of the redirect.
func newServer(t *testing.T, cfg *config.Config) (*httptest.Server, *http.Client) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Key = key
	if cfg.Lifetimes == (config.Lifetimes{}) {
		cfg.Lifetimes = config.DefaultLifetimes
	}
	h, err := server.New(cfg, testVersion)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client := srv.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Host == "app.test" {
			return http.ErrUseLastResponse
		}
		return nil
	}
	return srv, client
}

// authorizeAndSelect drives the authorize request to the picker, then posts the
// selection of the Alice persona, returning the resulting response (whose
// redirect carries the authorization code).
func authorizeAndSelect(t *testing.T, client *http.Client, srvURL, authURL string) *http.Response {
	t.Helper()
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	body := readBody(t, resp)
	authRequestID := between(body, `name="authRequestID" value="`, `"`)
	if authRequestID == "" {
		t.Fatalf("authRequestID not found in picker HTML: %s", body)
	}
	sel, err := client.PostForm(srvURL+"/login/select", url.Values{
		"authRequestID": {authRequestID},
		"sub":           {"usr_alice"},
	})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	return sel
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	s = s[i+len(start):]
	before, _, ok := strings.Cut(s, end)
	if !ok {
		return ""
	}
	return before
}

func codeFrom(resp *http.Response) string {
	if loc := resp.Header.Get("Location"); loc != "" {
		if u, err := url.Parse(loc); err == nil {
			if c := u.Query().Get("code"); c != "" {
				return c
			}
		}
	}
	return resp.Request.URL.Query().Get("code")
}

// decodeJWTPayload unmarshals a JWT's payload segment without verification —
// these tests assert claim contents, not signatures.
func decodeJWTPayload(t *testing.T, raw string, into any) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %d segments", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, into); err != nil {
		t.Fatal(err)
	}
}

// audSlice normalises the aud claim, which JSON may carry as a string or an
// array of strings.
func audSlice(v any) []string {
	switch a := v.(type) {
	case string:
		return []string{a}
	case []any:
		out := make([]string, 0, len(a))
		for _, e := range a {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
