package provider

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestObserveClientPresentation(t *testing.T) {
	t.Parallel()

	observe := func(r *http.Request) (presentation, int) {
		var p presentation
		reached := false
		h := ObserveClientPresentation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			p = presentationFrom(r.Context())
		}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if !reached {
			return presentation{}, rec.Code
		}
		return p, rec.Code
	}

	t.Run("secret in body", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("client_secret=s3cret"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if p, _ := observe(r); !p.clientSecret {
			t.Fatal("body client_secret should be observed")
		}
	})

	t.Run("secret in query", func(t *testing.T) {
		t.Parallel()

		// Non-compliant but op decodes the merged form, so the middleware
		// must see what op sees.
		r := httptest.NewRequest(http.MethodPost, "/oauth/token?client_secret=s3cret", strings.NewReader("grant_type=authorization_code"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if p, _ := observe(r); !p.clientSecret {
			t.Fatal("query client_secret should be observed — op reads the merged form")
		}
	})

	t.Run("empty basic password is not a secret", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=authorization_code"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth("client", "")
		if p, _ := observe(r); p.clientSecret {
			t.Fatal("an empty Basic password is not authentication")
		}
	})

	t.Run("malformed body answered with 400", func(t *testing.T) {
		t.Parallel()

		// If the middleware merely swallowed the ParseForm error, the cached
		// partial form would also skip op's own parse-error response.
		r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("a=%zz"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if _, code := observe(r); code != http.StatusBadRequest {
			t.Fatalf("malformed form should be rejected with 400, got %d", code)
		}
	})
}
