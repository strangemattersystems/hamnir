package provider

import (
	"context"
	"net/http"
)

// presentation captures how the relying party presented itself on the current
// request. Permissive mode fabricates a client per request, and zitadel's op
// branches purely on the client's declared properties — so the fabricated
// client must mirror the RP's actual choices: whether it authenticated with a
// client secret at the token endpoint, and which post-logout redirect it asked
// for at end_session.
type presentation struct {
	clientSecret          bool
	postLogoutRedirectURI string
}

type presentationKey struct{}

// ObserveClientPresentation records the RP's presentation into the request
// context before the op handler runs, so GetClientByClientID can shape the
// permissive client to match. Parsing the form here is safe: ParseForm is
// idempotent and op re-parses from the cached form values.
func ObserveClientPresentation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Answer parse failures here: net/http caches the partial form but not
		// the error, so op's own ParseForm would succeed and skip its
		// "error parsing form" response, surfacing misleading errors instead.
		if err := r.ParseForm(); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"error parsing form"}`))
			return
		}
		var p presentation
		// An empty Basic password is not authentication: oauth2 client libraries
		// send the header even for secretless public clients.
		if _, secret, ok := r.BasicAuth(); ok && secret != "" {
			p.clientSecret = true
		}
		// Read the merged form (query + body) — op decodes from r.Form, and the
		// permissive client must be shaped by what op will actually see.
		if r.Form.Get("client_secret") != "" {
			p.clientSecret = true
		}
		p.postLogoutRedirectURI = r.Form.Get("post_logout_redirect_uri")
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), presentationKey{}, p)))
	})
}

func presentationFrom(ctx context.Context) presentation {
	p, _ := ctx.Value(presentationKey{}).(presentation)
	return p
}
