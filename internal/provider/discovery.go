package provider

import (
	"net/http"
	"slices"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Discovery serves the OIDC discovery document. It mirrors op's own handler
// (op.discoveryHandler: Discover over CreateDiscoveryConfig with the issuer
// from context) but corrects the advertised response and grant types where
// op hardcodes support hamnir does not have (op/discovery.go, "TODO: ok for
// now" upstream; GrantTypeJWTAuthorizationSupported is unconditionally true):
//   - implicit response types and grant — hamnir is deliberately
//     authorization-code only; OAuth 2.1 removes the implicit grant and
//     RFC 9700 forbids it;
//   - the RFC 7523 jwt-bearer grant — hamnir's JWT-profile storage methods
//     are errNotSupported stubs, so the grant can never succeed.
func Discovery(p *op.Provider, s *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := op.ContextWithIssuer(r.Context(), p.IssuerFromRequest(r))
		disc := op.CreateDiscoveryConfig(ctx, p, s)
		disc.ResponseTypesSupported = []string{string(oidc.ResponseTypeCode)}
		disc.GrantTypesSupported = slices.DeleteFunc(disc.GrantTypesSupported,
			func(g oidc.GrantType) bool {
				return g == oidc.GrantTypeImplicit || g == oidc.GrantTypeBearer
			})
		op.Discover(w, disc)
	}
}
