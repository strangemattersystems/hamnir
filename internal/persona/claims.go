package persona

// standardScopeClaims maps each OIDC standard scope to the claims it releases,
// per OpenID Connect Core section 5.4.
var standardScopeClaims = map[string][]string{
	"profile": {
		"name", "family_name", "given_name", "middle_name", "nickname",
		"preferred_username", "profile", "picture", "website", "gender",
		"birthdate", "zoneinfo", "locale", "updated_at",
	},
	"email":   {"email", "email_verified"},
	"phone":   {"phone_number", "phone_number_verified"},
	"address": {"address"},
}

// standardClaims is the set of all OIDC standard claims (including sub), used to
// distinguish them from custom claims during release.
var standardClaims = func() map[string]bool {
	s := map[string]bool{"sub": true}
	for _, cs := range standardScopeClaims {
		for _, c := range cs {
			s[c] = true
		}
	}
	return s
}()

// ReleaseClaims returns the subset of claims that requestedScopes permit a
// client to receive. Standard OIDC claims are released only when the scope that
// governs them is requested; sub is always released. Custom claims named in
// scopeMap are gated behind their scope, while a custom claim absent from
// scopeMap is always released. Standard claims are matched first, so a scopeMap
// entry naming a standard claim has no effect.
func ReleaseClaims(claims map[string]any, requestedScopes []string, scopeMap map[string][]string) map[string]any {
	scopeSet := map[string]bool{}
	for _, s := range requestedScopes {
		scopeSet[s] = true
	}

	// Which standard claims are allowed by the requested scopes.
	allowedStandard := map[string]bool{"sub": true}
	for scope, cs := range standardScopeClaims {
		if scopeSet[scope] {
			for _, c := range cs {
				allowedStandard[c] = true
			}
		}
	}

	// Custom claims that are gated behind a named scope.
	gatedClaim := map[string]bool{}
	claimAllowedByMap := map[string]bool{}
	for scope, cs := range scopeMap {
		for _, c := range cs {
			gatedClaim[c] = true
			if scopeSet[scope] {
				claimAllowedByMap[c] = true
			}
		}
	}

	out := map[string]any{}
	for k, v := range claims {
		switch {
		case standardClaims[k]:
			if allowedStandard[k] {
				out[k] = v
			}
		case gatedClaim[k]:
			if claimAllowedByMap[k] {
				out[k] = v
			}
		default:
			out[k] = v // custom, not gated claims are always included
		}
	}
	return out
}
