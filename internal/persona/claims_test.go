package persona

import (
	"reflect"
	"testing"
)

func TestReleaseClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		claims   map[string]any
		scopes   []string
		scopeMap map[string][]string
		want     map[string]any
	}{
		{
			name:   "standard claims gated by scope",
			claims: map[string]any{"sub": "s", "email": "e", "email_verified": true, "name": "N"},
			scopes: []string{"openid", "email"},
			want:   map[string]any{"sub": "s", "email": "e", "email_verified": true},
		},
		{
			name:   "profile scope releases profile claims",
			claims: map[string]any{"sub": "s", "name": "N", "picture": "p"},
			scopes: []string{"openid", "profile"},
			want:   map[string]any{"sub": "s", "name": "N", "picture": "p"},
		},
		{
			name:   "custom claims included by default",
			claims: map[string]any{"sub": "s", "roles": []any{"coach"}, "tenant": "t"},
			scopes: []string{"openid"},
			want:   map[string]any{"sub": "s", "roles": []any{"coach"}, "tenant": "t"},
		},
		{
			name:     "custom claim withheld without its scope",
			claims:   map[string]any{"sub": "s", "roles": []any{"coach"}},
			scopes:   []string{"openid"},
			scopeMap: map[string][]string{"roles": {"roles"}},
			want:     map[string]any{"sub": "s"},
		},
		{
			name:     "custom claim released with its scope",
			claims:   map[string]any{"sub": "s", "roles": []any{"coach"}},
			scopes:   []string{"openid", "roles"},
			scopeMap: map[string][]string{"roles": {"roles"}},
			want:     map[string]any{"sub": "s", "roles": []any{"coach"}},
		},
		{
			name:     "scopeMap cannot grant a standard claim",
			claims:   map[string]any{"sub": "s", "email": "e"},
			scopes:   []string{"openid", "grant-email"},
			scopeMap: map[string][]string{"grant-email": {"email"}},
			want:     map[string]any{"sub": "s"},
		},
		{
			name:     "custom claim released when any gating scope is requested",
			claims:   map[string]any{"sub": "s", "roles": []any{"coach"}},
			scopes:   []string{"openid", "team"},
			scopeMap: map[string][]string{"admin": {"roles"}, "team": {"roles"}},
			want:     map[string]any{"sub": "s", "roles": []any{"coach"}},
		},
		{
			name:   "nil claims yields empty map",
			claims: nil,
			scopes: []string{"openid", "profile"},
			want:   map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ReleaseClaims(tt.claims, tt.scopes, tt.scopeMap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ReleaseClaims() = %v, want %v", got, tt.want)
			}
		})
	}
}
