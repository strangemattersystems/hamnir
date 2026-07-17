// Package persona indexes the configured [config.Persona] values for lookup and
// presentation, and derives the claims released to a client for a set of scopes.
package persona

import (
	"iter"
	"slices"

	"github.com/strangemattersystems/hamnir/internal/config"
)

// Set is a read-only index over the configured [config.Persona] values, built
// once at startup and safe for concurrent use.
type Set struct {
	bySub map[string]config.Persona
	all   []config.Persona
}

// NewSet indexes cfg's personas by their sub claim. When two share a sub the
// last wins; config validation rejects missing and duplicate subs, so a
// validated config never reaches that case.
func NewSet(cfg *config.Config) *Set {
	s := &Set{
		bySub: make(map[string]config.Persona, len(cfg.Personas)),
		all:   cfg.Personas,
	}
	for _, p := range cfg.Personas {
		sub, _ := p.Claims["sub"].(string)
		s.bySub[sub] = p
	}
	return s
}

// BySub returns the persona indexed under sub.
func (s *Set) BySub(sub string) (config.Persona, bool) {
	p, ok := s.bySub[sub]
	return p, ok
}

// All yields the configured personas in declaration order.
func (s *Set) All() iter.Seq[config.Persona] {
	return slices.Values(s.all)
}

// DisplayName returns a display label for p: its explicit Name if set,
// otherwise the first non-empty name, email, or sub claim, or "" if none is set.
func DisplayName(p config.Persona) string {
	if p.Name != "" {
		return p.Name
	}
	for _, key := range []string{"name", "email", "sub"} {
		if v, ok := p.Claims[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
