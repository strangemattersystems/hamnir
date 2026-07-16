package persona

import "github.com/strangemattersystems/hamnir/internal/config"

type Set struct {
	bySub map[string]config.Persona
	all   []config.Persona
}

func NewSet(cfg *config.Config) *Set {
	s := &Set{
		bySub: make(map[string]config.Persona, len(cfg.Personas)),
		all:   make([]config.Persona, 0, len(cfg.Personas)),
	}
	for _, p := range cfg.Personas {
		sub, _ := p.Claims["sub"].(string)
		s.bySub[sub] = p
		s.all = append(s.all, p)
	}
	return s
}

func (s *Set) BySub(sub string) (config.Persona, bool) {
	p, ok := s.bySub[sub]
	return p, ok
}

func (s *Set) All() []config.Persona {
	return s.all
}

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
