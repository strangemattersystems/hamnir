package persona

import (
	"slices"
	"testing"

	"github.com/strangemattersystems/hamnir/internal/config"
)

func TestDisplayName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		p    config.Persona
		want string
	}{
		{"explicit name", config.Persona{Name: "Alice", Claims: map[string]any{"sub": "s", "name": "N"}}, "Alice"},
		{"falls back to claims name", config.Persona{Claims: map[string]any{"sub": "s", "name": "N", "email": "e"}}, "N"},
		{"falls back to email", config.Persona{Claims: map[string]any{"sub": "s", "email": "e"}}, "e"},
		{"falls back to sub", config.Persona{Claims: map[string]any{"sub": "s"}}, "s"},
		{"skips empty claim value", config.Persona{Claims: map[string]any{"name": "", "email": "e"}}, "e"},
		{"skips non-string claim", config.Persona{Claims: map[string]any{"name": 123, "email": "e"}}, "e"},
		{"empty when no name and no fallback claims", config.Persona{Claims: map[string]any{"role": "admin"}}, ""},
		{"empty when claims nil", config.Persona{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := DisplayName(tt.p); got != tt.want {
				t.Fatalf("DisplayName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		personas []config.Persona
		lookup   string
		wantName string
	}{
		{
			// NewSet does not itself reject duplicate subs — config validation
			// does — so pin the constructor's behaviour: the last persona wins.
			name: "duplicate sub, last wins",
			personas: []config.Persona{
				{Name: "First", Claims: map[string]any{"sub": "dup"}},
				{Name: "Second", Claims: map[string]any{"sub": "dup"}},
			},
			lookup:   "dup",
			wantName: "Second",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			set := NewSet(&config.Config{Personas: tt.personas})
			p, ok := set.BySub(tt.lookup)
			if !ok {
				t.Fatalf("BySub(%q): expected to find persona", tt.lookup)
			}
			if p.Name != tt.wantName {
				t.Fatalf("BySub(%q).Name = %q, want %q", tt.lookup, p.Name, tt.wantName)
			}
		})
	}
}

func TestSet_BySub(t *testing.T) {
	t.Parallel()

	set := NewSet(&config.Config{Personas: []config.Persona{
		{Claims: map[string]any{"sub": "usr_alice"}},
		{Claims: map[string]any{"sub": "usr_bob"}},
	}})
	tests := []struct {
		name   string
		sub    string
		wantOK bool
	}{
		{"found", "usr_alice", true},
		{"found other", "usr_bob", true},
		{"not found", "nope", false},
		{"empty sub", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, ok := set.BySub(tt.sub); ok != tt.wantOK {
				t.Fatalf("BySub(%q) ok = %v, want %v", tt.sub, ok, tt.wantOK)
			}
		})
	}
}

func TestSet_All(t *testing.T) {
	t.Parallel()

	set := NewSet(&config.Config{Personas: []config.Persona{
		{Name: "Alice", Claims: map[string]any{"sub": "a"}},
		{Name: "Bob", Claims: map[string]any{"sub": "b"}},
	}})

	var names []string
	for p := range set.All() {
		names = append(names, p.Name)
	}
	if want := []string{"Alice", "Bob"}; !slices.Equal(names, want) {
		t.Fatalf("All() names = %v, want declaration order %v", names, want)
	}
}
