package persona

import (
	"testing"

	"github.com/strangemattersystems/hamnir/internal/config"
)

func TestDisplayName(t *testing.T) {
	tests := []struct {
		name string
		p    config.Persona
		want string
	}{
		{"explicit name", config.Persona{Name: "Alice", Claims: map[string]any{"sub": "s", "name": "N"}}, "Alice"},
		{"falls back to claims name", config.Persona{Claims: map[string]any{"sub": "s", "name": "N", "email": "e"}}, "N"},
		{"falls back to email", config.Persona{Claims: map[string]any{"sub": "s", "email": "e"}}, "e"},
		{"falls back to sub", config.Persona{Claims: map[string]any{"sub": "s"}}, "s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DisplayName(tt.p); got != tt.want {
				t.Fatalf("DisplayName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSet_BySub(t *testing.T) {
	cfg := &config.Config{Personas: []config.Persona{
		{Claims: map[string]any{"sub": "usr_alice"}},
	}}
	set := NewSet(cfg)

	t.Run("found", func(t *testing.T) {
		if _, ok := set.BySub("usr_alice"); !ok {
			t.Fatal("expected to find usr_alice")
		}
	})
	t.Run("not found", func(t *testing.T) {
		if _, ok := set.BySub("nope"); ok {
			t.Fatal("did not expect to find nope")
		}
	})
}
