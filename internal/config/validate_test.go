package config

import (
	"errors"
	"testing"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr error // nil means the config is expected to be valid
	}{
		{
			name: "duplicate sub",
			cfg: &Config{Personas: []Persona{
				{Claims: map[string]any{"sub": "dup"}},
				{Claims: map[string]any{"sub": "dup"}},
			}},
			wantErr: errDuplicateSub,
		},
		{
			name: "bad colour",
			cfg: &Config{
				Groups:   []Group{{ID: "g1", Colour: "red"}},
				Personas: []Persona{{Claims: map[string]any{"sub": "a"}}},
			},
			wantErr: errInvalidColour,
		},
		{
			name: "unknown group",
			cfg: &Config{Personas: []Persona{
				{Group: "nope", Claims: map[string]any{"sub": "a"}},
			}},
			wantErr: errUnknownGroup,
		},
		{
			name: "missing sub",
			cfg: &Config{Personas: []Persona{
				{Claims: map[string]any{"email": "a@b.test"}},
			}},
			wantErr: errMissingSub,
		},
		{
			name:    "empty group id",
			cfg:     &Config{Groups: []Group{{ID: ""}}},
			wantErr: errEmptyGroupID,
		},
		{
			name: "valid",
			cfg: &Config{
				Groups:   []Group{{ID: "g1", Colour: "#3fb950"}},
				Personas: []Persona{{Group: "g1", Claims: map[string]any{"sub": "a"}}},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
