package config

import (
	"errors"
	"testing"
)

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

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
		{
			name: "empty persona token",
			cfg: &Config{Personas: []Persona{
				{Claims: map[string]any{"sub": "a"}, Tokens: []string{""}},
			}},
			wantErr: errEmptyToken,
		},
		{
			name: "duplicate token across personas",
			cfg: &Config{Personas: []Persona{
				{Claims: map[string]any{"sub": "a"}, Tokens: []string{"tok"}},
				{Claims: map[string]any{"sub": "b"}, Tokens: []string{"tok"}},
			}},
			wantErr: errDuplicateToken,
		},
		{
			name: "duplicate token within a persona",
			cfg: &Config{Personas: []Persona{
				{Claims: map[string]any{"sub": "a"}, Tokens: []string{"tok", "tok"}},
			}},
			wantErr: errDuplicateToken,
		},
		{
			name: "valid persona tokens",
			cfg: &Config{Personas: []Persona{
				{Claims: map[string]any{"sub": "a"}, Tokens: []string{"a-ci", "a-local"}},
				{Claims: map[string]any{"sub": "b"}, Tokens: []string{"b-ci"}},
			}},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

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

func TestConfig_Validate_BrowserURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  Config
		want error
	}{
		{"browser_url without issuer", Config{BrowserURL: "http://localhost:5556"}, errBrowserURLNeedsIssuer},
		{"browser_url with issuer", Config{Issuer: "http://hamnir:5556", BrowserURL: "http://localhost:5556"}, nil},
		{"invalid browser_url", Config{Issuer: "http://hamnir:5556", BrowserURL: "://nope"}, errInvalidURL},
		{"invalid issuer", Config{Issuer: "notaurl"}, errInvalidURL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := tt.cfg.Validate(); !errors.Is(err, tt.want) {
				t.Fatalf("Validate() = %v, want %v", err, tt.want)
			}
		})
	}
}
