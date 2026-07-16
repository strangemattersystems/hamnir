package config

import (
	"errors"
	"testing"
)

func TestValidateDuplicateSub(t *testing.T) {
	cfg := &Config{Personas: []Persona{
		{Claims: map[string]any{"sub": "dup"}},
		{Claims: map[string]any{"sub": "dup"}},
	}}
	if err := cfg.Validate(); !errors.Is(err, errDuplicateSub) {
		t.Fatalf("want errDuplicateSub, got %v", err)
	}
}

func TestValidateBadColour(t *testing.T) {
	cfg := &Config{
		Groups:   []Group{{ID: "g1", Colour: "red"}},
		Personas: []Persona{{Claims: map[string]any{"sub": "a"}}},
	}
	if err := cfg.Validate(); !errors.Is(err, errInvalidColour) {
		t.Fatalf("want errInvalidColour, got %v", err)
	}
}

func TestValidateUnknownGroup(t *testing.T) {
	cfg := &Config{Personas: []Persona{
		{Group: "nope", Claims: map[string]any{"sub": "a"}},
	}}
	if err := cfg.Validate(); !errors.Is(err, errUnknownGroup) {
		t.Fatalf("want errUnknownGroup, got %v", err)
	}
}

func TestValidateMissingSub(t *testing.T) {
	cfg := &Config{Personas: []Persona{
		{Claims: map[string]any{"email": "a@b.test"}},
	}}
	if err := cfg.Validate(); !errors.Is(err, errMissingSub) {
		t.Fatalf("want errMissingSub, got %v", err)
	}
}

func TestValidateOK(t *testing.T) {
	cfg := &Config{
		Groups:   []Group{{ID: "g1", Colour: "#3fb950"}},
		Personas: []Persona{{Group: "g1", Claims: map[string]any{"sub": "a"}}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRunsValidation(t *testing.T) {
	p := writeTemp(t, `
personas:
  - claims: { sub: dup }
  - claims: { sub: dup }
`)
	if _, err := Load(p); !errors.Is(err, errDuplicateSub) {
		t.Fatalf("want Load to surface errDuplicateSub, got %v", err)
	}
}
