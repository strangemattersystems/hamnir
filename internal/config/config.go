package config

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
)

type Config struct {
	Issuer     string              `yaml:"issuer"`
	BrowserURL string              `yaml:"browser_url"`
	Clients    []Client            `yaml:"clients"`
	Groups     []Group             `yaml:"groups"`
	Scopes     map[string][]string `yaml:"scopes"`
	Personas   []Persona           `yaml:"personas"`
}

type Client struct {
	ID                     string   `yaml:"id"`
	RedirectURIs           []string `yaml:"redirect_uris"`
	PostLogoutRedirectURIs []string `yaml:"post_logout_redirect_uris"`
	Secret                 string   `yaml:"secret"`
}

type Group struct {
	ID     string `yaml:"id"`
	Label  string `yaml:"label"`
	Colour string `yaml:"colour"`
}

type Persona struct {
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	Group       string         `yaml:"group"`
	Claims      map[string]any `yaml:"claims"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.UnmarshalWithOptions(raw, &cfg, yaml.DisallowUnknownField()); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %q: %w", path, err)
	}
	return &cfg, nil
}
