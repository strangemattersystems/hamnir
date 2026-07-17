package config

import (
	"crypto/rsa"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

type Config struct {
	Issuer     string              `yaml:"issuer"`
	BrowserURL string              `yaml:"browser_url"`
	Clients    []Client            `yaml:"clients"`
	Groups     []Group             `yaml:"groups"`
	Scopes     map[string][]string `yaml:"scopes"`
	Audiences  []string            `yaml:"audiences"`
	Personas   []Persona           `yaml:"personas"`
	Static     Static              `yaml:"static"`
	Lifetimes  Lifetimes           `yaml:"lifetimes"`
	SigningKey string              `yaml:"signing_key"`

	// Key is SigningKey decoded, populated by Load. Never serialised.
	Key *rsa.PrivateKey `yaml:"-"`
}

type Static struct {
	Prefix string            `yaml:"prefix"`
	Paths  map[string]string `yaml:"paths"`
}

// Lifetimes configures how long issued tokens live, as Go duration strings in
// YAML ("90s", "5m", "24h"). Fields left at zero take their DefaultLifetimes
// value during Load; explicit values must be positive.
type Lifetimes struct {
	AccessToken  time.Duration `yaml:"access_token"`
	IDToken      time.Duration `yaml:"id_token"`
	RefreshToken time.Duration `yaml:"refresh_token"`
}

// DefaultLifetimes are the token lifetimes used for fields the config omits.
var DefaultLifetimes = Lifetimes{
	AccessToken:  5 * time.Minute,
	IDToken:      time.Hour,
	RefreshToken: 24 * time.Hour,
}

type Client struct {
	ID                     string   `yaml:"id"`
	RedirectURIs           []string `yaml:"redirect_uris"`
	PostLogoutRedirectURIs []string `yaml:"post_logout_redirect_uris"`
	Secret                 string   `yaml:"secret"`
	Audiences              []string `yaml:"audiences"`
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
	if err := cfg.normalise(); err != nil {
		return nil, fmt.Errorf("invalid config %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %q: %w", path, err)
	}
	if err := cfg.parseSigningKey(); err != nil {
		return nil, fmt.Errorf("invalid config %q: %w", path, err)
	}
	if err := cfg.resolveStaticClaims(); err != nil {
		return nil, fmt.Errorf("invalid config %q: %w", path, err)
	}
	return &cfg, nil
}

// normalise canonicalises the parsed config: the base URLs lose a trailing
// "/", each static mount key loses a single leading "/" (so "/avatars" and
// "avatars" are equivalent — configuring both is an error, not a silent
// collapse), and the substitution prefix gets its default. Everything
// downstream of Load can rely on these forms.
func (c *Config) normalise() error {
	c.Issuer = strings.TrimSuffix(c.Issuer, "/")
	c.BrowserURL = strings.TrimSuffix(c.BrowserURL, "/")
	if len(c.Static.Paths) > 0 {
		norm := make(map[string]string, len(c.Static.Paths))
		for k, v := range c.Static.Paths {
			mount := strings.TrimPrefix(k, "/")
			if _, exists := norm[mount]; exists {
				return fmt.Errorf("static mount %q: %w", mount, errDuplicateStaticMount)
			}
			norm[mount] = v
		}
		c.Static.Paths = norm
	}
	if c.Static.Prefix == "" {
		c.Static.Prefix = "hamnir://"
	}
	if c.Lifetimes.AccessToken == 0 {
		c.Lifetimes.AccessToken = DefaultLifetimes.AccessToken
	}
	if c.Lifetimes.IDToken == 0 {
		c.Lifetimes.IDToken = DefaultLifetimes.IDToken
	}
	if c.Lifetimes.RefreshToken == 0 {
		c.Lifetimes.RefreshToken = DefaultLifetimes.RefreshToken
	}
	return nil
}
