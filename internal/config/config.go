// Package config loads, normalises, and validates the hamnir server
// configuration from YAML into a [Config] ready for the rest of the server.
package config

import (
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

// Config is the fully parsed server configuration. A Config returned by [Load]
// has been normalised and validated, its signing key decoded into Key, and its
// static claim references resolved to absolute URLs.
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

// Static configures serving of persona assets. Prefix is the claim-value marker
// (default "hamnir://") that [Load] rewrites to absolute URLs, and Paths maps
// each mount name to a local directory.
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

// Client is a registered OAuth client. With no clients configured hamnir runs
// permissively, fabricating a client from each request instead.
type Client struct {
	ID                     string   `yaml:"id"`
	RedirectURIs           []string `yaml:"redirect_uris"`
	PostLogoutRedirectURIs []string `yaml:"post_logout_redirect_uris"`
	Secret                 string   `yaml:"secret"`
	Audiences              []string `yaml:"audiences"`
}

// Group labels and colours a set of personas in the picker UI.
type Group struct {
	ID     string `yaml:"id"`
	Label  string `yaml:"label"`
	Colour string `yaml:"colour"`
}

// Persona is a selectable test identity. Its Claims supply the identity's OIDC
// claims, released into tokens subject to the requested scopes. Tokens are
// optional static secrets exchangeable for real tokens via the RFC 8693 token
// exchange grant.
type Persona struct {
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	Group       string         `yaml:"group"`
	Claims      map[string]any `yaml:"claims"`
	Tokens      []string       `yaml:"tokens"`
}

// Load reads the YAML config at path and returns a ready-to-use [Config]. It
// parses with unknown fields rejected, normalises URLs and static mounts,
// validates the result, decodes the signing key, and resolves hamnir:// static
// claim references, so a nil error guarantees a fully usable config.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.UnmarshalWithOptions(raw, &cfg, yaml.DisallowUnknownField()); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}
	if err := cfg.normalise(filepath.Dir(path)); err != nil {
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
// collapse), relative mount dirs are anchored to the config file's directory
// (baseDir) so they mean the same thing wherever the process starts, and the
// substitution prefix gets its default. Everything downstream of Load can
// rely on these forms.
func (c *Config) normalise(baseDir string) error {
	c.Issuer = strings.TrimSuffix(c.Issuer, "/")
	c.BrowserURL = strings.TrimSuffix(c.BrowserURL, "/")
	if len(c.Static.Paths) > 0 {
		norm := make(map[string]string, len(c.Static.Paths))
		for k, v := range c.Static.Paths {
			mount := strings.TrimPrefix(k, "/")
			if _, exists := norm[mount]; exists {
				return fmt.Errorf("static mount %q: %w", mount, errDuplicateStaticMount)
			}
			// Empty dirs stay empty so Validate can reject them.
			if v != "" && !filepath.IsAbs(v) {
				v = filepath.Join(baseDir, v)
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
