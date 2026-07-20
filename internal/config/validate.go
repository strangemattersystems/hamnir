package config

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	errEmptyGroupID          = errors.New("empty group id")
	errInvalidColour         = errors.New("invalid hex colour")
	errMissingSub            = errors.New("missing sub claim")
	errDuplicateSub          = errors.New("duplicate sub")
	errUnknownGroup          = errors.New("unknown group reference")
	errBrowserURLNeedsIssuer = errors.New("browser_url requires a static issuer")
	errInvalidURL            = errors.New("invalid url")
	errEmptyStaticMount      = errors.New("empty static mount")
	errStaticMountTraversal  = errors.New(".. is not allowed in a mount name")
	errStaticMountSlash      = errors.New("\"/\" is not allowed in a mount name")
	errEmptyStaticDir        = errors.New("empty static directory")
	errDuplicateStaticMount  = errors.New("duplicate static mount")
	errEmptyClientID         = errors.New("empty client id")
	errDuplicateClientID     = errors.New("duplicate client id")
	errNegativeLifetime      = errors.New("negative lifetime")
	errEmptyAudience         = errors.New("empty audience")
	errDuplicateAudience     = errors.New("duplicate audience")
	errEmptyToken            = errors.New("empty persona token")
	errDuplicateToken        = errors.New("duplicate persona token")
)

var hexColour = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

// Validate checks the config's invariants: unique non-empty client ids, each
// persona a unique non-empty sub, persona tokens non-empty and unique across
// the config, known group references, well-formed colours and URLs,
// non-negative lifetimes, valid static mounts, and audience lists free of
// empty or duplicate entries. It runs as part of [Load].
func (c *Config) Validate() error {
	// Redirect URIs are deliberately NOT required: a back-channel-only client
	// (introspection/revocation) authenticates with id + secret and never
	// performs a redirect flow.
	clientIDs := map[string]bool{}
	for i, cl := range c.Clients {
		if cl.ID == "" {
			return fmt.Errorf("client #%d: %w", i+1, errEmptyClientID)
		}
		if clientIDs[cl.ID] {
			return fmt.Errorf("client %q: %w", cl.ID, errDuplicateClientID)
		}
		clientIDs[cl.ID] = true
		if err := validateAudiences(cl.Audiences); err != nil {
			return fmt.Errorf("client %q: audiences: %w", cl.ID, err)
		}
	}

	if err := validateAudiences(c.Audiences); err != nil {
		return fmt.Errorf("audiences: %w", err)
	}

	groupIDs := map[string]bool{}
	for i, g := range c.Groups {
		if g.ID == "" {
			return fmt.Errorf("group #%d: %w", i+1, errEmptyGroupID)
		}
		if g.Colour != "" && !hexColour.MatchString(g.Colour) {
			return fmt.Errorf("group %q: colour %q: %w", g.ID, g.Colour, errInvalidColour)
		}
		groupIDs[g.ID] = true
	}

	seenSub := map[string]bool{}
	seenToken := map[string]bool{}
	for i, p := range c.Personas {
		sub, _ := p.Claims["sub"].(string)
		if sub == "" {
			return fmt.Errorf("persona #%d: %w", i+1, errMissingSub)
		}
		if seenSub[sub] {
			return fmt.Errorf("sub %q: %w", sub, errDuplicateSub)
		}
		seenSub[sub] = true
		if p.Group != "" && !groupIDs[p.Group] {
			return fmt.Errorf("persona %q: group %q: %w", sub, p.Group, errUnknownGroup)
		}
		for _, tok := range p.Tokens {
			if tok == "" {
				return fmt.Errorf("persona %q: %w", sub, errEmptyToken)
			}
			if seenToken[tok] {
				return fmt.Errorf("persona %q: token %q: %w", sub, tok, errDuplicateToken)
			}
			seenToken[tok] = true
		}
	}

	if c.Issuer != "" {
		if err := validateURL(c.Issuer); err != nil {
			return fmt.Errorf("issuer %q: %w", c.Issuer, err)
		}
	}
	if c.BrowserURL != "" {
		if c.Issuer == "" {
			return errBrowserURLNeedsIssuer
		}
		if err := validateURL(c.BrowserURL); err != nil {
			return fmt.Errorf("browser_url %q: %w", c.BrowserURL, err)
		}
	}

	// Zero means "unset" (normalise fills in the default during Load), so
	// only explicitly negative values are rejected here.
	lifetimes := []struct {
		name string
		d    time.Duration
	}{
		{"access_token", c.Lifetimes.AccessToken},
		{"id_token", c.Lifetimes.IDToken},
		{"refresh_token", c.Lifetimes.RefreshToken},
	}
	for _, l := range lifetimes {
		if l.d < 0 {
			return fmt.Errorf("lifetimes.%s: %w", l.name, errNegativeLifetime)
		}
	}

	for mount, dir := range c.Static.Paths {
		if mount == "" {
			return errEmptyStaticMount
		}
		if strings.Contains(mount, "..") {
			return fmt.Errorf("static mount %q: %w", mount, errStaticMountTraversal)
		}
		// Claim references are split at the first "/" (<mount>/<file>), so a
		// mount name containing one would be servable yet unreferenceable.
		if strings.Contains(mount, "/") {
			return fmt.Errorf("static mount %q: %w", mount, errStaticMountSlash)
		}
		if dir == "" {
			return fmt.Errorf("static mount %q: %w", mount, errEmptyStaticDir)
		}
	}

	return nil
}

func validateAudiences(list []string) error {
	seen := map[string]bool{}
	for _, a := range list {
		if a == "" {
			return errEmptyAudience
		}
		if seen[a] {
			return fmt.Errorf("%q: %w", a, errDuplicateAudience)
		}
		seen[a] = true
	}
	return nil
}

func validateURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errInvalidURL
	}
	return nil
}
