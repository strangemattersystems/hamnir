package config

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
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
	errNoRedirectURIs        = errors.New("client has no redirect_uris")
)

var hexColour = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

func (c *Config) Validate() error {
	clientIDs := map[string]bool{}
	for i, cl := range c.Clients {
		if cl.ID == "" {
			return fmt.Errorf("client #%d: %w", i+1, errEmptyClientID)
		}
		if clientIDs[cl.ID] {
			return fmt.Errorf("client %q: %w", cl.ID, errDuplicateClientID)
		}
		clientIDs[cl.ID] = true
		if len(cl.RedirectURIs) == 0 {
			return fmt.Errorf("client %q: %w", cl.ID, errNoRedirectURIs)
		}
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

func validateURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errInvalidURL
	}
	return nil
}
