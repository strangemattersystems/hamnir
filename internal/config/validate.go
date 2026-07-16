package config

import (
	"errors"
	"fmt"
	"regexp"
)

var (
	errEmptyGroupID  = errors.New("empty group id")
	errInvalidColour = errors.New("invalid hex colour")
	errMissingSub    = errors.New("missing sub claim")
	errDuplicateSub  = errors.New("duplicate sub")
	errUnknownGroup  = errors.New("unknown group reference")
)

var hexColour = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

func (c *Config) Validate() error {
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
	return nil
}
