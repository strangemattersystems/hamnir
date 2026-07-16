package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/strangemattersystems/hamnir/internal/static"
)

var (
	ErrUnresolved = errors.New("unresolved static reference")
	ErrNoBase     = errors.New("static reference needs issuer or browser_url")
)

// baseURL is the browser-facing base against which static references resolve:
// browser_url when set, otherwise the issuer. Empty in dynamic-issuer mode.
func (c *Config) baseURL() string {
	if c.BrowserURL != "" {
		return c.BrowserURL
	}
	return c.Issuer
}

// resolveStaticClaims rewrites every persona claim value carrying the static
// prefix (e.g. "hamnir://avatars/eve.svg") to an absolute URL under the
// browser-facing base, verifying the mount is configured and the referenced
// file exists on disk. It runs as part of Load so that a config that loads
// cleanly is guaranteed to have no dangling static references.
func (c *Config) resolveStaticClaims() error {
	var errs []error
	for i := range c.Personas {
		for k, v := range c.Personas[i].Claims {
			c.Personas[i].Claims[k] = c.rewriteValue(v, &errs)
		}
	}
	return errors.Join(errs...)
}

func (c *Config) rewriteValue(v any, errs *[]error) any {
	switch t := v.(type) {
	case string:
		if !strings.HasPrefix(t, c.Static.Prefix) {
			return t
		}
		url, err := c.resolveRef(t)
		if err != nil {
			*errs = append(*errs, err)
			return t
		}
		return url
	case map[string]any:
		for k, e := range t {
			t[k] = c.rewriteValue(e, errs)
		}
		return t
	case []any:
		for i, e := range t {
			t[i] = c.rewriteValue(e, errs)
		}
		return t
	default:
		return v
	}
}

func (c *Config) resolveRef(value string) (string, error) {
	ref := strings.TrimPrefix(value, c.Static.Prefix)
	mount, rest, ok := strings.Cut(ref, "/")
	if !ok || mount == "" || rest == "" {
		return "", fmt.Errorf("%q: not <mount>/<file>: %w", value, ErrUnresolved)
	}
	if strings.Contains(rest, "..") {
		return "", fmt.Errorf("%q: path traversal: %w", value, ErrUnresolved)
	}
	dir, ok := c.Static.Paths[mount]
	if !ok {
		return "", fmt.Errorf("%q: unknown mount %q: %w", value, mount, ErrUnresolved)
	}
	base := c.baseURL()
	if base == "" {
		return "", fmt.Errorf("%q: %w", value, ErrNoBase)
	}
	info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rest)))
	if err != nil || info.IsDir() {
		return "", fmt.Errorf("%q: file not found under %q: %w", value, dir, ErrUnresolved)
	}
	return base + static.Root + mount + "/" + rest, nil
}
