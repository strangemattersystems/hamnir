package static

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/strangemattersystems/hamnir/internal/config"
)

const Root = "/.static/"

var (
	ErrUnresolved = errors.New("unresolved static reference")
	ErrNoBase     = errors.New("static reference needs issuer or browser_url")
)

func Base(cfg *config.Config) string {
	if cfg.BrowserURL != "" {
		return strings.TrimSuffix(cfg.BrowserURL, "/")
	}
	if cfg.Issuer != "" {
		return strings.TrimSuffix(cfg.Issuer, "/")
	}
	return ""
}

func RewriteClaims(cfg *config.Config, base string) error {
	prefix := cfg.Static.Prefix
	if prefix == "" {
		prefix = "hamnir://" // defensive: Load defaults this
	}
	var errs []error
	for i := range cfg.Personas {
		for k, v := range cfg.Personas[i].Claims {
			cfg.Personas[i].Claims[k] = rewriteValue(v, prefix, base, cfg.Static.Paths, &errs)
		}
	}
	return errors.Join(errs...)
}

func rewriteValue(v any, prefix, base string, paths map[string]string, errs *[]error) any {
	switch t := v.(type) {
	case string:
		if !strings.HasPrefix(t, prefix) {
			return t
		}
		url, err := resolve(t, prefix, base, paths)
		if err != nil {
			*errs = append(*errs, err)
			return t
		}
		return url
	case map[string]any:
		for k, e := range t {
			t[k] = rewriteValue(e, prefix, base, paths, errs)
		}
		return t
	case []any:
		for i, e := range t {
			t[i] = rewriteValue(e, prefix, base, paths, errs)
		}
		return t
	default:
		return v
	}
}

func resolve(value, prefix, base string, paths map[string]string) (string, error) {
	ref := strings.TrimPrefix(value, prefix)
	mount, rest, ok := strings.Cut(ref, "/")
	if !ok || mount == "" || rest == "" {
		return "", fmt.Errorf("%q: not <mount>/<file>: %w", value, ErrUnresolved)
	}
	if strings.Contains(rest, "..") {
		return "", fmt.Errorf("%q: path traversal: %w", value, ErrUnresolved)
	}
	dir, ok := paths[mount]
	if !ok {
		return "", fmt.Errorf("%q: unknown mount %q: %w", value, mount, ErrUnresolved)
	}
	if base == "" {
		return "", fmt.Errorf("%q: %w", value, ErrNoBase)
	}
	info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rest)))
	if err != nil || info.IsDir() {
		return "", fmt.Errorf("%q: file not found under %q: %w", value, dir, ErrUnresolved)
	}
	return base + Root + mount + "/" + rest, nil
}

func Register(mux *http.ServeMux, paths map[string]string) {
	for mount, dir := range paths {
		p := Root + mount + "/"
		mux.Handle(p, noDirList(http.StripPrefix(p, http.FileServer(http.Dir(dir)))))
	}
}

func noDirList(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}
