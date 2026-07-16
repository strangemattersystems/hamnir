package command

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/strangemattersystems/hamnir/internal/provider"
)

// minimalConfig is the starter config written by Init. It lives as a real .yaml
// file so it validates against the schema in an editor while we maintain it,
// rather than as an escaped Go string literal.
//
//go:embed init_config.yaml
var minimalConfig string

// Init writes a minimal config and generates a fresh signing key, printing a
// line per created file to w. Unless force is set, it refuses (writing nothing)
// when either target already exists.
func Init(w io.Writer, configPath, keyPath string, force bool) error {
	if !force {
		var existing []string
		if _, err := os.Stat(configPath); err == nil {
			existing = append(existing, configPath)
		}
		if _, err := os.Stat(keyPath); err == nil {
			existing = append(existing, keyPath)
		}
		if len(existing) > 0 {
			return fmt.Errorf("already exists: %s (use --force to overwrite)", strings.Join(existing, ", "))
		}
	}

	if dir := filepath.Dir(configPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
	}
	if err := os.WriteFile(configPath, []byte(minimalConfig), 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Fprintln(w, "created", configPath)

	if _, err := provider.GenerateKey(keyPath); err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	fmt.Fprintln(w, "created", keyPath)
	return nil
}
