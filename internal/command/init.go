package command

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/strangemattersystems/hamnir/internal/config"
)

// minimalConfig is the starter config written by Init. It lives as a real .yaml
// file so it validates against the schema in an editor while we maintain it,
// rather than as an escaped Go string literal. Init substitutes
// signingKeyPlaceholder with a freshly generated key.
//
//go:embed init_config.yaml
var minimalConfig string

// signingKeyPlaceholder is the template's stand-in signing_key value; Init
// replaces it with a freshly generated key.
const signingKeyPlaceholder = "REPLACED-BY-HAMNIR-INIT"

// Init writes a minimal config containing a freshly generated signing key,
// printing a line for the created file to w. Unless force is set, it refuses
// (writing nothing) when the target already exists.
func Init(w io.Writer, configPath string, force bool) error {
	if !force {
		if _, err := os.Stat(configPath); err == nil {
			return fmt.Errorf("already exists: %s (use --force to overwrite)", configPath)
		}
	}

	placeholder := "signing_key: " + signingKeyPlaceholder
	if !strings.Contains(minimalConfig, placeholder) {
		return errors.New("embedded init_config.yaml is missing the signing_key placeholder")
	}
	key, err := config.GenerateSigningKey()
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}
	body := strings.Replace(minimalConfig, placeholder, "signing_key: "+key, 1)

	if dir := filepath.Dir(configPath); dir != "" {
		//nolint:gosec // G301: this holds dev-only persona config, not credentials.
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
	}
	//nolint:gosec // G306: hamnir.yaml is dev-only config; its signing key is deliberately non-secret.
	if err := os.WriteFile(configPath, []byte(body), 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	_, err = fmt.Fprintln(w, "created", configPath)
	return err
}
