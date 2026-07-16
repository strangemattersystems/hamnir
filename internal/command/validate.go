package command

import (
	"fmt"
	"io"

	"github.com/strangemattersystems/hamnir/internal/config"
)

// Validate loads and validates the config at path (the same checks Serve runs),
// writing a success line to w. The load/validation error is returned unchanged
// on failure.
func Validate(w io.Writer, path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	noun := "personas"
	if len(cfg.Personas) == 1 {
		noun = "persona"
	}
	fmt.Fprintf(w, "ok: %s (%d %s)\n", path, len(cfg.Personas), noun)
	return nil
}
