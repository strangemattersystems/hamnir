package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/strangemattersystems/hamnir/internal/config"
)

func validateCommand() *cli.Command {
	return &cli.Command{
		Name:  "validate",
		Usage: "validate a config file without starting the server",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Value: "./hamnir.yaml", Usage: "path to config file"},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			return runValidate(os.Stdout, cmd.String("config"))
		},
	}
}

// runValidate loads and validates the config at path (the same checks serve
// runs), writing a success line to w. The load/validation error is returned
// unchanged on failure.
func runValidate(w io.Writer, path string) error {
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
