package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"
)

var (
	version  = "0.0.0-dev"
	revision = "unknown"
	date     = "unknown"
)

func main() {
	cli.VersionPrinter = func(cmd *cli.Command) {
		fmt.Printf("hamnir %s (rev %s, built %s)\n", version, revision, date)
	}

	cmd := &cli.Command{
		Name:    "hamnir",
		Usage:   "persona-first OIDC dev provider",
		Version: version,
		Commands: []*cli.Command{
			serveCommand(),
			initCommand(),
			validateCommand(),
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		// Errors from serve are already logged (slog) and arrive as an
		// ExitCoder with an empty message: just honour the code. Plain errors
		// from init/validate are printed here.
		if ec, ok := errors.AsType[cli.ExitCoder](err); ok {
			os.Exit(ec.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "hamnir:", err)
		os.Exit(1)
	}
}
