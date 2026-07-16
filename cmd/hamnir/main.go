package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/strangemattersystems/hamnir/internal/command"
)

var (
	version  = "0.0.0-dev"
	revision = "unknown"
	date     = "unknown"
)

func main() {
	cli.VersionPrinter = func(*cli.Command) {
		fmt.Printf("hamnir %s (rev %s, built %s)\n", version, revision, date)
	}

	root := &cli.Command{
		Name:    "hamnir",
		Usage:   "persona-first OIDC dev provider",
		Version: version,
		Commands: []*cli.Command{
			{
				Name:  "serve",
				Usage: "run the OIDC provider",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "config", Value: "./hamnir.yaml", Usage: "path to config file"},
					&cli.StringFlag{Name: "addr", Value: "127.0.0.1:5556", Usage: "listen address"},
					&cli.StringFlag{Name: "key-file", Value: "./.hamnir/key.pem", Usage: "signing key path"},
				},
				Action: func(_ context.Context, cmd *cli.Command) error {
					// serve owns structured JSON logging; init/validate stay plain.
					slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
					if err := command.Serve(cmd.String("config"), cmd.String("addr"), cmd.String("key-file")); err != nil {
						return cli.Exit("", 1) // already logged as JSON by command.Serve
					}
					return nil
				},
			},
			{
				Name:  "init",
				Usage: "scaffold a minimal config and signing key",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "config", Value: "./hamnir.yaml", Usage: "path to config file to create"},
					&cli.StringFlag{Name: "key-file", Value: "./.hamnir/key.pem", Usage: "signing key path to create"},
					&cli.BoolFlag{Name: "force", Usage: "overwrite existing files"},
				},
				Action: func(_ context.Context, cmd *cli.Command) error {
					return command.Init(os.Stdout, cmd.String("config"), cmd.String("key-file"), cmd.Bool("force"))
				},
			},
			{
				Name:  "validate",
				Usage: "validate a config file without starting the server",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "config", Value: "./hamnir.yaml", Usage: "path to config file"},
				},
				Action: func(_ context.Context, cmd *cli.Command) error {
					return command.Validate(os.Stdout, cmd.String("config"))
				},
			},
		},
	}

	if err := root.Run(context.Background(), os.Args); err != nil {
		// Errors from serve are already logged (slog) and arrive as an ExitCoder
		// with an empty message: just honour the code. Plain errors from
		// init/validate are printed here.
		if ec, ok := errors.AsType[cli.ExitCoder](err); ok {
			os.Exit(ec.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "hamnir:", err)
		os.Exit(1)
	}
}
