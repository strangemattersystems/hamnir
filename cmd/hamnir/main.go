package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v3"

	"github.com/strangemattersystems/hamnir/internal/command"
)

var (
	version  = "0.0.0-dev"
	revision = "unknown"
	date     = "unknown"
)

func main() {
	os.Exit(run())
}

func configFlag(usage string) *cli.StringFlag {
	return &cli.StringFlag{
		Name:    "config",
		Value:   "./hamnir.yaml",
		Usage:   usage,
		Sources: cli.EnvVars("HAMNIR_CONFIG"),
	}
}

func run() int {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

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
					configFlag("path to config file"),
					&cli.StringFlag{
						Name:    "addr",
						Value:   "127.0.0.1:5556",
						Usage:   "listen address",
						Sources: cli.EnvVars("HAMNIR_ADDR"),
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return command.Serve(ctx, cmd.String("config"), cmd.String("addr"))
				},
			},
			{
				Name:  "init",
				Usage: "scaffold a minimal config",
				Flags: []cli.Flag{
					configFlag("path to config file to create"),
					&cli.BoolFlag{Name: "force", Usage: "overwrite existing files"},
				},
				Action: func(_ context.Context, cmd *cli.Command) error {
					return command.Init(os.Stdout, cmd.String("config"), cmd.Bool("force"))
				},
			},
			{
				Name:  "validate",
				Usage: "validate a config file without starting the server",
				Flags: []cli.Flag{
					configFlag("path to config file"),
				},
				Action: func(_ context.Context, cmd *cli.Command) error {
					return command.Validate(os.Stdout, cmd.String("config"))
				},
			},
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := root.Run(ctx, os.Args); err != nil {
		if ec, ok := errors.AsType[cli.ExitCoder](err); ok {
			return ec.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "hamnir:", err)
		return 1
	}
	return 0
}
