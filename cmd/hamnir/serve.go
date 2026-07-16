package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/provider"
	"github.com/strangemattersystems/hamnir/internal/server"
)

func serveCommand() *cli.Command {
	return &cli.Command{
		Name:  "serve",
		Usage: "run the OIDC provider",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Value: "./hamnir.yaml", Usage: "path to config file"},
			&cli.StringFlag{Name: "addr", Value: "127.0.0.1:5556", Usage: "listen address"},
			&cli.StringFlag{Name: "key-file", Value: "./.hamnir/key.pem", Usage: "signing key path"},
		},
		Action: runServe,
	}
}

// runServe boots the OIDC provider. Startup failures are logged as JSON and
// surfaced as cli.Exit("", 1): main sees the ExitCoder and exits without
// re-printing, so the slog error line is the only output.
func runServe(_ context.Context, cmd *cli.Command) error {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	cfg, err := config.Load(cmd.String("config"))
	if err != nil {
		slog.Error("load config", "err", err)
		return cli.Exit("", 1)
	}
	if len(cfg.Clients) == 0 {
		slog.Warn("permissive dev mode — accepting any client_id and redirect_uri; DEV ONLY, do not expose to untrusted networks")
	}
	key, err := provider.LoadOrGenerateKey(cmd.String("key-file"))
	if err != nil {
		slog.Error("load signing key", "err", err)
		return cli.Exit("", 1)
	}
	h, err := server.New(cfg, key)
	if err != nil {
		slog.Error("build server", "err", err)
		return cli.Exit("", 1)
	}
	addr := cmd.String("addr")
	slog.Info("listening", "addr", addr)
	if err := http.ListenAndServe(addr, h); err != nil {
		slog.Error("server stopped", "err", err)
		return cli.Exit("", 1)
	}
	return nil
}
