package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/provider"
	"github.com/strangemattersystems/hamnir/internal/server"
)

var version = "0.0.0-dev"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	if len(os.Args) >= 2 && os.Args[1] == "--version" {
		fmt.Println("hamnir", version)
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		fmt.Fprintln(os.Stderr, "usage: hamnir serve [--config path] [--addr host:port] [--key-file path]")
		os.Exit(2)
	}

	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "./hamnir.yaml", "path to config file")
	addr := fs.String("addr", "127.0.0.1:5556", "listen address")
	keyFile := fs.String("key-file", "./.hamnir/key.pem", "signing key path")
	_ = fs.Parse(os.Args[2:])

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}
	if len(cfg.Clients) == 0 {
		slog.Warn("permissive dev mode — accepting any client_id and redirect_uri; DEV ONLY, do not expose to untrusted networks")
	}
	key, err := provider.LoadOrGenerateKey(*keyFile)
	if err != nil {
		slog.Error("load signing key", "err", err)
		os.Exit(1)
	}
	h, err := server.New(cfg, key)
	if err != nil {
		slog.Error("build server", "err", err)
		os.Exit(1)
	}
	slog.Info("listening", "addr", *addr)
	if err := http.ListenAndServe(*addr, h); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
