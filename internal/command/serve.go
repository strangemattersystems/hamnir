package command

import (
	"log/slog"
	"net/http"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/provider"
	"github.com/strangemattersystems/hamnir/internal/server"
)

// Serve boots the OIDC provider: it loads the config and signing key, builds the
// HTTP handler, and serves until ListenAndServe returns. Failures are logged as
// slog events and returned; the caller decides how to surface the exit. Serve
// emits through the default slog logger, which the caller configures.
func Serve(configPath, addr, keyFile string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		slog.Error("load config", "err", err)
		return err
	}
	if len(cfg.Clients) == 0 {
		slog.Warn("permissive dev mode — accepting any client_id and redirect_uri; DEV ONLY, do not expose to untrusted networks")
	}
	key, err := provider.LoadOrGenerateKey(keyFile)
	if err != nil {
		slog.Error("load signing key", "err", err)
		return err
	}
	h, err := server.New(cfg, key)
	if err != nil {
		slog.Error("build server", "err", err)
		return err
	}
	slog.Info("listening", "addr", addr)
	if err := http.ListenAndServe(addr, h); err != nil {
		slog.Error("server stopped", "err", err)
		return err
	}
	return nil
}
