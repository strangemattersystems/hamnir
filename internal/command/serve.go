package command

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/provider"
	"github.com/strangemattersystems/hamnir/internal/server"
)

const shutdownTimeout = 10 * time.Second

func Serve(ctx context.Context, configPath, addr, keyFile string) error {
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

	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	slog.Info("listening", "addr", addr)
	select {
	case err := <-serveErr:
		slog.Error("server stopped", "err", err)
		return err
	case <-ctx.Done():
		slog.Info("shutdown signal received, draining", "timeout", shutdownTimeout.String())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", "err", err)
		return err
	}
	slog.Info("shutdown complete")
	return nil
}
