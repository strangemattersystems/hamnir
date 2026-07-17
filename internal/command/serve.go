package command

import (
	"context"
	"errors"
	"fmt"
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
		return fmt.Errorf("load config: %w", err)
	}
	if len(cfg.Clients) == 0 {
		slog.Warn("permissive dev mode — accepting any client_id and redirect_uri; DEV ONLY, do not expose to untrusted networks")
	}

	key, err := provider.LoadOrGenerateKey(keyFile)
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}

	h, err := server.New(cfg, key)
	if err != nil {
		return fmt.Errorf("build server: %w", err)
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
		if err != nil {
			return fmt.Errorf("server stopped: %w", err)
		}
		return nil
	case <-ctx.Done():
		slog.Info("shutdown signal received, draining", "timeout", shutdownTimeout.String())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	slog.Info("shutdown complete")
	return nil
}
