package main

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/strangemattersystems/hamnir/internal/provider"
)

// minimalConfig is the starter config written by `hamnir init`. It lives as a
// real .yaml file so it validates against the schema in an editor while we
// maintain it, rather than as an escaped Go string literal.
//
//go:embed init_config.yaml
var minimalConfig string

func initCommand() *cli.Command {
	return &cli.Command{
		Name:  "init",
		Usage: "scaffold a minimal config and signing key",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Value: "./hamnir.yaml", Usage: "path to config file to create"},
			&cli.StringFlag{Name: "key-file", Value: "./.hamnir/key.pem", Usage: "signing key path to create"},
			&cli.BoolFlag{Name: "force", Usage: "overwrite existing files"},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			return runInit(os.Stdout, cmd.String("config"), cmd.String("key-file"), cmd.Bool("force"))
		},
	}
}

// runInit writes a minimal config and generates a fresh signing key, printing a
// line per created file to w. Unless force is set, it refuses (writing nothing)
// when either target already exists.
func runInit(w io.Writer, configPath, keyPath string, force bool) error {
	if !force {
		var existing []string
		if _, err := os.Stat(configPath); err == nil {
			existing = append(existing, configPath)
		}
		if _, err := os.Stat(keyPath); err == nil {
			existing = append(existing, keyPath)
		}
		if len(existing) > 0 {
			return fmt.Errorf("already exists: %s (use --force to overwrite)", strings.Join(existing, ", "))
		}
	}

	if dir := filepath.Dir(configPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
	}
	if err := os.WriteFile(configPath, []byte(minimalConfig), 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Fprintln(w, "created", configPath)

	if _, err := provider.GenerateKey(keyPath); err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	fmt.Fprintln(w, "created", keyPath)
	return nil
}
