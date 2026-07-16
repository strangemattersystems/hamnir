package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/strangemattersystems/hamnir/internal/config"
	"github.com/strangemattersystems/hamnir/internal/provider"
	"github.com/strangemattersystems/hamnir/internal/server"
)

var version = "0.0.0-dev"

func main() {
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
		log.Fatal(err)
	}
	if len(cfg.Clients) == 0 {
		log.Println("⚠ permissive dev mode — accepting any client_id and redirect_uri. DEV ONLY; do not expose to untrusted networks.")
	}
	key, err := provider.LoadOrGenerateKey(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	h, err := server.New(cfg, key)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("hamnir listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, h))
}
