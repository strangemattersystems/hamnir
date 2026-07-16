package command

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeValidConfig writes a minimal single-persona config and returns its path.
func writeValidConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hamnir.yaml")
	if err := os.WriteFile(p, []byte("personas:\n  - name: A\n    claims:\n      sub: a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// freeAddr reserves a currently-free loopback address and releases it, returning
// the address for a caller to bind. Inherently racy, but adequate for a test.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// waitReady blocks until addr accepts a TCP connection or the deadline passes.
func waitReady(t *testing.T, addr string) {
	t.Helper()
	for range 100 {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server at %s never became ready", addr)
}

func TestServe(t *testing.T) {
	t.Run("graceful shutdown on context cancel", func(t *testing.T) {
		cfg := writeValidConfig(t)
		key := filepath.Join(t.TempDir(), "key.pem")
		addr := freeAddr(t)

		ctx, cancel := context.WithCancel(context.Background())
		errc := make(chan error, 1)
		go func() { errc <- Serve(ctx, cfg, addr, key) }()

		waitReady(t, addr)
		cancel()

		select {
		case err := <-errc:
			if err != nil {
				t.Fatalf("Serve returned %v, want nil after graceful shutdown", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Serve did not return after context cancel")
		}
	})

	t.Run("errors when addr already in use", func(t *testing.T) {
		cfg := writeValidConfig(t)
		key := filepath.Join(t.TempDir(), "key.pem")

		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()

		if err := Serve(t.Context(), cfg, l.Addr().String(), key); err == nil {
			t.Fatal("Serve returned nil, want error for in-use addr")
		}
	})
}
