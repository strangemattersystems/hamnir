package command

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/strangemattersystems/hamnir/internal/config"
)

// testSigningKey is generated once; RSA-2048 generation is too slow to repeat
// per test.
var testSigningKey = sync.OnceValues(config.GenerateSigningKey)

// writeValidConfig writes a minimal single-persona config and returns its path.
func writeValidConfig(t *testing.T) string {
	t.Helper()
	key, err := testSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "hamnir.yaml")
	body := "personas:\n  - name: A\n    claims:\n      sub: a\nsigning_key: " + key + "\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
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
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

// waitReady blocks until addr accepts a TCP connection or the deadline passes.
func waitReady(t *testing.T, addr string) {
	t.Helper()
	for range 100 {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server at %s never became ready", addr)
}

// TestServe's subtests run in parallel; each binds its own free port. This is
// safe on op's package-global DefaultEndpoints only because no test config sets
// browser_url (which would trigger provider.NewProvider's in-place mutation of
// that global) — a future browser_url case here must not be parallel.
func TestServe(t *testing.T) {
	t.Parallel()

	t.Run("graceful shutdown", func(t *testing.T) {
		t.Parallel()

		cfg := writeValidConfig(t)
		addr := freeAddr(t)

		ctx, cancel := context.WithCancel(context.Background())
		errc := make(chan error, 1)
		go func() { errc <- Serve(ctx, cfg, addr, "test") }()

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

	t.Run("addr in use", func(t *testing.T) {
		t.Parallel()

		cfg := writeValidConfig(t)

		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()

		if err := Serve(t.Context(), cfg, l.Addr().String(), "test"); err == nil {
			t.Fatal("Serve returned nil, want error for in-use addr")
		}
	})

	t.Run("rejects an unloadable config", func(t *testing.T) {
		t.Parallel()

		missing := filepath.Join(t.TempDir(), "nope.yaml")
		if err := Serve(t.Context(), missing, "127.0.0.1:0", "test"); err == nil {
			t.Fatal("Serve with a missing config should fail before binding")
		}
	})
}
