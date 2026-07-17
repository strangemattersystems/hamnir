package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ecKeyB64 returns a valid-PKCS#8-but-not-RSA key value for error cases.
func ecKeyB64(t *testing.T) string {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestGenerateSigningKey(t *testing.T) {
	encoded, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	cfg := &Config{SigningKey: encoded}
	if err := cfg.parseSigningKey(); err != nil {
		t.Fatalf("generated key does not parse back: %v", err)
	}
	if cfg.Key == nil {
		t.Fatal("Key not populated")
	}
	if got := cfg.Key.N.BitLen(); got != 2048 {
		t.Errorf("key size = %d, want 2048", got)
	}
}

func TestConfig_parseSigningKey(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr error
	}{
		{"not base64", "not!!base64", errInvalidSigningKey},
		{"base64 but not PKCS#8", base64.StdEncoding.EncodeToString([]byte("garbage")), errInvalidSigningKey},
		{"PKCS#8 but not RSA", "", errInvalidSigningKey}, // value filled in below
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "PKCS#8 but not RSA" {
				tt.value = ecKeyB64(t)
			}
			cfg := &Config{SigningKey: tt.value}
			if err := cfg.parseSigningKey(); !errors.Is(err, tt.wantErr) {
				t.Fatalf("parseSigningKey() = %v, want %v", err, tt.wantErr)
			}
		})
	}

	t.Run("missing key", func(t *testing.T) {
		cfg := &Config{}
		if err := cfg.parseSigningKey(); !errors.Is(err, errMissingSigningKey) {
			t.Fatalf("parseSigningKey() = %v, want errMissingSigningKey", err)
		}
	})
}

func TestLoad_SigningKey(t *testing.T) {
	encoded, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(writeTemp(t, "personas:\n  - claims: { sub: s }\nsigning_key: "+encoded+"\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Key == nil {
		t.Fatal("Load did not populate Key")
	}

	t.Run("invalid key surfaces from Load", func(t *testing.T) {
		_, err := Load(writeTemp(t, "personas:\n  - claims: { sub: s }\nsigning_key: not!!base64\n"))
		if !errors.Is(err, errInvalidSigningKey) {
			t.Fatalf("Load = %v, want errInvalidSigningKey", err)
		}
	})

	t.Run("missing key surfaces from Load", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "hamnir.yaml")
		if err := os.WriteFile(p, []byte("personas:\n  - claims: { sub: s }\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); !errors.Is(err, errMissingSigningKey) {
			t.Fatalf("Load = %v, want errMissingSigningKey", err)
		}
	})
}
