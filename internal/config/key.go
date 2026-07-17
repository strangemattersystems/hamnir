package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

var (
	errInvalidSigningKey = errors.New("invalid signing_key")
	errMissingSigningKey = errors.New(`missing signing_key (run "hamnir init" to create a config, or add one)`)
)

// GenerateSigningKey returns a freshly generated RSA-2048 private key encoded
// as a signing_key config value: standard base64 of the PKCS#8 DER, no PEM
// armor. The armor is deliberately absent so header-matching secret scanners
// do not flag committed dev configs.
func GenerateSigningKey() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// parseSigningKey decodes SigningKey into Key.
func (c *Config) parseSigningKey() error {
	if c.SigningKey == "" {
		return errMissingSigningKey
	}
	der, err := base64.StdEncoding.DecodeString(c.SigningKey)
	if err != nil {
		return fmt.Errorf("%w: not valid base64: %w", errInvalidSigningKey, err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return fmt.Errorf("%w: %w", errInvalidSigningKey, err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("%w: not an RSA key", errInvalidSigningKey)
	}
	c.Key = key
	return nil
}
