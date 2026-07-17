package command

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		withoutKey bool
		wantErr    bool
		wantOut    string
	}{
		{
			name:    "valid",
			yaml:    "personas:\n  - name: A\n    claims:\n      sub: a\n",
			wantOut: "1 persona)",
		},
		{
			name:    "missing sub",
			yaml:    "personas:\n  - name: A\n    claims:\n      email: a@b.c\n",
			wantErr: true,
		},
		{
			name: "unresolved static ref",
			yaml: "issuer: http://localhost:5556\nstatic:\n  paths: { avatars: " + t.TempDir() + " }\n" +
				"personas:\n  - name: A\n    claims:\n      sub: a\n      picture: hamnir://avatars/missing.svg\n",
			wantErr: true,
		},
		{
			name:       "missing signing key",
			yaml:       "personas:\n  - name: A\n    claims:\n      sub: a\n",
			withoutKey: true,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "hamnir.yaml")
			body := tt.yaml
			if !tt.withoutKey {
				key, err := testSigningKey()
				if err != nil {
					t.Fatal(err)
				}
				body += "signing_key: " + key + "\n"
			}
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			err := Validate(&buf, p)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantOut != "" && !strings.Contains(buf.String(), tt.wantOut) {
				t.Errorf("output %q missing %q", buf.String(), tt.wantOut)
			}
		})
	}
}
