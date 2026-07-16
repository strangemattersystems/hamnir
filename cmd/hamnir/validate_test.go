package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunValidate(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
		wantOut string
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "hamnir.yaml")
			if err := os.WriteFile(p, []byte(tt.yaml), 0o644); err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			err := runValidate(&buf, p)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantOut != "" && !strings.Contains(buf.String(), tt.wantOut) {
				t.Errorf("output %q missing %q", buf.String(), tt.wantOut)
			}
		})
	}
}
