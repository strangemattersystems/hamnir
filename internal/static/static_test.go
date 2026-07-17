package static

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRegister(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "eve.svg"), []byte("<svg/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "nested.txt"), []byte("nested"), 0o600); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	Register(mux, map[string]string{"avatars": dir})

	tests := []struct {
		name       string
		path       string
		wantStatus int
		wantBody   string
	}{
		{"serves a file", "/.static/avatars/eve.svg", http.StatusOK, "<svg/>"},
		{"serves a nested file", "/.static/avatars/sub/nested.txt", http.StatusOK, "nested"},
		{"404 on directory listing", "/.static/avatars/", http.StatusNotFound, ""},
		{"404 on nested directory listing", "/.static/avatars/sub/", http.StatusNotFound, ""},
		{"404 on missing file", "/.static/avatars/missing.svg", http.StatusNotFound, ""},
		{"404 on unknown mount", "/.static/unknown/eve.svg", http.StatusNotFound, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))

			if rec.Code != tt.wantStatus {
				t.Fatalf("GET %s status = %d, want %d", tt.path, rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" && rec.Body.String() != tt.wantBody {
				t.Fatalf("GET %s body = %q, want %q", tt.path, rec.Body.String(), tt.wantBody)
			}
		})
	}

	t.Run("served files carry a cache lifetime", func(t *testing.T) {
		t.Parallel()

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.static/avatars/eve.svg", nil))
		if got := rec.Header().Get("Cache-Control"); got != cacheControlValue {
			t.Errorf("Cache-Control = %q, want %q", got, cacheControlValue)
		}
	})

	t.Run("directory 404 is not cached", func(t *testing.T) {
		t.Parallel()

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.static/avatars/", nil))
		if got := rec.Header().Get("Cache-Control"); got != "" {
			t.Errorf("a directory 404 should not set Cache-Control, got %q", got)
		}
	})
}
