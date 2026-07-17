package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// gzipServe runs handler through gzipHandler for the given method and
// Accept-Encoding, returning the recorded response.
func gzipServe(t *testing.T, method, acceptEnc string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/", nil)
	if acceptEnc != "" {
		req.Header.Set("Accept-Encoding", acceptEnc)
	}
	rec := httptest.NewRecorder()
	gzipHandler(handler).ServeHTTP(rec, req)
	return rec
}

func htmlHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, body)
	}
}

func TestGzipHandler(t *testing.T) {
	t.Parallel()

	body := "<html><body>" + strings.Repeat("hamnir ", 200) + "</body></html>"

	t.Run("compresses when the client accepts gzip", func(t *testing.T) {
		t.Parallel()

		rec := gzipServe(t, http.MethodGet, "gzip", htmlHandler(body))
		if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("Content-Encoding = %q, want gzip", got)
		}
		if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
			t.Error("Vary should include Accept-Encoding")
		}
		if rec.Body.Len() >= len(body) {
			t.Errorf("gzip did not shrink the body: %d >= %d", rec.Body.Len(), len(body))
		}
		zr, err := gzip.NewReader(rec.Body)
		if err != nil {
			t.Fatalf("response is not valid gzip: %v", err)
		}
		got, _ := io.ReadAll(zr)
		if string(got) != body {
			t.Error("decompressed body does not match the original")
		}
	})

	t.Run("passes through without Accept-Encoding", func(t *testing.T) {
		t.Parallel()

		rec := gzipServe(t, http.MethodGet, "", htmlHandler(body))
		if rec.Header().Get("Content-Encoding") != "" {
			t.Error("must not compress when the client does not accept gzip")
		}
		if rec.Body.String() != body {
			t.Error("body should be served verbatim")
		}
	})

	t.Run("skips non-compressible content types", func(t *testing.T) {
		t.Parallel()

		rec := gzipServe(t, http.MethodGet, "gzip", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(bytes.Repeat([]byte{0}, 1000))
		})
		if rec.Header().Get("Content-Encoding") == "gzip" {
			t.Error("must not gzip already-compressed media")
		}
	})

	t.Run("does not add a body to a 304", func(t *testing.T) {
		t.Parallel()

		// Static assets revalidate with 304; a gzip footer written onto one would
		// corrupt the response.
		rec := gzipServe(t, http.MethodGet, "gzip", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "image/svg+xml")
			w.WriteHeader(http.StatusNotModified)
		})
		if rec.Header().Get("Content-Encoding") == "gzip" {
			t.Error("a 304 must not be gzip-encoded")
		}
		if rec.Body.Len() != 0 {
			t.Errorf("a 304 must have no body, got %d bytes", rec.Body.Len())
		}
	})

	t.Run("passes HEAD through uncompressed", func(t *testing.T) {
		t.Parallel()

		rec := gzipServe(t, http.MethodHead, "gzip", htmlHandler(body))
		if rec.Header().Get("Content-Encoding") == "gzip" {
			t.Error("HEAD must not be gzip-encoded")
		}
	})

	t.Run("passes Range requests through uncompressed", func(t *testing.T) {
		t.Parallel()

		// A gzip stream cannot be range-served, so a Range request bypasses
		// compression and lets the underlying handler honour the range.
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		req.Header.Set("Range", "bytes=0-3")
		rec := httptest.NewRecorder()
		gzipHandler(htmlHandler(body)).ServeHTTP(rec, req)
		if rec.Header().Get("Content-Encoding") == "gzip" {
			t.Error("a Range request must not be gzip-encoded")
		}
	})
}
