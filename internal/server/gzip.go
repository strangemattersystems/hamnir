package server

import (
	"compress/gzip"
	"net/http"
	"strings"
)

// compressibleTypes are the Content-Type prefixes worth gzipping. Other media
// (images besides SVG, fonts, archives) is already compressed, so gzip would
// only burn CPU.
var compressibleTypes = []string{
	"text/",
	"application/json",
	"application/javascript",
	"image/svg+xml",
}

// gzipHandler wraps h to gzip-encode responses when the client accepts it and
// the response is a compressible type. HEAD and Range requests, and bodyless
// responses such as 204 and 304, pass through uncompressed — the 304 case
// matters because static assets revalidate with it.
func gzipHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead ||
			r.Header.Get("Range") != "" ||
			!strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			h.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Accept-Encoding")
		gw := &gzipResponseWriter{ResponseWriter: w}
		defer gw.close()
		h.ServeHTTP(gw, r)
	})
}

// gzipResponseWriter defers the compress-or-passthrough choice to WriteHeader,
// where both the status and the handler-set Content-Type are known. A non-nil
// gz means this response is being compressed.
type gzipResponseWriter struct {
	http.ResponseWriter
	gz          *gzip.Writer
	wroteHeader bool
}

func (g *gzipResponseWriter) WriteHeader(status int) {
	if g.wroteHeader {
		return
	}
	g.wroteHeader = true

	h := g.Header()
	bodyless := status < http.StatusOK || status == http.StatusNoContent || status == http.StatusNotModified
	if !bodyless && h.Get("Content-Encoding") == "" && isCompressible(h.Get("Content-Type")) {
		h.Del("Content-Length") // the encoded length differs; let Go chunk it
		h.Set("Content-Encoding", "gzip")
		g.gz = gzip.NewWriter(g.ResponseWriter)
	}
	g.ResponseWriter.WriteHeader(status)
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	if !g.wroteHeader {
		g.WriteHeader(http.StatusOK)
	}
	if g.gz != nil {
		return g.gz.Write(b)
	}
	return g.ResponseWriter.Write(b)
}

func (g *gzipResponseWriter) close() {
	if g.gz != nil {
		_ = g.gz.Close()
	}
}

func isCompressible(contentType string) bool {
	for _, t := range compressibleTypes {
		if strings.HasPrefix(contentType, t) {
			return true
		}
	}
	return false
}
