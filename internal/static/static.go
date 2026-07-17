// Package static serves persona assets, such as avatars, from local
// directories under a fixed URL root, with directory listings disabled.
package static

import (
	"net/http"
	"strings"
)

// Root is the URL path prefix under which every static mount is served.
const Root = "/.static/"

// Register mounts each directory in paths under [Root], keyed by mount name, so
// a file at paths["avatars"]/eve.svg is served at Root+"avatars/eve.svg".
func Register(mux *http.ServeMux, paths map[string]string) {
	for mount, dir := range paths {
		p := Root + mount + "/"
		mux.Handle(p, noDirList(http.StripPrefix(p, http.FileServer(http.Dir(dir)))))
	}
}

// noDirList wraps h to answer 404 for any request whose path ends in "/",
// suppressing [http.FileServer]'s directory listings and index.html serving.
func noDirList(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}
