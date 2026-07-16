package static

import (
	"net/http"
	"strings"
)

const Root = "/.static/"

func Register(mux *http.ServeMux, paths map[string]string) {
	for mount, dir := range paths {
		p := Root + mount + "/"
		mux.Handle(p, noDirList(http.StripPrefix(p, http.FileServer(http.Dir(dir)))))
	}
}

func noDirList(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}
