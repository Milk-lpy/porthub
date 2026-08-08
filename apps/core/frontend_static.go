package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func frontendHandler(dir string) http.HandlerFunc {
	index := filepath.Join(dir, "index.html")
	if dir == "" {
		return ui
	}
	fileServer := http.FileServer(http.Dir(dir))
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Recheck on every request. A temporarily unreadable or incomplete
		// release must not pin the process to the embedded recovery console
		// until the next Core restart.
		if _, err := os.Stat(index); err != nil {
			w.Header().Set("Cache-Control", "no-store")
			ui(w, r)
			return
		}
		clean := filepath.Clean(r.URL.Path)
		if clean == "." || clean == "/" {
			w.Header().Set("Cache-Control", "no-cache, must-revalidate")
			http.ServeFile(w, r, index)
			return
		}
		target := filepath.Join(dir, clean)
		if info, err := os.Stat(target); err == nil && !info.IsDir() {
			if filepath.Dir(clean) == string(filepath.Separator)+"assets" {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			fileServer.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		http.ServeFile(w, r, index)
	}
}
