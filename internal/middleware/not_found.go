package middleware

import (
	"gohst/internal/render"
	"net/http"
)

type responseWriter404 struct {
	http.ResponseWriter
	status int
}

func (w *responseWriter404) WriteHeader(status int) {
	w.status = status
	if status != http.StatusNotFound {
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *responseWriter404) Write(b []byte) (int, error) {
	if w.status == http.StatusNotFound {
		return len(b), nil // Suppress the default "404 page not found" text
	}
	return w.ResponseWriter.Write(b)
}

// NotFound returns a middleware that intercepts 404 responses and renders a custom 404 page.
func NotFound(templateName string) func(http.Handler) http.Handler {
	// Initialize a view instance for rendering the 404 page.
	// We do this once here so we don't re-parse templates on every 404.
	view := render.NewView()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rw := &responseWriter404{ResponseWriter: w}
			next.ServeHTTP(rw, r)

			if rw.status == http.StatusNotFound {
				// It was a 404! Render our custom page
				// We must explicitly set the status code here because we suppressed it earlier
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusNotFound)
				view.Render(w, r, templateName, nil)
			}
		})
	}
}
