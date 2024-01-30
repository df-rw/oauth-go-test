package main

import (
	"net/http"
)

// authProtected is chi middleware that checks if this client can use the
// routes that are "protected".
func (app *Application) authProtected(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if !app.sessionManager.Exists(ctx, "token") {
			app.render(w, "401", nil, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
