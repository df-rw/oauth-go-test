package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	app := New()

	// Router.
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	// oauth: our redirect path comes from config
	authRedirURL, err := url.Parse(app.cfg.GoogleRedirectURI)
	if err != nil {
		panic(err)
	}

	// Public endpoints.
	r.Group(func(r chi.Router) {
		r.Get("/", app.home)
		r.Get("/about", app.about)

		r.Post("/login", app.login)                // client hit the button
		r.Post("/logout", app.logout)              // client hit the other button
		r.Get(authRedirURL.Path, app.authRedirect) // oauth redirect path
		r.Get("/login-renew", app.loginRenew)
	})

	// Protected endpoints.
	r.Group(func(r chi.Router) {
		r.Use(app.authProtected)
		r.Get("/protected", app.protected)
	})

	r.NotFound(app.notFound)

	// Start listening.
	fmt.Printf("listening on port :%d\n", app.cfg.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", app.cfg.Port),
		app.sessionManager.LoadAndSave(r)))
}
