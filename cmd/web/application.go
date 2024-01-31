package main

import (
	"database/sql"
	"html/template"
	"time"

	"github.com/alexedwards/scs/sqlite3store"
	"github.com/alexedwards/scs/v2"
	"github.com/caarlos0/env/v10"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	_ "github.com/mattn/go-sqlite3"
)

type Config struct {
	Port               int    `env:"PORT"`
	GoogleClientID     string `env:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret string `env:"GOOGLE_CLIENT_SECRET"`
	GoogleRedirectURI  string `env:"GOOGLE_REDIRECT_URI"`
	DatabaseName       string `env:"DATABASE"`
}

type Application struct {
	templates      *template.Template
	cfg            Config
	authConf       *oauth2.Config
	sessionManager *scs.SessionManager
}

func New() *Application {
	// Load templates.
	templates := template.Must(template.ParseGlob("templates/*/*.tmpl"))

	// Make application.
	app := &Application{
		templates: templates,
	}

	// Load configuration.
	if err := godotenv.Load(); err != nil {
		panic(err)
	}
	if err := env.Parse(&app.cfg); err != nil {
		panic(err)
	}

	// FIXME not sure if this belongs here. We need the auth configuration
	// between sending the initial request and receiving the callback so
	// carrying it around in the application makes sense, kinda... ?
	app.authConf = &oauth2.Config{
		ClientID:     app.cfg.GoogleClientID,
		ClientSecret: app.cfg.GoogleClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  app.cfg.GoogleRedirectURI,

		// https://developers.google.com/identity/protocols/oauth2/scopes
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
	}

	// Session management using scs:
	// https://pkg.go.dev/github.com/alexedwards/scs/v2
	db, err := sql.Open("sqlite3", app.cfg.DatabaseName)
	if err != nil {
		panic(err)
	}

	app.sessionManager = scs.New()
	app.sessionManager.Lifetime = 24 * time.Hour
	app.sessionManager.Store = sqlite3store.New(db)

	return app
}
