package main

import (
	"net/http"
)

func (app *Application) render(w http.ResponseWriter, name string, pageData map[string]any, statusCode int) {
	w.Header().Set("Content-type", "text/html")
	w.WriteHeader(statusCode)

	// TODO replace this with write to buffer first, then send it
	// out, so we don't get partial writes
	err := app.templates.ExecuteTemplate(w, name, pageData)
	if err != nil {
		panic(err)
	}
}
