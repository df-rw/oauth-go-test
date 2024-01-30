package main

import (
	"log"
	"net/http"
	"runtime/debug"
)

func (app *Application) reportServerError(r *http.Request, err error) {
	var (
		message = err.Error()
		method  = r.Method
		url     = r.URL.String()
		trace   = string(debug.Stack())
	)

	log.Printf("%s: %s: %s: %s\n", message, method, url, trace)
}

func (app *Application) serverError(w http.ResponseWriter, r *http.Request, err error) {
	app.reportServerError(r, err)
	app.render(w, "500", nil, http.StatusInternalServerError)
}
