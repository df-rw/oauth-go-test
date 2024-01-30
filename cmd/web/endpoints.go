package main

import (
	"encoding/gob"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// init registers the oauth2.Token struct with gob. gob is used by our session
// manager to store session data:
// https://pkg.go.dev/github.com/alexedwards/scs/v2#readme-working-with-session-data
//
// The registration must be done prior to storing / retrieving data by the
// session manager.
func init() {
	gob.Register(oauth2.Token{})
}

func randomString(num int) string {
	a := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	l := len(a)
	var out []byte

	for i := 0; i < num; i++ {
		out = append(out, a[rand.Intn(l)])
	}

	return string(out)
}

// commonPageData returns a map of strings to datum. The strings will match any
// information required by templates through "dot".
func (app *Application) commonPageData(r *http.Request) map[string]any {
	loggedIn := app.sessionManager.Exists(r.Context(), "token")

	pageData := map[string]any{
		"LoggedIn":   loggedIn,
		"Servertime": time.Now().String(),
	}

	return pageData
}

// home renders the home page.
func (app *Application) home(w http.ResponseWriter, r *http.Request) {
	pageData := app.commonPageData(r)

	app.render(w, "home", pageData, http.StatusOK)
}

// about renders an about page.
func (app *Application) about(w http.ResponseWriter, r *http.Request) {
	pageData := app.commonPageData(r)

	app.render(w, "about", pageData, http.StatusOK)
}

// login starts off the oauth login process.
func (app *Application) login(w http.ResponseWriter, r *http.Request) {
	if app.sessionManager.Exists(r.Context(), "token") {
		http.Redirect(w, r, "/", http.StatusSeeOther) // FIXME check status
		return
	}

	state := randomString(32)
	// https://pkg.go.dev/golang.org/x/oauth2#GenerateVerifier
	verifier := oauth2.GenerateVerifier()

	app.sessionManager.Put(r.Context(), "state", state)
	app.sessionManager.Put(r.Context(), "verifier", verifier)

	// It looks like "state" can do double duty:
	// - can be used to protect against CSRF;
	// - used by client to maintain state between request and callback.
	// (https://pkg.go.dev/golang.org/x/oauth2#Config.AuthCodeURL)
	//
	// TODO We have a session manager in place which will sync request and
	// callback. We're using verifier for CSRF. So I guess we can just
	// follow the docs and generate a random string for state, check it
	// on oauth callback and be happy...?
	url := app.authConf.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))

	http.Redirect(w, r, url, http.StatusSeeOther) // FIXME check status
}

// authRedirect is the url called when we return from the authentication
// service. Here we check the response, exchange code for access token, store
// the token in the session, and carry on.
func (app *Application) authRedirect(w http.ResponseWriter, r *http.Request) {
	authState := r.FormValue("state")
	authCode := r.FormValue("code")

	state := app.sessionManager.GetString(r.Context(), "state")
	verifier := app.sessionManager.GetString(r.Context(), "verifier")

	if authState != state {
		app.serverError(w, r, errors.New("state mismatch"))
		return
	}

	// Exchange the code for access token; verify as well.
	token, err := app.authConf.Exchange(r.Context(), authCode, oauth2.VerifierOption(verifier))
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	app.sessionManager.Remove(r.Context(), "state")
	app.sessionManager.Remove(r.Context(), "verifier")

	app.sessionManager.Put(r.Context(), "token", *token)

	// Now when we want to use it, we need to:
	// client := app.authConf.Client(r.Context(), token)
	// client.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	// The token will auto-refresh according to the docs, which is nice.

	http.Redirect(w, r, "/protected", http.StatusSeeOther) // FIXME check status
}

// logout removes our session data.
func (app *Application) logout(w http.ResponseWriter, r *http.Request) {
	// FIXME is killing the token enough?
	_ = app.sessionManager.Destroy(r.Context())
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// protected renders a page that requires some sort of authentication to
// access. The protection happens in the middleware; see
// middleware.go:authProtected().
func (app *Application) protected(w http.ResponseWriter, r *http.Request) {
	pageData := app.commonPageData(r)

	token := app.sessionManager.Get(r.Context(), "token").(oauth2.Token)
	client := app.authConf.Client(r.Context(), &token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		app.serverError(w, r, err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	userinfo := map[string]any{}
	err = json.Unmarshal(body, &userinfo)
	if err != nil {
		app.serverError(w, r, err)
		return
	}
	pageData["Userinfo"] = userinfo

	app.render(w, "protected", pageData, http.StatusOK)
}

// notFound renders a 404 page, and sends a 404 status code.
func (app *Application) notFound(w http.ResponseWriter, r *http.Request) {
	app.render(w, "404", nil, http.StatusNotFound)
}
