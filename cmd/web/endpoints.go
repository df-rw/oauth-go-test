package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

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
		http.Redirect(w, r, "/protected", http.StatusSeeOther) // FIXME check status
		return
	}

	// It looks like "state" can do double duty:
	// - can be used to protect against CSRF;
	// - used by client to maintain state between request and callback.
	// (https://pkg.go.dev/golang.org/x/oauth2#Config.AuthCodeURL)
	//
	// We have a session manager in place which will sync request and callback.
	// We're using verifier for CSRF. So I guess we can just follow the docs
	// and generate a random string for state, check it on oauth callback and
	// be happy...?
	state := randomString(32)

	// https://pkg.go.dev/golang.org/x/oauth2#GenerateVerifier
	verifier := oauth2.GenerateVerifier()

	app.sessionManager.Put(r.Context(), "state", state)
	app.sessionManager.Put(r.Context(), "verifier", verifier)

	// https://pkg.go.dev/golang.org/x/oauth2#AuthCodeOption
	options := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier)}
	getConsent := app.sessionManager.Pop(r.Context(), "get-consent")
	if getConsent != nil {
		options = append(options, oauth2.ApprovalForce)
	}

	url := app.authConf.AuthCodeURL(state, options...)

	http.Redirect(w, r, url, http.StatusSeeOther) // FIXME check status
}

// authRedirect is the url called when we return from the authentication
// service. Here we check the response, exchange code for access token, store
// the token in the session, and carry on.
func (app *Application) authRedirect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authState := r.FormValue("state")
	authCode := r.FormValue("code")

	state := app.sessionManager.GetString(ctx, "state")
	verifier := app.sessionManager.GetString(ctx, "verifier")

	// Don't need these guys any more.
	app.sessionManager.Remove(ctx, "state")
	app.sessionManager.Remove(ctx, "verifier")

	if authState != state {
		app.serverError(w, r, errors.New("state mismatch"))
		return
	}

	// Exchange the code for access token; verify as well.
	token, err := app.authConf.Exchange(ctx, authCode, oauth2.VerifierOption(verifier))
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	if token.RefreshToken == "" {
		// The payload that has been returned to us is missing a refresh token.
		// This is because the user has already consented to using this
		// application prior to this exchange, and in that initial exchange, a
		// refresh token was supplied that was supposed to be stored
		// "permanently":
		// - https://developers.google.com/identity/openid-connect/openid-connect#refresh-tokens
		//
		// The refresh token is used by the Go oauth2 client automatically when
		// an API call is made to a google service and the access token has
		// expired.
		//
		// The only way to get another refresh token is to force the user to
		// consent again, which an be done by using oauth2.ApprovalForce on
		// AuthCodeURL():
		// - https://pkg.go.dev/golang.org/x/oauth2#AuthCodeOption
		//
		// So: we'll set a marker in this users' session to indicate to /login that
		// they need to give consent again.
		//
		// NOTE I think this dance is only required if we kill the session
		// (ie. the user logs out, our session store dies).
		// NOTE also have to consider what happens for multi-device case; if a
		// user first logs in on one device they'll get refresh token; they
		// login on another device they won't get a refresh token. Both devices
		// will have a different access token. Not sure how this works.
		app.sessionManager.Put(ctx, "get-consent", true)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Storing the token structure itself didn't work (probably PEBKAC). Throw
	// bytes at session store instead.
	t, err := json.Marshal(*token)
	if err != nil {
		app.serverError(w, r, fmt.Errorf("failed to marshal token"))
		return
	}
	app.sessionManager.Put(ctx, "token", t)

	http.Redirect(w, r, "/protected", http.StatusSeeOther) // FIXME check status
}

// logout removes our session data.
func (app *Application) logout(w http.ResponseWriter, r *http.Request) {
	_ = app.sessionManager.Destroy(r.Context())
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// protected renders a page that requires some sort of authentication to
// access. The protection happens in the middleware; see
// middleware.go:authProtected(). This endpoint also makes a call to a Google
// endpoint, to demonstrate the refresh token check / dance.
func (app *Application) protected(w http.ResponseWriter, r *http.Request) {
	pageData := app.commonPageData(r)

	// Grab our current auth token.
	var token oauth2.Token
	t, ok := app.sessionManager.Get(r.Context(), "token").([]byte)
	if !ok {
		app.serverError(w, r, fmt.Errorf("failed to type assert token"))
	}
	err := json.Unmarshal(t, &token)
	if err != nil {
		app.serverError(w, r, fmt.Errorf("failed to unmarshal token"))
		return
	}

	// Ok, well, let's try some random stackoverflow posts:
	// - https://stackoverflow.com/questions/46475997/renew-access-token-using-golang-oauth2-library
	// - https://stackoverflow.com/questions/52825464/how-to-use-google-refresh-token-when-the-access-token-is-expired-in-go
	newToken, err := app.authConf.TokenSource(context.TODO(), &token).Token()
	if err != nil {
		app.serverError(w, r, err)
		return
	}
	// If we've updated the token, store it.
	if newToken.AccessToken != token.AccessToken {
		fmt.Println("** access token has been updated")
		t, err := json.Marshal(*newToken)
		if err != nil {
			app.serverError(w, r, fmt.Errorf("failed to marshal token"))
			return
		}
		app.sessionManager.Put(r.Context(), "token", t)
	}

	// Create client with new token.
	client := app.authConf.Client(context.TODO(), newToken)

	// The client will automatically refresh expired tokens:
	// - https://pkg.go.dev/golang.org/x/oauth2#Config.Client
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + newToken.AccessToken)
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
	pageData["Token"] = newToken
	pageData["SessionManager"] = app.sessionManager

	app.render(w, "protected", pageData, http.StatusOK)
}

// notFound renders a 404 page, and sends a 404 status code.
func (app *Application) notFound(w http.ResponseWriter, r *http.Request) {
	app.render(w, "404", nil, http.StatusNotFound)
}
