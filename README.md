# Testing oauth stuff

Trying to figure out oauth with Go.

## Setup

`.env`

```
PORT=5175
GOOGLE_CLIENT_ID=<...>
GOOGLE_CLIENT_SECRET=<...>
GOOGLE_REDIRECT_URI=http://localhost:5175/auth/google/callback
```

## Install

```shell
% go get
```

## run

```shell
% make
```

## References

-   https://pkg.go.dev/golang.org/x/oauth2#section-readme
-   https://github.com/golang/oauth2/blob/master/google/example_test.go
-   https://developers.google.com/people/quickstart/go
-   https://medium.com/@_RR/google-oauth-2-0-and-golang-4cc299f8c1ed
