# Testing oauth stuff

Trying to figure out oauth with Go.

## Setup

### Environment

```shell
% cat > .env
PORT=5175
GOOGLE_CLIENT_ID=<...>
GOOGLE_CLIENT_SECRET=<...>
GOOGLE_REDIRECT_URI=http://localhost:5175/auth/google/callback
DATABASE=database.db
^D
```

### Database for session store

```shell
% cat | sqlite3 database.db
create table sessions (token text primary key, data BLOB not null, expiry real not null);
create index sessions_expiry_idx on sessions(expiry);
^D
```


## Install

```shell
% go get -v ./...
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
-   https://github.com/alexedwards/scs/tree/master/sqlite3store


## TODO

-   replace marshalling / unmarshalling the token with registration of it with gob
-   hmm, need to double check the Client call - using r.Context(), try context.TODO() instead
