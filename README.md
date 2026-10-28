# Pluto Auth

An independent, deliberately narrow hard fork of
[Limen](https://github.com/thecodearcher/limen) for Pluto APIs.

Module: `github.com/plutoframework/pluto-auth` (Go 1.25.5+).
Pre-release; no independent security audit or compatibility guarantee.

The active library provides opaque sessions, typed persistence and net/http
cookie authentication (with opt-in opaque bearer credentials). Optional modules add local password sign-in and a
Postgres store. Authentication establishes identity; application membership,
resource policies and [Pluto RBAC](https://github.com/plutoframework/pluto-rbac)
decide authorization. No hidden globals, startup DDL or automatic routes.

## Browse the implementation

- `session.go`, `manager.go`, `token.go`: session contract, lifecycle and tokens.
- `httpauth/`: net/http middleware, exact Origin guard and secure host cookies.
- `stores/memory/`: bounded store for tests and single-process development.
- `stores/postgres/`: independent pgx/sqlc module, schema and generated queries.
- `methods/password/`: independent Argon2id module and typed sign-in service.
- `docs/SECURITY-MODEL.md`: boundaries, defaults and deliberate limitations.
- `docs/PROVENANCE.md`: upstream baseline, attribution and fork decisions.

Core/httpauth/memory have no third-party dependencies. Password hashing uses
golang.org/x/crypto; Postgres uses pgx. Tooling dependencies, generated sqlc
sources and optional modules do not become core runtime dependencies. The
checked-in go.work joins modules for development; published modules contain
actual version requirements without local filesystem replacements.

## Session setup

```go
store, err := memory.New(1000)
if err != nil {
    return err
}

manager, err := auth.New(store, auth.DefaultConfig())
if err != nil {
    return err
}

transport, err := httpauth.New(manager, httpauth.Config{
    TrustedOrigins: []string{"https://app.example.com"},
})
if err != nil {
    return err
}

router.Handle("/api/profile", transport.Require(profileHandler))
```

Imports are `auth "github.com/plutoframework/pluto-auth"`, plus its `/httpauth`
and `/stores/memory` packages. Both Chi and http.ServeMux accept the handler.
Read the verified session with `httpauth.FromContext(request.Context())`.
Session metadata contains no roles, permissions or trusted tenant selection.

Manager.Start must follow credential verification. It is not a public login
operation. For local passwords, construct methods/password.NewAuthenticator
with your CredentialStore, Hasher, SessionIssuer (the manager), and a real
AttemptLimiter. SignIn returns an IssuedSession on success; send it with
transport.WriteCookie, never as a raw token in JSON. Authenticator does not
perform registration, account recovery or credential updates.

Wrap login handlers in transport.Guard for Origin validation. Require already
includes it for cookie-authenticated routes. Set Config.AllowBearer explicitly
for API clients; mixed cookie/Authorization or duplicate credentials are rejected.
Bearer credentials are not ambient cookies and do not require an Origin. Logout must revoke server state before
ClearCookie; cookie clearing alone does not revoke a stolen token. Do not mutate
business state in GET/HEAD/OPTIONS handlers. HTTPS is required for the cookie.
Credentialed CORS and proxy trust are explicit application configuration.

## Postgres

Import `github.com/plutoframework/pluto-auth/stores/postgres` separately.
Construct postgres.New(pool) with a pgxpool.Pool. Apply schema.sql through your
application migration system before serving requests; no constructor applies it.
Schedule Store.PruneExpired explicitly. The application owns its user table and
CredentialStore implementation, avoiding a generic untyped database abstraction.

## Local checks

```sh
mise trust
mise install
./scripts/fmt.sh
./scripts/check.sh
./scripts/test.sh -race
./scripts/fuzz.sh
python3 scripts/mutation-smoke.py
```

golangci-lint 2.15.0 combines gofumpt, gci, golines (80-column default) and
wsl_v5. The target is configurable in .golangci.yml. Files must remain under
1,000 lines; split files rather than compressing code.

The Postgres integration test creates/drops a random schema in the explicitly
configured database. Use a disposable local or CI database only:

```sh
export PLUTO_AUTH_TEST_DATABASE_URL='postgres://user:password@localhost/testdb'
./scripts/test.sh -race
```

Without that variable, the integration test reports a skip. CI supplies a real
Postgres service and runs it. Regenerate SQL via `mise run generate` (sqlc
1.30.0); sqlc is a development tool, not a runtime dependency.

Original MIT license and attribution are preserved. The upstream source and
tests remain available at tag `limen-baseline-a691ec9`; this is intentionally
not a drop-in replacement for Limen or a promise to maintain its plugin suite.
