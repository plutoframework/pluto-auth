# Pluto Auth

An independent, deliberately narrow hard fork of
[Limen](https://github.com/thecodearcher/limen) for Pluto APIs.

Module: `github.com/plutoframework/pluto-auth` (Go 1.25.5+).
Pre-release; no independent security audit or compatibility guarantee.

The active library provides opaque sessions, typed persistence and net/http
cookie authentication (with opt-in opaque bearer credentials). Optional modules add local enrollment, verified-email password sign-in,
verification/resend, password recovery, account disable and a Postgres store. Authentication establishes identity; application membership,
resource policies and [Pluto RBAC](https://github.com/plutoframework/pluto-rbac)
decide authorization. No hidden globals, startup DDL or automatic routes.

## Browse the implementation

- `session.go`, `manager.go`, `token.go`: session contract, lifecycle and tokens.
- `httpauth/`: net/http middleware, exact Origin guard and secure host cookies.
- `stores/memory/`: bounded store for tests and single-process development.
- `stores/postgres/`: independent pgx/sqlc module, schema and generated queries.
- `methods/password/`: independent Argon2id module, local credential service,
  required sender/limiter contracts and POST-only `passwordhttp` adapter.
- `docs/SECURITY-MODEL.md`: boundaries, defaults and deliberate limitations.
- `docs/PROVENANCE.md`: upstream baseline, attribution and fork decisions.

Core/httpauth/memory have no third-party dependencies. Password hashing uses
golang.org/x/crypto; Postgres uses pgx. Tooling dependencies, generated sqlc
sources and optional modules do not become core runtime dependencies. The
checked-in go.work joins modules for development; published modules contain
actual version requirements without local filesystem replacements.

## Account authentication and expansion

See [account authentication](AUTHENTICATION.md) for v0.4's shared account policy,
password evidence, recent-authentication guard and mandatory account-store upgrade
migration. [The roadmap](ROADMAP.md) places social/OIDC, MFA/passkeys and account
management in planned application capabilities, rather than permanent exclusions.

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
operation. For the complete local password lifecycle use
`password.NewService` with `postgres.NewLocal`, a Hasher, an AttemptLimiter and
an application-supplied Sender. The service constructs its session manager from
the same fenced store and requires verified email for sign-in. Successful
SignIn returns an IssuedSession; send it with transport.WriteCookie, never in
JSON. [Local integration/API guide](../docs/LOCAL-CREDENTIALS.md) includes the
compiling constructor and migration, delivery and operational boundaries.

The older NewAuthenticator remains a low-level compatibility API for externally
managed credentials. It does not implement verification, updates or issuance
fencing. Use the new service for this local account workflow.

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
Schedule Store.PruneExpired explicitly. Session-only users can keep their
existing schema and `postgres.New(pool)` adapter. Local-password users explicitly
apply optional migration `migrations/002_local_credentials.sql` and use
`postgres.NewLocal(pool)` for all local session operations. Auth owns minimal
account/hash/version and challenge state; application profiles, memberships and
RBAC remain application-owned. Schedule LocalStore.PruneExpiredChallenges too.
Never issue or rotate local account sessions through the session-only adapter.

## Local checks

```sh
mise trust
mise install
./scripts/fmt.sh
./scripts/check.sh
./scripts/test.sh -race
./scripts/fuzz.sh
# SQL mutations require the disposable PLUTO_AUTH_TEST_DATABASE_URL below.
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

## Scope

This round implements local password credentials only. Social/federated OIDC
providers, MFA/passkeys, frontend/admin UI and email-address changes are
planned in the [expansion roadmap](ROADMAP.md). OAuth authorization-server and
enterprise identity-platform roles remain separate scope decisions. There are no automatic admins, tenants or grants. Deployment still
requires real delivery, shared limits, trusted ingress, migrations and an
application-specific security review; this is not an audited production-ready
identity service.
