# PostgreSQL native factors (unreleased)

`totppostgres.New` composes the account-fenced `postgres.LocalStore` with typed
native-factor transactions. Apply schema and migrations 002–005 explicitly;
construction never runs DDL. Use this same store for password sign-in, factor
completion and all account-backed sessions/rotation. Do not use the session-only
adapter to issue account sessions.

See the [workflow guide](../../../docs/TOTP.md) and
[compiling constructor](examples/local/local.go). Supply host-managed seed
protection, real shared attempt/ingress limits, verified notifications and HTTPS.
Schedule `Store.Prune` for expired challenges. One pending record per account and
action bounds challenge growth per account; hosts still bound account creation.

Integration tests require a disposable `PLUTO_AUTH_TEST_DATABASE_URL`. They
create/drop isolated schemas and exercise actual PostgreSQL locks and rollback.
The local module replacements are development pins for unreleased APIs/schema;
replace them with coordinated published versions before releasing these modules.
