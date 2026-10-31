# Native second factors (unreleased)

The public [TOTP and recovery guide](https://plutoframework.github.io/pluto-site/docs/backend/totp/)
is the authoritative integration manual. It covers configuration and migrations,
password-pending sign-in, HTTP requests, enrollment/confirmation, recovery policy,
protected factor changes, key management and operational limits.

Implementation entrypoints in this repository:

- `methods/totp`: typed workflow, verifier, limiter/protector contracts and
  optional host-managed AES-256-GCM key ring.
- `methods/totp/totphttp`: bounded, Origin-checked JSON handlers with secure
  browser binding and no regular session before required factor completion.
- `stores/postgres/totp`: account-fenced proof consumption, session issuance and
  factor changes in the same transaction.
- `stores/postgres/migrations/005_totp.sql`: additive migration after 002–004;
  constructors never run DDL.
- [Compiling constructor](../stores/postgres/totp/examples/local/local.go):
  real password/factor integration with explicit host dependencies.

The modules remain unreleased and use local development replacements. Coordinated
module tags must replace those pins before publication. CLI/frontend scaffolding
lives outside this repository and is not implemented by this library change.
This is not an independently audited identity provider or a production-readiness
claim. Never issue local-account sessions through the session-only adapter.
