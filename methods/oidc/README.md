# OIDC protocol boundary (unreleased)

This module is the first increment of [auth issue 1](https://github.com/plutoframework/pluto-auth/issues/1).
It is not yet a complete sign-in workflow or a published module release.

- Discovery, authorization-code exchange and RS256 ID-token verification.
- Exact configured issuer, client audience, authorized party and nonce checks.
- S256 PKCE and expiring one-use transactions bound to a browser cookie.
- HTTPS-only discovered endpoints, disabled redirects, bounded response bodies
  and a bounded HTTP timeout. Basic client authentication only; no automatic
  exchange retries. Hosts must trust the configured issuer and transport.
- Verified identity consists only of issuer and subject. No email-based linking,
  business permissions, account creation or session issuance.

## Required host boundaries

`Transactions` must persist pending secrets securely with bounded capacity.
`Consume` must atomically match state, browser digest and expiry before deleting.
A wrong browser must not delete someone else's transaction. The included memory
implementation is a test fixture, not a production adapter.

The host generates a high-entropy browser binding and stores it in a Secure,
HttpOnly, SameSite=Lax cookie. It rate-limits begin/callback, rejects malformed or
duplicate callback query parameters, sets no-store responses and prevents secret
logging. Errors exposed to browsers must remain generic. The library does not
implement a public HTTP callback yet.

## Remaining work before release

- PostgreSQL transactions and external identity persistence, including a deliberate
  migration for accounts without a password hash.
- Account resolution through the current disabled/security-version/factor fence.
- Public HTTP boundary, Google profile, explicit linking and consumer scaffolds.
- Real PostgreSQL concurrency/rollback coverage and expanded protocol cases.

Do not mark the parent issue or milestone complete based on this module.

## Dependency boundary

CoreOS `go-oidc/v3` v3.21.0 verifies signed OIDC tokens; Go OAuth2 v0.36.0
implements code exchange. `go-jose/v4` v4.1.4 is transitive. These optional
pure-Go dependencies do not enter Auth's standard-library root. The pins retain
Go 1.25.5 compatibility; OAuth2 v0.37 requires Go 1.26.

```sh
GOWORK=off go test -race ./...
GOWORK=off go test -run '^$' -fuzz FuzzCallbackInput -fuzztime=5s
```

Tests use a TLS issuer with real RSA signatures. They are deterministic protocol
checks and do not claim a live provider test or independent security audit.
