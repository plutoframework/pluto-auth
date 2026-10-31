# PostgreSQL OIDC adapter

Optional module: `github.com/plutoframework/pluto-auth/stores/postgres/oidc`.
The parent session adapter does not import this module or OIDC dependencies.

- Apply parent migrations 001–004 explicitly before construction.
- `New(pool, key, capacity)` requires a host-managed, nonzero 32-byte AES key.
- `Save` encrypts nonce/PKCE proof with AES-GCM and binds ciphertext to state and
  browser digests. A shared database lock enforces finite pending capacity.
- `Consume` atomically matches state, browser and expiry before removing a row.
  Database time is rechecked after lock waits. Replays cannot exchange a code.
- `ResolveIdentity` uses only verified issuer/subject. Optional first-use enrollment
  creates a passwordless account; existing email strings never merge accounts.
- `Prune` removes up to 1,000 expired transactions. Schedule it periodically.

All replicas must share the same key and capacity policy. Key replacement
invalidates pending logins; it does not revoke established sessions. Store the
key outside the database, protect database backups and set ingress limits. The
fixed capacity lock serializes short begin transactions; it never spans provider
HTTP calls. No network call runs inside account/session database transactions.

Use parent `NewLocal` as the account-backed session store, including for federated
accounts. `Disable` and factor-policy changes apply the same version fence.
Never issue their sessions through the unfenced session-only `New` adapter.
In-flight previously authorized requests may complete after revocation.

Migration 004 preserves local credential data, adds explicit credential-kind
constraints and allows external accounts with empty local identifier/hash. Local
password lookup excludes them. No startup migrations or placeholder passwords.
An external account cannot acquire a local password through password recovery.
Explicit linking and adding credentials are separate protected workflows.

This release supports sign-in/enrollment, not linking/unlinking or native MFA.
Accounts requiring another factor fail closed. Enrollment grants no business role,
organization or resource access. Provider email claims are neither stored nor used.

Run `PLUTO_AUTH_TEST_DATABASE_URL=... go test -race ./...` against a disposable
PostgreSQL database. Tests create/drop isolated schemas and exercise encrypted
transactions, finite capacity, browser binding, concurrent consumption, actual
OIDC HTTP/session issuance, duplicate callbacks, email collision, rotation and
account disable. These tests are not a live Google test or an independent audit.

Browser clients request begin with `Accept: application/json`, then navigate to
`data.authorization_url`. This preserves `Origin` under a no-referrer document
policy. Native form navigation may send `Origin: null` and is rejected, rather
than weakening the trusted-Origin guard. Callback/session cookies remain native.
