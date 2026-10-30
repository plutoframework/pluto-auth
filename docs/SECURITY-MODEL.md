# Security contract

## Identity and authorization

Manager.Start is a trusted issuance primitive, not a login endpoint. It must
only follow verified credentials or another trusted authentication ceremony.
Password.Service provides the local credential lifecycle with verified-email
sign-in and auth-owned minimal account storage. The older Authenticator verifies
application-owned credentials only and does not supply lifecycle fencing.

Sessions carry a subject, not roles or a selected tenant. Resolve verified
memberships and pass their role IDs to Pluto RBAC in the application. Independently
enforce resource ownership, tenant boundaries and database query scoping. Never
derive roles from unsigned client claims or assume authentication grants access.

## Sessions and persistence

Tokens contain 32 cryptographically random bytes and are encoded as canonical
unpadded base64url. Only SHA-256 digests enter SessionStore. IssuedSession excludes
the token from JSON but callers must still avoid logging or formatting it.

The default absolute lifetime is 24 hours and idle timeout is 30 minutes. Use
explicit deployment settings for risk-sensitive apps. Activity cannot extend
the absolute deadline. Clock values must be UTC-consistent across app instances.
Custom clocks and stores must be concurrency safe. PostgreSQL timestamps have
microsecond precision; its adapter rounds positive idle durations up to that
precision, while the core uses Go's duration precision.

Use and Consume atomically validate expiry and idle activity. Rotation consumes
the old record before issuing a replacement, preserves the absolute deadline,
and cannot restore the old token after failure. Concurrent rotations have one
winner. Rotation is not fresh credential verification: do not use CreatedAt as
proof of recent authentication for sensitive actions. Such actions require a
separate credential challenge.

Revocation affects subsequent store operations, not requests already authorized.
DeleteSubject revokes records present at that operation; it is not a barrier
against concurrent or future issuance. The local password service and LocalStore add an issuance barrier: Create locks
the account and checks its credential version, verified flag and disabled flag.
Reset/Disable lock the same row, increment its version and delete all challenges
and sessions in one transaction. An old-password sign-in or consumed session
rotation cannot issue after that commit. Sessions issued before commit are
revoked by that transaction. Rotation retains the version. This guarantee needs
the same LocalStore for every local session operation; plain Store, custom
stores, direct SQL updates or a second issuance path can bypass it. Already
authorized requests still run; sensitive business transactions need their own
cooperative account-state/authorization checks.

Postgres operations never upsert activity. The application applies migrations
explicitly and schedules PruneExpired. Give the runtime DB role only the required
DML access, use TLS in production, and isolate migration privileges. Memory mode
is bounded and process local; a restart revokes all its sessions. It scans records
to prune expired entries during issuance and is not intended for large deployments.

## Browser boundary

httpauth uses a Secure, HttpOnly, SameSite=Lax, Path=/ cookie named
__Host-pluto_session without Domain. HTTPS is required; there is no insecure
production-cookie fallback. Cookie-authenticated unsafe methods require one exact
allowlisted Origin. Missing, null, multiple and untrusted origins fail closed.
Forwarded headers cannot override the origin allowlist.

Require includes the Origin guard for cookie credentials. Explicit bearer
credentials are opt-in (AllowBearer defaults false); unsafe bearer requests do
not require Origin because those credentials are not automatically attached by
browsers. Duplicate Authorization headers and any combination of session cookie
and Authorization fail closed. Token extracts the same credential for revocation
and never authenticates it on its own. Apply Guard to login and all unauthenticated
state-changing authentication routes as well. GET/HEAD/OPTIONS must never perform
business mutations. Configure credentialed CORS and TLS/proxy trust separately;
this package does not reflect arbitrary origins or provide CORS middleware.
SameSite=Lax supports same-site frontends; unrelated frontend sites and third-party
cookie restrictions need a separate design. Do not silently loosen these defaults.

## Password boundary

The optional module uses golang.org/x/crypto/argon2, random 16-byte salts,
32-byte derived keys and PHC encoding. Default costs are 64 MiB, 3 iterations,
4 lanes, and one concurrent computation per Hasher. Tune only after measuring
deployment capacity. The accepted verification range is 19–256 MiB, 2–6
iterations and 1–16 lanes. Old hashes outside that range need a deliberate
migration/reset policy. Never automatically downgrade stronger stored hashes.

Parsing checks exact algorithm/version and parameter structure before allocating
Argon2 memory. Passwords are limited to 1,024 bytes without truncation. Hash is a
cryptographic primitive: enrollment must separately enforce password length and
compromised-password policies. It does not silently normalize Unicode or trim.

Queueing honors cancellation, but an executing Argon2 computation cannot be
preempted. Bound HTTP bodies and concurrent requests at ingress as well. A
bounded compute semaphore does not itself bound the number of waiting requests.

Authenticator requires an AttemptLimiter. Provide bounded per-account limits
with storage shared by all production instances, plus trusted per-client ingress
limits. Identifiers must be canonical before sign-in to avoid alternate-key
limit bypasses. A no-op limiter is not a production implementation. Unknown
accounts receive dummy hash verification; this is not a constant-time network
API, particularly when stored hash parameters or DB lookup latency differ.

Wrong passwords, unknown and disabled accounts return ErrInvalidCredentials.
Storage/cancellation/hash errors fail closed. Map internal errors to generic
client responses; do not expose account existence, database errors or PHC hashes.

## Scope and verification

This is pre-release library code, not an independently audited identity provider.
Local enrollment, verification/resend, password sign-in, recovery/reset and
disable are implemented in the optional password/Postgres modules. Federated
OIDC/social providers, MFA/passkeys, OAuth authorization servers, API keys,
JWT issuance, frontend/admin UI, email changes, audit delivery and step-up auth
are planned in [the expansion roadmap](ROADMAP.md). The current release adds
[shared account decisions and evidence](AUTHENTICATION.md), not those method
implementations. The application explicitly mounts routes. See
[local credential contract](LOCAL-CREDENTIALS.md) for detailed policy, atomicity,
notification and integration requirements.

Tests cover session deadlines/revocation/rotation, password and parser failures,
HTTP cookies/origins, cancellation, and bounded fuzz and mutation samples. These
checks do not establish exhaustive coverage. Review new authentication methods
and account workflows before exposing them in production.
