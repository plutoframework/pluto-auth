# Account-backed authentication

Pluto Auth v0.4 adds shared account policy, server-local authentication decisions
and method evidence. The first integrated method is the existing password
service. This is the foundation for native social sign-in, MFA and step-up flows;
the optional [OIDC workflow](OIDC.md) now verifies provider sign-in. Native TOTP
verification is available in the optional [native second-factor workflow](TOTP.md)
(unreleased).

## Upgrade

Session-only users of `postgres.New` retain their original schema and API.
Account-backed `postgres.NewLocal` users must explicitly apply these in order:

1. `schema.sql` — original sessions.
2. `migrations/002_local_credentials.sql` — password accounts and challenges.
3. `migrations/003_authentication.sql` — account factor policy and evidence.
4. `migrations/004_external_accounts.sql` — explicit local/external credential kinds.
5. Optionally, `migrations/005_totp.sql` — native TOTP factors, pending challenges
   and recovery digests, when using `stores/postgres/totp`.

Apply each once through application migration tooling. No constructor runs DDL.
Migration 003 preserves old sessions with **unknown** authentication evidence.
They continue ordinary authentication but cannot satisfy recent-authentication
checks until the user signs in again. Rotation does not upgrade their evidence.

## Password sign-in records real verification

Use the existing `password.Service` with `postgres.NewLocal`. Its `SignIn`
verifies the password, creates a completed server-local decision and atomically
issues through the account-backed store. No extra ceremony code is needed in a
normal password login handler. The existing HTTP adapter sets the secure cookie.

`Session.Authentication` contains the original primary method/time and, when
verified by a configured method adapter, additional-factor method/time. It is
server-only metadata, omitted from JSON. `CreatedAt` remains the session record's
creation time; it is not proof of recent authentication after rotation.

## Protect a sensitive operation

This mounting excerpt assumes the existing local-credential `handler`, a mux,
and an application handler which retains RBAC and resource checks:

```go
sensitive, err := handler.Transport().RequireAuthentication(
	auth.Requirement{MaxAge: 5 * time.Minute},
	authorizedPurchaseDecision,
)
if err != nil {
	return err
}

mux.Handle("POST /api/purchases/{purchaseID}/decision", sensitive)
```

Imports include `auth "github.com/plutoframework/pluto-auth"` and `time`.
The guard first authenticates the cookie or explicitly enabled bearer credential
and preserves Origin validation. Missing authentication returns 401; insufficient
or stale evidence returns 403 with `authentication_required`. Re-signing in
through the existing password flow creates fresh evidence. The guard does not
redirect or invent a reauthentication UI, and it grants no business permission.
For operations called outside HTTP (including agent tools), carry the verified
session in server-owned dependencies and apply `CheckAuthentication` or
`Evidence.Check` at the operation boundary too. Never trust client-supplied evidence.

`Requirement{SecondFactor: true}` additionally requires verified factor evidence.
`MaxAge` measures the original primary verification, including after rotation;
reaching the exact age limit fails closed. Future timestamps and legacy unknown
evidence fail closed. These method labels are not NIST assurance-level claims.

## Method adapters share one decision

`auth.AccountState` contains the subject, shared security version, disabled state
and required-factor policy. It contains no password hash, role or tenant.
`NewCeremony` starts an immutable server-local decision with a bounded lifetime.
Verified method adapters advance it through:

- `awaiting_primary`: no identity proof has completed.
- `awaiting_factor`: primary verified, required additional verification missing.
- `authenticated`: the declared requirements are satisfied.

`password.Service.BeginSignIn` verifies the real password and returns the latter
two stages without issuing a token. `Complete` cannot produce an issuance proof
while required verification is missing. `Manager.StartAuthenticated` only accepts
a completed, unexpired proof and an `AccountSessionStore` implementation.

**Transitions do not verify credentials.** `PrimaryVerified` and
`SecondFactorVerified` accept facts from trusted method implementations only.
Never call them from request/model method labels or reconstruct a decision from
browser JSON. The decision is not a session, pending cookie, bearer challenge or
durable workflow. Method adapters own challenge storage, expiration, binding,
one-time proof consumption and account recovery.

The PostgreSQL store rechecks account/version/policy under the same row lock used
by reset, disable and factor-policy changes. It checks the issuance deadline
against database time after lock waits, rolling back incomplete session inserts.
A prior lookup or completed decision
cannot override a newer policy. Rotation preserves evidence and the original
absolute session deadline. Password recovery does not remove a required factor.

## Policy management and compatibility

`LocalStore.SetSecondFactorRequired` is a trusted server policy primitive. Both
changes advance the account version and atomically revoke its sessions and
password challenges. It is not enrollment or recovery. Do not enable this policy
until a verified factor implementation and a recovery path are configured.
The optional [TOTP module](TOTP.md) now provides enrollment/verification and
recovery with protected lifecycle APIs. Corresponding cross-repository CLI/UI
flows remain follow-up work; they are not supplied by the core foundation.

The existing `Start` and `StartVersioned` remain trusted issuance primitives.
`LocalStore` rejects them when they would bypass a required factor. Never issue
local-account sessions through the session-only `postgres.New` adapter.

Custom legacy `password.AccountStore` implementations keep their existing API.
Their `SignIn` retains versioned issuance without manufacturing method evidence.
To support evidence, implement `auth.AccountSessionStore.CreateAuthenticated`,
atomically check current account state with `AccountState.Accepts`, preserve
evidence through use/consume, and reject policy bypass through legacy Create.
A session-only store cannot silently substitute for this contract.

## Verification

Tests cover incomplete/expired decisions, method ordering, original timestamps,
unknown legacy evidence, HTTP Origin/freshness checks, password recovery and
PostgreSQL migration/rotation. Barrier tests change account policy between proof
completion and session creation. Existing reset/disable issuance-race tests cover
the preferred account-backed path. Fuzz and mutation checks are bounded samples;
no independent security audit or complete identity-provider claim is made.

See the [expansion roadmap](ROADMAP.md) and
[OWASP authentication guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
