# Local password credential lifecycle

This MVP owns an account ID, canonical email, Argon2id password hash, verified /
disabled flags, credential version and one challenge per purpose. It owns no
application profile, role, tenant or membership. Enrollment never grants access
to business resources. Social/federated OIDC, MFA, OAuth authorization servers,
frontend/admin UI and email-address changes remain outside this round.

## Configure the service and HTTP adapter

Requires Go 1.25.5+, PostgreSQL, explicit migrations, an HTTPS application origin,
a context-aware notification sender, account attempt limits and trusted-client
ingress limits. Install the published modules:

```sh
go get github.com/plutoframework/pluto-auth@v0.3.0
go get github.com/plutoframework/pluto-auth/methods/password@v0.3.0
go get github.com/plutoframework/pluto-auth/stores/postgres@v0.3.0
```

This complete composition function builds the actual PostgreSQL-backed service
and POST-only HTTP adapter. The caller supplies delivery and limit enforcement;
those arguments are required integrations, not optional no-op defaults.

<!-- example-source: stores/postgres/examples/local/local.go -->

```go
// Package local shows explicit construction with application-owned delivery and
// limits. It does not bootstrap demo credentials, listen or send any messages.
package local

import (
	"context"
	"net/http"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/httpauth"
	"github.com/plutoframework/pluto-auth/methods/password"
	"github.com/plutoframework/pluto-auth/methods/password/passwordhttp"
	"github.com/plutoframework/pluto-auth/stores/postgres"

	"github.com/jackc/pgx/v5/pgxpool"
)

// New assumes Schema and LocalSchema were explicitly migrated. Production
// callers supply shared account limits, trusted-client ingress limits, a real
// sender with fixed HTTPS link destinations, and optionally a local blocklist.
func New(
	ctx context.Context,
	pool *pgxpool.Pool,
	sender password.Sender,
	limiter password.AttemptLimiter,
	ingress func(http.Handler) http.Handler,
	trustedOrigins []string,
	policy password.PasswordPolicy,
) (*password.Service, *passwordhttp.Handler, error) {
	store, err := postgres.NewLocal(pool)
	if err != nil {
		return nil, nil, err
	}

	hasher, err := password.NewHasher(password.DefaultConfig())
	if err != nil {
		return nil, nil, err
	}

	config := password.DefaultLifecycleConfig()
	config.Policy = policy

	service, err := password.NewService(
		ctx,
		store,
		hasher,
		limiter,
		sender,
		auth.DefaultConfig(),
		config,
	)
	if err != nil {
		return nil, nil, err
	}

	handler, err := passwordhttp.New(service, passwordhttp.Config{
		Transport: httpauth.Config{
			TrustedOrigins: trustedOrigins,
		},
		Ingress: ingress,
	})
	if err != nil {
		return nil, nil, err
	}

	return service, handler, nil
}
```

<!-- /example-source -->

Call `New` during application startup, handle its error, then mount the returned
handler. This mounting excerpt assumes `handler` came from that constructor and
`profileHandler` is your existing application handler:

```go
mux := http.NewServeMux()
mux.Handle("/auth/", http.StripPrefix("/auth", handler))
mux.Handle("GET /api/profile", handler.Transport().Require(profileHandler))
```

The adapter sets the secure session cookie after verified-email sign-in. Keep
HTTPS and the exact trusted Origin configured. `profileHandler` reads the
verified session with `httpauth.FromContext(request.Context())`, then resolves
membership and resource permissions through application operations.

### Apply schemas and wire dependencies

1. Apply the original `stores/postgres/schema.sql` as migration 001, then optional
   `stores/postgres/migrations/002_local_credentials.sql` as migration 002 through
   application migration tooling. No startup DDL is performed. Existing
   session-only users need no new schema or accounts and can retain `postgres.New`.
2. Construct `postgres.NewLocal(pool)`, `password.NewHasher`, and
   `password.NewService(ctx, store, hasher, limiter, sender, sessionConfig,
   lifecycleConfig)`. Sender and limiter are mandatory. Service constructs the
   manager against that same account/session backend.
3. Construct `passwordhttp.New(service, config)`. Supply exact TrustedOrigins in
   config.Transport and mandatory config.Ingress. Mount it explicitly, for example
   `mux.Handle("/auth/", http.StripPrefix("/auth", handler))`. Use HTTPS.
4. Remove demo password maps and all demo `manager.Start(subject)` login paths.
   Protect business routes with `handler.Transport().Require(...)` and read
   `httpauth.FromContext`. Resolve app memberships/RBAC separately.
5. Schedule `PruneExpired` and `PruneExpiredChallenges`; choose retention and
   cleanup for abandoned unverified accounts at the application boundary. Do not
   delete/recreate accounts as a substitute for Disable or reset fencing.

Use `service.Sessions()` for authentication, revocation and rotation of local
sessions. Do not use session-only `postgres.New` or direct SQL to issue/rotate
sessions for local account IDs. `StartVersioned` is a trusted primitive, not a
public login API. The older `NewAuthenticator` remains compatible for external
credential stores but does not implement this workflow or its issuance barrier.

## Enroll, verify and sign in

Against your running HTTPS application, submit enrollment with an allowlisted
Origin. This is example input for a disposable development account; choose a
private password for real accounts:

```sh
curl --fail-with-body https://app.example.test/auth/enroll \
  --header 'Origin: https://app.example.test' \
  --json @- <<'JSON'
{
  "email": "reader@example.test",
  "password": "A long local example password 42!"
}
JSON
```

A successful request returns HTTP 202 with `{"code":"accepted"}`. That same
response is used for duplicate or ineligible enrollment, so it does not prove an
account was created. The configured sender delivers the verification challenge.
The confirmation page explicitly POSTs its token to `/auth/verify`; it must not
submit automatically on page load or consume tokens on GET.

After verification, POST the account's email/password to `/auth/signin` with the
same trusted Origin. The browser receives a Secure, HttpOnly session cookie;
there is no session token in JSON. Send same-origin browser API requests with
cookies. Protect business routes with `Require`, then perform membership/RBAC and
resource checks. Public enrollment grants none of those permissions.

For recovery, POST email to `/auth/recovery`. The reset page explicitly submits
the delivered token and new password to `/auth/reset`. Successful reset revokes
old sessions; the user signs in again. POST `/auth/logout` to revoke the active
session and clear its cookie. The table below gives every route's exact input.

The [full purchasing application](https://github.com/plutoframework/pluto-example/blob/main/docs/REFERENCE.md)
implements these HTTP flows with real PostgreSQL and local Mailpit delivery.
Its Mailpit sender is a development adapter, not a production email provider.

## Service API and HTTP wire contract

All methods take context. `Enroll(email, password)`, RequestVerification(email)
and RequestRecovery(email) return only an error; they never return account IDs,
tokens or challenge state. Successful requests receive `202 {"code":"accepted"}`
regardless of duplicate enrollment, nonexistent account or ineligible state.
Duplicate enrollment does not replace an existing password or challenge.
RequestVerification sends only for unverified, enabled accounts; recovery sends
only for verified, enabled accounts. Explicit resend replaces the previous
challenge of that purpose. Wrong password, unknown, unverified and disabled
accounts all return ErrInvalidCredentials / the same HTTP 401 response.

The adapter exposes these relative routes, all POST and JSON:

| Route | Input | Success |
| --- | --- | --- |
| `/enroll` | `email`, `password` | 202 accepted |
| `/verification` | `email` | 202 accepted |
| `/verify` | `token` | 200 accepted |
| `/signin` | `email`, `password` | 200 accepted + secure session cookie |
| `/recovery` | `email` | 202 accepted |
| `/reset` | `token`, `password` | 200 accepted; reauthentication required |
| `/logout` | session cookie; no body required | 200 accepted + cleared cookie |

No raw challenge/session token appears in response JSON. Input is bounded to
8 KiB with typed decoding, unknown/duplicate fields, non-object bodies, trailing
JSON and wrong content types rejected. New password policy errors are generic
400, invalid/expired/replayed challenges generic 400, limiter denial/failure 429,
other dependency failures generic 503. OnError receives redacted public sentinels;
Transport.WriteError can customize Origin/session middleware responses. Never
log request bodies, cookies, authorization headers or error values from senders.
All responses passing the Origin guard set Cache-Control: no-store.

The entire adapter, including login and unauthenticated changes, requires exact
Origin validation for unsafe methods. This also applies to its opt-in bearer
logout route; broader httpauth bearer behavior remains unchanged. GET and HEAD
never consume challenges: they receive a method error. A frontend confirmation
page can receive an emailed token, then explicitly POST it with the trusted
Origin. It must not auto-submit on page load. Link scanners therefore cannot
verify/reset merely by GET. Do not put passwords/tokens into API query strings.

## Identifier and password policy

Email policy is deliberately limited: ASCII dot-atom local part (1–64 bytes),
DNS domain with at least two labels (each 1–63 bytes), whole address at most
254 bytes. No whitespace trimming, display names, quoted locals, address
literals, SMTPUTF8, Unicode/IDNA conversion or provider-specific alias rewriting.
Both parts are lowercased by application policy, including the normally
case-sensitive SMTP local part. Do not migrate existing case-distinct identifiers
without reviewing collisions. All lookup and limiter keys use the same canonical
value. Delivery uses that value, not an unchecked input/header.

Enrollment/reset require at least 15 Unicode code points of valid UTF-8 and at
most 1,024 bytes. Spaces and Unicode are permitted without composition rules,
trimming or normalization; byte-distinct strings remain distinct passwords.
Sign-in checks the exact supplied bytes against the stored hash. The optional
PasswordPolicy can reject compromised/common passwords using a local corpus;
any error fails closed. Supply a maintained blocklist policy in deployments
that need it; no external service or network call is mandatory or bundled.
There is no claim of NIST conformance. The length choice follows the
[NIST single-factor password guidance](https://pages.nist.gov/800-63-4/sp800-63b.html).

The existing bounded Argon2id hasher is reused. Reset uses HashAtLeast, preserving
each memory/iteration/parallelism and salt/key length dimension of a stronger
stored hash. Sign-in never rewrites a hash. NeedsRehash remains a parameter
difference indicator, not permission to replace a stronger hash with defaults;
custom migrations should use HashAtLeast and the same transaction fence.

## Challenges, transactions and revocation

Each challenge has 256 random bits from crypto/rand and canonical base64url
encoding. Storage sees SHA-256(purpose || NUL || token), never the raw token.
Verification and recovery use distinct digest namespaces and explicit purposes.
The sole outstanding challenge per account/purpose is replaced on resend; an
old/superseded token fails. Default verification TTL is 24 hours (maximum 48),
recovery 30 minutes (maximum 1 hour). A challenge is valid only when
created <= operation time < expiry and its credential version matches.

Verification locks the account, rechecks the challenge, updates verified state
and deletes the challenge in one transaction. Reset reads the challenge to select
hashing costs, performs KDF work outside the transaction, then locks the account
and rechecks purpose, expiry, eligibility and expected version. It updates the
hash, increments credential version and deletes every challenge and subject
session in one transaction. Failures roll back the entire operation. Concurrent
consumes have one winner. Reset does not sign in automatically.

Session Create locks the same account and checks version, verified and enabled
state before inserting both session and version binding in one transaction.
If an old-password sign-in wins that lock first, reset subsequently deletes its
session. If reset wins first, old-version issuance fails. Disable uses the same
version increment/revocation transaction. Rotation preserves the consumed
version, so a reset/disable between consume and replacement cannot resurrect a
session. Session use additionally checks the version binding and account state.

These guarantees require the same LocalStore and database. Application writes
must use this lifecycle, never update a hash/disabled flag independently.
DeleteSubject alone removes existing records and is not an issuance barrier.
Requests that authenticated before a revocation may finish; sensitive business
transactions need cooperative authorization/state checks. Replicas need a
consistent authoritative database and clock. This is not cross-store atomicity.
The original session-only Store ignores credential versions by design.

## Delivery and retry

Sender.Send receives a sensitive Notification with canonical email, purpose, raw
token and expiry. Supply a real bounded, context-aware sender. There is no
production no-op sender, bundled SMTP account, delivery provider or jobs coupling.
No emails/network messages are sent by tests. Do not log/format Notification;
JSON deliberately omits all its fields.

The transaction commits BEFORE delivery. A provider failure or process crash
between commit and delivery leaves a valid challenge whose raw token cannot be
recovered from storage. Public acceptance is unchanged to avoid a delivery-error
existence oracle. OnDeliveryError receives only ErrDelivery, without recipient,
account ID, token or original provider error. Install this hook for operational
failure metrics; it is not a durable delivery receipt. Ask users to resend or
request recovery again, which replaces the challenge with a new random token.
Do not retry enrollment to resend: duplicate enrollment intentionally does nothing.
Concurrent deliveries can arrive out of order; only the latest challenge works.

Applications construct links from fixed, trusted HTTPS confirmation/reset page
URLs and the purpose. Never use request Host, forwarded headers, client return
URLs or arbitrary redirects. Prefer passing tokens in URL fragments to avoid
server access logs/referrers, and use a no-referrer confirmation page without
third-party content. Raw email links and delivery/outbox payloads are secrets.
Persisting plaintext tokens in an outbox defeats the hashed-at-rest property;
this MVP deliberately uses synchronous post-commit delivery. Any future durable
outbox requires a separately reviewed confidentiality/key-management design.
Recovery behavior follows the
[OWASP reset guidance](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html).

## Limits and deployment responsibilities

AttemptLimiter is mandatory and runs before lookup/hash/send for valid email
requests. Keys are SHA-256(operation || NUL || canonical email); challenge
consumption uses purpose-specific token-derived keys. Malformed input is bounded
and rejected without expensive work. Limiters must have bounded key storage,
expiry and shared enforcement across production replicas; errors deny requests.
Hashing identifiers is not a promise of PII anonymization. WindowLimiter is a
bounded fixed-window implementation for single-process deployment/development;
capacity exhaustion denies new keys instead of evicting active limits. It is
not distributed and offers no horizontal coordination.

The mandatory HTTP ingress middleware must additionally bound concurrency,
queueing and per-client/network requests before JSON/KDF work. Use an ingress
proxy's authenticated client identity or a properly configured trusted-proxy
chain, never an arbitrary X-Forwarded-For value. Configure HTTP read/header/time
limits and application timeouts. Hasher queueing honors cancellation; an active
Argon2 computation cannot be interrupted. Sender must honor context and delivery
timeouts. There is no claim of constant-time network behavior: KDF costs, SQL
lookups, sender work and eligibility paths can differ.

Use TLS for the application and database, restrict runtime DB privileges to DML,
and isolate migration privileges. Bound signup/storage abuse and define abandoned
account retention; the library does not run background cleanup automatically.
Do not tell users to verify enrollment they did not initiate. Email verification
proves mailbox-token possession, not a person's legal identity or membership.

## Verification performed

Unit/security behavior tests cover generic denials, duplicate enrollment,
policy bounds, missing/failed dependencies, delivery-after-commit, supersession,
purpose separation, expiry, replay and concurrent consumption. Barrier tests
pause old-password sign-in at issuance, commit reset/disable, then prove rejection;
rotation also retains its fence. Disposable Postgres tests exercise actual
uniqueness, rollback after partial work, session/challenge deletion and concurrent
consumes. HTTP tests cover Origin, scanner GETs, bounded/ambiguous JSON, cookies
and logout. Fuzzing and focused guard mutations are bounded samples, not exhaustive
verification. A focused maintainer self-review found no high-confidence unresolved
vulnerability in these flows; this is not an independent audit or production
readiness certification.
