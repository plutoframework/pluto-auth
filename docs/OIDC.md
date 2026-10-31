# OIDC sign-in

Use an OpenID Connect provider, including Google, through the optional
`methods/oidc` and `stores/postgres/oidc` modules. Identity is the verified
issuer/subject pair. A matching provider email never merges a local account.

## Install and migrate

```sh
go get github.com/plutoframework/pluto-auth/methods/oidc@v0.1.1
go get github.com/plutoframework/pluto-auth/stores/postgres@v0.5.0
go get github.com/plutoframework/pluto-auth/stores/postgres/oidc@v0.1.1
```

Apply the session schema, then migrations 002, 003 and **004_external_accounts.sql**
from the parent PostgreSQL adapter. Existing local-password deployments upgrading
the parent adapter also apply 004. It preserves existing local credentials and
makes credential kind explicit. Constructors run no DDL.

## Configure the provider

Register an exact HTTPS callback, for example
`https://app.example/auth/oidc/callback`. Configure the client ID/secret, issuer
and a separate random 32-byte transaction-encryption key in your secret manager.
Never place client secrets or the key in `pluto.toml`, frontend code or Git.
All replicas share the key and finite pending-transaction capacity.

Use Google issuer `https://accounts.google.com`, or `oidc.NewGoogle` which pins
that issuer. Generic providers must support authorization code, S256 PKCE,
RS256-signed ID tokens and Basic token-endpoint client authentication. Unsupported
profiles fail closed; GitHub OAuth is a separate adapter, not OIDC.

## Wire the server

The complete compiling composition is in
[the PostgreSQL adapter example](../stores/postgres/oidc/example_test.go).
It accepts an existing pool, key, provider configuration and actual trusted-client
ingress limiter. It constructs encrypted persistence, the fenced session manager,
OIDC service and HTTP handler. No test provider, no-op limiter or delivery stub is
substituted in the application example.

Mount using `http.StripPrefix("/auth/oidc", handler)`:

- `POST /auth/oidc/begin` requires an exact trusted Origin. Frontends send
  `Accept: application/json` through a same-origin API request, then navigate to
  `data.authorization_url`. This preserves strict referrer policies and sets a
  Secure/HttpOnly binding cookie. Without that Accept header, trusted clients
  receive the original 303 redirect.
- `GET /auth/oidc/callback` checks state, cookie, nonce, PKCE, signature, issuer,
  audience and authorized party before account resolution and session issuance.
- The final 303 goes to a fixed configured local success path. Browser/provider
  inputs never choose it. Tokens appear only in the Secure/HttpOnly session cookie.

TLS must be available at the browser-facing origin. Do not weaken cookies or allow
HTTP provider endpoints for development. A local TLS proxy can forward to the
loopback API. Configure exact frontend origins and deployment forwarding rules.

## Enrollment and authorization

`allowEnrollment` is an explicit service choice. Disable it for invitation-only
applications. First-use enrollment creates an independent external account with
no local credentials or business membership. An administrator/application workflow
must grant tenant membership separately. Current RBAC/resource checks still run
on every protected operation. No auth response participates in business replay.

Account disable and factor-policy/version changes recheck under the session
issuance fence. Rotation preserves original method evidence. A required second
factor currently denies this sign-in rather than issuing a partial session.
Linking, unlinking and native factor challenges remain separate roadmap issues.

OIDC evidence timestamps describe this verified OIDC transaction. They do not
prove when the user last typed a password at the identity provider. Do not use
that timestamp alone to promise provider credential reauthentication; configure
and validate a provider-specific reauthentication policy for that requirement.

## Operate and test

- Bound begin/callback requests by trusted client identity and concurrency.
- Pending proofs are encrypted, capacity-limited and one use. Prune expiry in
  bounded batches. Failed exchanges require a new begin; no automatic retries.
- Do not log callback queries, provider tokens, cookie values, nonce/PKCE proof or
  client credentials. Configure proxy/access-log redaction too.
- Handle provider downtime with a generic sign-in error and a new login attempt.
- Keep fixed success/callback URLs; never construct them from Host headers.
- Run the TLS/RSA protocol and PostgreSQL/browser tests from the owning modules.
  They validate contracts locally; no live provider call or independent audit is
  claimed.

## Complete composition

<!-- example-source: stores/postgres/oidc/example_test.go -->
```go
package oidcpostgres_test

import (
	"context"
	"net/http"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/httpauth"
	"github.com/plutoframework/pluto-auth/methods/oidc"
	"github.com/plutoframework/pluto-auth/methods/oidc/oidchttp"
	"github.com/plutoframework/pluto-auth/stores/postgres"
	oidcpostgres "github.com/plutoframework/pluto-auth/stores/postgres/oidc"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ConfigureOIDC accepts real host integrations; it does not execute at package
// initialization. Apply explicit migrations before calling it at startup.
func ConfigureOIDC(
	ctx context.Context,
	pool *pgxpool.Pool,
	key []byte,
	provider oidc.Config,
	origins []string,
	ingress func(http.Handler) http.Handler,
) (http.Handler, error) {
	pending, err := oidcpostgres.New(pool, key, 10000)
	if err != nil {
		return nil, err
	}

	accounts, err := postgres.NewLocal(pool)
	if err != nil {
		return nil, err
	}

	sessions, err := auth.New(accounts, auth.DefaultConfig())
	if err != nil {
		return nil, err
	}

	provider.Transactions = pending

	client, err := oidc.New(ctx, provider)
	if err != nil {
		return nil, err
	}

	service, err := oidc.NewService(client, pending, sessions, false)
	if err != nil {
		return nil, err
	}

	return oidchttp.New(service, oidchttp.Config{
		Transport:       httpauth.Config{TrustedOrigins: origins},
		Ingress:         ingress,
		SuccessPath:     "/",
		CookieNamespace: provider.Issuer + ":" + provider.ClientID,
	})
}
```
<!-- /example-source -->
