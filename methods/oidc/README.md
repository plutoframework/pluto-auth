# OpenID Connect sign-in

Optional module: `github.com/plutoframework/pluto-auth/methods/oidc` v0.1.1.

- Signed OIDC discovery/code flow with S256 PKCE, nonce and browser binding.
- Exact configured issuer, client audience and authorized-party validation.
- Bounded HTTPS transport, no redirects or automatic exchange retries.
- `NewGoogle` pins Google's issuer; generic `New` accepts a trusted issuer.
- `Service` resolves issuer/subject through explicit account persistence and
  issues through the shared account/version/factor fence.
- `oidchttp` owns trusted-Origin begin and callback routes and Secure/HttpOnly
  cookies. It never redirects to browser/provider-supplied destinations.

Read the [complete server workflow](../../docs/OIDC.md) and
[PostgreSQL adapter](../../stores/postgres/oidc/README.md). The compiling
composition accepts real provider configuration, a host-managed encryption key
and trusted-client ingress. No credentials or no-op integrations are included.

Identity does not grant business membership or permissions. First-use enrollment
is an explicit choice. Matching email strings never merge accounts. Linking,
unlinking, GitHub OAuth and native factor challenges remain separate milestones;
an account requiring another factor fails closed.

CoreOS OIDC v3.21.0, Go OAuth2 v0.36.0 and go-jose v4.1.4 stay in optional modules;
Auth's root remains standard-library-only. These pins support Go 1.25.5.

```sh
GOWORK=off go test -race ./...
GOWORK=off go test -run '^$' -fuzz FuzzCallbackInput -fuzztime=5s
```

TLS/RSA protocol and PostgreSQL tests verify local contracts. No live Google
call or independent security audit is claimed.
