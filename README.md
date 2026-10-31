<p align="center">
  <img src="https://raw.githubusercontent.com/plutoframework/pluto/main/assets/readme/banner.svg" alt="Pluto — a small framework, wide open possibilities" width="100%" />
</p>

# Pluto Auth

Identity with explicit boundaries, from credentials to sessions.

[Website](https://plutoframework.github.io/pluto-site/) · [Documentation](https://plutoframework.github.io/pluto-site/docs/backend/auth/) · [CLI demo](https://github.com/plutoframework/pluto/blob/main/docs/DEMO.md) · [First issues](https://github.com/plutoframework/pluto/blob/main/CONTRIBUTING.md#starter-tasks)

## What you get

- Opaque sessions, secure cookie adapters and typed persistence.
- Optional verified-email enrollment, sign-in, verification and recovery.
- Native TOTP, single-use recovery codes and protected factor changes (unreleased).
- Separate identity from membership, RBAC and resource authorization.

## Get started

### 1. Install

From a Go **1.25.5+** module:

```sh
go get github.com/plutoframework/pluto-auth@v0.4.0
```

Password and PostgreSQL modules are optional; pin them explicitly when needed:

```sh
go get github.com/plutoframework/pluto-auth/methods/password@v0.4.0
go get github.com/plutoframework/pluto-auth/stores/postgres@v0.5.0
```

### 2. Wire the real credential lifecycle

Use the [compiling PostgreSQL constructor](stores/postgres/examples/local/local.go)
and [local-credential guide](docs/LOCAL-CREDENTIALS.md) to construct the password
service, session manager and HTTP transport. Supply a real notification sender,
shared attempt limits, trusted origins and migrations before mounting its handlers.
Successful verified-email sign-in issues the secure session cookie; enrollment
alone grants no application membership or permission.

For a running integration, follow the [purchasing application](https://github.com/plutoframework/pluto-example/blob/main/docs/REFERENCE.md).
Its PostgreSQL-backed enrollment, verification, sign-in and recovery use Mailpit
for local delivery. Replace development delivery and limits for deployment.

### Testing: exercise session middleware in process


This complete in-process walkthrough mounts a protected handler and exercises
anonymous access, a trusted synthetic session and revocation. Save it as
`cmd/session/main.go` and run `go run ./cmd/session`, or run
`go run ./examples/protected-http` from this repository.

<!-- example-source: examples/protected-http/main.go -->

```go
// An in-process HTTP walkthrough with trusted synthetic session issuance.
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/httpauth"
	"github.com/plutoframework/pluto-auth/stores/memory"
)

func application() (http.Handler, *auth.Manager, error) {
	store, err := memory.New(100)
	if err != nil {
		return nil, nil, err
	}

	manager, err := auth.New(store, auth.DefaultConfig())
	if err != nil {
		return nil, nil, err
	}

	transport, err := httpauth.New(manager, httpauth.Config{
		TrustedOrigins: []string{"https://app.example.test"},
		AllowBearer:    true,
	})
	if err != nil {
		return nil, nil, err
	}

	account := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := httpauth.FromContext(r.Context())
		if !ok || session.SubjectID == "" {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		w.Header().Set("Content-Type", "application/json")

		_, _ = w.Write([]byte(`{"authenticated":true}`))
	})
	mux := http.NewServeMux()
	mux.Handle("GET /account", transport.Guard(transport.Require(account)))

	return mux, manager, nil
}

func request(handler http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(
		http.MethodGet,
		"https://app.example.test/account",
		nil,
	)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)

	return response
}

func main() {
	handler, manager, err := application()
	if err != nil {
		panic(err)
	}

	fmt.Println("anonymous:", request(handler, "").Code)

	// Trusted test setup, never a login route. Real apps verify credentials
	// before issuance and use the local credential service for password users.
	issued, err := manager.Start(context.Background(), "synthetic-account")
	if err != nil {
		panic(err)
	}

	fmt.Println("authenticated:", request(handler, issued.Token).Code)

	if err := manager.Revoke(context.Background(), issued.Token); err != nil {
		panic(err)
	}

	fmt.Println("revoked:", request(handler, issued.Token).Code)
}
```

<!-- /example-source -->

Expected output:

```text
anonymous: 401
authenticated: 200
revoked: 401
```

Session issuance is trusted fixture setup, never an HTTP login endpoint. The
example deliberately opts into bearer auth for its synthetic API client. Browser
apps should use the secure cookie adapter; real password accounts use the
credential service and its version fence. The [tests](examples/protected-http/main_test.go)
exercise the mounted route without printing tokens. Memory is development-only.

## Account authentication foundation

Password sign-in now persists server-owned method evidence. Rotation preserves
its original verification time; sensitive routes can require recent verification.
The [account authentication guide](docs/AUTHENTICATION.md) includes the migration,
HTTP guard and custom-store compatibility contract. The optional
[native second-factor workflow](https://plutoframework.github.io/pluto-site/docs/backend/totp/) adds TOTP, pending sign-in,
single-use recovery codes and protected factor changes. See the
[expansion roadmap](docs/ROADMAP.md) for remaining ecosystem integration.

## Read further

- [API and integration reference](docs/REFERENCE.md)
- [Field guide](https://plutoframework.github.io/pluto-site/docs/backend/auth/)
- [Pluto ecosystem](https://github.com/plutoframework/pluto#the-ecosystem)

## Boundaries

An independent Limen hard fork: preserve LICENSE, NOTICE and provenance. Pre-release and not independently audited. Read the security model before deployment.

## Contribute

Start with [CONTRIBUTING.md](CONTRIBUTING.md), then choose a [good first issue](https://github.com/plutoframework/pluto/blob/main/CONTRIBUTING.md#starter-tasks).

MIT licensed. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## OIDC and Google sign-in

Use the optional [OIDC workflow](docs/OIDC.md) for native provider sign-in with
PKCE, verified ID tokens, encrypted PostgreSQL login transactions and fenced
account sessions. Apply migration 004 on account-backed upgrades. Email strings
never merge accounts; linking and native MFA remain separate roadmap work.
