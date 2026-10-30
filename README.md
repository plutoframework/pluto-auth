<p align="center">
  <img src="https://raw.githubusercontent.com/plutoframework/pluto/main/assets/readme/banner.svg" alt="Pluto — a small framework, wide open possibilities" width="100%" />
</p>

# Pluto Auth

Identity with explicit boundaries, from credentials to sessions.

[Website](https://plutoframework.github.io/pluto-site/) · [Documentation](https://plutoframework.github.io/pluto-site/docs/backend/auth/) · [CLI demo](https://github.com/plutoframework/pluto/blob/main/docs/DEMO.md) · [First issues](https://github.com/plutoframework/pluto/blob/main/CONTRIBUTING.md#starter-tasks)

## What you get

- Opaque sessions, secure cookie adapters and typed persistence.
- Optional verified-email enrollment, sign-in, verification and recovery.
- Separate identity from membership, RBAC and resource authorization.

## Get started

### 1. Install

From a Go **1.25.5+** module:

```sh
go get github.com/plutoframework/pluto-auth@v0.3.0
```

Password and PostgreSQL modules are optional; pin them explicitly when needed:

```sh
go get github.com/plutoframework/pluto-auth/methods/password@v0.3.0
go get github.com/plutoframework/pluto-auth/stores/postgres@v0.3.0
```

### 2. Start with session construction

Save this as `cmd/session/main.go`, then run `go run ./cmd/session`:

```go
package main

import (
    "fmt"

    auth "github.com/plutoframework/pluto-auth"
    "github.com/plutoframework/pluto-auth/stores/memory"
)

func main() {
    store, err := memory.New(100)
    if err != nil {
        panic(err)
    }

    _, err = auth.New(store, auth.DefaultConfig())
    if err != nil {
        panic(err)
    }

    fmt.Println("Session manager ready")
}
```

This bounded memory example demonstrates construction, not production storage.
It issues no token and grants no role.

### 3. Wire credential flows deliberately

Follow the [credential integration guide](docs/LOCAL-CREDENTIALS.md). Supply real
delivery, shared attempt limits and trusted ingress; apply migrations explicitly.
Use the HTTP adapter's secure cookies and Origin checks. Enrollment grants no
business membership, and authentication never replaces resource authorization.

## Read further

- [API and integration reference](docs/REFERENCE.md)
- [Field guide](https://plutoframework.github.io/pluto-site/docs/backend/auth/)
- [Pluto ecosystem](https://github.com/plutoframework/pluto#the-ecosystem)

## Boundaries

An independent Limen hard fork: preserve LICENSE, NOTICE and provenance. Pre-release and not independently audited. Read the security model before deployment.

## Contribute

Start with [CONTRIBUTING.md](CONTRIBUTING.md), then choose a [good first issue](https://github.com/plutoframework/pluto/blob/main/CONTRIBUTING.md#starter-tasks).

MIT licensed. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
