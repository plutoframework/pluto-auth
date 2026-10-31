#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"
for module in . methods/password methods/oidc methods/totp stores/postgres stores/postgres/oidc stores/postgres/totp; do
  cd "$root/$module"
  go test "$@" ./...
done
