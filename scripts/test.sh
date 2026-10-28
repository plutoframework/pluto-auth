#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"
for module in . methods/password stores/postgres; do
  cd "$root/$module"
  go test "$@" ./...
done
