#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Go 1.25 can fail when duration-based fuzzing expires (go.dev/issue/75804).
# Use execution budgets; the test timeout bounds initial corpus checks.
# CI separately limits the entire fuzz step to five minutes.
# HTTP targets construct requests, so use a smaller execution budget.
go test -run '^$' -fuzz '^FuzzTokenDigest$' \
  -fuzztime=250000x -timeout=2m -parallel=2 .
go test -run '^$' -fuzz '^FuzzCeremonyTransitions$' \
  -fuzztime=250000x -timeout=2m -parallel=2 .
cd methods/password
go test -run '^$' -fuzz '^FuzzPHCParser$' \
  -fuzztime=250000x -timeout=2m -parallel=2 .
go test -run '^$' -fuzz '^FuzzEmailAndChallenge$' \
  -fuzztime=250000x -timeout=2m -parallel=2 .
go test -run '^$' -fuzz '^FuzzBoundedJSON$' \
  -fuzztime=5000x -timeout=2m -parallel=2 ./passwordhttp

cd ../totp
go test -run '^$' -fuzz '^FuzzMatch$' \
  -fuzztime=250000x -timeout=2m -parallel=2 .
go test -run '^$' -fuzz '^FuzzBoundedJSON$' \
  -fuzztime=5000x -timeout=2m -parallel=2 ./totphttp

cd ../oidc
go test -run '^$' -fuzz '^FuzzCallbackInput$' \
  -fuzztime=250000x -timeout=2m -parallel=2 .
