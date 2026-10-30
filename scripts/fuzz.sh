#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
go test -run '^$' -fuzz '^FuzzTokenDigest$' -fuzztime=5s -parallel=2 .
go test -run '^$' -fuzz '^FuzzCeremonyTransitions$' -fuzztime=5s -parallel=2 .
cd methods/password
go test -run '^$' -fuzz '^FuzzPHCParser$' -fuzztime=5s -parallel=2 .
go test -run '^$' -fuzz '^FuzzEmailAndChallenge$' -fuzztime=5s -parallel=2 .
go test -run '^$' -fuzz '^FuzzBoundedJSON$' -fuzztime=5s -parallel=2 ./passwordhttp
