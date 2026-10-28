#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
go test -run '^$' -fuzz '^FuzzTokenDigest$' -fuzztime=5s -parallel=2 .
cd methods/password
go test -run '^$' -fuzz '^FuzzPHCParser$' -fuzztime=5s -parallel=2 .
