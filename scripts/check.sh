#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"

python3 - <<'PYTHON'
from pathlib import Path

for path in Path('.').rglob('*'):
    if not path.is_file() or '.git' in path.parts:
        continue
    data = path.read_bytes()
    if b'\0' not in data and len(data.splitlines()) > 1000:
        raise SystemExit(f'File exceeds 1,000 lines: {path}')
PYTHON

for module in . methods/password stores/postgres; do
  cd "$root/$module"
  "$root/scripts/golangci.sh" fmt --diff ./... > /tmp/pluto-auth-format-$$.diff
  if [[ -s /tmp/pluto-auth-format-$$.diff ]]; then
    cat /tmp/pluto-auth-format-$$.diff
    rm /tmp/pluto-auth-format-$$.diff
    exit 1
  fi
  rm /tmp/pluto-auth-format-$$.diff
  "$root/scripts/golangci.sh" run ./...
  go test ./...
  go vet ./...
  go build ./...
done
