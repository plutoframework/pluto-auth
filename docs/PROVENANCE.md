# Provenance and independent maintenance

This repository preserves the complete Limen history through:

- Repository: https://github.com/thecodearcher/limen
- Commit: `a691ec98c6c28ac26c2077e4f8f74b9fe7f4d86a`
- Local baseline tag: `limen-baseline-a691ec9`
- License: MIT, original copyright and permission notice retained in LICENSE
- Baseline captured: 2026-10-27

Before changes, `GOTOOLCHAIN=local GOWORK=off go test ./...` passed in the
upstream root module and the credential-password module using Go 1.25.5 on
darwin/arm64. Other upstream modules were not validated. These results establish
a reference point, not an audit or a guarantee of security.

The first Pluto revision deliberately removes the upstream framework, generic
schema/query machinery, SDKs, authorization system and unrelated auth plugins
from the active tree. Their original implementations and tests remain in Git
history, accessible with `git show limen-baseline-a691ec9:<path>`.

The active session manager, HTTP adapter and typed stores are new Pluto
implementations. The Argon2id/PHC implementation in methods/password/hasher.go
adapts upstream plugins/credential-password/hasher.go. Round-trip, wrong-password,
PHC format, Unicode and long-password invariants are retained in standard Go
tests; upstream test files are not presented as covering the new architecture.
Verification uses encoded costs and validates parameter/length bounds before
computation. Optional modules carry copies of the upstream license and NOTICE.

This is an independent hard fork. There is no API compatibility or automatic
merge commitment. Maintainers should monitor upstream security advisories and
relevant fixes, assess them against this architecture, and port applicable fixes
with regression tests. Direct and transitive runtime dependencies, dev tools and
CI actions are separately pinned/reviewed; a small manifest is not an audit.

The `upstream` Git remote is read-only project provenance. Publish Pluto changes
only to `origin` at github.com/plutoframework/pluto-auth. Retain this document and
attribution if code is moved or split into another repository.

The local credential lifecycle, ASCII email policy, purpose-separated challenges,
POST-only adapter and optional account/challenge/session-binding migration are
new Pluto implementations. Hash replacement reuses the bounded Argon2id hasher
and retains stronger stored cost/salt/key dimensions; no new password algorithm
or social/OIDC provider was forked. Credential versions extend session rotation
without changing the original session-only Postgres schema/API. Transaction
rollback, concurrent challenge consumption and old-password issuance barriers are
covered by disposable Postgres tests. A focused maintainer self-review used the
security-review skill; it is not independent security assurance.
