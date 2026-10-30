# Explicit additive migrations

- 001: apply the original `../schema.sql` (sessions only, unchanged).
- 002: optionally apply `002_local_credentials.sql` for `NewLocal` and the local
  credential lifecycle. This adds separate tables; it does not attach accounts
  to existing opaque sessions or impose a new foreign key on their subjects.

- 003: account-backed v0.4 deployments also apply `003_authentication.sql`.
  It adds factor policy and evidence without granting fresh proof to old sessions.

Migration execution/version tracking and privileges belong to the application.
Constructors never execute DDL. Apply each migration once, in order. Existing
session-only `New` users can continue with 001 alone. Rollback of 002 is an
application migration decision; revoking local sessions before dropping its
binding/account tables is necessary. Do not route local session operations
through the session-only adapter to bypass the account fence.
