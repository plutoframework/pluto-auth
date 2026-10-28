# Working on Pluto Auth

- This is an independent, pre-release hard fork of Limen. Preserve LICENSE,
  NOTICE and docs/PROVENANCE.md. Upstream history is intentionally retained.
- Core, httpauth and the memory store remain standard-library-only. Optional
  methods/password and stores/postgres are separate Go modules.
- Authentication establishes identity. Do not implement roles, permissions,
  tenant selection or ownership checks here; use Pluto RBAC and application
  membership/resource policies. Never trust client-supplied roles or tenant IDs.
- Use explicit injection and typed persistence. No package globals for active
  configuration, init registration, generic map-based queries or startup DDL.
- Never persist/log raw session tokens or passwords. Store token digests and
  Argon2id PHC hashes. Keep cookie, Origin, expiration and cancellation checks.
- Store Use and Consume must be atomic with revocation. Consume is single use.
  Activity/rotation cannot extend absolute expiry. Revocation does not cancel
  in-flight authorized requests or prevent future/concurrent session issuance.
- Keep files under 1,000 lines, with the configurable 80-column formatting
  target and expanded whitespace. Split source; never compress to evade limits.
- Run scripts/fmt.sh, scripts/check.sh, scripts/test.sh -race, scripts/fuzz.sh
  and scripts/mutation-smoke.py for security behavior changes. Build errors and
  timeouts do not count as killed mutants. Postgres integration needs a
  disposable PLUTO_AUTH_TEST_DATABASE_URL and must pass in CI.
- Do not claim an independent security audit or production readiness. Document
  missing auth flows and storage/concurrency limits honestly.
