# Authentication expansion

Pluto owns common application authentication workflows end to end. Keep the root
standard-library-only and isolate optional protocol dependencies in method modules.
Port useful Limen behavior and tests into typed Pluto boundaries; preserve upstream
attribution, but do not restore its generic schema/plugin framework wholesale.

| Milestone | Status | Deliverable |
| --- | --- | --- |
| Shared account/ceremony foundation | v0.4 | Version/policy fence, method evidence, password integration, freshness guard |
| Social and federated sign-in | In progress | OIDC/Google sign-in delivered; GitHub and explicit linking/unlinking remain |
| Native second-factor workflow | Next | TOTP setup/verification, hashed single-use recovery codes, protected factor changes |
| Account security management | Planned | Email/password changes, session/device management and step-up UI |
| Passwordless and machine access | Planned | Passkeys, magic links and scoped API keys |

Each workflow includes the library, explicit PostgreSQL migration, HTTP adapter,
CLI scaffolding, configured frontend components, runnable documentation and denied
path/concurrency tests. A method is not complete merely because an interface exists.

Common guarantees:

- New methods share account disable/security-version and session revocation rules.
- Incomplete factor challenges never become normal authenticated sessions.
- Linking requires deliberate proof; matching email strings alone do not merge users.
- Authentication creates no business membership, tenant authority or permissions.
- Reset/factor changes cannot silently downgrade authentication requirements.
- No production no-op security dependencies or automatic startup migrations.

Running Pluto as an OAuth/OIDC authorization server, SAML federation and SCIM are
separate scope decisions. They are not prerequisites for ordinary social sign-in.

Tracking: [OIDC vertical](https://github.com/plutoframework/pluto-auth/issues/1),
[provider adapters](https://github.com/plutoframework/pluto-auth/issues/2),
[explicit linking](https://github.com/plutoframework/pluto-auth/issues/3) and the
[ecosystem index](https://github.com/plutoframework/pluto/issues/1).
