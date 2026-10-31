# Native second factors (unreleased)

See the [workflow and security contract](../../docs/TOTP.md) for TOTP setup,
pending password sign-in, recovery codes, protected changes and key management.
This optional module uses only the standard library and the root auth module.
`totphttp` supplies bounded, Origin-checked JSON routes and secure browser binding.

Inject a real shared `Limiter`, a host-managed `Protector`, and a `Store` whose
proof consumption/session creation/security changes commit atomically. The
[supplied PostgreSQL adapter](../../stores/postgres/totp) implements that contract.
There is no native-factor memory adapter. Never log setup URIs, codes or seeds.

The local root replacement is a development pin for the unreleased ceremony
metadata API. Coordinated module releases must replace it before publication.
