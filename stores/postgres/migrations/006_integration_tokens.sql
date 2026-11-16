-- Optional service-caller integration tokens. Apply explicitly, never at
-- startup. It is independent of the account tables (002-005): it needs no
-- accounts, sessions or foreign keys. Only token digests are stored.
CREATE TABLE pluto_auth_integration_tokens (
    id text PRIMARY KEY CHECK (id <> ''),
    token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    tenant_id text NOT NULL CHECK (tenant_id <> ''),
    principal text NOT NULL CHECK (principal <> ''),
    created_at timestamptz NOT NULL,
    rotated_at timestamptz,
    revoked_at timestamptz
);

CREATE INDEX pluto_auth_integration_tokens_tenant_idx
    ON pluto_auth_integration_tokens (tenant_id, principal);
