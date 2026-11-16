-- Optional device authorization grant (RFC 8628). Apply AFTER the sessions
-- schema. Codes and tokens are stored only as SHA-256 digests. No tenant
-- column: these tables are framework identity infrastructure, not tenant data.
CREATE TABLE pluto_auth_device_requests (
    id text PRIMARY KEY CHECK (id <> ''),
    device_digest bytea NOT NULL UNIQUE CHECK (octet_length(device_digest) = 32),
    user_digest bytea NOT NULL UNIQUE CHECK (octet_length(user_digest) = 32),
    client_id text NOT NULL CHECK (client_id <> ''),
    scopes text[] NOT NULL CHECK (cardinality(scopes) > 0),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
    last_polled_at timestamptz,
    interval_ms bigint NOT NULL CHECK (interval_ms > 0),
    state text NOT NULL CHECK (state IN ('pending', 'approved', 'denied')),
    subject_id text NOT NULL DEFAULT '',
    tenant_id text NOT NULL DEFAULT '',
    approved_scopes text[] NOT NULL DEFAULT '{}',
    CHECK (
        state <> 'approved' OR
        (subject_id <> '' AND tenant_id <> '' AND
         cardinality(approved_scopes) > 0 AND approved_scopes <@ scopes)
    )
);

CREATE INDEX pluto_auth_device_requests_expiry_idx
    ON pluto_auth_device_requests (expires_at);

CREATE TABLE pluto_auth_device_grants (
    id text PRIMARY KEY CHECK (id <> ''),
    subject_id text NOT NULL CHECK (subject_id <> ''),
    tenant_id text NOT NULL CHECK (tenant_id <> ''),
    client_id text NOT NULL CHECK (client_id <> ''),
    actor_type text NOT NULL CHECK (actor_type <> ''),
    scopes text[] NOT NULL CHECK (cardinality(scopes) > 0),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
    revoked_at timestamptz
);

CREATE INDEX pluto_auth_device_grants_subject_idx
    ON pluto_auth_device_grants (subject_id);

CREATE INDEX pluto_auth_device_grants_expiry_idx
    ON pluto_auth_device_grants (expires_at);

-- Access rows are deleted on rotation and revocation. Refresh rows stay,
-- marked used, so replaying a rotated token is detected as reuse.
CREATE TABLE pluto_auth_device_tokens (
    digest bytea PRIMARY KEY CHECK (octet_length(digest) = 32),
    kind text NOT NULL CHECK (kind IN ('access', 'refresh')),
    id text NOT NULL CHECK (id <> ''),
    grant_id text NOT NULL
        REFERENCES pluto_auth_device_grants (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);

CREATE INDEX pluto_auth_device_tokens_grant_idx
    ON pluto_auth_device_tokens (grant_id);
