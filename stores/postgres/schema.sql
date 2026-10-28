-- Apply explicitly through the application's migration tooling.
-- Authentication never creates or modifies a schema during startup.
CREATE TABLE pluto_auth_sessions (
    token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    id text NOT NULL UNIQUE CHECK (id <> ''),
    subject_id text NOT NULL CHECK (subject_id <> ''),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    CHECK (expires_at > created_at),
    CHECK (last_seen_at >= created_at)
);

CREATE INDEX pluto_auth_sessions_subject_idx
    ON pluto_auth_sessions (subject_id);

CREATE INDEX pluto_auth_sessions_expiry_idx
    ON pluto_auth_sessions (expires_at);
