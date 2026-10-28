-- Optional additive local-password migration. Apply schema.sql (001 sessions)
-- first. Existing session-only deployments do not need this migration.
CREATE TABLE pluto_auth_accounts (
    id text PRIMARY KEY CHECK (id <> ''),
    email text NOT NULL UNIQUE CHECK (email <> '' AND email = lower(email)),
    password_hash text NOT NULL CHECK (password_hash <> ''),
    credential_version bigint NOT NULL DEFAULT 1 CHECK (credential_version > 0),
    verified boolean NOT NULL DEFAULT false,
    disabled boolean NOT NULL DEFAULT false
);

CREATE TABLE pluto_auth_challenges (
    token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    account_id text NOT NULL REFERENCES pluto_auth_accounts(id) ON DELETE CASCADE,
    purpose text NOT NULL CHECK (purpose IN ('verify_email', 'recover_password')),
    credential_version bigint NOT NULL CHECK (credential_version > 0),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
    UNIQUE (account_id, purpose)
);
CREATE INDEX pluto_auth_challenges_expiry_idx ON pluto_auth_challenges(expires_at);

-- Separate binding preserves the original session-only schema and adapter.
CREATE TABLE pluto_auth_local_sessions (
    token_digest bytea PRIMARY KEY
        REFERENCES pluto_auth_sessions(token_digest) ON DELETE CASCADE,
    account_id text NOT NULL REFERENCES pluto_auth_accounts(id) ON DELETE CASCADE,
    credential_version bigint NOT NULL CHECK (credential_version > 0)
);
