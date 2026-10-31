-- Optional native second factors. Apply after 004, never at startup.
CREATE TABLE pluto_auth_totp_factors (
    account_id text PRIMARY KEY REFERENCES pluto_auth_accounts(id) ON DELETE CASCADE,
    generation text NOT NULL,
    encrypted_seed bytea NOT NULL,
    last_step bigint NOT NULL CHECK (last_step >= -1)
);

CREATE TABLE pluto_auth_totp_recovery (
    account_id text NOT NULL REFERENCES pluto_auth_accounts(id) ON DELETE CASCADE,
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    PRIMARY KEY (account_id, digest)
);

CREATE TABLE pluto_auth_totp_pending (
    account_id text NOT NULL REFERENCES pluto_auth_accounts(id) ON DELETE CASCADE,
    purpose text NOT NULL CHECK (purpose IN
        ('signin', 'enroll', 'replace', 'remove', 'regenerate')),
    digest bytea NOT NULL UNIQUE CHECK (octet_length(digest) = 32),
    browser_digest bytea NOT NULL CHECK (octet_length(browser_digest) = 32),
    credential_version bigint NOT NULL,
    primary_method text NOT NULL,
    primary_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    candidate_generation text NOT NULL,
    candidate_seed bytea NOT NULL,
    PRIMARY KEY (account_id, purpose),
    CHECK (expires_at > primary_at),
    CHECK (expires_at <= primary_at + interval '10 minutes')
);
CREATE INDEX pluto_auth_totp_pending_expiry
    ON pluto_auth_totp_pending (expires_at);
