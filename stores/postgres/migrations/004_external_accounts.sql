-- Explicit migration after 003. Passwordless accounts have no local identifier
-- or hash. No placeholder passwords and no provider email-based account merge.
ALTER TABLE pluto_auth_accounts
    ADD COLUMN local_credentials boolean NOT NULL DEFAULT true;
ALTER TABLE pluto_auth_accounts
    DROP CONSTRAINT pluto_auth_accounts_email_key,
    DROP CONSTRAINT pluto_auth_accounts_email_check,
    DROP CONSTRAINT pluto_auth_accounts_password_hash_check;
ALTER TABLE pluto_auth_accounts ADD CONSTRAINT account_credentials CHECK (
    (local_credentials AND email <> '' AND email = lower(email)
        AND password_hash <> '') OR
    (NOT local_credentials AND email = '' AND password_hash = '')
);
CREATE UNIQUE INDEX pluto_auth_accounts_email_key
    ON pluto_auth_accounts(email) WHERE local_credentials;

CREATE TABLE pluto_auth_external_identities (
    issuer text NOT NULL CHECK (issuer <> '' AND octet_length(issuer) <= 2048),
    subject text NOT NULL CHECK (subject <> '' AND octet_length(subject) <= 1024),
    account_id text NOT NULL REFERENCES pluto_auth_accounts(id) ON DELETE CASCADE,
    PRIMARY KEY (issuer, subject)
);
CREATE INDEX pluto_auth_external_account_idx
    ON pluto_auth_external_identities(account_id);

CREATE TABLE pluto_auth_oidc_transactions (
    state_digest bytea PRIMARY KEY CHECK (octet_length(state_digest) = 32),
    browser_digest bytea NOT NULL CHECK (octet_length(browser_digest) = 32),
    encrypted_proof bytea NOT NULL CHECK (octet_length(encrypted_proof) <= 2048),
    expires_at timestamptz NOT NULL
);
CREATE INDEX pluto_auth_oidc_expiry_idx ON pluto_auth_oidc_transactions(expires_at);
