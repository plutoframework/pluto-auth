-- Apply after 001 sessions and 002 local credentials. Existing evidence stays
-- unknown: migration must not manufacture fresh authentication for old sessions.
ALTER TABLE pluto_auth_accounts
    ADD COLUMN second_factor_required boolean NOT NULL DEFAULT false;

ALTER TABLE pluto_auth_local_sessions
    ADD COLUMN primary_method text NOT NULL DEFAULT ''
        CHECK (primary_method IN ('', 'password', 'oidc', 'oauth', 'passkey')),
    ADD COLUMN primary_at timestamptz NOT NULL DEFAULT '0001-01-01 00:00:00+00',
    ADD COLUMN second_factor_method text NOT NULL DEFAULT ''
        CHECK (second_factor_method IN ('', 'totp', 'recovery_code')),
    ADD COLUMN second_factor_at timestamptz NOT NULL DEFAULT '0001-01-01 00:00:00+00',
    ADD CONSTRAINT authentication_primary_time CHECK (
        (primary_method = '') = (primary_at = '0001-01-01 00:00:00+00')
    ),
    ADD CONSTRAINT authentication_factor_time CHECK (
        (second_factor_method = '') =
        (second_factor_at = '0001-01-01 00:00:00+00')
    ),
    ADD CONSTRAINT authentication_factor_order CHECK (
        second_factor_method = '' OR
        (primary_method <> '' AND second_factor_at >= primary_at)
    );
