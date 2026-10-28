-- name: EnrollAccount :exec
INSERT INTO pluto_auth_accounts (id, email, password_hash)
VALUES ($1, $2, $3);

-- name: LookupAccount :one
SELECT * FROM pluto_auth_accounts WHERE email = $1;

-- name: LockAccountEmail :one
SELECT * FROM pluto_auth_accounts WHERE email = $1 FOR UPDATE;

-- name: LockAccountID :one
SELECT * FROM pluto_auth_accounts WHERE id = $1 FOR UPDATE;

-- name: ReplaceChallenge :exec
INSERT INTO pluto_auth_challenges (
    token_digest, account_id, purpose, credential_version, created_at, expires_at
) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (account_id, purpose) DO UPDATE SET
    token_digest = EXCLUDED.token_digest,
    credential_version = EXCLUDED.credential_version,
    created_at = EXCLUDED.created_at,
    expires_at = EXCLUDED.expires_at;

-- name: ChallengeAccount :one
SELECT a.* FROM pluto_auth_accounts a
JOIN pluto_auth_challenges c ON a.id = c.account_id
WHERE c.token_digest = sqlc.arg(digest) AND c.purpose = sqlc.arg(purpose)
    AND c.credential_version = a.credential_version AND NOT a.disabled
    AND c.created_at <= sqlc.arg(now_at)::timestamptz
    AND c.expires_at > sqlc.arg(now_at)::timestamptz
    AND ((c.purpose = 'verify_email' AND NOT a.verified)
        OR (c.purpose = 'recover_password' AND a.verified));

-- name: VerifyAccount :exec
UPDATE pluto_auth_accounts SET verified = true WHERE id = $1;

-- name: ResetAccount :exec
UPDATE pluto_auth_accounts
SET password_hash = $2, credential_version = credential_version + 1
WHERE id = $1;

-- name: DisableAccount :exec
UPDATE pluto_auth_accounts
SET disabled = true, credential_version = credential_version + 1
WHERE id = $1;

-- name: DeleteAccountChallenges :exec
DELETE FROM pluto_auth_challenges WHERE account_id = $1;

-- name: DeleteVerificationChallenge :exec
DELETE FROM pluto_auth_challenges
WHERE account_id = $1 AND purpose = 'verify_email';

-- name: BindLocalSession :exec
INSERT INTO pluto_auth_local_sessions
(token_digest, account_id, credential_version) VALUES ($1, $2, $3);

-- name: UseLocalSession :one
UPDATE pluto_auth_sessions s
SET last_seen_at = GREATEST(s.last_seen_at, sqlc.arg(now_at)::timestamptz)
FROM pluto_auth_local_sessions b, pluto_auth_accounts a
WHERE s.token_digest = sqlc.arg(digest) AND s.token_digest = b.token_digest
    AND s.subject_id = a.id AND b.account_id = a.id
    AND b.credential_version = a.credential_version
    AND a.verified AND NOT a.disabled
    AND s.created_at <= sqlc.arg(now_at)::timestamptz
    AND s.expires_at > sqlc.arg(now_at)::timestamptz
    AND (sqlc.arg(idle_microseconds)::bigint = 0 OR s.last_seen_at >
        sqlc.arg(now_at)::timestamptz -
        sqlc.arg(idle_microseconds)::bigint * interval '1 microsecond')
RETURNING s.id, s.subject_id, s.created_at, s.expires_at, s.last_seen_at,
    b.credential_version;

-- name: ConsumeLocalSession :one
DELETE FROM pluto_auth_sessions s
USING pluto_auth_local_sessions b, pluto_auth_accounts a
WHERE s.token_digest = sqlc.arg(digest) AND s.token_digest = b.token_digest
    AND s.subject_id = a.id AND b.account_id = a.id
    AND b.credential_version = a.credential_version
    AND a.verified AND NOT a.disabled
    AND s.created_at <= sqlc.arg(now_at)::timestamptz
    AND s.expires_at > sqlc.arg(now_at)::timestamptz
    AND (sqlc.arg(idle_microseconds)::bigint = 0 OR s.last_seen_at >
        sqlc.arg(now_at)::timestamptz -
        sqlc.arg(idle_microseconds)::bigint * interval '1 microsecond')
RETURNING s.id, s.subject_id, s.created_at, s.expires_at, s.last_seen_at;

-- name: PruneExpiredChallenges :execrows
DELETE FROM pluto_auth_challenges WHERE expires_at <= $1;

-- name: LookupLocalSessionVersion :one
SELECT credential_version FROM pluto_auth_local_sessions WHERE token_digest = $1;
