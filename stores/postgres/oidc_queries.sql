-- name: LockOIDCCapacity :exec
SELECT pg_advisory_xact_lock(734821995);

-- name: PruneOIDCTransactions :execrows
DELETE FROM pluto_auth_oidc_transactions WHERE state_digest IN (
    SELECT state_digest FROM pluto_auth_oidc_transactions
    WHERE expires_at <= clock_timestamp() ORDER BY expires_at LIMIT 1000
);

-- name: SaveOIDCTransaction :execrows
INSERT INTO pluto_auth_oidc_transactions
    (state_digest, browser_digest, encrypted_proof, expires_at)
SELECT $1, $2, $3, $4
WHERE (SELECT count(*) FROM pluto_auth_oidc_transactions)
    < sqlc.arg(capacity)::bigint
    AND clock_timestamp() < $4::timestamptz;

-- name: ConsumeOIDCTransaction :one
DELETE FROM pluto_auth_oidc_transactions
WHERE state_digest = $1 AND browser_digest = $2
    AND expires_at > sqlc.arg(now_at)::timestamptz
    AND expires_at > clock_timestamp()
RETURNING encrypted_proof, expires_at;

-- name: LockExternalIdentity :exec
SELECT pg_advisory_xact_lock(sqlc.arg(lock_key)::bigint);

-- name: LookupExternalIdentity :one
SELECT a.id, a.credential_version, a.disabled, a.second_factor_required
FROM pluto_auth_external_identities e
JOIN pluto_auth_accounts a ON a.id = e.account_id
WHERE e.issuer = $1 AND e.subject = $2 FOR UPDATE OF a;

-- name: CreateExternalAccount :exec
INSERT INTO pluto_auth_accounts
    (id, email, password_hash, local_credentials)
VALUES ($1, '', '', false);

-- name: BindExternalIdentity :exec
INSERT INTO pluto_auth_external_identities (issuer, subject, account_id)
VALUES ($1, $2, $3);
