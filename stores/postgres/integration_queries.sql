-- name: InsertIntegrationToken :exec
INSERT INTO pluto_auth_integration_tokens
    (id, token_digest, tenant_id, principal, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: LookupIntegrationToken :one
SELECT id, tenant_id, principal, created_at
FROM pluto_auth_integration_tokens
WHERE token_digest = $1 AND revoked_at IS NULL;

-- name: RotateIntegrationToken :one
UPDATE pluto_auth_integration_tokens
SET token_digest = sqlc.arg(new_digest), rotated_at = clock_timestamp()
WHERE id = $1 AND revoked_at IS NULL
RETURNING id, tenant_id, principal, created_at;

-- name: RevokeIntegrationToken :exec
UPDATE pluto_auth_integration_tokens
SET revoked_at = clock_timestamp()
WHERE id = $1 AND revoked_at IS NULL;
