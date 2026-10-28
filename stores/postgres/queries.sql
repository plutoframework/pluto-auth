-- name: CreateSession :exec
INSERT INTO pluto_auth_sessions (
    token_digest, id, subject_id, created_at, expires_at, last_seen_at
) VALUES ($1, $2, $3, $4, $5, $6);

-- name: UseSession :one
UPDATE pluto_auth_sessions
SET last_seen_at = GREATEST(last_seen_at, sqlc.arg(now_at)::timestamptz)
WHERE token_digest = sqlc.arg(digest)
    AND created_at <= sqlc.arg(now_at)::timestamptz
    AND expires_at > sqlc.arg(now_at)::timestamptz
    AND (sqlc.arg(idle_microseconds)::bigint = 0 OR last_seen_at >
        sqlc.arg(now_at)::timestamptz -
        sqlc.arg(idle_microseconds)::bigint * interval '1 microsecond')
RETURNING id, subject_id, created_at, expires_at, last_seen_at;

-- name: ConsumeSession :one
DELETE FROM pluto_auth_sessions
WHERE token_digest = sqlc.arg(digest)
    AND created_at <= sqlc.arg(now_at)::timestamptz
    AND expires_at > sqlc.arg(now_at)::timestamptz
    AND (sqlc.arg(idle_microseconds)::bigint = 0 OR last_seen_at >
        sqlc.arg(now_at)::timestamptz -
        sqlc.arg(idle_microseconds)::bigint * interval '1 microsecond')
RETURNING id, subject_id, created_at, expires_at, last_seen_at;

-- name: DeleteSession :exec
DELETE FROM pluto_auth_sessions WHERE token_digest = $1;

-- name: DeleteSubjectSessions :exec
DELETE FROM pluto_auth_sessions WHERE subject_id = $1;

-- name: PruneExpiredSessions :execrows
DELETE FROM pluto_auth_sessions WHERE expires_at <= $1;
