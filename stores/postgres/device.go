package postgres

import (
	"context"
	_ "embed"
	"errors"
	"slices"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/device"

	"github.com/jackc/pgx/v5"
)

// DeviceSchema is optional migration 006 (device authorization grant).
//
//go:embed migrations/006_device_grants.sql
var DeviceSchema string

// DeviceStore persists device requests and token families. Every operation
// that must be atomic runs in one transaction holding row locks.
type DeviceStore struct {
	database TransactionDB
}

func NewDevice(database TransactionDB) (*DeviceStore, error) {
	if database == nil {
		return nil, auth.ErrInvalidConfig
	}

	return &DeviceStore{database: database}, nil
}

func (s *DeviceStore) transaction(
	ctx context.Context,
	operation func(pgx.Tx) error,
) error {
	tx, err := s.database.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return err
	}

	err = operation(tx)

	// A commitError persists the transaction's writes, then reports its cause.
	var settled *commitError
	if errors.As(err, &settled) {
		if err := tx.Commit(ctx); err != nil {
			return err
		}

		return settled.cause
	}

	if err != nil {
		rollback, cancel := context.WithTimeout(
			context.Background(), 5*time.Second)
		defer cancel()

		_ = tx.Rollback(rollback)

		return err
	}

	return tx.Commit(ctx)
}

// commitError carries a protocol failure whose side effects (for example a
// family revocation after refresh reuse) must still be committed.
type commitError struct{ cause error }

func (e *commitError) Error() string { return e.cause.Error() }

func (s *DeviceStore) CreateAuthorization(
	ctx context.Context,
	a device.Authorization,
) error {
	return s.transaction(ctx, func(tx pgx.Tx) error {

		// Expired requests (including one holding this user code) are
		// pruned in small batches so abandoned requests cannot accumulate.
		if _, err := tx.Exec(ctx, `
DELETE FROM pluto_auth_device_requests
WHERE user_digest = $1 AND expires_at <= $2
   OR id IN (
       SELECT id FROM pluto_auth_device_requests
       WHERE expires_at <= $2 LIMIT 16)`,
			a.User[:], a.CreatedAt); err != nil {
			return err
		}

		tag, err := tx.Exec(ctx, `
INSERT INTO pluto_auth_device_requests (
    id, device_digest, user_digest, client_id, scopes, created_at,
    expires_at, interval_ms, state)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')
ON CONFLICT DO NOTHING`,
			a.ID, a.Device[:], a.User[:], a.ClientID, a.Scopes, a.CreatedAt,
			a.ExpiresAt, a.Interval.Milliseconds())
		if err != nil {
			return err
		}

		if tag.RowsAffected() != 1 {
			return device.ErrConflict
		}

		return nil
	})
}

const requestColumns = `
id, device_digest, user_digest, client_id, scopes, created_at, expires_at,
last_polled_at, interval_ms, state, subject_id, tenant_id, approved_scopes`

func scanRequest(row pgx.Row) (device.Authorization, error) {
	var (
		a        device.Authorization
		deviceD  []byte
		userD    []byte
		polled   *time.Time
		interval int64
	)

	err := row.Scan(&a.ID, &deviceD, &userD, &a.ClientID, &a.Scopes,
		&a.CreatedAt, &a.ExpiresAt, &polled, &interval, &a.State,
		&a.Subject, &a.Tenant, &a.Approved)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, device.ErrNotFound
	}

	if err != nil {
		return a, err
	}

	copy(a.Device[:], deviceD)
	copy(a.User[:], userD)

	if polled != nil {
		a.LastPolled = *polled
	}

	a.Interval = time.Duration(interval) * time.Millisecond

	return a, nil
}

func (s *DeviceStore) FindAuthorization(
	ctx context.Context,
	user auth.Digest,
	now time.Time,
) (device.Authorization, error) {
	return scanRequest(s.database.QueryRow(ctx, `SELECT `+requestColumns+`
FROM pluto_auth_device_requests
WHERE user_digest = $1 AND expires_at > $2`, user[:], now))
}

func (s *DeviceStore) Decide(
	ctx context.Context,
	user auth.Digest,
	now time.Time,
	decision device.Decision,
) error {
	return s.transaction(ctx, func(tx pgx.Tx) error {
		a, err := scanRequest(tx.QueryRow(ctx, `SELECT `+requestColumns+`
FROM pluto_auth_device_requests
WHERE user_digest = $1 AND expires_at > $2 FOR UPDATE`, user[:], now))
		if err != nil {
			return err
		}

		if a.State != device.StatePending {
			return device.ErrNotFound
		}

		if !decision.Approve {
			_, err = tx.Exec(ctx, `
UPDATE pluto_auth_device_requests SET state = 'denied' WHERE id = $1`, a.ID)

			return err
		}

		for _, scope := range decision.Scopes {
			if !slices.Contains(a.Scopes, scope) {
				return device.ErrScope
			}
		}

		_, err = tx.Exec(ctx, `
UPDATE pluto_auth_device_requests
SET state = 'approved', subject_id = $2, tenant_id = $3, approved_scopes = $4
WHERE id = $1`, a.ID, decision.Subject, decision.Tenant, decision.Scopes)

		return err
	})
}

func (s *DeviceStore) Poll(
	ctx context.Context,
	code auth.Digest,
	now time.Time,
	r device.Redemption,
) (device.PollResult, error) {
	var result device.PollResult

	err := s.transaction(ctx, func(tx pgx.Tx) error {
		a, err := scanRequest(tx.QueryRow(ctx, `SELECT `+requestColumns+`
FROM pluto_auth_device_requests WHERE device_digest = $1 FOR UPDATE`, code[:]))
		if err != nil {
			return err
		}

		if a.ClientID != r.ClientID {
			return device.ErrNotFound
		}

		if !now.Before(a.ExpiresAt) {
			if _, err := tx.Exec(ctx, `
DELETE FROM pluto_auth_device_requests WHERE id = $1`, a.ID); err != nil {
				return err
			}

			return &commitError{cause: device.ErrExpired}
		}

		if !a.LastPolled.IsZero() &&
			now.Before(a.LastPolled.Add(a.Interval)) {
			a.Interval += r.Step

			if _, err := tx.Exec(ctx, `
UPDATE pluto_auth_device_requests
SET last_polled_at = $2, interval_ms = $3 WHERE id = $1`,
				a.ID, now, a.Interval.Milliseconds()); err != nil {
				return err
			}

			result = device.PollResult{
				State: device.PollSlowDown, Interval: a.Interval,
			}

			return nil
		}

		if _, err := tx.Exec(ctx, `
UPDATE pluto_auth_device_requests SET last_polled_at = $2 WHERE id = $1`,
			a.ID, now); err != nil {
			return err
		}

		switch a.State {
		case device.StateDenied:
			result.State = device.PollDenied

			_, err = tx.Exec(ctx, `
DELETE FROM pluto_auth_device_requests WHERE id = $1`, a.ID)

			return err
		case device.StateApproved:
			grant := device.Grant{
				ID: r.GrantID, Subject: a.Subject, Tenant: a.Tenant,
				ClientID: a.ClientID, ActorType: r.ActorType,
				Scopes: a.Approved, CreatedAt: now,
				ExpiresAt: now.Add(r.MaxLifetime),
			}

			if _, err := tx.Exec(ctx, `
INSERT INTO pluto_auth_device_grants (
    id, subject_id, tenant_id, client_id, actor_type, scopes, created_at,
    expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
				grant.ID, grant.Subject, grant.Tenant, grant.ClientID,
				grant.ActorType, grant.Scopes, grant.CreatedAt,
				grant.ExpiresAt); err != nil {
				return err
			}

			if err := insertTokens(ctx, tx, grant, r.AccessID, r.Access,
				r.AccessExpires, r.Refresh, r.RefreshExpires); err != nil {
				return err
			}

			if _, err := tx.Exec(ctx, `
DELETE FROM pluto_auth_device_requests WHERE id = $1`, a.ID); err != nil {
				return err
			}

			result = device.PollResult{State: device.PollIssued, Grant: grant}

			return nil
		}

		result = device.PollResult{
			State: device.PollPending, Interval: a.Interval,
		}

		return nil
	})
	if err != nil {
		return device.PollResult{}, err
	}

	return result, nil
}

func insertTokens(
	ctx context.Context,
	tx pgx.Tx,
	grant device.Grant,
	accessID string,
	access auth.Digest,
	accessExpires time.Time,
	refresh auth.Digest,
	refreshExpires time.Time,
) error {
	if accessExpires.After(grant.ExpiresAt) {
		accessExpires = grant.ExpiresAt
	}

	if refreshExpires.After(grant.ExpiresAt) {
		refreshExpires = grant.ExpiresAt
	}

	if _, err := tx.Exec(ctx, `
INSERT INTO pluto_auth_device_tokens (digest, kind, id, grant_id, expires_at)
VALUES ($1, 'access', $2, $3, $4)`,
		access[:], accessID, grant.ID, accessExpires); err != nil {
		return err
	}

	_, err := tx.Exec(ctx, `
INSERT INTO pluto_auth_device_tokens (digest, kind, id, grant_id, expires_at)
VALUES ($1, 'refresh', $2, $3, $4)`,
		refresh[:], accessID+".r", grant.ID, refreshExpires)

	return err
}

const grantColumns = `
g.id, g.subject_id, g.tenant_id, g.client_id, g.actor_type, g.scopes,
g.created_at, g.expires_at, g.revoked_at`

func scanGrant(row pgx.Row, extra ...any) (device.Grant, error) {
	var (
		g       device.Grant
		revoked *time.Time
	)

	dest := append([]any{
		&g.ID, &g.Subject, &g.Tenant, &g.ClientID,
		&g.ActorType, &g.Scopes, &g.CreatedAt, &g.ExpiresAt, &revoked,
	}, extra...)

	err := row.Scan(dest...)
	if errors.Is(err, pgx.ErrNoRows) {
		return g, device.ErrNotFound
	}

	if revoked != nil {
		g.RevokedAt = *revoked
	}

	return g, err
}

func (s *DeviceStore) Rotate(
	ctx context.Context,
	presented auth.Digest,
	now time.Time,
	r device.Rotation,
) (device.Grant, error) {
	var out device.Grant

	err := s.transaction(ctx, func(tx pgx.Tx) error {
		var (
			expires time.Time
			used    *time.Time
		)

		grant, err := scanGrant(tx.QueryRow(ctx, `
SELECT `+grantColumns+`, t.expires_at, t.used_at
FROM pluto_auth_device_tokens t
JOIN pluto_auth_device_grants g ON g.id = t.grant_id
WHERE t.digest = $1 AND t.kind = 'refresh' FOR UPDATE OF t, g`,
			presented[:]), &expires, &used)
		if err != nil {
			return err
		}

		if grant.ClientID != r.ClientID {
			return device.ErrNotFound
		}

		if used != nil {
			if _, err := tx.Exec(ctx, `
UPDATE pluto_auth_device_grants SET revoked_at = COALESCE(revoked_at, $2)
WHERE id = $1`, grant.ID, now); err != nil {
				return err
			}

			if _, err := tx.Exec(ctx, `
DELETE FROM pluto_auth_device_tokens
WHERE grant_id = $1 AND kind = 'access'`, grant.ID); err != nil {
				return err
			}

			return &commitError{cause: device.ErrReuse}
		}

		if !grant.Active(now) || !now.Before(expires) {
			return device.ErrNotFound
		}

		for _, scope := range r.Narrow {
			if !slices.Contains(grant.Scopes, scope) {
				return device.ErrScope
			}
		}

		if len(r.Narrow) > 0 {
			grant.Scopes = r.Narrow

			if _, err := tx.Exec(ctx, `
UPDATE pluto_auth_device_grants SET scopes = $2 WHERE id = $1`,
				grant.ID, grant.Scopes); err != nil {
				return err
			}
		}

		if _, err := tx.Exec(ctx, `
UPDATE pluto_auth_device_tokens SET used_at = $2 WHERE digest = $1`,
			presented[:], now); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, `
DELETE FROM pluto_auth_device_tokens
WHERE grant_id = $1 AND kind = 'access'`, grant.ID); err != nil {
			return err
		}

		out = grant

		return insertTokens(ctx, tx, grant, r.AccessID, r.Access,
			r.AccessExpires, r.Refresh, r.RefreshExpires)
	})
	if err != nil {
		return device.Grant{}, err
	}

	return out, nil
}

func (s *DeviceStore) Access(
	ctx context.Context,
	digest auth.Digest,
	now time.Time,
) (device.Grant, device.Token, error) {
	var token device.Token

	grant, err := scanGrant(s.database.QueryRow(ctx, `
SELECT `+grantColumns+`, t.id, t.expires_at
FROM pluto_auth_device_tokens t
JOIN pluto_auth_device_grants g ON g.id = t.grant_id
WHERE t.digest = $1 AND t.kind = 'access' AND t.expires_at > $2
  AND g.revoked_at IS NULL AND g.expires_at > $2`,
		digest[:], now), &token.ID, &token.ExpiresAt)

	return grant, token, err
}

func (s *DeviceStore) RevokeToken(
	ctx context.Context,
	digest auth.Digest,
) error {
	return s.transaction(ctx, func(tx pgx.Tx) error {
		return revokeWhere(ctx, tx, `
id = (SELECT grant_id FROM pluto_auth_device_tokens WHERE digest = $1)`,
			digest[:])
	})
}

func revokeWhere(
	ctx context.Context,
	tx pgx.Tx,
	condition string,
	args ...any,
) error {
	if _, err := tx.Exec(ctx, `
DELETE FROM pluto_auth_device_tokens WHERE kind = 'access' AND grant_id IN (
    SELECT id FROM pluto_auth_device_grants WHERE `+condition+`)`,
		args...); err != nil {
		return err
	}

	_, err := tx.Exec(ctx, `
UPDATE pluto_auth_device_grants SET revoked_at = now()
WHERE revoked_at IS NULL AND `+condition, args...)

	return err
}

func (s *DeviceStore) RevokeGrant(
	ctx context.Context,
	subject, id string,
) error {
	return s.transaction(ctx, func(tx pgx.Tx) error {
		var found string

		err := tx.QueryRow(ctx, `
SELECT id FROM pluto_auth_device_grants
WHERE id = $1 AND subject_id = $2 AND revoked_at IS NULL FOR UPDATE`,
			id, subject).Scan(&found)
		if errors.Is(err, pgx.ErrNoRows) {
			return device.ErrNotFound
		}

		if err != nil {
			return err
		}

		return revokeWhere(ctx, tx, `id = $1`, id)
	})
}

func (s *DeviceStore) RevokeSubject(
	ctx context.Context,
	subject string,
) error {
	return s.transaction(ctx, func(tx pgx.Tx) error {
		return revokeWhere(ctx, tx, `subject_id = $1`, subject)
	})
}

func (s *DeviceStore) ListGrants(
	ctx context.Context,
	subject string,
	now time.Time,
) ([]device.Grant, error) {
	rows, err := s.database.Query(ctx, `
SELECT `+grantColumns+` FROM pluto_auth_device_grants g
WHERE g.subject_id = $1 AND g.revoked_at IS NULL AND g.expires_at > $2
ORDER BY g.created_at, g.id`, subject, now)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var out []device.Grant

	for rows.Next() {
		grant, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}

		out = append(out, grant)
	}

	return out, rows.Err()
}

func (s *DeviceStore) Prune(
	ctx context.Context,
	now time.Time,
) (int64, error) {
	var removed int64

	err := s.transaction(ctx, func(tx pgx.Tx) error {
		first, err := tx.Exec(ctx, `
DELETE FROM pluto_auth_device_requests WHERE expires_at <= $1`, now)
		if err != nil {
			return err
		}

		second, err := tx.Exec(ctx, `
DELETE FROM pluto_auth_device_grants WHERE expires_at <= $1`, now)
		if err != nil {
			return err
		}

		removed = first.RowsAffected() + second.RowsAffected()

		return nil
	})

	return removed, err
}

var _ device.Store = (*DeviceStore)(nil)
