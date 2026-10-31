// Package totppostgres implements transactional native second-factor storage.
package totppostgres

import (
	"context"
	"errors"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/methods/totp"
	"github.com/plutoframework/pluto-auth/stores/postgres"
	"github.com/plutoframework/pluto-auth/stores/postgres/internal/db"

	"github.com/jackc/pgx/v5"
)

type Store struct {
	*postgres.LocalStore
	database postgres.TransactionDB
}

func New(database postgres.TransactionDB) (*Store, error) {
	local, err := postgres.NewLocal(database)
	if err != nil {
		return nil, err
	}

	return &Store{LocalStore: local, database: database}, nil
}

func (s *Store) transaction(
	ctx context.Context,
	fn func(pgx.Tx, *db.Queries) error,
) error {
	tx, err := s.database.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return err
	}

	defer func() {
		rollback, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()

		_ = tx.Rollback(rollback)
	}()

	if err := fn(tx, db.New(tx)); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func state(row db.PlutoAuthAccount) auth.AccountState {
	return auth.AccountState{
		SubjectID:            row.ID,
		Version:              row.CredentialVersion,
		Disabled:             row.Disabled,
		SecondFactorRequired: row.SecondFactorRequired,
	}
}

func eligible(row db.PlutoAuthAccount, version int64) bool {
	return !row.Disabled && (!row.LocalCredentials || row.Verified) &&
		row.CredentialVersion == version
}

func (s *Store) Save(ctx context.Context, p totp.Pending) error {
	return s.transaction(ctx, func(tx pgx.Tx, q *db.Queries) error {
		row, err := q.LockAccountID(ctx, p.Account.SubjectID)
		if err != nil {
			return err
		}

		var now time.Time
		if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").
			Scan(&now); err != nil {
			return err
		}

		if !eligible(row, p.Account.Version) || p.Browser == (auth.Digest{}) ||
			p.Digest == (auth.Digest{}) || now.Before(p.PrimaryAt) || !now.Before(p.Expires) ||
			p.Expires.After(p.PrimaryAt.Add(10*time.Minute)) ||
			(p.Primary != auth.MethodPassword && p.Primary != auth.MethodOIDC && p.Primary != auth.MethodPasskey && p.Primary != auth.MethodOAuth) {
			return totp.ErrDenied
		}

		_, err = tx.Exec(ctx, `INSERT INTO pluto_auth_totp_pending
   (account_id,purpose,digest,browser_digest,credential_version,primary_method,
    primary_at,expires_at,candidate_generation,candidate_seed)
   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
   ON CONFLICT (account_id,purpose) DO UPDATE SET
    digest=EXCLUDED.digest,browser_digest=EXCLUDED.browser_digest,
    credential_version=EXCLUDED.credential_version,
    primary_method=EXCLUDED.primary_method,primary_at=EXCLUDED.primary_at,
    expires_at=EXCLUDED.expires_at,
    candidate_generation=EXCLUDED.candidate_generation,
    candidate_seed=EXCLUDED.candidate_seed`, p.Account.SubjectID, string(p.Action), p.Digest[:], p.Browser[:], p.Account.Version, string(p.Primary), p.PrimaryAt, p.Expires, p.Candidate.Generation, nonNil(p.Candidate.EncryptedSeed))

		return err
	})
}

func nonNil(value []byte) []byte {
	if value == nil {
		return []byte{}
	}

	return value
}

type queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func load(
	ctx context.Context,
	q queryer,
	digest, browser auth.Digest,
	now time.Time,
) (totp.Pending, error) {
	var (
		p               totp.Pending
		action, primary string
	)

	err := q.QueryRow(ctx, `SELECT p.account_id,p.credential_version,
  a.second_factor_required,p.purpose,p.primary_method,p.primary_at,p.expires_at,
  p.candidate_generation,p.candidate_seed
  FROM pluto_auth_totp_pending p JOIN pluto_auth_accounts a ON a.id=p.account_id
  WHERE p.digest=$1 AND p.browser_digest=$2 AND p.primary_at <= $3
   AND p.expires_at > $3 AND p.expires_at > clock_timestamp()
   AND p.credential_version=a.credential_version AND NOT a.disabled
   AND (NOT a.local_credentials OR a.verified)`, digest[:], browser[:], now).Scan(
		&p.Account.SubjectID, &p.Account.Version, &p.Account.SecondFactorRequired,
		&action, &primary, &p.PrimaryAt, &p.Expires, &p.Candidate.Generation, &p.Candidate.EncryptedSeed)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, totp.ErrDenied
	}

	p.Digest, p.Browser, p.Action, p.Primary = digest, browser, totp.Action(
		action,
	), auth.Method(
		primary,
	)
	p.Candidate.LastStep = -1

	return p, err
}

func (s *Store) Load(
	ctx context.Context,
	digest, browser auth.Digest,
	now time.Time,
) (totp.Pending, error) {
	return load(ctx, s.database, digest, browser, now)
}

func factor(
	ctx context.Context,
	q queryer,
	subject string,
) (totp.Factor, error) {
	var f totp.Factor

	err := q.QueryRow(ctx, `SELECT generation,encrypted_seed,last_step
  FROM pluto_auth_totp_factors WHERE account_id=$1`, subject).Scan(&f.Generation, &f.EncryptedSeed, &f.LastStep)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, auth.ErrNotFound
	}

	return f, err
}

func (s *Store) Factor(
	ctx context.Context,
	subject string,
) (totp.Factor, error) {
	return factor(ctx, s.database, subject)
}

func (s *Store) Prune(ctx context.Context) (int64, error) {
	tag, err := s.database.Exec(
		ctx,
		`DELETE FROM pluto_auth_totp_pending WHERE expires_at <= clock_timestamp()`,
	)

	return tag.RowsAffected(), err
}

var _ totp.Store = (*Store)(nil)
