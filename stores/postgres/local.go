package postgres

import (
	"context"
	_ "embed"
	"errors"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/methods/password"
	"github.com/plutoframework/pluto-auth/stores/postgres/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// LocalSchema is optional migration 002; apply AFTER the original Schema.
// No constructor executes DDL. Session-only users need neither this migration
// nor LocalStore. Use LocalStore for ALL local account issuance and rotation.
//
//go:embed migrations/002_local_credentials.sql
var LocalSchema string

// AuthenticationSchema adds shared account policy and session evidence after
// LocalSchema. Existing account-backed deployments explicitly apply it on upgrade.
//
//go:embed migrations/003_authentication.sql
var AuthenticationSchema string

// ExternalSchema allows accounts without password credentials after migration 003.
//
//go:embed migrations/004_external_accounts.sql
var ExternalSchema string

// TransactionDB must start top-level transactions, never nested savepoints.
// A pgxpool.Pool is appropriate; pgx.Tx intentionally does not implement it.
type TransactionDB interface {
	DBTX
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// LocalStore adds accounts, single-use challenges and credential-fenced session
// issuance. The original Store remains the session-only adapter. Do not use that
// adapter to issue or rotate sessions for local-password account subjects.
type LocalStore struct {
	*Store
	database TransactionDB
}

func NewLocal(database TransactionDB) (*LocalStore, error) {
	base, err := New(database)
	if err != nil {
		return nil, err
	}

	return &LocalStore{Store: base, database: database}, nil
}

func (s *LocalStore) transaction(ctx context.Context,
	operation func(*db.Queries) error,
) error {
	tx, err := s.database.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return err
	}

	defer func() {
		rollbackContext, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()

		_ = tx.Rollback(rollbackContext)
	}()

	if err := operation(db.New(tx)); err != nil {
		return storeError(err)
	}

	return tx.Commit(ctx)
}

func accountRecord(row db.PlutoAuthAccount) password.Account {
	return password.Account{
		ID:                   row.ID,
		Email:                row.Email,
		Hash:                 row.PasswordHash,
		Version:              row.CredentialVersion,
		Verified:             row.Verified,
		Disabled:             row.Disabled,
		SecondFactorRequired: row.SecondFactorRequired,
	}
}

func replaceChallenge(ctx context.Context, q *db.Queries,
	account password.Account, challenge password.Challenge,
) error {
	return q.ReplaceChallenge(ctx, db.ReplaceChallengeParams{
		TokenDigest: challenge.Digest[:], AccountID: account.ID,
		Purpose: string(challenge.Purpose), CredentialVersion: account.Version,
		CreatedAt: challenge.CreatedAt, ExpiresAt: challenge.ExpiresAt,
	})
}

func (s *LocalStore) Enroll(ctx context.Context,
	account password.Account, challenge password.Challenge,
) error {
	canonical, err := password.CanonicalEmail(account.Email)
	if err != nil || canonical != account.Email || account.Version != 1 ||
		account.Verified || account.Disabled || challenge.Purpose != password.VerifyEmail {
		return password.ErrInvalidConfig
	}

	err = s.transaction(ctx, func(q *db.Queries) error {
		if err := q.EnrollAccount(ctx, db.EnrollAccountParams{
			ID:    account.ID,
			Email: account.Email, PasswordHash: account.Hash,
		}); err != nil {
			return err
		}

		return replaceChallenge(ctx, q, account, challenge)
	})

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" &&
		pgErr.ConstraintName == "pluto_auth_accounts_email_key" {
		return password.ErrConflict
	}

	return err
}

func (s *LocalStore) LookupAccount(ctx context.Context,
	email string,
) (password.Account, error) {
	row, err := s.queries.LookupAccount(ctx, email)
	return accountRecord(row), storeError(err)
}

func (s *LocalStore) ReplaceChallenge(ctx context.Context, email string,
	challenge password.Challenge,
) (password.Account, error) {
	var account password.Account

	err := s.transaction(ctx, func(q *db.Queries) error {
		row, err := q.LockAccountEmail(ctx, email)
		if err != nil {
			return err
		}

		account = accountRecord(row)

		eligible := challenge.Purpose == password.VerifyEmail &&
			!account.Verified ||
			challenge.Purpose == password.RecoverPassword && account.Verified
		if account.Disabled || !eligible {
			return auth.ErrNotFound
		}

		return replaceChallenge(ctx, q, account, challenge)
	})

	return account, err
}

func challengeAccount(ctx context.Context, q *db.Queries,
	purpose password.Purpose, digest auth.Digest, now time.Time,
) (password.Account, error) {
	row, err := q.ChallengeAccount(ctx, db.ChallengeAccountParams{
		Digest: digest[:], Purpose: string(purpose), NowAt: now,
	})

	return accountRecord(row), storeError(err)
}

func (s *LocalStore) ChallengeAccount(ctx context.Context,
	purpose password.Purpose, digest auth.Digest, now time.Time,
) (password.Account, error) {
	return challengeAccount(ctx, s.queries, purpose, digest, now)
}

// Resolve without locking, lock the account, then recheck the challenge. Every
// writer locks account BEFORE modifying challenges/sessions, avoiding inverse
// lock order and rejecting superseded tokens after a lock wait.
func lockedChallenge(ctx context.Context, q *db.Queries,
	purpose password.Purpose, digest auth.Digest, now time.Time,
) (password.Account, error) {
	account, err := challengeAccount(ctx, q, purpose, digest, now)
	if err != nil {
		return password.Account{}, err
	}

	if _, err := q.LockAccountID(ctx, account.ID); err != nil {
		return password.Account{}, err
	}

	return challengeAccount(ctx, q, purpose, digest, now)
}

func (s *LocalStore) Verify(ctx context.Context,
	digest auth.Digest, now time.Time,
) error {
	return s.transaction(ctx, func(q *db.Queries) error {
		account, err := lockedChallenge(
			ctx,
			q,
			password.VerifyEmail,
			digest,
			now,
		)
		if err != nil {
			return err
		}

		if err := q.VerifyAccount(ctx, account.ID); err != nil {
			return err
		}

		return q.DeleteVerificationChallenge(ctx, account.ID)
	})
}

func (s *LocalStore) Reset(ctx context.Context, digest auth.Digest,
	version int64, hash string, now time.Time,
) error {
	return s.transaction(ctx, func(q *db.Queries) error {
		account, err := lockedChallenge(
			ctx,
			q,
			password.RecoverPassword,
			digest,
			now,
		)
		if err != nil {
			return err
		}

		if account.Version != version {
			return auth.ErrNotFound
		}

		if err := q.ResetAccount(ctx, db.ResetAccountParams{
			ID: account.ID, PasswordHash: hash,
		}); err != nil {
			return err
		}

		return invalidateAccount(ctx, q, account.ID)
	})
}

func (s *LocalStore) Disable(ctx context.Context, id string) error {
	return s.transaction(ctx, func(q *db.Queries) error {
		if _, err := q.LockAccountID(ctx, id); err != nil {
			return err
		}

		if err := q.DisableAccount(ctx, id); err != nil {
			return err
		}

		return invalidateAccount(ctx, q, id)
	})
}

func invalidateAccount(ctx context.Context, q *db.Queries, id string) error {
	if err := q.DeleteAccountChallenges(ctx, id); err != nil {
		return err
	}

	return q.DeleteSubjectSessions(ctx, id)
}

func (s *LocalStore) PruneExpiredChallenges(ctx context.Context,
	now time.Time,
) (int64, error) {
	return s.queries.PruneExpiredChallenges(ctx, now)
}

var _ password.AccountStore = (*LocalStore)(nil)
