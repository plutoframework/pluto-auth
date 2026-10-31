package totppostgres

import (
	"context"
	"errors"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/methods/totp"
	"github.com/plutoframework/pluto-auth/stores/postgres/internal/db"

	"github.com/jackc/pgx/v5"
)

func (s *Store) Commit(ctx context.Context, c totp.Commit) error {
	return s.transaction(ctx, func(tx pgx.Tx, q *db.Queries) error {
		row, err := q.LockAccountID(ctx, c.Pending.Account.SubjectID)
		if err != nil {
			return err
		}

		var now time.Time
		if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").
			Scan(&now); err != nil {
			return err
		}

		p, err := load(ctx, tx, c.Pending.Digest, c.Pending.Browser, now)
		if err != nil {
			return err
		}

		if p.Account.SubjectID != row.ID ||
			p.Account.Version != c.Pending.Account.Version ||
			p.Action != c.Pending.Action ||
			!eligible(row, p.Account.Version) ||
			(!row.LocalCredentials && p.Primary != auth.MethodOIDC) ||
			!now.Before(p.PrimaryAt.Add(5*time.Minute)) {
			return totp.ErrDenied
		}

		f, err := factor(ctx, tx, row.ID)

		exists := err == nil
		if err != nil && !errors.Is(err, auth.ErrNotFound) {
			return err
		}

		if f.Generation != c.ExpectedGeneration {
			return totp.ErrDenied
		}

		if p.Action == totp.Enroll {
			if exists || row.SecondFactorRequired {
				return totp.ErrDenied
			}
		} else {
			if !exists {
				return totp.ErrDenied
			}

			if c.Recovery != (auth.Digest{}) {
				tag, err := tx.Exec(ctx, `DELETE FROM pluto_auth_totp_recovery
     WHERE account_id=$1 AND digest=$2`, row.ID, c.Recovery[:])
				if err != nil {
					return err
				}

				if tag.RowsAffected() != 1 {
					return totp.ErrDenied
				}
			} else {
				if c.Step <= f.LastStep || !currentStep(c.Step, now) {
					return totp.ErrDenied
				}

				if _, err := tx.Exec(
					ctx,
					`UPDATE pluto_auth_totp_factors SET last_step=$2
     WHERE account_id=$1`,
					row.ID,
					c.Step,
				); err != nil {
					return err
				}
			}
		}

		if p.Action == totp.SignIn {
			if !row.SecondFactorRequired {
				return totp.ErrDenied
			}

			if err := insertSession(ctx, q, state(row), p, c); err != nil {
				return err
			}

			_, err = tx.Exec(
				ctx,
				`DELETE FROM pluto_auth_totp_pending WHERE digest=$1`,
				p.Digest[:],
			)

			return err
		}

		switch p.Action {
		case totp.Enroll, totp.Replace:
			if p.Candidate.Generation == "" ||
				len(p.Candidate.EncryptedSeed) == 0 ||
				!currentStep(c.NewStep, now) {
				return totp.ErrDenied
			}

			_, err = tx.Exec(
				ctx,
				`INSERT INTO pluto_auth_totp_factors
    (account_id,generation,encrypted_seed,last_step) VALUES ($1,$2,$3,$4)
    ON CONFLICT (account_id) DO UPDATE SET generation=EXCLUDED.generation,
    encrypted_seed=EXCLUDED.encrypted_seed,last_step=EXCLUDED.last_step`,
				row.ID,
				p.Candidate.Generation,
				p.Candidate.EncryptedSeed,
				c.NewStep,
			)
		case totp.Remove:
			_, err = tx.Exec(
				ctx,
				`DELETE FROM pluto_auth_totp_factors WHERE account_id=$1`,
				row.ID,
			)
		case totp.Regenerate:
		default:
			return totp.ErrDenied
		}

		if err != nil {
			return err
		}

		if _, err := tx.Exec(
			ctx,
			`DELETE FROM pluto_auth_totp_recovery WHERE account_id=$1`,
			row.ID,
		); err != nil {
			return err
		}

		if p.Action != totp.Remove {
			if len(c.RecoveryDigests) != 10 {
				return totp.ErrDenied
			}

			for _, digest := range c.RecoveryDigests {
				if digest == (auth.Digest{}) {
					return totp.ErrDenied
				}

				if _, err := tx.Exec(
					ctx,
					`INSERT INTO pluto_auth_totp_recovery (account_id,digest)
     VALUES ($1,$2)`,
					row.ID,
					digest[:],
				); err != nil {
					return err
				}
			}
		}

		if err := q.SetSecondFactorPolicy(ctx, db.SetSecondFactorPolicyParams{
			ID: row.ID, SecondFactorRequired: p.Action != totp.Remove,
		}); err != nil {
			return err
		}

		if err := q.DeleteAccountChallenges(ctx, row.ID); err != nil {
			return err
		}

		if err := q.DeleteSubjectSessions(ctx, row.ID); err != nil {
			return err
		}

		_, err = tx.Exec(
			ctx,
			`DELETE FROM pluto_auth_totp_pending WHERE account_id=$1`,
			row.ID,
		)

		return err
	})
}

func currentStep(step int64, now time.Time) bool {
	return step >= 0 && step >= now.Unix()/30-1 && step <= now.Unix()/30+1
}

func insertSession(
	ctx context.Context,
	q *db.Queries,
	account auth.AccountState,
	p totp.Pending,
	c totp.Commit,
) error {
	session := c.Session

	method := auth.MethodTOTP
	if c.Recovery != (auth.Digest{}) {
		method = auth.MethodRecoveryCode
	}

	if account.Accepts(session) != nil ||
		session.Authentication.Primary != p.Primary ||
		!session.Authentication.PrimaryAt.Equal(p.PrimaryAt) ||
		session.Authentication.SecondFactor != method ||
		!session.IssuanceDeadline.Equal(p.Expires) ||
		c.SessionDigest == (auth.Digest{}) {
		return totp.ErrDenied
	}

	if err := q.CreateSession(ctx, db.CreateSessionParams{
		TokenDigest: c.SessionDigest[:],
		ID:          session.ID,
		SubjectID:   session.SubjectID,
		CreatedAt:   session.CreatedAt,
		ExpiresAt:   session.ExpiresAt,
		LastSeenAt:  session.LastSeenAt,
	}); err != nil {
		return err
	}

	count, err := q.BindLocalSession(ctx, db.BindLocalSessionParams{
		TokenDigest:       c.SessionDigest[:],
		AccountID:         session.SubjectID,
		CredentialVersion: session.CredentialVersion,
		PrimaryMethod: string(
			session.Authentication.Primary,
		),
		PrimaryAt: session.Authentication.PrimaryAt,
		SecondFactorMethod: string(
			session.Authentication.SecondFactor,
		),
		SecondFactorAt:   session.Authentication.SecondFactorAt,
		IssuanceDeadline: session.IssuanceDeadline,
	})
	if err != nil {
		return err
	}

	if count != 1 {
		return totp.ErrDenied
	}

	return nil
}
