package postgres

import (
	"context"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/postgres/internal/db"
)

func (s *LocalStore) Create(ctx context.Context, digest auth.Digest,
	session auth.Session,
) error {
	return s.transaction(ctx, func(q *db.Queries) error {
		row, err := q.LockAccountID(ctx, session.SubjectID)
		if err != nil {
			if storeError(err) == auth.ErrNotFound {
				return auth.ErrUnauthenticated
			}

			return err
		}

		state := auth.AccountState{
			SubjectID:            row.ID,
			Version:              row.CredentialVersion,
			Disabled:             row.Disabled,
			SecondFactorRequired: row.SecondFactorRequired,
		}
		if !row.Verified || state.Accepts(session) != nil {
			return auth.ErrUnauthenticated
		}

		if err := q.CreateSession(ctx, db.CreateSessionParams{
			TokenDigest: digest[:],
			ID:          session.ID,
			SubjectID:   session.SubjectID,
			CreatedAt:   session.CreatedAt,
			ExpiresAt:   session.ExpiresAt,
			LastSeenAt:  session.LastSeenAt,
		}); err != nil {
			return err
		}

		count, err := q.BindLocalSession(ctx, db.BindLocalSessionParams{
			TokenDigest: digest[:], AccountID: session.SubjectID,
			CredentialVersion:  session.CredentialVersion,
			PrimaryMethod:      string(session.Authentication.Primary),
			PrimaryAt:          session.Authentication.PrimaryAt,
			SecondFactorMethod: string(session.Authentication.SecondFactor),
			SecondFactorAt:     session.Authentication.SecondFactorAt,
			IssuanceDeadline:   session.IssuanceDeadline,
		})
		if err != nil {
			return err
		}

		if count != 1 {
			return auth.ErrAuthenticationRequired
		}

		return nil
	})
}

func (s *LocalStore) Use(ctx context.Context, digest auth.Digest,
	now time.Time, idle time.Duration,
) (auth.Session, error) {
	row, err := s.queries.UseLocalSession(ctx, db.UseLocalSessionParams{
		Digest: digest[:], NowAt: now, IdleMicroseconds: idleMicroseconds(idle),
	})
	if err != nil {
		return auth.Session{}, storeError(err)
	}

	return auth.Session{
		ID: row.ID, SubjectID: row.SubjectID, CreatedAt: row.CreatedAt,
		ExpiresAt: row.ExpiresAt, LastSeenAt: row.LastSeenAt,
		CredentialVersion: row.CredentialVersion,
		Authentication: auth.Evidence{
			Primary:   auth.Method(row.PrimaryMethod),
			PrimaryAt: row.PrimaryAt,
			SecondFactor: auth.Method(
				row.SecondFactorMethod,
			),
			SecondFactorAt: row.SecondFactorAt,
		},
	}, nil
}

func (s *LocalStore) Consume(ctx context.Context, digest auth.Digest,
	now time.Time, idle time.Duration,
) (auth.Session, error) {
	var session auth.Session

	err := s.transaction(ctx, func(q *db.Queries) error {
		binding, err := q.LookupLocalSessionAuthentication(ctx, digest[:])
		if err != nil {
			return err
		}

		row, err := q.ConsumeLocalSession(ctx, db.ConsumeLocalSessionParams{
			Digest:           digest[:],
			NowAt:            now,
			IdleMicroseconds: idleMicroseconds(idle),
		})
		if err != nil {
			return err
		}

		session = auth.Session{
			ID:                row.ID,
			SubjectID:         row.SubjectID,
			CreatedAt:         row.CreatedAt,
			ExpiresAt:         row.ExpiresAt,
			LastSeenAt:        row.LastSeenAt,
			CredentialVersion: binding.CredentialVersion,
			Authentication: auth.Evidence{
				Primary: auth.Method(
					binding.PrimaryMethod,
				),
				PrimaryAt: binding.PrimaryAt,
				SecondFactor: auth.Method(
					binding.SecondFactorMethod,
				),
				SecondFactorAt: binding.SecondFactorAt,
			},
		}

		return nil
	})

	return session, err
}

// CreateAuthenticated atomically rechecks the current account and factor policy.
// It shares the exact row lock used by reset, disable and policy changes.
func (s *LocalStore) CreateAuthenticated(
	ctx context.Context,
	digest auth.Digest,
	session auth.Session,
) error {
	if session.Authentication.IsZero() {
		return auth.ErrUnauthenticated
	}

	return s.Create(ctx, digest, session)
}

func (s *LocalStore) AccountState(
	ctx context.Context,
	subject string,
) (auth.AccountState, error) {
	row, err := s.queries.LookupAccountID(ctx, subject)
	if err != nil {
		return auth.AccountState{}, storeError(err)
	}

	return auth.AccountState{
		SubjectID: row.ID, Version: row.CredentialVersion,
		Disabled: row.Disabled, SecondFactorRequired: row.SecondFactorRequired,
	}, nil
}

// SetSecondFactorRequired is a trusted policy operation, not factor enrollment.
// Enabling requires a configured, verified second-factor method and recovery path.
// Both directions advance the shared version and revoke sessions/challenges.
func (s *LocalStore) SetSecondFactorRequired(
	ctx context.Context,
	subject string,
	required bool,
) error {
	return s.transaction(ctx, func(q *db.Queries) error {
		row, err := q.LockAccountID(ctx, subject)
		if err != nil {
			return err
		}

		if row.Disabled {
			return auth.ErrUnauthenticated
		}

		if err := q.SetSecondFactorPolicy(ctx, db.SetSecondFactorPolicyParams{
			ID: subject, SecondFactorRequired: required,
		}); err != nil {
			return err
		}

		if err := q.DeleteAccountChallenges(ctx, subject); err != nil {
			return err
		}

		return q.DeleteSubjectSessions(ctx, subject)
	})
}

var _ auth.AccountSessionStore = (*LocalStore)(nil)
