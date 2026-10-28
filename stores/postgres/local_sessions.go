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

		if !row.Verified || row.Disabled || session.CredentialVersion <= 0 ||
			session.CredentialVersion != row.CredentialVersion {
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

		return q.BindLocalSession(ctx, db.BindLocalSessionParams{
			TokenDigest: digest[:], AccountID: session.SubjectID,
			CredentialVersion: session.CredentialVersion,
		})
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
	}, nil
}

func (s *LocalStore) Consume(ctx context.Context, digest auth.Digest,
	now time.Time, idle time.Duration,
) (auth.Session, error) {
	var session auth.Session

	err := s.transaction(ctx, func(q *db.Queries) error {
		version, err := q.LookupLocalSessionVersion(ctx, digest[:])
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
			CredentialVersion: version,
		}

		return nil
	})

	return session, err
}
