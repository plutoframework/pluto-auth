// Package postgres implements typed session storage with pgx and sqlc.
// Schema application and cleanup scheduling are explicit application concerns.
package postgres

import (
	"context"
	_ "embed"
	"errors"
	"time"

	auth "github.com/plutoframework/pluto-auth"
	"github.com/plutoframework/pluto-auth/stores/postgres/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Schema is a reference migration. The application owns its migration history.
//
//go:embed schema.sql
var Schema string

// DBTX accepts a pool, connection, or transaction. Production concurrency
// requires a pool; a single pgx connection/transaction is not concurrency safe.
type DBTX interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type Store struct {
	queries *db.Queries
}

func New(database DBTX) (*Store, error) {
	if database == nil {
		return nil, auth.ErrInvalidConfig
	}

	return &Store{queries: db.New(database)}, nil
}

func (s *Store) Create(
	ctx context.Context,
	digest auth.Digest,
	session auth.Session,
) error {
	return s.queries.CreateSession(ctx, db.CreateSessionParams{
		TokenDigest: digest[:],
		ID:          session.ID,
		SubjectID:   session.SubjectID,
		CreatedAt:   session.CreatedAt,
		ExpiresAt:   session.ExpiresAt,
		LastSeenAt:  session.LastSeenAt,
	})
}

func (s *Store) Use(
	ctx context.Context,
	digest auth.Digest,
	now time.Time,
	idle time.Duration,
) (auth.Session, error) {
	row, err := s.queries.UseSession(ctx, db.UseSessionParams{
		Digest:           digest[:],
		NowAt:            now,
		IdleMicroseconds: idleMicroseconds(idle),
	})
	if err != nil {
		return auth.Session{}, storeError(err)
	}

	return auth.Session{
		ID:         row.ID,
		SubjectID:  row.SubjectID,
		CreatedAt:  row.CreatedAt,
		ExpiresAt:  row.ExpiresAt,
		LastSeenAt: row.LastSeenAt,
	}, nil
}

func (s *Store) Consume(
	ctx context.Context,
	digest auth.Digest,
	now time.Time,
	idle time.Duration,
) (auth.Session, error) {
	row, err := s.queries.ConsumeSession(ctx, db.ConsumeSessionParams{
		Digest:           digest[:],
		NowAt:            now,
		IdleMicroseconds: idleMicroseconds(idle),
	})
	if err != nil {
		return auth.Session{}, storeError(err)
	}

	return auth.Session{
		ID:         row.ID,
		SubjectID:  row.SubjectID,
		CreatedAt:  row.CreatedAt,
		ExpiresAt:  row.ExpiresAt,
		LastSeenAt: row.LastSeenAt,
	}, nil
}

func (s *Store) Delete(ctx context.Context, digest auth.Digest) error {
	return s.queries.DeleteSession(ctx, digest[:])
}

func (s *Store) DeleteSubject(ctx context.Context, subject string) error {
	return s.queries.DeleteSubjectSessions(ctx, subject)
}

func (s *Store) PruneExpired(
	ctx context.Context,
	now time.Time,
) (int64, error) {
	return s.queries.PruneExpiredSessions(ctx, now)
}

// PostgreSQL timestamps have microsecond precision. Round a positive timeout up
// so a sub-microsecond timeout never becomes the sentinel for disabled expiry.
func idleMicroseconds(idle time.Duration) int64 {
	value := idle.Microseconds()
	if idle > 0 && idle%time.Microsecond != 0 {
		value++
	}

	return value
}

func storeError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.ErrNotFound
	}

	return err
}

var _ auth.SessionStore = (*Store)(nil)
