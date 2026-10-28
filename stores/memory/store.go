// Package memory provides a process-local store for tests and development.
// Restarts revoke all sessions. Multiple processes require shared persistence.
package memory

import (
	"context"
	"errors"
	"sync"
	"time"

	auth "github.com/plutoframework/pluto-auth"
)

type record struct {
	session auth.Session
}

type Store struct {
	mu       sync.Mutex
	sessions map[auth.Digest]record
	capacity int
}

// New bounds retained records. Expired records are pruned during creation.
func New(capacity int) (*Store, error) {
	if capacity <= 0 {
		return nil, auth.ErrInvalidConfig
	}

	return &Store{
		sessions: make(map[auth.Digest]record),
		capacity: capacity,
	}, nil
}

func (s *Store) Create(
	ctx context.Context,
	digest auth.Digest,
	session auth.Session,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	if _, exists := s.sessions[digest]; exists {
		return errors.New("auth: duplicate session")
	}

	for key, item := range s.sessions {
		if !session.CreatedAt.Before(item.session.ExpiresAt) {
			delete(s.sessions, key)
		}
	}

	if len(s.sessions) >= s.capacity {
		return errors.New("auth: session capacity reached")
	}

	s.sessions[digest] = record{session: session}

	return nil
}

func (s *Store) Use(
	ctx context.Context,
	digest auth.Digest,
	now time.Time,
	idle time.Duration,
) (auth.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return auth.Session{}, err
	}

	item, exists := s.sessions[digest]
	if !exists || !auth.Active(item.session, now, idle) {
		return auth.Session{}, auth.ErrNotFound
	}

	if now.After(item.session.LastSeenAt) {
		item.session.LastSeenAt = now
	}

	s.sessions[digest] = item

	return item.session, nil
}

func (s *Store) Delete(ctx context.Context, digest auth.Digest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	delete(s.sessions, digest)

	return nil
}

func (s *Store) Consume(
	ctx context.Context,
	digest auth.Digest,
	now time.Time,
	idle time.Duration,
) (auth.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return auth.Session{}, err
	}

	item, exists := s.sessions[digest]
	if !exists || !auth.Active(item.session, now, idle) {
		return auth.Session{}, auth.ErrNotFound
	}

	delete(s.sessions, digest)

	return item.session, nil
}

func (s *Store) DeleteSubject(ctx context.Context, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	for digest, item := range s.sessions {
		if item.session.SubjectID == subject {
			delete(s.sessions, digest)
		}
	}

	return nil
}

var _ auth.SessionStore = (*Store)(nil)
