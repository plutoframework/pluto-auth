package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Manager struct {
	store  SessionStore
	config Config
}

func New(store SessionStore, config Config) (*Manager, error) {
	if store == nil || config.Clock == nil || config.TTL <= 0 ||
		config.IdleTimeout < 0 || config.IdleTimeout > config.TTL {
		return nil, ErrInvalidConfig
	}

	return &Manager{store: store, config: config}, nil
}

// Start issues a fresh session after the caller has verified credentials.
// It does not authenticate a subject merely because its identifier is supplied.
func (m *Manager) Start(
	ctx context.Context,
	subjectID string,
) (IssuedSession, error) {
	now := m.config.Clock().UTC()

	return m.issue(ctx, subjectID, now, now.Add(m.config.TTL))
}

func (m *Manager) issue(
	ctx context.Context,
	subjectID string,
	now time.Time,
	expires time.Time,
) (IssuedSession, error) {
	if err := ctx.Err(); err != nil {
		return IssuedSession{}, err
	}

	if strings.TrimSpace(subjectID) == "" || len(subjectID) > 256 {
		return IssuedSession{}, ErrInvalidSubject
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return IssuedSession{}, fmt.Errorf("auth: generate token: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(secret)

	digest, err := TokenDigest(token)
	if err != nil {
		return IssuedSession{}, err
	}

	session := Session{
		ID:         rand.Text(),
		SubjectID:  subjectID,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  expires,
	}

	if err := m.store.Create(ctx, digest, session); err != nil {
		return IssuedSession{}, fmt.Errorf("auth: create session: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return IssuedSession{}, err
	}

	return IssuedSession{Session: session, Token: token}, nil
}

func (m *Manager) Authenticate(
	ctx context.Context,
	token string,
) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}

	digest, err := TokenDigest(token)
	if err != nil {
		return Session{}, ErrUnauthenticated
	}

	now := m.config.Clock().UTC()

	session, err := m.store.Use(ctx, digest, now, m.config.IdleTimeout)
	if errors.Is(err, ErrNotFound) {
		return Session{}, ErrUnauthenticated
	}

	if err != nil {
		return Session{}, fmt.Errorf("auth: use session: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return Session{}, err
	}

	if !Active(session, now, m.config.IdleTimeout) {
		return Session{}, ErrUnauthenticated
	}

	return session, nil
}

func (m *Manager) Revoke(ctx context.Context, token string) error {
	digest, err := TokenDigest(token)
	if err != nil {
		return err
	}

	return m.store.Delete(ctx, digest)
}

func (m *Manager) RevokeSubject(ctx context.Context, subjectID string) error {
	if strings.TrimSpace(subjectID) == "" {
		return ErrInvalidSubject
	}

	return m.store.DeleteSubject(ctx, subjectID)
}

// Rotate revokes the current token before issuing its replacement. Failure
// after revocation requires a new login; an old token is never restored.
// The replacement preserves the original absolute deadline.
func (m *Manager) Rotate(
	ctx context.Context,
	token string,
) (IssuedSession, error) {
	digest, err := TokenDigest(token)
	if err != nil {
		return IssuedSession{}, err
	}

	now := m.config.Clock().UTC()

	session, err := m.store.Consume(ctx, digest, now, m.config.IdleTimeout)
	if errors.Is(err, ErrNotFound) {
		return IssuedSession{}, ErrUnauthenticated
	}

	if err != nil {
		return IssuedSession{}, err
	}

	if !Active(session, now, m.config.IdleTimeout) {
		return IssuedSession{}, ErrUnauthenticated
	}

	return m.issue(ctx, session.SubjectID, now, session.ExpiresAt)
}
