package auth

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound        = errors.New("auth: session not found")
	ErrUnauthenticated = errors.New("auth: unauthenticated")
	ErrInvalidConfig   = errors.New("auth: invalid configuration")
	ErrInvalidSubject  = errors.New("auth: invalid subject")
)

// Digest is a SHA-256 digest of a cryptographically random session token.
// Stores persist this digest, never the bearer token.
type Digest [32]byte

// Session contains identity and lifetime metadata, never roles or credentials.
type Session struct {
	ID         string    `json:"id"`
	SubjectID  string    `json:"subject_id"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	// CredentialVersion is an optional issuance fence for local account stores.
	// Zero denotes an opaque session without a local credential binding.
	CredentialVersion int64    `json:"-"`
	Authentication    Evidence `json:"-"`
	// IssuanceDeadline is a transient Create-time bound, not session lifetime.
	IssuanceDeadline time.Time `json:"-"`
}

// IssuedSession is returned only at issuance. Token must never be logged.
// JSON encoding intentionally omits it; use the HTTP cookie adapter.
type IssuedSession struct {
	Session Session `json:"session"`
	Token   string  `json:"-"`
}

// SessionStore operations must honor cancellation and be concurrency safe.
// Use atomically rejects missing, expired, or idle sessions and updates activity.
// It must not recreate deleted sessions or extend ExpiresAt. Activity timestamps
// must never move backwards. Revocation affects subsequent Use calls; it cannot
// cancel requests that already authenticated. Delete operations are idempotent.
type SessionStore interface {
	Create(context.Context, Digest, Session) error
	Use(context.Context, Digest, time.Time, time.Duration) (Session, error)
	// Consume atomically validates and deletes a session for one-use rotation.
	Consume(context.Context, Digest, time.Time, time.Duration) (Session, error)
	Delete(context.Context, Digest) error
	DeleteSubject(context.Context, string) error
}

// Config is explicit and copied by New. Clock must be concurrency safe.
// ExpiresAt is always an absolute deadline, independent of activity.
type Config struct {
	TTL         time.Duration
	IdleTimeout time.Duration
	Clock       func() time.Time
}

func DefaultConfig() Config {
	return Config{
		TTL:         24 * time.Hour,
		IdleTimeout: 30 * time.Minute,
		Clock:       time.Now,
	}
}

// Active reports whether a record is inside its absolute and idle deadlines.
// It is exported so storage adapters can share the exact boundary semantics.
func Active(session Session, now time.Time, idle time.Duration) bool {
	if session.ID == "" || session.SubjectID == "" {
		return false
	}

	if now.Before(session.CreatedAt) || !now.Before(session.ExpiresAt) {
		return false
	}

	return idle == 0 || now.Before(session.LastSeenAt.Add(idle))
}
