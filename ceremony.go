package auth

import (
	"context"
	"time"
)

type Stage string

const (
	AwaitingPrimary Stage = "awaiting_primary"
	AwaitingFactor  Stage = "awaiting_factor"
	Authenticated   Stage = "authenticated"
)

// Ceremony is an immutable, server-local authentication decision. It does not
// verify credentials, store challenges or grant a session. Verified methods call
// its transitions only after completing their actual verification protocol.
// Never reconstruct it from browser JSON or use it as a pending session cookie.
type Ceremony struct {
	account  AccountState
	started  time.Time
	expires  time.Time
	required bool
	evidence Evidence
}

func NewCeremony(
	account AccountState,
	requireSecondFactor bool,
	now time.Time,
	lifetime time.Duration,
) (Ceremony, error) {
	if !account.valid() || now.IsZero() || lifetime <= 0 ||
		lifetime > 10*time.Minute {
		return Ceremony{}, ErrInvalidConfig
	}

	return Ceremony{
		account: account,
		started: now.UTC(), expires: now.Add(lifetime).UTC(),
		required: account.SecondFactorRequired || requireSecondFactor,
	}, nil
}

// Account returns a copy of server-owned state, not proof of authentication.
func (c Ceremony) Account() AccountState { return c.account }

// PrimaryEvidence returns server-verified primary metadata and the original
// ceremony deadline for durable method adapters. These values are not browser
// proof and must never be accepted from client JSON.
func (c Ceremony) PrimaryEvidence() (Method, time.Time, time.Time) {
	return c.evidence.Primary, c.evidence.PrimaryAt, c.expires
}

func (c Ceremony) Stage() Stage {
	if c.evidence.Primary == "" {
		return AwaitingPrimary
	}

	if c.required && c.evidence.SecondFactor == "" {
		return AwaitingFactor
	}

	return Authenticated
}

func (c Ceremony) active(now time.Time) error {
	if !c.account.valid() || c.started.IsZero() || now.Before(c.started) ||
		!now.Before(c.expires) {
		return ErrCeremonyExpired
	}

	return nil
}

func (c Ceremony) PrimaryVerified(
	method Method,
	now time.Time,
) (Ceremony, error) {
	if err := c.active(now); err != nil {
		return Ceremony{}, err
	}

	if c.Stage() != AwaitingPrimary || !method.primary() {
		return Ceremony{}, ErrCeremonyTransition
	}

	c.evidence.Primary = method
	c.evidence.PrimaryAt = now.UTC()

	return c, nil
}

func (c Ceremony) SecondFactorVerified(
	method Method,
	now time.Time,
) (Ceremony, error) {
	if err := c.active(now); err != nil {
		return Ceremony{}, err
	}

	if c.Stage() != AwaitingFactor || !method.secondary() ||
		now.Before(c.evidence.PrimaryAt) {
		return Ceremony{}, ErrCeremonyTransition
	}

	c.evidence.SecondFactor = method
	c.evidence.SecondFactorAt = now.UTC()

	return c, nil
}

// Authentication is a completed server-local decision, not a reusable browser
// token. The host owns method proof consumption and any cross-request challenge.
// Persistence rechecks the current account fence when a session is issued.
type Authentication struct {
	account  AccountState
	evidence Evidence
	expires  time.Time
}

func (c Ceremony) Complete(now time.Time) (Authentication, error) {
	if err := c.active(now); err != nil {
		return Authentication{}, err
	}

	if c.Stage() != Authenticated || c.evidence.Check(Requirement{
		SecondFactor: c.required,
	}, now) != nil {
		return Authentication{}, ErrAuthenticationRequired
	}

	return Authentication{
		account:  c.account,
		evidence: c.evidence,
		expires:  c.expires,
	}, nil
}

func (m *Manager) StartAuthenticated(
	ctx context.Context,
	proof Authentication,
) (IssuedSession, error) {
	now := m.config.Clock().UTC()
	if !proof.account.valid() || !now.Before(proof.expires) ||
		proof.evidence.Check(Requirement{
			SecondFactor: proof.account.SecondFactorRequired,
		}, now) != nil {
		return IssuedSession{}, ErrAuthenticationRequired
	}

	if _, ok := m.store.(AccountSessionStore); !ok {
		return IssuedSession{}, ErrInvalidConfig
	}

	return m.issue(ctx, proof.account.SubjectID, proof.account.Version,
		now, now.Add(m.config.TTL), proof.evidence, proof.expires)
}
