package auth

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrAuthenticationRequired = errors.New(
		"auth: further authentication required",
	)
	ErrCeremonyExpired = errors.New(
		"auth: authentication ceremony expired",
	)
	ErrCeremonyTransition = errors.New(
		"auth: invalid authentication transition",
	)
)

type Method string

const (
	MethodPassword     Method = "password"
	MethodOIDC         Method = "oidc"
	MethodOAuth        Method = "oauth"
	MethodPasskey      Method = "passkey"
	MethodTOTP         Method = "totp"
	MethodRecoveryCode Method = "recovery_code"
)

func (method Method) primary() bool {
	switch method {
	case MethodPassword, MethodOIDC, MethodOAuth, MethodPasskey:
		return true
	default:
		return false
	}
}

func (method Method) secondary() bool {
	return method == MethodTOTP || method == MethodRecoveryCode
}

// AccountState is the shared issuance fence, not a profile or permission grant.
// Method implementations load it from trusted persistence after verification.
type AccountState struct {
	SubjectID            string
	Version              int64
	Disabled             bool
	SecondFactorRequired bool
}

func (account AccountState) valid() bool {
	return account.SubjectID != "" && len(account.SubjectID) <= 256 &&
		utf8.ValidString(account.SubjectID) &&
		strings.TrimSpace(account.SubjectID) == account.SubjectID &&
		account.Version > 0 && !account.Disabled
}

// Evidence records verified methods and their original verification times.
// Rotation must copy these values, never replace them with rotation time.
// This is server-owned data; a decoded client value proves nothing.
type Evidence struct {
	Primary        Method    `json:"-"`
	PrimaryAt      time.Time `json:"-"`
	SecondFactor   Method    `json:"-"`
	SecondFactorAt time.Time `json:"-"`
}

func (e Evidence) IsZero() bool {
	return e.Primary == "" && e.PrimaryAt.IsZero() &&
		e.SecondFactor == "" && e.SecondFactorAt.IsZero()
}

func (e Evidence) valid(now time.Time) bool {
	if !e.Primary.primary() || e.PrimaryAt.IsZero() || now.Before(e.PrimaryAt) {
		return false
	}

	if e.SecondFactor == "" {
		return e.SecondFactorAt.IsZero()
	}

	return e.SecondFactor.secondary() && !e.SecondFactorAt.IsZero() &&
		!e.SecondFactorAt.Before(e.PrimaryAt) && !now.Before(e.SecondFactorAt)
}

// Requirement adds freshness and/or a verified second factor to authentication.
// It never replaces current permission, account or resource checks.
type Requirement struct {
	MaxAge       time.Duration
	SecondFactor bool
}

func (requirement Requirement) Validate() error {
	if requirement.MaxAge < 0 {
		return ErrInvalidConfig
	}

	return nil
}

func (e Evidence) Check(requirement Requirement, now time.Time) error {
	if err := requirement.Validate(); err != nil {
		return err
	}

	if !e.valid(now) || requirement.SecondFactor && e.SecondFactor == "" {
		return ErrAuthenticationRequired
	}

	if requirement.MaxAge > 0 &&
		!now.Before(e.PrimaryAt.Add(requirement.MaxAge)) {
		return ErrAuthenticationRequired
	}

	return nil
}

// AccountSessionStore must check account state, version and factor policy under
// the same lock/transaction as CreateAuthenticated. Use/Consume must reject stale
// or disabled accounts. Legacy Create must not bypass required-factor policy.
// Implementations must preserve Evidence during Use, Consume and rotation.
// Recheck a nonzero IssuanceDeadline at the persistence write, after lock waits.
type AccountSessionStore interface {
	SessionStore
	CreateAuthenticated(context.Context, Digest, Session) error
}

// Accepts is shared validation for account-backed persistence implementations.
// Call under the account issuance fence; a prior lookup alone is insufficient.
func (account AccountState) Accepts(session Session) error {
	if !account.valid() || session.SubjectID != account.SubjectID ||
		session.CredentialVersion != account.Version {
		return ErrUnauthenticated
	}

	if session.Authentication.IsZero() && !account.SecondFactorRequired {
		return nil
	}

	if err := session.Authentication.Check(Requirement{
		SecondFactor: account.SecondFactorRequired,
	}, session.CreatedAt); err != nil {
		return ErrUnauthenticated
	}

	return nil
}

// CheckAuthentication checks evidence from an already authenticated session.
// It does not look up a token or establish current account/resource authority.
func (m *Manager) CheckAuthentication(
	session Session,
	requirement Requirement,
) error {
	now := m.config.Clock().UTC()
	if !Active(session, now, m.config.IdleTimeout) {
		return ErrUnauthenticated
	}

	return session.Authentication.Check(requirement, now)
}
